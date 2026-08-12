"""Tests for the full-AUR baseline corpus builder."""

import gzip
import io
import json
import tarfile
from unittest.mock import patch

from trustsight.full_aur.metadata import fetch_metadata


class _ChunkReader:
    """Simulate a streaming HTTP response."""

    def __init__(self, chunks: list[bytes], headers: dict[str, str] = None):
        self._chunks = list(chunks)
        self.headers = headers or {}

    def read(self, size: int = -1) -> bytes:
        if not self._chunks:
            return b""
        if size < 0 or size >= len(self._chunks[0]):
            return self._chunks.pop(0)
        chunk = self._chunks[0][:size]
        self._chunks[0] = self._chunks[0][size:]
        return chunk


def test_fetch_metadata_on_progress_callback():
    """on_progress callback is called during download with correct pos/total."""

    entries = [
        {"Name": "pkg-a", "Version": "1.0", "Maintainer": "alice"},
        {"Name": "pkg-b", "Version": "2.0", "Maintainer": "bob"},
    ]
    raw = gzip.compress(json.dumps(entries).encode())
    total = len(raw)

    reader = _ChunkReader([raw[:total // 2], raw[total // 2:]], {"Content-Length": str(total)})

    with patch("trustsight.full_aur.metadata.urlopen", return_value=reader):
        calls: list[tuple[int, int]] = []
        result = fetch_metadata(on_progress=lambda pos, t: calls.append((pos, t)))

    assert result == {"pkg-a": entries[0], "pkg-b": entries[1]}
    assert len(calls) >= 1, "on_progress was never called"
    for pos, t in calls:
        assert t == total, f"expected total={total}, got {t}"
    assert calls[-1][0] == total, "final progress must match Content-Length"


def test_fetch_metadata_no_callback():
    """fetch_metadata works without on_progress."""
    entries = [{"Name": "pkg-a", "Version": "1.0"}]
    raw = gzip.compress(json.dumps(entries).encode())

    reader = _ChunkReader([raw], {"Content-Length": str(len(raw))})
    with patch("trustsight.full_aur.metadata.urlopen", return_value=reader):
        result = fetch_metadata()

    assert result == {"pkg-a": entries[0]}


def _snapshot_tarball(name: str, pkgbuild: str, extra: dict[str, bytes] | None = None) -> bytes:
    """Build an AUR-style snapshot tarball in memory."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = pkgbuild.encode()
        info = tarfile.TarInfo(f"{name}/PKGBUILD")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
        for path, content in (extra or {}).items():
            info = tarfile.TarInfo(f"{name}/{path}")
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def test_fetch_pkgbuild_with_tree_extracts_manifest():
    """The snapshot path returns the PKGBUILD plus a committed-file manifest."""
    from trustsight.full_aur import fetch as F

    elf = b"\x7fELF" + b"\x00" * 32
    body = _snapshot_tarball("demo", "pkgname=demo\npkgver=1.0\n", {
        "evil": elf,
        "icon.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 8,
    })
    with patch.object(F, "_http_get", return_value=body):
        text, manifest, trailer_finding = F.fetch_pkgbuild_with_tree("demo")

    assert text == "pkgname=demo\npkgver=1.0\n"
    assert manifest is not None
    assert trailer_finding is None
    heads = dict(manifest)
    assert "demo/PKGBUILD" in heads
    assert heads["demo/evil"] == elf
    assert heads["demo/icon.png"].startswith(b"\x89PNG")


def test_fetch_pkgbuild_with_tree_falls_back_to_cgit():
    """Without a usable snapshot tarball, the cgit text-only path is used."""
    from trustsight.full_aur import fetch as F

    with patch.object(F, "_http_get", side_effect=[None, b"pkgname=demo\n"]):
        text, manifest, trailer_finding = F.fetch_pkgbuild_with_tree("demo")

    assert text == "pkgname=demo\n"
    assert manifest is None
    assert trailer_finding is None


def test_fetch_pkgbuild_with_tree_flags_trailing_archive_bytes():
    """The snapshot path surfaces R122 when the archive has trailing junk."""
    from trustsight.full_aur import fetch as F

    body = _snapshot_tarball("demo", "pkgname=demo\npkgver=1.0\n") + b"JUNK"
    with patch.object(F, "_http_get", return_value=body):
        text, manifest, trailer_finding = F.fetch_pkgbuild_with_tree("demo")

    assert text == "pkgname=demo\npkgver=1.0\n"
    assert manifest is not None
    assert trailer_finding is not None
    assert trailer_finding["rule_id"] == "R122"
    assert trailer_finding["params"]["kind"] == "gzip"
    assert trailer_finding["params"]["trailing_bytes"] == 4


# --- parallel prefetch for the bootstrap (ordered, error-tolerant) ---


def test_iter_prefetched_preserves_order_under_concurrency():
    import random
    import time

    from trustsight.full_aur.pipeline import _iter_prefetched

    def fetch(name):
        time.sleep(random.uniform(0, 0.005))  # variable latency
        return (f"pkgbuild-{name}", None, None)

    names = [f"pkg-{i}" for i in range(60)]
    out = list(_iter_prefetched(names, fetch, workers=8))
    assert [n for n, _ in out] == names
    assert out[3][1] == ("pkgbuild-pkg-3", None, None)


def test_iter_prefetched_yields_none_for_a_failing_fetch():
    from trustsight.full_aur.pipeline import _iter_prefetched

    def fetch(name):
        if name == "boom":
            raise RuntimeError("network")
        return (f"ok-{name}", None, None)

    out = dict(_iter_prefetched(["a", "boom", "b"], fetch, workers=4))
    assert out["boom"] == (None, None, None)
    assert out["a"] == ("ok-a", None, None)


# --- polite fetching: rate cap + backoff on 429/5xx/reset ---


def _fast_fetch(monkeypatch):
    """Neutralise the real sleeps so retry logic runs instantly in tests."""
    import trustsight.full_aur.fetch as fetch
    monkeypatch.setattr(fetch, "_MIN_REQUEST_INTERVAL", 0.0)
    monkeypatch.setattr(fetch, "_BACKOFF_BASE", 0.0)
    monkeypatch.setattr(fetch, "_BACKOFF_MAX", 0.0)
    monkeypatch.setattr("time.sleep", lambda *_: None)
    return fetch


def test_http_get_retries_429_then_succeeds(monkeypatch):
    import urllib.error

    fetch = _fast_fetch(monkeypatch)
    calls = {"n": 0}

    class _Resp:
        def read(self, _n): 
            if not hasattr(self, "_done"):
                self._done = True
                return b"payload"
            return b""

    def fake_urlopen(req, timeout=0):
        calls["n"] += 1
        if calls["n"] < 3:
            raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests",
                                         {"Retry-After": "0"}, None)
        return _Resp()

    monkeypatch.setattr(fetch.urllib.request, "urlopen", fake_urlopen)
    assert fetch._http_get("https://x/y") == b"payload"
    assert calls["n"] == 3   # two 429s, then success


def test_http_get_retries_connection_reset(monkeypatch):
    import urllib.error

    fetch = _fast_fetch(monkeypatch)
    calls = {"n": 0}

    class _Resp:
        def read(self, _n):
            if not hasattr(self, "_done"):
                self._done = True
                return b"ok"
            return b""

    def fake_urlopen(req, timeout=0):
        calls["n"] += 1
        if calls["n"] == 1:
            raise urllib.error.URLError(ConnectionResetError(104, "reset"))
        return _Resp()

    monkeypatch.setattr(fetch.urllib.request, "urlopen", fake_urlopen)
    assert fetch._http_get("https://x/y") == b"ok"
    assert calls["n"] == 2


def test_http_get_does_not_retry_a_404(monkeypatch):
    import urllib.error

    fetch = _fast_fetch(monkeypatch)
    calls = {"n": 0}

    def fake_urlopen(req, timeout=0):
        calls["n"] += 1
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)

    monkeypatch.setattr(fetch.urllib.request, "urlopen", fake_urlopen)
    assert fetch._http_get("https://x/y") is None
    assert calls["n"] == 1   # 404 is terminal, no retries


def test_http_get_gives_up_after_max_retries(monkeypatch):
    import urllib.error

    fetch = _fast_fetch(monkeypatch)
    calls = {"n": 0}

    def fake_urlopen(req, timeout=0):
        calls["n"] += 1
        raise urllib.error.HTTPError(req.full_url, 503, "Unavailable", {}, None)

    monkeypatch.setattr(fetch.urllib.request, "urlopen", fake_urlopen)
    assert fetch._http_get("https://x/y") is None
    assert calls["n"] == fetch._MAX_RETRIES + 1
