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
        text, manifest, trailer_finding, refused = F.fetch_pkgbuild_with_tree("demo")

    assert text == "pkgname=demo\npkgver=1.0\n"
    assert manifest is not None
    assert trailer_finding is None
    assert refused is False
    heads = dict(manifest)
    assert "demo/PKGBUILD" in heads
    assert heads["demo/evil"] == elf
    assert heads["demo/icon.png"].startswith(b"\x89PNG")


def test_fetch_pkgbuild_with_tree_falls_back_to_cgit():
    """Without a usable snapshot tarball, the cgit text-only path is used."""
    from trustsight.full_aur import fetch as F

    with patch.object(F, "_http_get", side_effect=[None, b"pkgname=demo\n"]):
        text, manifest, trailer_finding, refused = F.fetch_pkgbuild_with_tree("demo")

    assert text == "pkgname=demo\n"
    assert manifest is None
    assert trailer_finding is None
    assert refused is False  # absent, not refused


def test_fetch_pkgbuild_with_tree_flags_trailing_archive_bytes():
    """The snapshot path surfaces H070 when the archive has trailing junk."""
    from trustsight.full_aur import fetch as F

    body = _snapshot_tarball("demo", "pkgname=demo\npkgver=1.0\n") + b"JUNK"
    with patch.object(F, "_http_get", return_value=body):
        text, manifest, trailer_finding, refused = F.fetch_pkgbuild_with_tree("demo")

    assert text == "pkgname=demo\npkgver=1.0\n"
    assert manifest is not None
    assert trailer_finding is not None
    assert trailer_finding["rule_id"] == "H070"
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
        return (f"ok-{name}", None, None, False)

    out = dict(_iter_prefetched(["a", "boom", "b"], fetch, workers=4))
    # The placeholder must match the 4-tuple shape ``_store`` unpacks; a
    # 3-tuple here raised ValueError out of the analysis loop and aborted
    # the whole cycle.
    assert out["boom"] == (None, None, None, False)
    assert out["a"] == ("ok-a", None, None, False)


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


def test_a_raising_fetch_is_tolerated_and_the_cycle_completes(monkeypatch):
    """The prefetch error path must reach ``_store`` in the shape it unpacks.

    ``_iter_prefetched`` yields a placeholder for a fetch that raised; it
    used to be a 3-tuple, so ``_store``'s four-value unpack raised
    ValueError, escaping the analysis loop (the enclosing try only has a
    finally for the progress bar) and aborting the whole corpus cycle.
    """
    import trustsight.full_aur.pipeline as pipeline

    saved: dict = {}
    monkeypatch.setattr(pipeline, "fetch_metadata",
                        lambda *a, **k: {"demo": {"Version": "1.0", "Maintainer": "a"}})
    monkeypatch.setattr(pipeline, "load_metadata",
                        lambda *a, **k: {"demo": {"Version": "1.0", "Maintainer": "a"}})
    monkeypatch.setattr(pipeline, "diff_metadata",
                        lambda old, new: {"demo": "modified"})
    monkeypatch.setattr(pipeline, "load_resume_state", lambda *a, **k: None)
    monkeypatch.setattr(pipeline, "fetch_pkgbuild_with_tree",
                        lambda *a, **k: (_ for _ in ()).throw(
                            RuntimeError("network")))
    monkeypatch.setattr(pipeline, "is_reserved_name", lambda _n: False)
    monkeypatch.setattr(pipeline, "_pkg_or_base", lambda _m: "demo")
    monkeypatch.setattr(pipeline, "save_metadata", lambda *a, **k: None)
    monkeypatch.setattr(pipeline, "clear_resume_state", lambda: None)
    monkeypatch.setattr(pipeline, "_run_corpus_sweep", lambda *a, **k: [])
    monkeypatch.setattr(pipeline, "record_alerts", lambda *a, **k: [])
    monkeypatch.setattr(pipeline, "save_resume_state",
                        lambda state: saved.update(state))

    result = pipeline.run_baseline_build()

    # A fetch failure is marked done, so a resume does not retry it forever.
    assert result.processed == 1
    assert saved.get("processed") == ["demo"]


def test_a_not_vetted_package_survives_the_cycle_and_is_retried(monkeypatch):
    """A6: the tokenizer sandbox failing one package must not abort the cycle.

    ``run_baseline_build`` analyses every changed package in one loop, so an
    uncaught ``TokenizerUnavailable`` would end a whole bootstrap.  The
    package must instead be skipped, left out of the resume set so a later
    pass retries it once the sandbox can answer, and never persisted.
    """
    import trustsight.full_aur.pipeline as pipeline
    from trustsight.tokenizer import TokenizerUnavailable

    saved: dict = {}
    monkeypatch.setattr(pipeline, "fetch_metadata",
                        lambda *a, **k: {"demo": {"Version": "1.0", "Maintainer": "a"}})
    monkeypatch.setattr(pipeline, "load_metadata",
                        lambda *a, **k: {"demo": {"Version": "1.0", "Maintainer": "a"}})
    monkeypatch.setattr(pipeline, "diff_metadata",
                        lambda old, new: {"demo": "modified"})
    monkeypatch.setattr(pipeline, "load_resume_state", lambda *a, **k: None)
    monkeypatch.setattr(pipeline, "fetch_pkgbuild_with_tree",
                        lambda *a, **k: ("pkgver=1\n", None, None, False))
    monkeypatch.setattr(pipeline, "get_pkgbuild_snapshot", lambda *a, **k: None)
    monkeypatch.setattr(pipeline, "is_reserved_name", lambda _n: False)
    monkeypatch.setattr(pipeline, "_pkg_or_base", lambda _m: "demo")
    monkeypatch.setattr(pipeline, "source_repos_from_pkgbuild", lambda *a, **k: [])
    monkeypatch.setattr(pipeline, "save_pkgbuild_snapshot", lambda **k: None)
    monkeypatch.setattr(pipeline, "save_package_profile", lambda **k: None)
    monkeypatch.setattr(pipeline, "clear_resume_state", lambda: None)
    monkeypatch.setattr(pipeline, "save_metadata", lambda *a, **k: None)
    monkeypatch.setattr(pipeline, "_run_corpus_sweep", lambda *a, **k: [])
    monkeypatch.setattr(pipeline, "record_alerts", lambda *a, **k: [])
    monkeypatch.setattr(pipeline, "save_resume_state",
                        lambda state: saved.update(state))
    monkeypatch.setattr(pipeline, "analyze_package_text",
                        lambda *a, **k: (_ for _ in ()).throw(
                            TokenizerUnavailable("boom")))

    result = pipeline.run_baseline_build()

    assert result.processed == 0
    assert saved.get("processed") == []


def test_corpus_diff_uses_the_shell_aware_line_splitter():
    """A U+2028 is not a line break to the corpus diff, as it is not to makepkg.

    Python's ``splitlines`` breaks on U+2028; the shell-aware ``split_lines``
    does not.  The corpus adapter used the former and the git adapter the
    latter, so identical recipe texts produced different hunk boundaries and
    rules could fire on one path and not the other.
    """
    from trustsight.full_aur.analyze import _make_diff_text
    from trustsight.tokenizer import split_lines as shell_split

    old = "pkgver=1.0\n"
    new = "pkgver=1.1  # \u2028 note\n"
    corpus = _make_diff_text(old, new)
    # The U+2028 stays inside the added line rather than splitting it, which
    # is what Python's splitlines would have done.
    added = [ln for ln in shell_split(corpus) if ln.startswith("+") and "note" in ln]
    assert len(added) == 1 and "\u2028" in added[0]


def test_load_snapshot_treats_non_object_json_as_corrupt(tmp_path):
    """A snapshot that is valid JSON but not an object reads as corrupt.

    ``data.get`` on a list or a string raised AttributeError, which escaped
    unguarded callers (``corpus pivot``, the exporter) as a raw traceback;
    unparseable JSON already degraded to None, and this is the same case.
    """
    from trustsight.full_aur.metadata import load_snapshot

    bad_list = tmp_path / "list.json"
    bad_list.write_text("[]")
    assert load_snapshot(bad_list) is None

    bad_str = tmp_path / "str.json"
    bad_str.write_text('"x"')
    assert load_snapshot(bad_str) is None

    good = tmp_path / "good.json"
    good.write_text('{"snapshot_time": 5, "packages": {"p": {}}}')
    assert load_snapshot(good) == ({"p": {}}, 5)


def test_removals_only_cycle_still_records_the_adoption_feed(monkeypatch):
    """A delta with only removals must still reach ``_record_cycle_feed``.

    The ``if not to_process:`` early return used to run before the feed was
    recorded, silently dropping removal events from cycle_events and skewing
    the Class D baselines derived from them (H073's introduction rate,
    H058's maintainer activity).
    """
    import trustsight.full_aur.pipeline as pipeline

    old = {
        "keep": {"Version": "1.0", "Maintainer": "a", "LastModified": 100},
        "gone": {"Version": "2.0", "Maintainer": "b", "LastModified": 200},
    }
    new = {"keep": {"Version": "1.0", "Maintainer": "a", "LastModified": 100}}
    recorded: list[dict] = []
    monkeypatch.setattr(pipeline, "fetch_metadata", lambda *a, **k: new)
    monkeypatch.setattr(pipeline, "load_metadata", lambda *a, **k: old)
    monkeypatch.setattr(pipeline, "load_resume_state", lambda *a, **k: None)
    monkeypatch.setattr(pipeline, "save_metadata", lambda *a, **k: None)
    monkeypatch.setattr(pipeline, "clear_resume_state", lambda: None)
    monkeypatch.setattr(pipeline, "record_cycle_events",
                        lambda events: recorded.extend(events))

    result = pipeline.run_baseline_build()

    assert result.removed == 1 and result.processed == 0
    assert [e["package_name"] for e in recorded] == ["gone"]
    assert recorded[0]["status"] == "removed"


def _stub_cycle(monkeypatch, pipeline, scores_by_name, order=None):
    """Wire a two-package delta cycle with controllable per-package scores."""
    from types import SimpleNamespace

    meta = {name: {"Version": "1.0", "Maintainer": "m"}
            for name in scores_by_name}
    monkeypatch.setattr(pipeline, "fetch_metadata", lambda *a, **k: dict(meta))
    monkeypatch.setattr(pipeline, "load_metadata", lambda *a, **k: dict(meta))
    monkeypatch.setattr(pipeline, "diff_metadata",
                        lambda old, new: {name: "modified" for name in meta})
    monkeypatch.setattr(pipeline, "load_resume_state", lambda *a, **k: None)
    monkeypatch.setattr(pipeline, "fetch_pkgbuild_with_tree",
                        lambda *a, **k: ("pkgbuild", None, None, False))
    monkeypatch.setattr(pipeline, "is_reserved_name", lambda _n: False)
    monkeypatch.setattr(pipeline, "_pkg_or_base", lambda _m: "demo")
    monkeypatch.setattr(pipeline, "save_resume_state", lambda state: None)
    monkeypatch.setattr(pipeline, "clear_resume_state", lambda: None)
    monkeypatch.setattr(pipeline, "_run_corpus_sweep", lambda *a, **k: [])
    monkeypatch.setattr(pipeline, "record_alerts", lambda *a, **k: [])
    if order is not None:
        monkeypatch.setattr(pipeline, "save_metadata",
                            lambda *a, **k: order.append("snapshot"))
        monkeypatch.setattr(pipeline, "_record_cycle_feed",
                            lambda *a, **k: order.append("feed"))
    monkeypatch.setattr(
        pipeline, "analyze_package_text",
        lambda pkg_name, **kw: SimpleNamespace(
            new_version="1.0", final_score=scores_by_name[pkg_name],
            score_breakdown=[], ioc_matches=[]),
    )


def test_a_capped_cycle_still_reports_its_over_threshold_packages(monkeypatch):
    """A capped chunk returns before the sweep, but its worst packages must
    still be on the cycle's alert lists.

    The bootstrap is ~60 chunks and the alert lists were computed only after
    the partial-cycle return, so every chunk but the last reported nothing:
    the worst findings of a whole bootstrap never notified.
    """
    import trustsight.full_aur.pipeline as pipeline

    _stub_cycle(monkeypatch, pipeline, {"a-hot": 90, "z-calm": 5})
    monkeypatch.setattr(pipeline, "_max_per_cycle", lambda: 1)

    result = pipeline.run_baseline_build()

    # The chunk is partial, and its scores are still reported.
    assert result.processed == 1
    assert result.flagged == [("a-hot", 90)]
    assert result.over_threshold == [("a-hot", 90)]
    assert result.detail["a-hot"]["score"] == 90
    assert result.detail["a-hot"]["new_version"] == "1.0"


def test_the_feed_is_recorded_before_the_snapshot_advances(monkeypatch):
    """A crash between advancing the snapshot and recording the feed lost
    the cycle from the adoption baselines forever; the feed lands first."""
    import trustsight.full_aur.pipeline as pipeline

    order: list[str] = []
    _stub_cycle(monkeypatch, pipeline, {"demo": 5}, order=order)

    pipeline.run_baseline_build()

    assert order == ["feed", "snapshot"]


# --- --since backfill ---

_DAY = 86400


def _stub_since_cycle(monkeypatch, pipeline, packages):
    """Wire a backfill cycle: *packages* is {name: (last_modified, score)}."""
    from types import SimpleNamespace

    meta = {name: {"Version": "1.0", "Maintainer": "m", "LastModified": ts}
            for name, (ts, _score) in packages.items()}
    monkeypatch.setattr(pipeline, "fetch_metadata", lambda *a, **k: dict(meta))
    monkeypatch.setattr(pipeline, "load_metadata", lambda *a, **k: dict(meta))
    monkeypatch.setattr(pipeline, "diff_metadata", lambda old, new: {})
    monkeypatch.setattr(pipeline, "load_resume_state", lambda *a, **k: None)
    monkeypatch.setattr(pipeline, "fetch_pkgbuild_with_tree",
                        lambda *a, **k: ("pkgbuild", None, None, False))
    monkeypatch.setattr(pipeline, "is_reserved_name", lambda _n: False)
    monkeypatch.setattr(pipeline, "_pkg_or_base", lambda _m: "demo")
    monkeypatch.setattr(pipeline, "save_resume_state", lambda state: None)
    monkeypatch.setattr(pipeline, "clear_resume_state", lambda: None)
    monkeypatch.setattr(pipeline, "_run_corpus_sweep", lambda *a, **k: [])
    monkeypatch.setattr(pipeline, "record_alerts", lambda *a, **k: [])
    monkeypatch.setattr(
        pipeline, "analyze_package_text",
        lambda pkg_name, **kw: SimpleNamespace(
            new_version="1.0", final_score=packages[pkg_name][1],
            score_breakdown=[], ioc_matches=[]),
    )


def _cursor():
    from trustsight.db import get_metadata
    return get_metadata("since_cursor")


def _clear_cursor():
    from trustsight.db import set_metadata
    set_metadata("since_cursor", "")
    set_metadata("since_origin", "")


def test_since_replays_one_aur_day_per_cycle(monkeypatch):
    """The backfill processes exactly the packages whose AUR LastModified
    falls in the cursor's day, alerts on them, and advances one day."""
    import time as _time
    import trustsight.full_aur.pipeline as pipeline

    now = int(_time.time())
    day1 = now - 2 * _DAY
    day2 = now - _DAY
    _stub_since_cycle(monkeypatch, pipeline, {
        "old-pkg": (day1 + 100, 90),
        "newer-pkg": (day2 + 100, 5),
    })
    monkeypatch.setattr(pipeline, "save_metadata", lambda *a, **k: None)

    result = pipeline.run_baseline_build(since=day1)

    try:
        assert result.backfilling
        assert result.processed == 1            # only the day-1 package
        assert result.over_threshold == [("old-pkg", 90)]
        assert _cursor() == str(day1 + _DAY)    # one day advanced, no more
    finally:
        _clear_cursor()


def test_since_skips_empty_days_inside_the_cycle(monkeypatch):
    """Empty days must not become cycles of their own: the cursor walks to
    the first non-empty day without any package work in between."""
    import time as _time
    import trustsight.full_aur.pipeline as pipeline

    now = int(_time.time())
    day1 = now - 5 * _DAY
    day4 = now - 2 * _DAY
    _stub_since_cycle(monkeypatch, pipeline, {"only-pkg": (day4 + 100, 5)})
    monkeypatch.setattr(pipeline, "save_metadata", lambda *a, **k: None)

    result = pipeline.run_baseline_build(since=day1)

    try:
        assert result.backfilling
        assert result.processed == 1
        assert _cursor() == str(day4 + _DAY)
    finally:
        _clear_cursor()


def test_since_joins_the_live_stream_when_caught_up(monkeypatch):
    """When the replay reaches today, the snapshot advances and the cursor
    clears, so the next cycle is an ordinary delta again."""
    from types import SimpleNamespace

    import time as _time
    import trustsight.full_aur.pipeline as pipeline

    now = int(_time.time())
    # Freeze the cycle clock.  The caught-up decision compares the drained
    # day's end against the cycle's start reading; pinning both to ``now``
    # keeps the exact-equality assertion from flaking when a wall-clock
    # second boundary falls between the test's read and the pipeline's.
    monkeypatch.setattr(
        pipeline,
        "time",
        SimpleNamespace(
            time=lambda: now, strftime=_time.strftime, gmtime=_time.gmtime
        ),
    )
    today = now - 100
    saved: list = []
    _stub_since_cycle(monkeypatch, pipeline, {"fresh-pkg": (today, 5)})
    monkeypatch.setattr(pipeline, "save_metadata",
                        lambda *a, **k: saved.append("saved"))

    result = pipeline.run_baseline_build(since=now - _DAY)

    try:
        assert not result.backfilling
        assert result.processed == 1
        assert saved == ["saved"]
        assert _cursor() in (None, "")
    finally:
        _clear_cursor()


def test_since_resumes_the_cursor_across_a_restart(monkeypatch):
    """Re-passing the same --since on a service restart must resume the
    replay, not start it over: the flag names the origin, the cursor
    tracks progress."""
    import time as _time
    import trustsight.full_aur.pipeline as pipeline

    now = int(_time.time())
    day1 = now - 2 * _DAY
    day2 = now - _DAY
    _stub_since_cycle(monkeypatch, pipeline, {
        "old-pkg": (day1 + 100, 5),
        "newer-pkg": (day2 + 100, 90),
    })
    monkeypatch.setattr(pipeline, "save_metadata", lambda *a, **k: None)

    try:
        first = pipeline.run_baseline_build(since=day1)
        assert first.processed == 1 and first.over_threshold == []
        # Same --since again, as a restarted service would pass: resume,
        # so day 2 is the bucket now, not day 1 again.
        second = pipeline.run_baseline_build(since=day1)
        assert second.processed == 1
        assert second.over_threshold == [("newer-pkg", 90)]
    finally:
        _clear_cursor()


def test_a_304_with_validators_but_no_snapshot_refetches(monkeypatch):
    """A --since replay advances no snapshot while the ETag file already
    exists, so taking a 304 at face value hands back an empty dict and
    every cycle refuses forever.  The fetch falls back to unconditional."""
    import urllib.error
    import trustsight.full_aur.metadata as metadata

    calls = []

    body = gzip.compress(b"[]")

    class _Resp:
        status = 200
        headers = {"Content-Length": str(len(body)), "ETag": "x",
                   "Last-Modified": "y"}

        def __init__(self):
            self._pos = 0

        def read(self, n=-1):
            chunk = body[self._pos:self._pos + n]
            self._pos += len(chunk)
            return chunk

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=0):
        calls.append(bool(req.headers))
        if req.headers:
            raise urllib.error.HTTPError(req.full_url, 304, "Not Modified", {}, None)
        return _Resp()

    monkeypatch.setattr(metadata, "urlopen", fake_urlopen)
    monkeypatch.setattr(metadata, "_read_validators", lambda: ("x", "y"))
    monkeypatch.setattr(metadata, "load_metadata", lambda *a, **k: None)
    monkeypatch.setattr(metadata, "_write_validators", lambda *a: None)
    monkeypatch.setattr(metadata, "save_metadata", lambda *a, **k: None)

    # An empty-body reply parses to no packages; what matters is that the
    # unconditional refetch happened at all.
    metadata.fetch_metadata()
    assert calls == [True, False]


def test_h103_reaches_the_corpus_first_seen_path():
    from trustsight.config import ensure_default_configs
    from trustsight.db import init_db
    from trustsight.full_aur.analyze import TemporalContext, analyze_package_text

    ensure_default_configs()
    init_db()

    pkgbuild = (
        "pkgname=demo\npkgver=1.0\ninstall=demo.install\n"
        "source=('https://example.invalid/demo-1.0.tar.gz')\n"
        "sha256sums=('aaaa')\n"
    )
    srcinfo = (
        "pkgbase = demo\n\tpkgver = 1.0\n\tinstall = demo.install\n"
        "\tsource = https://example.invalid/demo-1.0.tar.gz\n"
        "\tsha256sums = bbbb\n"
    )
    fact = analyze_package_text(
        pkg_name="demo", old_pkgbuild=None, new_pkgbuild=pkgbuild,
        maintainer="tester", temporal=TemporalContext(), srcinfo=srcinfo,
    )
    assert any(e.rule_id == "H103" for e in fact.score_breakdown)
