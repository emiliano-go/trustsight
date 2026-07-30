"""Tests for the full-AUR baseline corpus builder."""

import gzip
import json
from unittest.mock import MagicMock, patch

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
