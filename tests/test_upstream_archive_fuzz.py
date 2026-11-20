"""The archive parser treats every byte as hostile and never raises."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from trustsight.analysis.upstream_archive import parse_upstream_archive


@settings(max_examples=60, deadline=None)
@given(st.binary(max_size=8192))
def test_random_bytes_are_a_bounded_result_not_a_crash(data):
    result = parse_upstream_archive(data)
    assert set(result) == {
        "manifest_texts", "artifacts", "inventory", "inventory_truncated",
        "ambiguous", "complete", "refused", "malformed",
    }
    assert isinstance(result["manifest_texts"], list)
    assert len(result["manifest_texts"]) <= 64
    for path, text in result["manifest_texts"]:
        assert isinstance(path, str) and isinstance(text, str)
        assert len(text.encode("utf-8")) <= 512 * 1024
