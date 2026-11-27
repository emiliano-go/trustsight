"""The process-wide metadata provider cache and the depth-0 fast path."""

from trustsight import deps
from trustsight import depth
from trustsight.full_aur import metadata as metadata_module
from trustsight.full_aur.analyze._helpers import _walk_corpus_dependencies


def test_provider_is_reused_for_one_dump(monkeypatch):
    dump = {"pkg": {"Depends": []}}
    monkeypatch.setattr(metadata_module, "current_dump", lambda: dump)
    depth.reset_default_metadata()

    first = depth.default_metadata()
    second = depth.default_metadata()

    assert first is second


def test_provider_is_rebuilt_when_the_dump_changes(monkeypatch):
    dump = {"pkg": {"Depends": []}}
    monkeypatch.setattr(metadata_module, "current_dump", lambda: dump)
    depth.reset_default_metadata()
    first = depth.default_metadata()

    bigger = {"pkg": {"Depends": []}, "other": {"Depends": []}}
    monkeypatch.setattr(metadata_module, "current_dump", lambda: bigger)
    second = depth.default_metadata()

    assert second is not first


def test_depth_zero_does_not_build_the_provider(monkeypatch):
    def fail() -> None:
        raise AssertionError("depth 0 must not build the metadata provider")

    monkeypatch.setattr(depth, "default_metadata", fail)

    result = _walk_corpus_dependencies("probe", 0, {}, set())

    assert result.reports == []


def test_normalize_dependency_is_memoized():
    deps.normalize_dependency.cache_clear()

    assert deps.normalize_dependency("Python-Requests>=2") == "python-requests"
    deps.normalize_dependency("Python-Requests>=2")

    assert deps.normalize_dependency.cache_info().hits >= 1
