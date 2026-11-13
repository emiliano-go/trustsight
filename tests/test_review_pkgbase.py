"""Split packages share one AUR git repository."""

from trustsight import review


class _Project:
    def last_fetch_time(self):
        return 123

    def close(self):
        pass


def test_prefetch_fetches_a_split_base_once(monkeypatch):
    calls = []

    def clone_or_fetch(name, mtime):
        calls.append((name, mtime))
        return _Project()

    monkeypatch.setattr("trustsight.fetcher.clone_or_fetch", clone_or_fetch)
    hints = review.prefetch([
        {"name": "gpu-unlock-firmware", "package_base": "gpu-unlock",
         "last_modified": 10},
        {"name": "gpu-unlock-dkms", "package_base": "gpu-unlock",
         "last_modified": 10},
    ])
    assert calls == [("gpu-unlock", 10)]
    assert hints == {"gpu-unlock-firmware": 10, "gpu-unlock-dkms": 10}


def test_the_batch_passes_the_package_base_to_analysis(monkeypatch):
    seen = []

    class Fact:
        score_breakdown = []

    def fake_analyze(name, **kwargs):
        seen.append((name, kwargs.get("package_base")))
        return Fact()

    monkeypatch.setattr(review, "analyze_package", fake_analyze)
    monkeypatch.setattr(review, "prefetch", lambda *args, **kwargs: {})
    monkeypatch.setattr(review, "verdict_for", lambda fact: "ok")
    monkeypatch.setattr(review, "cached_note", lambda fact: "")
    monkeypatch.setattr(review, "no_aur_change_note", lambda fact: "")
    monkeypatch.setattr(review, "evaluate_fact",
                        lambda fact: {"package": "split", "suppressed_rules": []})
    monkeypatch.setattr("trustsight.rules.precompile_shipped_patterns", lambda: None)
    monkeypatch.setattr("trustsight.rules.precompile_structural_patterns", lambda: None)

    results = review.analyze_outdated_batch(
        [{"name": "split", "package_base": "base", "current_version": "1.0"}],
        depth=0,
    )
    assert seen == [("split", "base")]
    assert results[0]["package"] == "split"
