from trustsight.llm import _assert_verdict, fallback_verdict
from trustsight.schema import DiffSummary, PackageFact, ScoreEntry, SourceChanges


def test_fallback_verdict_no_changes():
    fact = PackageFact(package_name="test")
    verdict = fallback_verdict(fact)
    assert "no structural changes" in verdict


def test_fallback_verdict_with_changes():
    fact = PackageFact(
        package_name="test",
        diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
        source_changes=SourceChanges(added_urls=["https://example.com/pkg.tar.gz"]),
        maintainer_changed=True,
    )
    verdict = fallback_verdict(fact)
    assert "PKGBUILD" in verdict
    assert "1 source URL(s)" in verdict
    assert "maintainer changed" in verdict


# --- LLM verdict assertions ---

def test_assert_empty_verdict():
    fact = PackageFact(package_name="test")
    assert _assert_verdict("", fact) is False


def test_assert_too_short_verdict():
    fact = PackageFact(package_name="test")
    assert _assert_verdict("short", fact) is False


def test_assert_too_long_verdict():
    fact = PackageFact(package_name="test")
    long_v = "x" * 2001
    assert _assert_verdict(long_v, fact) is False


def test_assert_score_in_verdict():
    fact = PackageFact(package_name="test", final_score=35)
    assert _assert_verdict("The score is 35 out of 100", fact) is False


def test_assert_passes_good_verdict():
    fact = PackageFact(package_name="test", final_score=35)
    v = "The PKGBUILD adds a new source from an unknown domain. The Medium score reflects the untrusted source combined with a valid checksum."
    assert _assert_verdict(v, fact) is True


def test_assert_low_score_no_alarmist_words():
    fact = PackageFact(package_name="test", final_score=5)
    assert _assert_verdict("This is a malicious dangerous attack", fact) is False


def test_assert_fatal_must_be_mentioned():
    fact = PackageFact(
        package_name="test", final_score=100,
        score_breakdown=[ScoreEntry(rule_id="R012", severity="FATAL", weight=0, reason="injection")],
    )
    assert _assert_verdict("The package looks fine", fact) is False


def test_assert_fatal_mentioned_passes():
    fact = PackageFact(
        package_name="test", final_score=100,
        score_breakdown=[ScoreEntry(rule_id="R012", severity="FATAL", weight=0, reason="injection")],
    )
    v = "A prompt injection pattern was detected in the PKGBUILD. This is a FATAL finding."
    assert _assert_verdict(v, fact) is True
