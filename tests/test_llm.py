from trustsight.llm import fallback_verdict
from trustsight.schema import DiffSummary, PackageFact, SourceChanges


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
