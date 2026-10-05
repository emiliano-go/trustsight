"""Spec §7: function-body-scoped rules.

C015 (re-filed from H100) reads ``RecipeDoc.functions["package"]`` only:
a fetch at artifact-assembly time bypasses source-array accounting.  The
write-outside-$pkgdir half of §7 is already H076's, scoped to the build
functions - pinned here so the filing stays honest.
"""

from trustsight.analysis.pipeline import scan_diff
from trustsight.config import load_config


def _rule_ids(text: str) -> set[str]:
    fact = scan_diff(text, config=load_config(), package_name="demo")
    return {entry.rule_id for entry in fact.score_breakdown}


def _diff(body: str) -> str:
    added = "".join(f"+{line}\n" for line in body.splitlines())
    count = 2 + len(body.splitlines())
    return (
        f"--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,{count} @@\n"
        " pkgname=demo\n pkgver=1.0\n"
        + added
    )


def test_fetch_in_package_fires():
    ids = _rule_ids(_diff(
        "package() {\n"
        "  curl -o \"$pkgdir/out\" https://example.invalid/x\n"
        "}\n"
    ))
    assert "C015" in ids


def test_fetch_in_build_does_not_fire():
    ids = _rule_ids(_diff(
        "build() {\n"
        "  curl -o out https://example.invalid/x\n"
        "}\n"
    ))
    assert "C015" not in ids


def test_a_one_line_package_body_fires():
    ids = _rule_ids(_diff(
        "package() { wget -O \"$pkgdir/o\" https://example.invalid/x; }\n"
    ))
    assert "C015" in ids


def test_a_redefined_function_keeps_the_last_body():
    """bash semantics: the last definition is the one makepkg runs."""
    quiet = _rule_ids(_diff(
        "package() {\n  curl -o x https://example.invalid/x\n}\n"
        "package() {\n  install -Dm644 file \"$pkgdir/file\"\n}\n"
    ))
    assert "C015" not in quiet
    loud = _rule_ids(_diff(
        "package() {\n  install -Dm644 file \"$pkgdir/file\"\n}\n"
        "package() {\n  curl -o x https://example.invalid/x\n}\n"
    ))
    assert "C015" in loud


def test_write_outside_staging_in_package_is_h076():
    ids = _rule_ids(_diff(
        "package() {\n  cp payload /etc/cron.d/evil\n}\n"
    ))
    assert "H076" in ids
