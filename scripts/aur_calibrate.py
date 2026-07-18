"""Calibration runner: scan a corpus and report per-stratum FP rates.

Usage:
    python scripts/aur_calibrate.py --from-dir tests/fixtures/benign-corpus
    python scripts/aur_calibrate.py --from-dir tests/fixtures/benign-corpus \\
        --manifest tests/fixtures/corpus.lock --json results.json
    python scripts/aur_calibrate.py --ablate tokenizer --json results.json
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from trustsight.analysis import scan_diff
from trustsight.config import load_config, load_rules, ensure_default_configs
from trustsight.rules import apply_rules, get_raw_diff_lines
from trustsight.tokenizer import tokenize_and_resolve


FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
STRATA_ORDER = [
    "bin_repack", "vcs_git", "source_patched", "dkms_kernel",
    "lang_ecosystem", "autotools", "data_fonts", "large_electron",
]


def scan_diff_ablate(diff_text: str, ablate: str, rules: list[dict]) -> dict:
    """Run the pipeline with optional ablation. Returns a result dict."""
    if ablate == "delta":
        diff_text = "\n".join(
            "+ " + line for line in diff_text.splitlines()
            if not line.startswith("---") and not line.startswith("+++")
            and not line.startswith("@")
        )

    raw_lines = get_raw_diff_lines(diff_text)

    if ablate == "tokenizer":
        resolved_strings = raw_lines
        unresolved_strings = []
    else:
        resolved_strings, unresolved_strings = tokenize_and_resolve(
            diff_text
        )

    triggered_rules = apply_rules(resolved_strings, raw_lines, rules)

    return {
        "triggered_rules": triggered_rules,
        "score": sum(
            {"FATAL": 100, "CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5, "INFO": 0}.get(
                r.get("severity", "INFO"), 0
            )
            for r in triggered_rules
        ),
        "severities": [r.get("severity", "INFO") for r in triggered_rules],
        "rule_ids": list(set(r["rule_id"] for r in triggered_rules)),
    }


def collect_results(corpus_dir: Path, manifest_path: Path | None,
                    ablate: str, rules: list[dict]) -> dict:
    """Scan all diffs in a corpus and aggregate per-stratum results."""
    strata_lookup = {}
    if manifest_path and manifest_path.exists():
        lock = json.loads(manifest_path.read_text())
        strata_lookup = {e["pkg"]: e["stratum"] for e in lock.get("entries", [])}

    per_stratum: dict = defaultdict(
        lambda: {"diffs": 0, "pkgs": set(), "scores": [],
                 "rules": Counter(), "rule_details": defaultdict(list)}
    )

    for diff_file in sorted(corpus_dir.rglob("*.diff")):
        pkg = diff_file.name.split("__")[0]
        stratum = strata_lookup.get(pkg, "unknown")
        diff_text = diff_file.read_text()

        result = scan_diff_ablate(diff_text, ablate, rules)

        per_stratum[stratum]["diffs"] += 1
        per_stratum[stratum]["pkgs"].add(pkg)
        per_stratum[stratum]["scores"].append(result["score"])
        for rid in result["rule_ids"]:
            per_stratum[stratum]["rules"][rid] += 1
            per_stratum[stratum]["rule_details"][rid].append({
                "pkg": pkg,
                "file": diff_file.name,
            })

    # Convert sets to counts
    output = {}
    for stratum, data in per_stratum.items():
        total = data["diffs"]
        scores = sorted(data["scores"])
        output[stratum] = {
            "n_diffs": total,
            "n_pkgs": len(data["pkgs"]),
            "p95": scores[int(len(scores) * 0.95)] if scores else 0,
            "median": scores[len(scores) // 2] if scores else 0,
            "zero_pct": sum(1 for s in scores if s == 0) / total if total > 0 else 0,
            "rules": {rid: count / total for rid, count in data["rules"].items()},
        }
    return output


def print_table(results: dict):
    """Print per-stratum results as a table."""
    all_rules = sorted(set(
        rid for s in results.values() for rid in s.get("rules", {})
    ))

    header = f"{'rule \\ stratum':<20}"
    strata_list = [s for s in STRATA_ORDER if s in results]
    unknown = [s for s in results if s not in STRATA_ORDER]
    display_strata = strata_list + unknown

    for s in display_strata:
        header += f"  {s:<14}"
    header += f"  {'all':<14}"
    print(header)
    print("-" * len(header))

    all_agg = {"diffs": 0, "scores": [], "rules": Counter()}
    for s in display_strata:
        d = results[s]
        all_agg["diffs"] += d["n_diffs"]
        all_agg["scores"].extend([0] * d["n_diffs"])
        for rid, rate in d.get("rules", {}).items():
            all_agg["rules"][rid] += rate * d["n_diffs"]

    if all_agg["diffs"] > 0:
        for rid in all_rules:
            all_agg["rules"][rid] /= all_agg["diffs"]

    for rid in all_rules:
        row = f"{rid:<20}"
        for s in display_strata:
            rate = results[s].get("rules", {}).get(rid, 0)
            row += f"  {rate:>6.1%}       "
        rate = all_agg["rules"].get(rid, 0)
        row += f"  {rate:>6.1%}       "
        print(row)

    row = f"{'p95 score':<20}"
    for s in display_strata:
        row += f"  {results[s]['p95']:>6}        "
    all_scores = []
    for s in display_strata:
        n = results[s]["n_diffs"]
        all_scores.extend([results[s]["p95"]] * n)
    all_p95 = sorted(all_scores)[int(len(all_scores) * 0.95)] if all_scores else 0
    row += f"  {all_p95:>6}        "
    print(row)

    row = f"{'% zero':<20}"
    for s in display_strata:
        row += f"  {results[s]['zero_pct']:>6.1%}       "
    all_zero = sum(results[s]["zero_pct"] * results[s]["n_diffs"] for s in display_strata)
    all_total = sum(results[s]["n_diffs"] for s in display_strata)
    row += f"  {all_zero/all_total:>6.1%}       " if all_total > 0 else "  ---            "
    print(row)

    row = f"{'diffs/pkgs':<20}"
    for s in display_strata:
        row += f"  {results[s]['n_diffs']:>3}/{results[s]['n_pkgs']:<3}       "
    total_d = sum(results[s]["n_diffs"] for s in display_strata)
    total_p = sum(results[s]["n_pkgs"] for s in display_strata)
    row += f"  {total_d:>3}/{total_p:<3}       "
    print(row)


def main():
    parser = argparse.ArgumentParser(description="Calibration runner")
    parser.add_argument("--from-dir", type=Path, help="directory of .diff files")
    parser.add_argument("--manifest", type=Path, help="corpus.lock path")
    parser.add_argument("--ablate", choices=["none", "denoise", "tokenizer", "delta"],
                        default="none", help="ablation mode")
    parser.add_argument("--json", type=Path, help="output JSON path")
    parser.add_argument("--max-diffs-per-pkg", type=int, default=25)
    args = parser.parse_args()

    ensure_default_configs()
    config = load_config()
    rules = load_rules()

    corpus_dir = args.from_dir or (FIXTURES / "benign-corpus")
    if not corpus_dir.exists():
        print(f"Corpus directory not found: {corpus_dir}", file=sys.stderr)
        print("Run build_corpus.py first, or point --from-dir at a corpus.", file=sys.stderr)
        sys.exit(1)

    print(f"corpus: {corpus_dir}")
    print(f"ablation: {args.ablate}")
    print()

    results = collect_results(corpus_dir, args.manifest, args.ablate, rules)

    if results:
        print_table(results)

    if args.json:
        output = {
            "generated": "2026-07-16",
            "corpus": str(corpus_dir),
            "ablate": args.ablate,
            "strata": results,
        }
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(output, indent=2) + "\n")
        print(f"\nResults written to {args.json}")


if __name__ == "__main__":
    main()
