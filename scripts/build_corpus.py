"""Build a stratified calibration corpus from the AUR mirror.

Uses a single shared bare clone of the AUR monorepo with per-branch
refspec fetching. After the initial clone (~2-3 min), subsequent
package fetches are ~400ms each.

Usage:
    python scripts/build_corpus.py \\
        --strata scripts/strata.toml \\
        --manifest tests/fixtures/corpus.lock \\
        --out tests/fixtures/benign-corpus
"""

import argparse
import gzip
import json
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.request
from pathlib import Path

AUR_META = "https://aur.archlinux.org/packages-meta-ext-v1.json.gz"
REPO_BASE = "https://github.com/archlinux/aur.git"
CACHE_DIR = Path.home() / ".cache" / "trustsight"
FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def fetch_meta(force: bool = False) -> list[dict]:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = CACHE_DIR / "aur-meta.json"
    if cache_path.exists() and not force:
        print(f"  Using cached meta ({cache_path.stat().st_size >> 20} MB)")
        return json.loads(cache_path.read_text())
    print(f"  Fetching {AUR_META} ...", end=" ", flush=True)
    start = time.time()
    with urllib.request.urlopen(AUR_META, timeout=180) as resp:
        raw = resp.read()
    data = json.loads(gzip.decompress(raw))
    cache_path.write_text(json.dumps(data))
    print(f"{len(data)} packages ({len(raw) >> 20} MB, {time.time() - start:.1f}s)")
    return data


def ensure_aur_clone() -> Path:
    """One bare clone of the AUR monorepo, reused across runs."""
    repo_dir = CACHE_DIR / "aur.git"
    if repo_dir.exists():
        return repo_dir
    print("  Cloning AUR mirror (first time, may take a while)...")
    start = time.time()
    result = subprocess.run(
        ["git", "clone", "--bare", REPO_BASE, str(repo_dir)],
        capture_output=True, text=True, timeout=600,
    )
    if result.returncode != 0:
        print(f"  Clone failed: {result.stderr.strip()[:200]}", file=sys.stderr)
        sys.exit(1)
    _ensure_xfuncname(repo_dir)
    print(f"  Done ({time.time() - start:.1f}s)")
    return repo_dir


def fetch_branch(repo_dir: Path, branch: str) -> bool:
    """Fetch a single branch from the AUR mirror. Fast after the initial clone."""
    refspec = f"refs/heads/{branch}:refs/heads/{branch}"
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "fetch", "--quiet", "origin", refspec],
        capture_output=True, text=True, timeout=60,
    )
    return result.returncode == 0


def count_commits(repo_dir: Path, branch: str) -> int:
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "rev-list", "--count", branch],
        capture_output=True, text=True, timeout=30,
    )
    return int(result.stdout.strip()) if result.returncode == 0 else 0


def get_commits(repo_dir: Path, branch: str, max_count: int = 100) -> list[str]:
    """Get commit SHAs for a branch, newest first."""
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "log", branch, "--format=%H", f"-{max_count}"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        return []
    return result.stdout.strip().splitlines()


XFUNCNAME = (
    r"^((prepare|build|check|package[[:alnum:]_-]*|pkgver|"
    r"(post|pre)_(install|upgrade|remove))[[:space:]]*\(\))[[:space:]]*\{.*$"
)


def _ensure_xfuncname(repo_dir: Path) -> None:
    """Install xfuncname so git diff -W produces useful hunk headers."""
    attrs = repo_dir / "info" / "attributes"
    if not attrs.exists():
        attrs.write_text("PKGBUILD diff=pkgbuild\n*.install diff=pkgbuild\n")
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "diff.pkgbuild.xfuncname", XFUNCNAME],
        capture_output=True, timeout=10,
    )


def get_diff(repo_dir: Path, old_sha: str, new_sha: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_dir),
         "-c", f"diff.pkgbuild.xfuncname={XFUNCNAME}",
         "diff", "-W", f"{old_sha}..{new_sha}"],
        capture_output=True, text=False, timeout=30,
    )
    return result.stdout.decode("utf-8", errors="replace")


def filter_by_stratum(pkgs: list[dict], stratum_name: str) -> list[dict]:
    sel = {
        "bin_repack": lambda n, d: n.endswith("-bin") and not n.endswith("-git"),
        "vcs_git": lambda n, d: n.endswith("-git"),
        "lang_ecosystem": lambda n, d: any(
            n.startswith(p) for p in ("python-", "ruby-", "perl-", "rust-", "go-")
        ),
        "data_fonts": lambda n, d: any(
            n.startswith(p) for p in ("ttf-", "otf-", "fonts-")
        ) or "font" in d,
        "dkms_kernel": lambda n, d: "dkms" in n.lower() or "dkms" in d,
        "source_patched": lambda n, d: "patch" in d or n.endswith("-patched"),
        "autotools": lambda n, d: ("autotools" in d or "configure" in d
                                   or "autoconf" in d or "automake" in d),
        "large_electron": lambda n, d: "electron" in n.lower() or "asar" in d,
    }
    fn = sel.get(stratum_name)
    if fn is None:
        return pkgs
    filtered = []
    for p in pkgs:
        name = p.get("Name", "")
        desc = (p.get("Description", "") or "").lower()
        if fn(name, desc):
            filtered.append(p)
    return filtered


def main():
    parser = argparse.ArgumentParser(description="Build stratified calibration corpus")
    parser.add_argument("--strata", type=Path, required=True, help="strata.toml path")
    parser.add_argument("--manifest", type=Path, default=FIXTURES / "corpus.lock")
    parser.add_argument("--out", type=Path, default=FIXTURES / "benign-corpus")
    parser.add_argument("--max-per-stratum", type=int, default=40)
    parser.add_argument("--max-diffs-per-pkg", type=int, default=30)
    parser.add_argument("--min-diffs", type=int, default=3)
    parser.add_argument("--refresh-meta", action="store_true", help="re-fetch meta")
    args = parser.parse_args()

    if not args.strata.exists():
        print(f"Error: strata file not found: {args.strata}", file=sys.stderr)
        sys.exit(1)

    strata = tomllib.loads(args.strata.read_text())
    args.out.mkdir(parents=True, exist_ok=True)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)

    print("=== Fetching AUR metadata ===")
    all_pkgs = fetch_meta(force=args.refresh_meta)

    print("\n=== Setting up AUR clone ===")
    aur_repo = ensure_aur_clone()

    lock_entries = []
    pkg_counter = 0
    diff_counter = 0
    total_fetch_time = 0.0
    total_diff_time = 0.0

    for stratum_name, cfg in strata.get("strata", {}).items():
        target = cfg.get("target", 20)
        print(f"\n=== {stratum_name} (target: {target}) ===")

        candidates = filter_by_stratum(all_pkgs, stratum_name)
        print(f"  Candidates: {len(candidates)}")

        by_popularity = sorted(
            candidates, key=lambda p: p.get("Popularity", 0), reverse=True
        )

        selected = 0
        for pkg in by_popularity[:args.max_per_stratum]:
            if selected >= target:
                break
            name = pkg.get("Name", "")
            if not name:
                continue

            pkg_counter += 1
            print(f"  [{pkg_counter}] {name} (pop={pkg.get('Popularity', 0):.3f})...",
                  end=" ", flush=True)

            t0 = time.time()
            ok = fetch_branch(aur_repo, name)
            t_fetch = time.time() - t0
            total_fetch_time += t_fetch
            if not ok:
                print(f"no branch")
                continue

            commit_count = count_commits(aur_repo, name)
            if commit_count < args.min_diffs:
                print(f"too few commits ({commit_count})")
                continue

            t1 = time.time()
            commits = get_commits(aur_repo, name, args.max_diffs_per_pkg + 1)
            diffs_found = 0
            for i in range(len(commits) - 1):
                if diffs_found >= args.max_diffs_per_pkg:
                    break
                diff_text = get_diff(aur_repo, commits[i + 1], commits[i])
                if diff_text.strip():
                    lock_entries.append({
                        "pkg": name,
                        "stratum": stratum_name,
                        "old_sha": commits[i + 1],
                        "new_sha": commits[i],
                    })
                    fname = f"{name}__{commits[i + 1][:12]}..{commits[i][:12]}.diff"
                    (args.out / fname).write_text(diff_text)
                    diffs_found += 1
                    diff_counter += 1

            t_diff = time.time() - t1
            total_diff_time += t_diff

            if diffs_found >= args.min_diffs:
                selected += 1
                print(f"{diffs_found} diffs ({t_fetch:.1f}s + {t_diff:.1f}s)"
                      f" → {selected}/{target}")
            else:
                print(f"only {diffs_found} diffs, skipping")

        if selected == 0:
            print(f"  WARNING: 0/{target} selected for {stratum_name}", file=sys.stderr)

    lock = {
        "generated": time.strftime("%Y-%m-%d"),
        "strata_file": str(args.strata.resolve()),
        "total_entries": len(lock_entries),
        "xfuncname": XFUNCNAME,
        "diff_flags": ["-W"],
        "entries": sorted(lock_entries, key=lambda e: (e["stratum"], e["pkg"], e["old_sha"])),
    }
    args.manifest.write_text(json.dumps(lock, indent=2) + "\n")

    print(f"\n{'=' * 50}")
    print(f"Packages tried: {pkg_counter}")
    print(f"Diffs written: {diff_counter}")
    print(f"Lock entries:  {len(lock_entries)}")
    print(f"Fetch time:    {total_fetch_time:.1f}s")
    print(f"Diff time:     {total_diff_time:.1f}s")
    print(f"Lock file:     {args.manifest}")
    print(f"Corpus dir:    {args.out}")


if __name__ == "__main__":
    main()
