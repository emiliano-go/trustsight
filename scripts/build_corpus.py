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
import hashlib
import json
import shutil
import subprocess
import sys
import time
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]
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


CLONE_TIMEOUT_S = 6 * 60 * 60


def _corpus_content_hash(corpus_dir: Path) -> str:
    """SHA-256 over the sorted concatenation of all diff file bytes.

    Must stay byte-for-byte identical to the same helper in
    ``rebaseline.py``; the two are compared against the
    ``corpus_content_sha256`` recorded in ``baseline.json``.
    """
    h = hashlib.sha256()
    for dp in sorted(corpus_dir.rglob("*.diff")):
        h.update(dp.read_bytes())
    return h.hexdigest()


def _clone_is_usable(repo_dir: Path) -> bool:
    """Check that *repo_dir* is a complete, readable bare repository.

    A clone interrupted partway leaves the directory in place.  Without
    this check the next run would silently reuse the partial repo and
    produce a corpus with missing packages.

    ``rev-parse --git-dir`` is not sufficient: ``git clone --bare``
    creates a structurally valid git directory before it starts
    transferring objects, so an interrupted clone still answers it.  A
    complete clone has refs and no leftover temporary pack.
    """
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "for-each-ref", "--count=1"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return False
    return not list((repo_dir / "objects" / "pack").glob("tmp_pack_*"))


def ensure_aur_clone() -> Path:
    """One bare clone of the AUR monorepo, reused across runs."""
    repo_dir = CACHE_DIR / "aur.git"
    if repo_dir.exists():
        if _clone_is_usable(repo_dir):
            return repo_dir
        print("  Existing clone is incomplete, removing and re-cloning...")
        shutil.rmtree(repo_dir, ignore_errors=True)

    print("  Cloning AUR mirror (first time, tens of GB, can take hours)...")
    start = time.time()
    try:
        result = subprocess.run(
            ["git", "clone", "--bare", "--progress", REPO_BASE, str(repo_dir)],
            capture_output=True, text=True, timeout=CLONE_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        # Leaving the partial clone behind would poison every later run.
        shutil.rmtree(repo_dir, ignore_errors=True)
        print(f"  Clone exceeded {CLONE_TIMEOUT_S}s and was removed", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        shutil.rmtree(repo_dir, ignore_errors=True)
        raise

    if result.returncode != 0:
        shutil.rmtree(repo_dir, ignore_errors=True)
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


ABBREV = 12


def get_diff(repo_dir: Path, old_sha: str, new_sha: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_dir),
         "-c", f"diff.pkgbuild.xfuncname={XFUNCNAME}",
         # Pin the abbreviation length in the "index <old>..<new>" line.
         # Git otherwise scales it to the object count of the repository,
         # so a sparse reconstruction repo emits 7 chars where the full
         # AUR mirror emitted 12: byte-different diffs for identical
         # commits, which would invalidate the corpus content hash.
         "-c", f"core.abbrev={ABBREV}",
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


def ensure_sparse_repo(repo_dir: Path) -> Path:
    """A bare repo pointed at the AUR mirror, with nothing fetched yet.

    Reconstruction needs the few hundred package branches named in the
    manifest, not the whole monorepo, so this deliberately skips the
    clone in :func:`ensure_aur_clone` and lets callers fetch branches on
    demand.  That is what makes reconstruction viable in CI: a branch
    fetch is ~2s, against tens of GB for the full mirror.
    """
    if not (repo_dir / "objects").is_dir():
        repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "init", "--quiet", "--bare", str(repo_dir)],
            check=True, capture_output=True, timeout=30,
        )
    existing = subprocess.run(
        ["git", "-C", str(repo_dir), "remote"],
        capture_output=True, text=True, timeout=30,
    ).stdout.split()
    if "origin" not in existing:
        subprocess.run(
            ["git", "-C", str(repo_dir), "remote", "add", "origin", REPO_BASE],
            check=True, capture_output=True, timeout=30,
        )
    _ensure_xfuncname(repo_dir)
    return repo_dir


def reconstruct_from_manifest(manifest: Path, out_dir: Path, repo_dir: Path) -> int:
    """Rebuild the exact corpus named by *manifest*. Returns an exit code.

    The corpus is not committed (``*.diff`` is gitignored), so the lock
    is the only durable description of it.  Regenerating the diffs from
    the recorded sha pairs (rather than re-selecting packages by
    popularity, which yields a different corpus on every run) is what
    lets CI reproduce the bytes the baseline was computed from.
    """
    lock = json.loads(manifest.read_text())
    entries = lock.get("entries", [])
    if not entries:
        print(f"Manifest has no entries: {manifest}", file=sys.stderr)
        return 1

    by_pkg: dict[str, list[dict]] = {}
    for entry in entries:
        by_pkg.setdefault(entry["pkg"], []).append(entry)

    out_dir.mkdir(parents=True, exist_ok=True)
    ensure_sparse_repo(repo_dir)

    written, failures = 0, []
    start = time.time()
    for i, (pkg, items) in enumerate(sorted(by_pkg.items()), 1):
        print(f"  [{i}/{len(by_pkg)}] {pkg}...", end=" ", flush=True)
        if not fetch_branch(repo_dir, pkg):
            print("no branch")
            failures.append(f"{pkg}: branch missing from mirror")
            continue

        produced = 0
        for entry in items:
            old_sha, new_sha = entry["old_sha"], entry["new_sha"]
            fname = f"{pkg}__{old_sha[:12]}..{new_sha[:12]}.diff"
            diff_text = get_diff(repo_dir, old_sha, new_sha)
            # An unreachable sha makes git exit non-zero with empty stdout.
            # Writing the empty result would silently shrink the corpus and
            # shift every FP rate computed from it, so treat it as fatal.
            if not diff_text.strip():
                failures.append(f"{fname}: empty diff (sha unreachable?)")
                continue
            (out_dir / fname).write_text(diff_text)
            produced += 1
            written += 1
        print(f"{produced}/{len(items)} diffs")

    print(f"\n{'=' * 50}")
    print(f"Packages:    {len(by_pkg)}")
    print(f"Diffs:       {written}/{len(entries)}")
    print(f"Elapsed:     {time.time() - start:.1f}s")
    print(f"Corpus dir:  {out_dir}")

    if failures:
        print(f"\n{len(failures)} entries could not be reconstructed:", file=sys.stderr)
        for f in failures[:40]:
            print(f"  {f}", file=sys.stderr)
        if len(failures) > 40:
            print(f"  ... and {len(failures) - 40} more", file=sys.stderr)
        return 1

    print(f"\nCorpus content sha256: {_corpus_content_hash(out_dir)}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Build stratified calibration corpus")
    parser.add_argument("--strata", type=Path, help="strata.toml path (selection mode only)")
    parser.add_argument("--manifest", type=Path, default=FIXTURES / "corpus.lock")
    parser.add_argument("--out", type=Path, default=FIXTURES / "benign-corpus")
    parser.add_argument("--max-per-stratum", type=int, default=40)
    parser.add_argument("--max-diffs-per-pkg", type=int, default=30)
    parser.add_argument("--min-diffs", type=int, default=3)
    parser.add_argument("--refresh-meta", action="store_true", help="re-fetch meta")
    parser.add_argument(
        "--from-manifest", action="store_true",
        help="rebuild the exact corpus named by --manifest instead of "
             "re-selecting packages (deterministic; use this in CI)",
    )
    parser.add_argument(
        "--repo-dir", type=Path, default=CACHE_DIR / "aur.git",
        help="bare AUR repo used as the object cache",
    )
    args = parser.parse_args()

    if args.from_manifest:
        if not args.manifest.exists():
            print(f"Error: manifest not found: {args.manifest}", file=sys.stderr)
            sys.exit(1)
        sys.exit(reconstruct_from_manifest(args.manifest, args.out, args.repo_dir))

    if args.strata is None:
        print("Error: --strata is required unless --from-manifest is given",
              file=sys.stderr)
        sys.exit(1)
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
                print("no branch")
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

    # Strata overlap: python-foo-git matches both lang_ecosystem and vcs_git,
    # so such a package is walked once per stratum and its diffs appear twice.
    # On disk the second pass just overwrites the first (same filename), but
    # the lock kept both entries and per-stratum FP rates double-counted them.
    # Last stratum wins, matching the overwrite order the corpus already has.
    deduped: dict[tuple[str, str, str], dict] = {}
    for entry in lock_entries:
        deduped[(entry["pkg"], entry["old_sha"], entry["new_sha"])] = entry
    lock_entries = list(deduped.values())

    lock = {
        "generated": time.strftime("%Y-%m-%d"),
        "strata_file": args.strata.name,
        "total_entries": len(lock_entries),
        "xfuncname": XFUNCNAME,
        "diff_flags": ["-W"],
        "core_abbrev": ABBREV,
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
