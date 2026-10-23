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
import tomllib
import urllib.request
from pathlib import Path

import corpus_select
import corpus_provenance

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
            # The clone may have arrived from anywhere: the operator can
            # fill the cache in themselves (it is tens of gigabytes), or an
            # older version of this script left it there.  Neither
            # `git clone --bare` nor `git init --bare` writes an
            # `info/attributes`, so a reused clone is unprepared until
            # _ensure_xfuncname says otherwise - and an unprepared clone
            # groups the hunks differently, which changes the corpus bytes.
            _ensure_xfuncname(repo_dir)
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

#: The attributes that route PKGBUILD (and a package's install script)
#: through the ``pkgbuild`` diff driver, whose ``xfuncname`` is
#: :data:`XFUNCNAME`.  The driver is what makes ``git diff -W`` group the
#: hunks by function; without the mapping git groups them by its own
#: default heuristic and the diffs differ byte-for-byte.
_XFUNC_ATTRIBUTES = (
    "PKGBUILD diff=pkgbuild",
    "*.install diff=pkgbuild",
)


def _ensure_xfuncname(repo_dir: Path) -> None:
    """Install xfuncname so git diff -W produces useful hunk headers.

    Two things are needed and only one of them is a config value: the
    ``pkgbuild`` driver has to be *mapped* for ``PKGBUILD`` (a line in
    ``info/attributes``), and the driver's ``xfuncname`` has to be set (the
    repo config below).  The config alone configures a driver nothing uses,
    so without the attributes line ``-W`` falls back to git's default
    function-context heuristic, the hunks are grouped differently, and the
    diffs are byte-different from the ones the baseline was measured with.

    So the mapping is *ensured* rather than merely created: a clone that
    already carries an ``info/attributes`` of its own keeps it and gains
    the two lines it is missing.
    """
    attrs = repo_dir / "info" / "attributes"
    attrs.parent.mkdir(parents=True, exist_ok=True)
    existing = (
        attrs.read_text(encoding="utf-8").splitlines() if attrs.exists() else []
    )
    missing = [line for line in _XFUNC_ATTRIBUTES if line not in existing]
    if missing:
        prefix = "\n" if existing and existing[-1].strip() else ""
        with attrs.open("a", encoding="utf-8") as handle:
            handle.write(prefix + "\n".join(missing) + "\n")
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
    """Stage 1 of the selector: metadata-only shape matching."""
    return [p for p in pkgs if corpus_select.metadata_match(p, stratum_name)]


def repo_tree(repo_dir: Path, branch: str) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "ls-tree", "-r", "--name-only", branch],
        capture_output=True, text=True, timeout=60,
    )
    return result.stdout.splitlines() if result.returncode == 0 else []


def repo_file(repo_dir: Path, branch: str, name: str,
              max_bytes: int = 512 * 1024) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "show", f"{branch}:{name}"],
        capture_output=True, text=False, timeout=60,
    )
    if result.returncode != 0 or len(result.stdout) > max_bytes:
        return ""
    return result.stdout.decode("utf-8", errors="replace")


def distinct_authors(repo_dir: Path, branch: str, limit: int = 200) -> int:
    result = subprocess.run(
        ["git", "-C", str(repo_dir), "log", branch, "--format=%ae", f"-{limit}"],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        return 0
    return len({line.strip().lower() for line in result.stdout.splitlines() if line.strip()})


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
    parser.add_argument("--max-per-stratum", type=int, default=120)
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
    parser.add_argument(
        "--append", action="store_true",
        help="keep every package already in --manifest and add candidates "
             "until each stratum reaches its target (corpus v2)",
    )
    parser.add_argument(
        "--corpus-version", type=int, default=1,
        help="version recorded in the lock (append mode usually 2)",
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

    print("\n=== Setting up AUR object cache ===")
    # Selection mode fetches only the branches it examines.  A full bare
    # clone of the AUR monorepo is tens of GB; the sparse cache is the same
    # object store the reconstruction path uses.
    aur_repo = ensure_sparse_repo(args.repo_dir)
    indicators = corpus_provenance.load_indicators()
    provenance_excluded: list[dict] = []

    previous_lock = None
    lock_entries: list[dict] = []
    if args.append and args.manifest.exists():
        previous_lock = json.loads(args.manifest.read_text())
        lock_entries = list(previous_lock.get("entries", []))
        if not any(args.out.glob("*.diff")):
            print("=== Reconstructing the existing corpus first ===")
            code = reconstruct_from_manifest(args.manifest, args.out, args.repo_dir)
            if code != 0:
                sys.exit(code)
    existing_names = {e["pkg"] for e in lock_entries}
    existing_by_stratum: dict[str, set[str]] = {}
    for entry in lock_entries:
        existing_by_stratum.setdefault(entry["stratum"], set()).add(entry["pkg"])

    pkg_counter = 0
    diff_counter = 0
    total_fetch_time = 0.0
    total_diff_time = 0.0

    for stratum_name, cfg in strata.get("strata", {}).items():
        target = cfg.get("target", 20)
        already = len(existing_by_stratum.get(stratum_name, ()))
        print(f"\n=== {stratum_name} (target: {target}, existing: {already}) ===")

        candidates = filter_by_stratum(all_pkgs, stratum_name)
        print(f"  Candidates: {len(candidates)}")

        by_popularity = sorted(
            candidates, key=lambda p: p.get("Popularity", 0), reverse=True
        )

        selected = already
        cap = cfg.get("max_candidates", args.max_per_stratum)
        for pkg in by_popularity[:cap]:
            if selected >= target:
                break
            name = pkg.get("Name", "")
            if not name or name in existing_names:
                continue
            reason = corpus_provenance.package_excluded(name, indicators)
            if reason:
                provenance_excluded.append({"pkg": name, "reason": reason})
                print(f"{name}: excluded by provenance ({reason})")
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

            if corpus_select.requires_tree(stratum_name):
                paths = repo_tree(aur_repo, name)
                pkgbuild = repo_file(aur_repo, name, "PKGBUILD")
                authors = (distinct_authors(aur_repo, name)
                           if stratum_name == "maintainer_churn" else None)
                if not corpus_select.tree_match(
                        pkg, stratum_name, paths=paths,
                        pkgbuild=pkgbuild, authors=authors):
                    print("shape mismatch")
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
        "corpus_version": args.corpus_version,
        "total_entries": len(lock_entries),
        "xfuncname": XFUNCNAME,
        "diff_flags": ["-W"],
        "core_abbrev": ABBREV,
        "entries": sorted(lock_entries, key=lambda e: (e["stratum"], e["pkg"], e["old_sha"])),
        "provenance": {
            "indicator_source_sha256": indicators["source_sha256"],
            "excluded": provenance_excluded,
            "excluded_of": f"{len(provenance_excluded)} candidates excluded",
        },
    }
    if previous_lock is not None:
        import hashlib
        lock["previous_lock_sha256"] = hashlib.sha256(
            json.dumps(previous_lock, sort_keys=True).encode()).hexdigest()
        old = previous_lock.get("provenance") or {}
        lock["provenance"]["excluded"] = (
            list(old.get("excluded") or []) + provenance_excluded)
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
