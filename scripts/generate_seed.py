"""Build the novelty seed database from the AUR git mirror.

Why the git mirror and not the metadata dump: `packages-meta-ext-v1.json.gz`
carries Name, Maintainer, Description, Depends and the project homepage,
but **not** the `source=()` array.  Source URLs exist only in each
package's `.SRCINFO`, so they have to come from the repository itself.

Without a seed, a fresh install has an empty `source_urls` table, so
`url_first_globally` fires for github.com, kernel.org and every other
ordinary host, and `maturity()` returns 0 because there is no analysis
history.  The first is a false positive; the second gates tier C off
entirely and leaves every Medium verdict downgraded to INCONCLUSIVE.

The seed fixes both: real URLs make novelty meaningful, and a bootstrap
observation count lets maturity reflect what the database actually knows.
Real analyses take over as soon as they outnumber the seed.

Usage:
    python scripts/generate_seed.py --out src/trustsight/data/seed.db
    python scripts/generate_seed.py --out seed.db --limit 500   # quick run
"""

import argparse
import gzip
import shutil
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path

import pygit2

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from trustsight.novelty import normalize_url  # noqa: E402
from trustsight.fetcher import extract_maintainer  # noqa: E402
from trustsight.srcinfo import parse_srcinfo  # noqa: E402

CACHE_DIR = Path.home() / ".cache" / "trustsight"
AUR_REPO = CACHE_DIR / "aur.git"

SEED_TIMESTAMP = "2024-01-01T00:00:00"

SCHEMA = """
CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    current_version TEXT,
    last_checked TEXT
);
CREATE TABLE IF NOT EXISTS source_urls (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE NOT NULL,
    first_seen_package_id INTEGER,
    first_seen_globally_timestamp TEXT,
    total_uses INTEGER DEFAULT 1,
    last_seen_timestamp TEXT
);
CREATE TABLE IF NOT EXISTS maintainer_counts (
    name TEXT PRIMARY KEY,
    count INTEGER
);
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE INDEX IF NOT EXISTS idx_source_urls_url ON source_urls(url);
"""


def open_repo(path: Path) -> pygit2.Repository:
    return pygit2.Repository(str(path))


def list_branches(repo: pygit2.Repository) -> list[str]:
    """Every package branch in the mirror."""
    prefix = "refs/heads/"
    return [
        name[len(prefix):]
        for name in repo.references
        if name.startswith(prefix)
    ]


def read_tree_files(repo: pygit2.Repository, branch: str) -> tuple[str, str]:
    """Return (.SRCINFO, PKGBUILD) text at the tip of *branch*.

    Reads blobs straight out of the object database.  Shelling out to
    `git show` twice per branch costs a process spawn each time, which
    dominates the run across ~116k branches.
    """
    try:
        tree = repo.revparse_single(f"refs/heads/{branch}").peel(pygit2.Commit).tree
    except (KeyError, pygit2.GitError, ValueError, TypeError):
        return "", ""

    def blob(name: str) -> str:
        try:
            entry = tree[name]
        except KeyError:
            return ""
        try:
            return repo[entry.id].data.decode("utf-8", errors="replace")
        except (KeyError, AttributeError, ValueError):
            return ""

    return blob(".SRCINFO"), blob("PKGBUILD")


def extract_sources(srcinfo_text: str) -> list[str]:
    """Return source URLs from parsed .SRCINFO.

    Includes the arch-suffixed arrays (source_x86_64 and friends), which
    is where -bin packages usually put their real download.
    """
    parsed = parse_srcinfo(srcinfo_text)
    urls = []
    for key, values in parsed.items():
        if key != "source" and not key.startswith("source_"):
            continue
        for value in values:
            # `source` entries may be "filename::url"; keep the URL half.
            candidate = value.split("::", 1)[-1].strip()
            if candidate.startswith(("http://", "https://", "git+http")):
                urls.append(candidate)
    return urls


def build(out_path: Path, limit: int = 0, progress_every: int = 2000) -> dict:
    if not AUR_REPO.exists():
        print(f"AUR mirror not found at {AUR_REPO}.", file=sys.stderr)
        print("Run scripts/build_corpus.py first to create it.", file=sys.stderr)
        sys.exit(1)

    print("=== Listing package branches ===")
    repo = open_repo(AUR_REPO)
    branches = list_branches(repo)
    if limit:
        branches = branches[:limit]
    print(f"  {len(branches)} branches")

    url_counter: Counter[str] = Counter()
    maint_counter: Counter[str] = Counter()
    packages_with_sources = 0
    start = time.time()

    print("\n=== Reading .SRCINFO ===")
    for i, branch in enumerate(branches, 1):
        srcinfo_text, pkgbuild_text = read_tree_files(repo, branch)
        if not srcinfo_text:
            continue
        urls = extract_sources(srcinfo_text)
        # The maintainer is a PKGBUILD comment, so it must be read the
        # same way the running tool reads it or the names will not match.
        maintainer = extract_maintainer(pkgbuild_text)
        if urls:
            packages_with_sources += 1
        for url in urls:
            url_counter[normalize_url(url)] += 1
        if maintainer:
            maint_counter[maintainer] += 1
        if i % progress_every == 0:
            rate = i / max(time.time() - start, 0.001)
            print(f"  {i}/{len(branches)} branches, {len(url_counter)} urls "
                  f"({rate:.0f}/s)")

    print(f"\n  {packages_with_sources} packages had source URLs")
    print(f"  {len(url_counter)} distinct normalized URLs")
    print(f"  {len(maint_counter)} distinct maintainers")

    if out_path.exists():
        out_path.unlink()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(out_path))
    conn.executescript(SCHEMA)
    # first_seen_package_id references packages(id); the importing client
    # enables foreign_keys, so the row has to exist.
    conn.execute(
        "INSERT OR IGNORE INTO packages (id, name) VALUES (0, '__seed__')"
    )
    conn.executemany(
        """INSERT OR IGNORE INTO source_urls
           (url, first_seen_package_id, first_seen_globally_timestamp,
            total_uses, last_seen_timestamp)
           VALUES (?, 0, ?, ?, ?)""",
        [(u, SEED_TIMESTAMP, c, SEED_TIMESTAMP) for u, c in url_counter.items()],
    )
    conn.executemany(
        "INSERT OR REPLACE INTO maintainer_counts (name, count) VALUES (?, ?)",
        list(maint_counter.items()),
    )
    # The bootstrap maturity value.  It is the number of packages the seed
    # actually observed, not an arbitrary constant, so a partial seed
    # produces proportionally lower maturity.
    conn.executemany(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
        [
            ("seed_observation_count", str(packages_with_sources)),
            ("seed_version", time.strftime("%Y-%m-%d")),
            ("seed_url_count", str(len(url_counter))),
        ],
    )
    conn.commit()
    conn.execute("VACUUM")
    conn.close()

    raw_size = out_path.stat().st_size
    gz_path = out_path.with_suffix(out_path.suffix + ".gz")
    with open(out_path, "rb") as src, gzip.open(gz_path, "wb", compresslevel=9) as dst:
        shutil.copyfileobj(src, dst)

    print(f"\n{'=' * 50}")
    print(f"Seed written:   {out_path} ({raw_size >> 20} MB)")
    print(f"Compressed:     {gz_path} ({gz_path.stat().st_size >> 20} MB)")
    print(f"Observations:   {packages_with_sources}")
    print(f"Elapsed:        {time.time() - start:.1f}s")
    return {
        "urls": len(url_counter),
        "maintainers": len(maint_counter),
        "observations": packages_with_sources,
    }


def main():
    parser = argparse.ArgumentParser(description="Build the novelty seed DB")
    parser.add_argument("--out", type=Path,
                        default=Path("src/trustsight/data/seed.db"))
    parser.add_argument("--limit", type=int, default=0,
                        help="Only read this many branches (for a quick run)")
    args = parser.parse_args()
    build(args.out, limit=args.limit)


if __name__ == "__main__":
    main()
