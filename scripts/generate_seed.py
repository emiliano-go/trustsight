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
import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pygit2

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from trustsight.novelty import normalize_url  # noqa: E402
from trustsight.deps import normalize_dependency  # noqa: E402
from trustsight.fetcher import extract_maintainer  # noqa: E402
from trustsight.seed_build import _identity_key  # noqa: E402
from trustsight.srcinfo import parse_srcinfo  # noqa: E402

CACHE_DIR = Path.home() / ".cache" / "trustsight"
AUR_REPO = CACHE_DIR / "aur.git"
DEFAULT_METADATA = CACHE_DIR / "corpus" / "packages-meta-ext-v1.json"

SEED_TIMESTAMP = "2024-01-01T00:00:00"
MAX_METADATA_BYTES = 512 * 1024 * 1024

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
    count INTEGER,
    source TEXT
);
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS dependency_names (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE,
    first_seen_globally_timestamp TEXT,
    observation_count INTEGER
);
CREATE INDEX IF NOT EXISTS idx_source_urls_url ON source_urls(url);
CREATE INDEX IF NOT EXISTS idx_dependency_names_name ON dependency_names(name);
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


_DEP_FIELDS = ("depends", "makedepends", "optdepends", "checkdepends")


def extract_dependency_names(srcinfo_text: str) -> list[str]:
    """Return every dependency, package, and provides name in a .SRCINFO.

    Package names and ``provides`` aliases are included deliberately: a
    dependency satisfied by an alias (``libfoo.so``) or by a package that
    nothing else depends on is not novel, and omitting them would make
    D001 fire on ordinary packages.

    Arch-suffixed arrays (``depends_x86_64``) count too, since that is
    where -bin packages put their real dependencies.
    """
    parsed = parse_srcinfo(srcinfo_text)
    names: list[str] = []
    for key, values in parsed.items():
        base = key.split("_")[0]
        if base not in _DEP_FIELDS and key not in ("pkgname", "pkgbase", "provides"):
            continue
        for value in values:
            name = normalize_dependency(value)
            if name:
                names.append(name)
    return names


def load_metadata(path: Path) -> tuple[dict[str, dict], str]:
    """Load the AUR metadata snapshot and index it by package base.

    The snapshot is the authority for the current maintainer.  The AUR git
    mirror is the authority for the recipe, but its ``# Maintainer:``
    comment can be stale, so it is kept as a named alias rather than
    discarded.
    """
    if path.stat().st_size > MAX_METADATA_BYTES:
        raise ValueError(
            f"metadata snapshot exceeds {MAX_METADATA_BYTES} bytes: {path}")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    entries = json.loads(raw.decode("utf-8"))
    if not isinstance(entries, list):
        raise ValueError("metadata snapshot must be a JSON array")
    index: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        base = str(entry.get("PackageBase") or entry.get("Name") or "").strip()
        if not base:
            continue
        # A split package may appear before its base with no maintainer.
        # Keep the first non-empty value, and never replace it with an
        # empty one.
        if base not in index or (
            not index[base].get("Maintainer") and entry.get("Maintainer")
        ):
            index[base] = entry
    return index, digest


def maintainer_records(
    authoritative: str,
    comment: str,
    *,
    metadata_present: bool,
    metadata_loaded: bool = True,
) -> tuple[list[dict], str]:
    """Return the seed records for one package and a coverage label.

    The authoritative field owns the active package count.  The comment is
    an alias with count zero, so it makes an established name known to
    novelty lookups without inflating its package count.  An orphan has no
    active maintainer; its comment is still useful as a known alias.
    """
    primary = (authoritative or "").strip()
    alias = (comment or "").strip()
    if primary:
        records = [{
            "name": primary,
            "package_count": 1,
            "source": "aur-metadata",
        }]
        if alias and _identity_key(alias) != _identity_key(primary):
            records.append({
                "name": alias,
                "package_count": 0,
                "source": "aur-comment-alias",
            })
        return records, "metadata"
    if metadata_loaded and metadata_present:
        if alias:
            return [{
                "name": alias,
                "package_count": 0,
                "source": "aur-comment-orphan",
            }], "orphan"
        return [], "orphan"
    if metadata_loaded and not metadata_present:
        if alias:
            return [{
                "name": alias,
                "package_count": 0,
                "source": "aur-comment-missing",
            }], "missing"
        return [], "missing"
    if alias:
        return [{
            "name": alias,
            "package_count": 1,
            "source": "aur-comment",
        }], "comment"
    return [], "none"


def build(
    out_path: Path,
    limit: int = 0,
    progress_every: int = 2000,
    metadata_path: Path | None = None,
) -> dict:
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

    metadata: dict[str, dict] = {}
    metadata_digest = ""
    if metadata_path is not None:
        print(f"=== Reading metadata {metadata_path} ===")
        metadata, metadata_digest = load_metadata(metadata_path)
        print(f"  {len(metadata)} package bases")

    url_counter: Counter[str] = Counter()
    maintainer_rows: dict[str, dict] = {}
    dep_counter: Counter[str] = Counter()
    packages_with_sources = 0
    coverage = Counter()
    start = time.time()

    print("\n=== Reading .SRCINFO ===")
    for i, branch in enumerate(branches, 1):
        srcinfo_text, pkgbuild_text = read_tree_files(repo, branch)
        if not srcinfo_text:
            continue
        urls = extract_sources(srcinfo_text)
        # The maintainer is a PKGBUILD comment, so it must be read the
        # same way the running tool reads it or the names will not match.
        comment = extract_maintainer(pkgbuild_text, srcinfo_text)
        meta = metadata.get(branch)
        records, kind = maintainer_records(
            str((meta or {}).get("Maintainer") or ""),
            comment or "",
            metadata_present=meta is not None,
            metadata_loaded=bool(metadata),
        )
        coverage[kind] += 1
        if urls:
            packages_with_sources += 1
        for url in urls:
            url_counter[normalize_url(url)] += 1
        for dep in extract_dependency_names(srcinfo_text):
            dep_counter[dep] += 1
        for record in records:
            name = record["name"]
            row = maintainer_rows.setdefault(
                name, {"count": 0, "source": record["source"],
                       "primary": False})
            row["count"] += record["package_count"]
            if record["package_count"] > 0:
                row["source"] = record["source"]
                row["primary"] = True
            elif not row["primary"]:
                row["source"] = record["source"]
        if i % progress_every == 0:
            rate = i / max(time.time() - start, 0.001)
            print(f"  {i}/{len(branches)} branches, {len(url_counter)} urls "
                  f"({rate:.0f}/s)")

    print(f"\n  {packages_with_sources} packages had source URLs")
    print(f"  {len(url_counter)} distinct normalized URLs")
    print(f"  {len(maintainer_rows)} distinct maintainers")
    print(f"  {len(dep_counter)} distinct dependency names")
    print(f"  maintainer coverage: {dict(coverage)}")

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
        """INSERT OR REPLACE INTO maintainer_counts (name, count, source)
           VALUES (?, ?, ?)""",
        [(name, row["count"], row["source"])
         for name, row in maintainer_rows.items()],
    )
    conn.executemany(
        """INSERT OR IGNORE INTO dependency_names
           (name, first_seen_globally_timestamp, observation_count)
           VALUES (?, ?, ?)""",
        [(n, SEED_TIMESTAMP, c) for n, c in dep_counter.items()],
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
            ("seed_dependency_count", str(len(dep_counter))),
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
        "maintainers": len(maintainer_rows),
        "maintainer_observations": sum(
            row["count"] for row in maintainer_rows.values()),
        "dependency_names": len(dep_counter),
        "observations": packages_with_sources,
        "package_count": len(branches),
        "authoritative_maintainers": coverage["metadata"],
        "comment_aliases": coverage["metadata"] + coverage["orphan"],
        "orphan_packages": coverage["orphan"],
        "missing_metadata_packages": coverage["missing"],
        "comment_only_packages": coverage["comment"],
        "metadata_package_count": len(metadata),
        "metadata_sha256": metadata_digest,
    }


def build_provenance(
    *,
    source: str,
    package_count: int,
    packages_with_sources: int,
    maintainer_count: int,
    observation_count: int,
    mirror_size_bytes: int,
    command: str,
    built_at: str | None = None,
    maintainer_source: str = "aur-comment",
    metadata_sha256: str = "",
    metadata_package_count: int = 0,
    authoritative_maintainers: int = 0,
    comment_aliases: int = 0,
    orphan_packages: int = 0,
    missing_metadata_packages: int = 0,
) -> dict:
    """Assemble the seed-provenance record for a fresh build.

    The record is what lets a third party reproduce the published seed and
    compare what they got: the exact mirror path, the sizes it observed,
    the build timestamp and the command line that produced it.  It is
    written by ``--provenance-out`` and shipped inside the seed archive as
    ``trustsight-seed-v2/seed-provenance.json``; it is metadata about the
    build, never part of the hashed content.
    """
    return {
        "format_version": "1.0.0",
        "source": source,
        "package_count": package_count,
        "packages_with_sources": packages_with_sources,
        "maintainer_count": maintainer_count,
        "observation_count": observation_count,
        "mirror_size_bytes": mirror_size_bytes,
        "built_at": built_at or datetime.now(timezone.utc).isoformat(),
        "command": command,
        "maintainer_source": maintainer_source,
        "metadata_sha256": metadata_sha256,
        "metadata_package_count": metadata_package_count,
        "authoritative_maintainers": authoritative_maintainers,
        "comment_aliases": comment_aliases,
        "orphan_packages": orphan_packages,
        "missing_metadata_packages": missing_metadata_packages,
    }


def _mirror_size_bytes(path: Path) -> int:
    """Total size of the mirror on disk, via ``du -sb``."""
    out = subprocess.check_output(["du", "-sb", str(path)], text=True)
    return int(out.split()[0])


def main():
    parser = argparse.ArgumentParser(description="Build the novelty seed DB")
    parser.add_argument("--out", type=Path,
                        default=Path("src/trustsight/data/seed.db"))
    parser.add_argument("--limit", type=int, default=0,
                        help="Only read this many branches (for a quick run)")
    parser.add_argument("--provenance-out", type=Path, default=None,
                        help="Write seed-provenance.json describing this build")
    parser.add_argument(
        "--metadata", type=Path, default=None,
        help=("AUR packages-meta-ext JSON snapshot. Defaults to the cached "
              "corpus snapshot when present; otherwise the PKGBUILD comment "
              "is used as a fallback."),
    )
    args = parser.parse_args()
    metadata_path = args.metadata
    if metadata_path is None and DEFAULT_METADATA.is_file():
        metadata_path = DEFAULT_METADATA
    stats = build(args.out, limit=args.limit, metadata_path=metadata_path)

    if args.provenance_out:
        provenance = build_provenance(
            source=str(AUR_REPO),
            package_count=stats["package_count"],
            packages_with_sources=stats["observations"],
            maintainer_count=stats["maintainers"],
            observation_count=stats["maintainer_observations"],
            mirror_size_bytes=_mirror_size_bytes(AUR_REPO),
            command=" ".join(sys.argv),
            maintainer_source=(
                "aur-metadata" if stats["authoritative_maintainers"] else
                "aur-comment"),
            metadata_sha256=stats["metadata_sha256"],
            metadata_package_count=stats["metadata_package_count"],
            authoritative_maintainers=stats["authoritative_maintainers"],
            comment_aliases=stats["comment_aliases"],
            orphan_packages=stats["orphan_packages"],
            missing_metadata_packages=stats["missing_metadata_packages"],
        )
        args.provenance_out.parent.mkdir(parents=True, exist_ok=True)
        args.provenance_out.write_text(
            json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
        )
        print(f"Provenance written: {args.provenance_out}")


if __name__ == "__main__":
    main()
