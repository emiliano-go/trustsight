"""Build a v2 hashed maintainer seed.

The seed format stores only salted SHA-256 hashes of maintainer names and
emails, together with non-identifying metadata such as package counts and
first-seen timestamps.  No plaintext identity is written to the seed.
"""

import hashlib
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .bounded_io import read_file_capped

DEFAULT_HASH_ALGORITHM = "sha256"
SEED_FORMAT_VERSION = "2.0.0"

# Ceiling on the provenance file copied into a seed.  It is a short JSON
# record of how the seed was built; the bound is here because every read of
# a path an operator supplied is bounded, not because this one is risky.
MAX_PROVENANCE_BYTES = 4 * 1024 * 1024

# Ceiling on the raw maintainer records a seed is built from.  The real
# input is ~36k records scraped from AUR git history; this is well above
# that and well below what would exhaust the builder.
MAX_RAW_MAINTAINERS_BYTES = 512 * 1024 * 1024


def _generate_salt() -> str:
    """Return a fresh 32-byte salt as hex."""
    return os.urandom(32).hex()


#: Characters that are invisible but split a name into two identities.
_ZERO_WIDTH = dict.fromkeys(
    (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E), None
)

#: Confusables folded to the ASCII letter they imitate.
#:
#: `Alice`, `alice`, `аlice` (Cyrillic а) and `ali<ZWSP>ce` are four
#: identities to a hash of the raw text and one person to a reader. That
#: split is not only an evasion: rotating the spelling means the
#: longitudinal signals - maintainer stability, the observation floor -
#: never accumulate, so an account can stay permanently new.
#:
#: Every step below is chosen to be a *no-op on ASCII*, because this is the
#: hashing chokepoint the shipped seed corpus was built through: an
#: existing plain-name entry has to keep hashing to the value already
#: recorded, or every lookup against the seed would miss.
_CONFUSABLE_FOLD = {
    ord("\u0430"): "a", ord("\u0435"): "e", ord("\u043e"): "o",
    ord("\u0440"): "p", ord("\u0441"): "c", ord("\u0445"): "x",
    ord("\u0443"): "y", ord("\u0456"): "i", ord("\u04cf"): "l",
    ord("\u0261"): "g", ord("\u03bf"): "o", ord("\u0391"): "a",
    ord("\u0392"): "b", ord("\u0395"): "e", ord("\u039a"): "k",
    ord("\u039c"): "m", ord("\u039d"): "n", ord("\u03a1"): "p",
    ord("\u03a4"): "t", ord("\u0405"): "s", ord("\u04bb"): "h",
}


def _identity_key(value: str) -> str:
    """The one spelling of an identity, for hashing and comparison."""
    import unicodedata

    text = unicodedata.normalize("NFKC", value)
    text = text.translate(_ZERO_WIDTH)
    text = text.translate(_CONFUSABLE_FOLD)
    return text.strip().lower()


def _hash_value(value: str, salt: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> str:
    """Return the salted hash of *value* as a hex string.

    The input is normalised to ``strip().lower()`` before hashing (spec
    §3.3.1): a maintainer whose name or email differs only in case or
    surrounding whitespace must hash to the same value, or the novelty
    signal would read every casing as a new identity.  This is the single
    hashing chokepoint - ``db._hash_maintainer_value`` delegates here - so
    the seed, the plaintext migration and every lookup normalise identically
    and cannot drift apart.
    """
    if algorithm != DEFAULT_HASH_ALGORITHM:
        raise ValueError(f"unsupported hash algorithm: {algorithm}")
    normalized = _identity_key(value)
    return hashlib.sha256(f"{salt}|{normalized}".encode("utf-8")).hexdigest()


def _normalise_maintainer(raw: dict) -> dict:
    """Return a cleaned maintainer record with explicit defaults."""
    name = (raw.get("name") or "").strip()
    if not name:
        raise ValueError("maintainer record missing name")
    email = (raw.get("email") or "").strip() or None
    packages = raw.get("packages")
    if packages is not None and not isinstance(packages, list):
        raise ValueError("packages must be a list")
    return {
        "name": name,
        "email": email,
        "first_seen": raw.get("first_seen") or datetime.now(timezone.utc).isoformat(),
        "package_count": int(raw.get("package_count", 0) or 0),
        "packages": packages,
        "source": raw.get("source") or "aur",
    }


def build_seed(
    raw_maintainers: list[dict],
    out_dir: Path,
    hash_algorithm: str = DEFAULT_HASH_ALGORITHM,
    provenance: Path | None = None,
) -> dict:
    """Build a v2 hashed maintainer seed under *out_dir*.

    *raw_maintainers* is a list of dicts with keys ``name`` (required),
    ``email`` (optional), ``first_seen`` (optional ISO timestamp),
    ``package_count`` (optional int), ``packages`` (optional list of str),
    and ``source`` (optional str).

    Writes ``trustsight-seed-v2/seed_meta.json`` and
    ``trustsight-seed-v2/maintainers.jsonl`` under *out_dir*.  If
    *provenance* is given, the file is copied verbatim into the seed
    directory as ``seed-provenance.json``; it is metadata about the build,
    never part of the hashed content.

    Returns the seed metadata dict.
    """
    out_dir = Path(out_dir)
    seed_dir = out_dir / "trustsight-seed-v2"
    seed_dir.mkdir(parents=True, exist_ok=True)

    if provenance is not None and not Path(provenance).is_file():
        raise SystemExit(f"provenance file not found: {provenance}")

    salt = _generate_salt()
    now = datetime.now(timezone.utc).isoformat()

    # Fold duplicate names so package counts accumulate deterministically.
    by_name: dict[str, dict] = defaultdict(
        lambda: {
            "email": None,
            "first_seen": None,
            "package_count": 0,
            "packages": set(),
            "source": "aur",
        }
    )
    for raw in raw_maintainers:
        rec = _normalise_maintainer(raw)
        bucket = by_name[rec["name"]]
        if rec["email"]:
            bucket["email"] = rec["email"]
        if bucket["first_seen"] is None or (
            rec["first_seen"] and rec["first_seen"] < bucket["first_seen"]
        ):
            bucket["first_seen"] = rec["first_seen"]
        bucket["package_count"] += rec["package_count"]
        if rec["packages"]:
            bucket["packages"].update(rec["packages"])
        if rec["source"]:
            bucket["source"] = rec["source"]

    count = len(by_name)
    meta = {
        "format_version": SEED_FORMAT_VERSION,
        "salt": salt,
        "hash_algorithm": hash_algorithm,
        "count": count,
        "built_at": now,
        "seed_hash": "",  # filled after hashing the contents
    }

    maintainer_lines = []
    for name, rec in by_name.items():
        name_hash = _hash_value(name, salt, hash_algorithm)
        email_hash = _hash_value(rec["email"], salt, hash_algorithm) if rec["email"] else None
        packages = sorted(rec["packages"]) if rec["packages"] else None
        package_count = rec["package_count"]
        if not package_count and packages:
            package_count = len(packages)
        line = {
            "name_hash": name_hash,
            "email_hash": email_hash,
            "first_seen": rec["first_seen"] or now,
            "package_count": max(1, package_count) if package_count else 1,
            "packages": packages,
            "source": rec["source"],
        }
        maintainer_lines.append(line)

    # Deterministic seed_hash over the final contents.
    h = hashlib.sha256()
    h.update(json.dumps(meta, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    for line in sorted(maintainer_lines, key=lambda x: x["name_hash"]):
        h.update(json.dumps(line, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    meta["seed_hash"] = h.hexdigest()

    meta_path = seed_dir / "seed_meta.json"
    maint_path = seed_dir / "maintainers.jsonl"

    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
        fh.write("\n")

    with open(maint_path, "w", encoding="utf-8") as fh:
        for line in maintainer_lines:
            fh.write(json.dumps(line, separators=(",", ":")) + "\n")

    if provenance is not None:
        prov_dst = seed_dir / "seed-provenance.json"
        prov_dst.write_bytes(
            read_file_capped(
                Path(provenance), MAX_PROVENANCE_BYTES, "seed provenance file"
            )
        )

    return {
        **meta,
        "seed_dir": str(seed_dir),
        "maintainers_file": str(maint_path),
    }


def _read_raw_maintainers(path: Path) -> list[dict]:
    """Read raw maintainer records from a JSON array or JSONL file."""
    text = read_file_capped(
        path, MAX_RAW_MAINTAINERS_BYTES, "raw maintainer records"
    ).decode("utf-8")
    if text.strip().startswith("["):
        return json.loads(text)
    records = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))
    return records


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Build a v2 hashed maintainer seed from raw maintainer data."
    )
    parser.add_argument(
        "input",
        type=Path,
        help="JSON or JSONL file of raw maintainer records",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("trustsight-seed-v2"),
        help="Output directory (default: trustsight-seed-v2)",
    )
    parser.add_argument(
        "--algorithm",
        default=DEFAULT_HASH_ALGORITHM,
        help="Hash algorithm (default: sha256)",
    )
    parser.add_argument(
        "--provenance",
        type=Path,
        default=None,
        help="seed-provenance.json to copy into the seed directory verbatim",
    )
    args = parser.parse_args()

    raw = _read_raw_maintainers(args.input)
    result = build_seed(raw, args.out, args.algorithm, args.provenance)
    print(f"Wrote {result['count']} hashed maintainers to {result['seed_dir']}")
    print(f"  salt: {result['salt']}")
    print(f"  seed_hash: {result['seed_hash']}")


if __name__ == "__main__":
    main()
