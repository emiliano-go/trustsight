#!/usr/bin/env python3
"""Assemble the signed ``baseline-*`` assets for a TrustSight release.

Every baseline the tool consumes at runtime is distributed as a release
asset in the TrustSight repository with the ``baseline-`` prefix, and a
baseline release ships the whole family:

* ``baseline-seed.tar.gz`` - the v2 hashed maintainer seed (built
  separately by ``scripts/build_hashed_seed.py``, given here as a
  ``trustsight-seed-v2/`` directory and repackaged)
* ``baseline-corpus.tar.zst`` - the corpus baseline (built separately
  with ``trustsight full-aur --export``, given here as a file and
  re-signed)

Every asset also gets a detached ``.sig`` sibling: the raw 64-byte
Ed25519 signature, over the exact asset bytes, under the distribution key.
The tool verifies that signature against the pinned public key before it
reads the payload.  The script self-verifies every signature with the
program's own verifier before it writes anything, so it cannot emit a
release the tool would refuse.

The distribution key never enters this repository.  Give the workflow
the raw private key via the Actions secret; for a local run, pass a
PEM key or a raw 32-byte key file.

The IOC pairs are *not* part of the baseline family.  With ``--ioc-only``
the script emits just the signed ``baseline-ioc-<source>-<incident>`` pairs
for the dedicated ``ioc-<date>`` channel release, so a time-sensitive
indicator set is republished without a full baseline cut.  No seed, corpus
or ``baseline-manifest.json`` is written.

Usage::

    python scripts/build_release_baselines.py \
        --out dist/ \
        --sign-key /tmp/distribution-key.pem \
        --seed-v2-dir /tmp/seed-v2 \
        --corpus /tmp/corpus.tar.zst

    python scripts/build_release_baselines.py \
        --out dist/ \
        --sign-key /tmp/distribution-key.pem \
        --ioc-only \
        --ioc data/iocs/asa-2026.json --ioc-source emiliano-go --ioc-incident asa-2026

The watchlist is likewise its own channel.  ``--watchlist-only`` emits just
the signed ``watchlist-official.json`` for a ``watchlist-<date>`` release;
its input carries public package names and already-salted maintainer hashes
(never plaintext):

    python scripts/build_release_baselines.py \
        --out dist/ \
        --sign-key /tmp/distribution-key.pem \
        --watchlist-only \
        --watchlist data/watchlist/official.json
"""

import argparse
import hashlib
import json
import shutil
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from build_ioc_baseline import _load_ed25519_private, _normalise_entries, build as build_ioc  # noqa: E402
from trustsight.full_aur.export import verify_artifact  # noqa: E402

BASELINE_MANIFEST = "baseline-manifest.json"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sign_asset(data: bytes, private_key) -> bytes:
    """Return the raw detached signature and self-verify it first."""
    signature = private_key.sign(data)
    pubkey = private_key.public_key().public_bytes_raw()
    if not verify_artifact(data, signature, pubkey):
        raise RuntimeError("internal error: produced a signature verification rejects")
    return signature


def write_signed_asset(out_dir: Path, name: str, data: bytes, private_key, assets: list[dict]):
    """Write an asset, its detached signature, and its manifest record."""
    signature = sign_asset(data, private_key)
    (out_dir / name).write_bytes(data)
    (out_dir / f"{name}.sig").write_bytes(signature)
    assets.append({
        "name": name,
        "sha256": sha256_bytes(data),
        "size": len(data),
        "signature": signature.hex(),
    })
    print(f"  {name} ({len(data):,} bytes, signed)")


def build_seed_asset(seed_v2_dir: Path, out_dir: Path, private_key, assets: list[dict]):
    """Repackage a trustsight-seed-v2 directory as baseline-seed.tar.gz."""
    seed_v2 = seed_v2_dir / "trustsight-seed-v2"
    if not seed_v2.is_dir():
        raise SystemExit(f"{seed_v2_dir} does not contain a trustsight-seed-v2/ directory")
    name = "baseline-seed.tar.gz"
    path = out_dir / name
    with tarfile.open(path, "w:gz") as tf:
        for item in sorted(seed_v2.rglob("*")):
            arcname = f"trustsight-seed-v2/{item.relative_to(seed_v2).as_posix()}"
            if item.is_dir():
                tf.add(item, arcname=arcname, recursive=False)
            else:
                tf.add(item, arcname=arcname)
    write_signed_asset(out_dir, name, path.read_bytes(), private_key, assets)


def copy_seed_asset(seed_archive: Path, out_dir: Path, private_key, assets: list[dict]):
    """Preserve a maintainer-built seed while adding its release signature."""
    write_signed_asset(
        out_dir, "baseline-seed.tar.gz", seed_archive.read_bytes(), private_key, assets
    )


def build_ioc_assets(args, out_dir: Path, private_key, assets: list[dict]):
    """Build and sign one manifest/iocs pair per --ioc input.

    The curator key that signs each manifest (and is recorded inside it) is
    ``--ioc-sign-key`` when given, otherwise the distribution key; the
    distribution ``.sig`` is always added on top.
    """
    curator_key = args.ioc_sign_key or args.sign_key
    for ioc_file, source, incident in zip(args.ioc, args.ioc_source, args.ioc_incident):
        rows = json.loads(ioc_file.read_text(encoding="utf-8"))
        if not isinstance(rows, list):
            raise SystemExit(f"{ioc_file}: input must be a JSON array of IOC entries")
        entries = _normalise_entries(rows, source)
        tmp = Path(tempfile.mkdtemp(prefix="baseline-ioc-"))
        try:
            build_ioc(entries, source, tmp, incident, 30, curator_key)
            name = f"baseline-ioc-{source}-{incident or 'incident'}"
            for part, filename in (("manifest", "manifest.json"), ("iocs", "iocs.jsonl")):
                data = (tmp / filename).read_bytes()
                suffix = "jsonl" if part == "iocs" else "json"
                write_signed_asset(out_dir, f"{name}-{part}.{suffix}", data, private_key, assets)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


WATCHLIST_ASSET = "watchlist-official.json"


def build_watchlist_asset(args, out_dir: Path, private_key, assets: list[dict]):
    """Build and sign the single watchlist document for the watchlist-* channel.

    The input carries public package names and already-salted maintainer
    hashes, never plaintext: hashing happens out of band with the
    installation's salt, exactly as the baseline seed is built.  The document
    also records the salt those hashes were built under, so an import can
    adopt it or skip the hashes when a different salt is already stored.
    """
    rows = json.loads(args.watchlist.read_text(encoding="utf-8"))
    if not isinstance(rows, dict):
        raise SystemExit(f"{args.watchlist}: input must be a JSON object")
    packages = rows.get("packages") or {}
    maintainers = rows.get("maintainers") or {}
    if not isinstance(packages, dict) or not isinstance(maintainers, dict):
        raise SystemExit(
            f"{args.watchlist}: 'packages' and 'maintainers' must be objects")
    for name in packages:
        if not str(name).strip():
            raise SystemExit(f"{args.watchlist}: empty package name")
    for name_hash in maintainers:
        value = str(name_hash).strip()
        if len(value) != 64 or any(c not in "0123456789abcdefABCDEF" for c in value):
            raise SystemExit(
                f"{args.watchlist}: maintainer key {value!r} is not a "
                "64-character hex hash")
    salt = str(args.watchlist_salt or rows.get("salt") or "").strip()
    if maintainers and not salt:
        raise SystemExit(
            f"{args.watchlist}: maintainer hashes need --watchlist-salt "
            "(the salt they were built under)")
    document = {
        "schema_version": 1,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "source": str(args.watchlist_source or "emiliano-go"),
        "salt": salt,
        "packages": packages,
        "maintainers": maintainers,
    }
    data = (json.dumps(document, indent=2) + "\n").encode("utf-8")
    write_signed_asset(out_dir, WATCHLIST_ASSET, data, private_key, assets)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("dist"),
                        help="Output directory for the baseline-* assets (default: dist/)")
    parser.add_argument("--sign-key", required=True, type=Path,
                        help="ed25519 private key: PEM or raw 32-byte file (distribution key)")
    seed_group = parser.add_mutually_exclusive_group()
    seed_group.add_argument("--seed-v2-dir", type=Path, default=None,
                            help="Directory containing trustsight-seed-v2/ to repackage")
    seed_group.add_argument("--seed-archive", type=Path, default=None,
                            help="Existing canonical baseline-seed.tar.gz to re-sign")
    parser.add_argument("--ioc", type=Path, action="append", default=[],
                        help="Curated IOC JSON input file (repeatable; requires --ioc-only)")
    parser.add_argument("--ioc-source", action="append", default=[],
                        help="Curator source name, one per --ioc")
    parser.add_argument("--ioc-incident", action="append", default=[],
                        help="Incident identifier, one per --ioc")
    parser.add_argument("--ioc-sign-key", type=Path, default=None,
                        help="Curator key for the IOC manifests (default: the distribution key)")
    parser.add_argument("--corpus", type=Path, default=None,
                        help="Corpus baseline artifact (.tar.zst) to re-sign")
    parser.add_argument("--baseline-version", type=int, default=None,
                        help="Monotonic release version recorded in the signed "
                             "baseline-manifest.json (default: the current epoch)")
    parser.add_argument("--expires-at", default="",
                        help="Optional ISO timestamp after which the signed "
                             "baseline must not be imported")
    parser.add_argument("--ioc-only", action="store_true",
                        help="Build only the IOC pair(s), for the dedicated "
                             "ioc-* channel: no seed, corpus or "
                             "baseline-manifest.json is emitted")
    parser.add_argument("--watchlist", type=Path, default=None,
                        help="Watchlist input JSON ({packages, maintainers, salt})")
    parser.add_argument("--watchlist-source", default="emiliano-go",
                        help="Source name recorded in the watchlist document")
    parser.add_argument("--watchlist-salt", default="",
                        help="Salt the maintainer hashes were built under")
    parser.add_argument("--watchlist-only", action="store_true",
                        help="Build only the watchlist document, for the "
                             "dedicated watchlist-* channel: no seed, corpus, "
                             "IOC pair or baseline-manifest.json is emitted")
    args = parser.parse_args()

    if len(args.ioc) != len(args.ioc_source) or len(args.ioc) != len(args.ioc_incident):
        parser.error("one --ioc-source and one --ioc-incident per --ioc input")
    if args.ioc and not args.ioc_only:
        parser.error("--ioc ships only on the ioc-* channel: pass --ioc-only")
    if args.ioc_only and not args.ioc:
        parser.error("--ioc-only needs at least one --ioc input")
    if args.ioc_only and (args.seed_v2_dir or args.seed_archive or args.corpus):
        parser.error("--ioc-only cannot be combined with a seed or --corpus")
    if args.watchlist and not args.watchlist_only:
        parser.error("--watchlist ships only on the watchlist-* channel: "
                     "pass --watchlist-only")
    if args.watchlist_only and not args.watchlist:
        parser.error("--watchlist-only needs --watchlist")
    if args.watchlist_only and (args.seed_v2_dir or args.seed_archive
                                or args.corpus or args.ioc):
        parser.error("--watchlist-only cannot be combined with a seed, "
                     "--corpus or an IOC input")

    out_dir = args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    if not args.seed_v2_dir and not args.seed_archive and not args.ioc \
            and not args.corpus and not args.watchlist:
        parser.error("nothing to build: pass a seed, --ioc, --corpus "
                     "or --watchlist")

    private_key = _load_ed25519_private(args.sign_key)
    pubkey_hex = private_key.public_key().public_bytes_raw().hex()

    assets: list[dict] = []
    if args.ioc_only:
        # The ioc-* channel carries only the IOC pairs: a baseline-manifest.json
        # here would be a baseline-family artifact on the wrong release, and the
        # baseline family never carries the pairs.
        print(f"Building the ioc-* assets into {out_dir}")
        build_ioc_assets(args, out_dir, private_key, assets)
        print(f"Wrote {len(assets)} IOC asset(s) for the ioc-* channel.")
        return 0

    if args.watchlist_only:
        # Like ioc-only: the watchlist-* channel carries exactly one signed
        # document, never a baseline-family artifact.
        print(f"Building the watchlist-* asset into {out_dir}")
        build_watchlist_asset(args, out_dir, private_key, assets)
        print(f"Wrote {len(assets)} watchlist asset(s) for the watchlist-* channel.")
        return 0

    print(f"Building release baselines into {out_dir}")
    if args.seed_v2_dir:
        build_seed_asset(args.seed_v2_dir, out_dir, private_key, assets)
    if args.seed_archive:
        copy_seed_asset(args.seed_archive, out_dir, private_key, assets)
    if args.corpus:
        data = args.corpus.read_bytes()
        write_signed_asset(out_dir, "baseline-corpus.tar.zst", data, private_key, assets)

    manifest = {
        "schema_version": 1,
        "version": (
            args.baseline_version
            if args.baseline_version is not None
            else int(datetime.now(timezone.utc).timestamp())
        ),
        "built_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": args.expires_at,
        "distribution_pubkey": pubkey_hex,
        "assets": assets,
    }
    write_signed_asset(
        out_dir,
        BASELINE_MANIFEST,
        (json.dumps(manifest, indent=2) + "\n").encode("utf-8"),
        private_key,
        [],
    )
    print(f"Wrote {BASELINE_MANIFEST} with {len(assets)} asset(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
