#!/usr/bin/env python3
"""Assemble the signed ``baseline-*`` assets for a TrustSight release.

Every baseline the tool consumes at runtime is distributed as a release
asset in the TrustSight repository with the ``baseline-`` prefix, and a
release ships the whole family:

* ``baseline-seed.tar.gz`` - the v2 hashed maintainer seed (built
  separately by ``scripts/build_hashed_seed.py``, given here as a
  ``trustsight-seed-v2/`` directory and repackaged)
* ``baseline-ioc-<source>-<incident>-manifest.json`` and
  ``baseline-ioc-<source>-<incident>-iocs.jsonl`` - one pair per curated
  IOC input file; the manifest carries the curator key and its own
  signature, exactly as ``scripts/build_ioc_baseline.py`` produces
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

Usage::

    python scripts/build_release_baselines.py \
        --out dist/ \
        --sign-key /tmp/distribution-key.pem \
        --seed-v2-dir /tmp/seed-v2 \
        --ioc data/iocs/asa-2026.json --ioc-source emiliano-go --ioc-incident asa-2026 \
        --corpus /tmp/corpus.tar.zst
"""

import argparse
import hashlib
import json
import shutil
import sys
import tarfile
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
        tmp = Path(shutil.mkdtemp(prefix="baseline-ioc-"))
        try:
            build_ioc(entries, source, tmp, incident, 30, curator_key)
            name = f"baseline-ioc-{source}-{incident or 'incident'}"
            for part, filename in (("manifest", "manifest.json"), ("iocs", "iocs.jsonl")):
                data = (tmp / filename).read_bytes()
                write_signed_asset(out_dir, f"{name}-{part}.json", data, private_key, assets)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("dist"),
                        help="Output directory for the baseline-* assets (default: dist/)")
    parser.add_argument("--sign-key", required=True, type=Path,
                        help="ed25519 private key: PEM or raw 32-byte file (distribution key)")
    parser.add_argument("--seed-v2-dir", type=Path, default=None,
                        help="Directory containing trustsight-seed-v2/ to repackage")
    parser.add_argument("--ioc", type=Path, action="append", default=[],
                        help="Curated IOC JSON input file (repeatable)")
    parser.add_argument("--ioc-source", action="append", default=[],
                        help="Curator source name, one per --ioc")
    parser.add_argument("--ioc-incident", action="append", default=[],
                        help="Incident identifier, one per --ioc")
    parser.add_argument("--ioc-sign-key", type=Path, default=None,
                        help="Curator key for the IOC manifests (default: the distribution key)")
    parser.add_argument("--corpus", type=Path, default=None,
                        help="Corpus baseline artifact (.tar.zst) to re-sign")
    args = parser.parse_args()

    if len(args.ioc) != len(args.ioc_source) or len(args.ioc) != len(args.ioc_incident):
        parser.error("one --ioc-source and one --ioc-incident per --ioc input")

    out_dir = args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    if not args.seed_v2_dir and not args.ioc and not args.corpus:
        parser.error("nothing to build: pass --seed-v2-dir, --ioc, or --corpus")

    private_key = _load_ed25519_private(args.sign_key)
    pubkey_hex = private_key.public_key().public_bytes_raw().hex()

    assets: list[dict] = []
    print(f"Building release baselines into {out_dir}")
    if args.seed_v2_dir:
        build_seed_asset(args.seed_v2_dir, out_dir, private_key, assets)
    if args.ioc:
        build_ioc_assets(args, out_dir, private_key, assets)
    if args.corpus:
        data = args.corpus.read_bytes()
        write_signed_asset(out_dir, "baseline-corpus.tar.zst", data, private_key, assets)

    manifest = {
        "schema_version": 1,
        "built_at": datetime.now(timezone.utc).isoformat(),
        "distribution_pubkey": pubkey_hex,
        "assets": assets,
    }
    (out_dir / BASELINE_MANIFEST).write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Wrote {BASELINE_MANIFEST} with {len(assets)} asset(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())