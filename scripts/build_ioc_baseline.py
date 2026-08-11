"""Build a signed IOC federation baseline (v0.12.0 spec A13b).

Produces the directory `trustsight ioc import` verifies: a `manifest.json`
plus an `iocs.jsonl`, with the Ed25519 signature and public key carried as
hex fields inside the manifest. The signature covers the canonical manifest
(its `signature` field emptied) concatenated with `iocs.jsonl`, exactly as
`ioc_baseline._verify_signature` recomputes it. The script self-verifies with
that same function before it writes, so it cannot emit an artifact the
importer would reject.

It deliberately does NOT invent indicators. You supply a curated,
primary-sourced input file; the script only normalises, signs and packages it.

Input file (`--from-file`): a JSON array of entries, each at minimum::

    {"type": "domain|hash|package", "value": "evil.example",
     "confidence": "confirmed", "provenance": "ASA-2026-06",
     "campaign": "some-incident", "expires_at": "2026-12-31T00:00:00Z"}

Keys are optional except `type` and `value`. An `evidence_url` is folded into
`provenance` when `provenance` is absent, so the source link is not lost.

Usage::

    python scripts/build_ioc_baseline.py \
        --from-file data/iocs/some-incident.json \
        --source emiliano-go \
        --incident some-incident \
        --out ioc-baselines/some-incident \
        --sign trustsight-release.pem      # PEM or raw 32-byte ed25519 key

    # unsigned, for a local baseline you import with --allow-unsigned:
    python scripts/build_ioc_baseline.py --from-file ... --allow-unsigned
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from trustsight.ioc_baseline import (  # noqa: E402
    _IOC_TYPES,
    _load_manifest,
    _normalize_value,
    _verify_signature,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_ed25519_private(key_path: Path):
    """Load an ed25519 private key from a raw-32-byte file or a PEM file."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    raw = key_path.read_bytes()
    if len(raw) == 32:
        return Ed25519PrivateKey.from_private_bytes(raw)
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    return load_pem_private_key(raw, password=None)


def _normalise_entries(rows: list[dict], source: str) -> list[dict]:
    """Validate and canonicalise input rows into stored iocs.jsonl entries."""
    out: list[dict] = []
    for i, row in enumerate(rows, start=1):
        type_ = str(row.get("type", "")).strip().lower()
        if type_ not in _IOC_TYPES:
            raise ValueError(f"entry {i}: unknown type {row.get('type')!r}")
        value = _normalize_value(type_, row.get("value", ""))
        if value is None:
            raise ValueError(f"entry {i}: unusable {type_} value {row.get('value')!r}")
        provenance = str(row.get("provenance", "")).strip()
        if not provenance and row.get("evidence_url"):
            provenance = str(row["evidence_url"]).strip()
        out.append({
            "type": type_,
            "value": value,
            "source": source,
            "confidence": str(row.get("confidence", "")).strip().lower(),
            "provenance": provenance,
            "campaign": str(row.get("campaign", row.get("incident", ""))).strip(),
            "added": str(row.get("added", row.get("first_seen", ""))).strip(),
            "expires_at": str(row.get("expires_at", row.get("expires", ""))).strip(),
        })
    # Deterministic order so the signed bytes are reproducible.
    out.sort(key=lambda e: (e["type"], e["value"]))
    return out


def build(
    entries: list[dict],
    source: str,
    out_dir: Path,
    incident: str | None,
    valid_days: int,
    key_path: Path | None,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "manifest.json"
    iocs_path = out_dir / "iocs.jsonl"

    # iocs.jsonl: one canonical object per line; signed over these exact bytes.
    iocs_text = "\n".join(
        json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        for e in entries
    )
    if iocs_text:
        iocs_text += "\n"
    iocs_path.write_text(iocs_text, encoding="utf-8")

    public_key_hex = ""
    if key_path is not None:
        private_key = _load_ed25519_private(key_path)
        public_key_hex = private_key.public_key().public_bytes_raw().hex()

    manifest = {
        "version": 1,
        "source": source,
        "created_at": _now_iso(),
        "expires_at": "",
        "signature": "",
        "public_key": public_key_hex,
        "entry_count": len(entries),
    }
    if incident:
        manifest["incident"] = incident
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")

    if key_path is not None:
        # Recompute the exact payload the verifier signs over, reusing the
        # verifier's own manifest parsing so the two cannot drift.
        parsed = _load_manifest(manifest_path)
        signed_manifest = {
            "version": parsed.version,
            "source": parsed.source,
            "created_at": parsed.created_at,
            "expires_at": parsed.expires_at,
            "signature": "",
            "public_key": parsed.public_key,
            **parsed.extra,
        }
        payload = json.dumps(
            signed_manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8") + iocs_path.read_bytes()
        signature_hex = private_key.sign(payload).hex()
        manifest["signature"] = signature_hex
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")

        # Self-verify with the real verifier; refuse to emit a bad artifact.
        if not _verify_signature(manifest_path, iocs_path, signature_hex, public_key_hex):
            raise RuntimeError(
                "internal error: produced a signature the importer would reject"
            )

    return {
        "dir": str(out_dir),
        "entries": len(entries),
        "signed": key_path is not None,
        "source": source,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a signed IOC baseline directory.")
    parser.add_argument("--from-file", required=True, type=Path,
                        help="JSON array of curated IOC entries.")
    parser.add_argument("--source", required=True,
                        help="Curator name; must match the pinned feed source.")
    parser.add_argument("--incident", default=None, help="Incident identifier for the manifest.")
    parser.add_argument("--out", type=Path, default=None,
                        help="Output directory (default: ioc-baselines/<source>).")
    parser.add_argument("--valid-days", type=int, default=30,
                        help="Reserved for a future manifest expiry; entries carry their own.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sign", type=Path, help="ed25519 private key (PEM or raw 32 bytes).")
    group.add_argument("--allow-unsigned", action="store_true",
                       help="Build an unsigned baseline (imports only with --allow-unsigned).")
    args = parser.parse_args()

    rows = json.loads(args.from_file.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        print("input must be a JSON array of IOC entries", file=sys.stderr)
        return 2
    entries = _normalise_entries(rows, args.source)
    out_dir = args.out or Path("ioc-baselines") / args.source
    result = build(
        entries, args.source, out_dir, args.incident, args.valid_days,
        None if args.allow_unsigned else args.sign,
    )
    signed = "signed" if result["signed"] else "UNSIGNED"
    print(f"Built {result['dir']} with {result['entries']} IOC(s) ({signed}).")
    if not result["signed"]:
        print("  Import with: trustsight ioc import <dir> --allow-unsigned")
    else:
        print("  Import with: trustsight ioc import <dir>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
