"""Bootstrap and incremental corpus pipeline."""

import logging
import time
from pathlib import Path
from typing import Optional

from ..analysis import _ensure_init
from ..config import load_config
from ..db import (
    get_pkgbuild_snapshot,
    save_package_profile,
    save_pkgbuild_snapshot,
)
from ..schema import TemporalContext
from .analyze import analyze_package_text
from .fetch import (
    clear_resume_state,
    fetch_pkgbuild,
    load_resume_state,
    save_resume_state,
)
from .metadata import (
    diff_metadata,
    fetch_metadata,
    load_metadata_snapshot,
    save_metadata_snapshot,
)

log = logging.getLogger(__name__)

_META_SNAPSHOT_PATH = Path("full-aur-meta.json.gz")


def _pkg_or_base(meta: dict) -> str:
    """Return the package base name for metadata lookups.

    Most AUR packages have the same Name and PackageBase.  For split
    packages the PKGBUILD lives under the PackageBase.
    """
    return meta.get("PackageBase") or meta["Name"]


def run_baseline_build(
    resume: bool = False,
    export_path: Optional[str] = None,
    sign_key: Optional[str] = None,
    json_output: bool = False,
) -> None:
    """Bootstrap or update the full-AUR corpus.

    Fetches the metadata snapshot, diffs against the stored copy (or
    treats every package as new for a fresh bootstrap), downloads
    PKGBUILDs, analyses each package, stores results, and optionally
    exports a signed baseline artifact.
    """
    _ensure_init()
    config = load_config()

    if json_output:
        import json as _json
        _log = lambda msg: print(_json.dumps({"msg": msg}))
    else:
        _log = lambda msg: log.info(msg)

    _log("Fetching AUR metadata snapshot …")
    new_meta = fetch_metadata()
    meta_count = len(new_meta)
    _log(f"Fetched {meta_count} package entries")

    old_meta = load_metadata_snapshot(_META_SNAPSHOT_PATH)

    if old_meta is None:
        added = sorted(new_meta)
        changed: list[str] = []
        _log("No prior snapshot found; processing all packages")
    else:
        added, changed, removed = diff_metadata(old_meta, new_meta)
        _log(f"Delta: {len(added)} added, {len(changed)} changed, {len(removed)} removed")

    to_process = added + changed

    if not to_process:
        _log("Nothing to process")
        save_metadata_snapshot(new_meta, _META_SNAPSHOT_PATH)
        return

    resume_state = load_resume_state() if resume else None
    processed: set[str] = set(resume_state.get("processed", [])) if resume_state else set()

    _log(f"Processing {len(to_process)} packages ({len(processed)} previously done)")
    batch_start = time.time()

    for i, name in enumerate(to_process):
        if name in processed:
            continue

        meta = new_meta.get(name)
        if meta is None:
            log.warning("metadata for %s vanished; skipping", name)
            continue

        pkgbase = _pkg_or_base(meta)

        old_snapshot = get_pkgbuild_snapshot(name)
        old_pkgbuild = old_snapshot["pkgbuild_text"] if old_snapshot else None
        prev_last_modified: Optional[int] = (
            old_snapshot["last_modified"] if old_snapshot else None
        )

        new_pkgbuild = fetch_pkgbuild(pkgbase)
        if new_pkgbuild is None:
            log.warning("could not fetch PKGBUILD for %s (base: %s)", name, pkgbase)
            save_resume_state({"processed": sorted(processed | {name})})
            continue

        fact = analyze_package_text(
            pkg_name=name,
            old_pkgbuild=old_pkgbuild,
            new_pkgbuild=new_pkgbuild,
            maintainer=meta.get("Maintainer") or "",
            temporal=TemporalContext(
                last_modified=meta.get("LastModified"),
                first_seen=meta.get("FirstSubmitted"),
                previous_modified=prev_last_modified,
                source="aur_metadata",
            ),
        )

        save_pkgbuild_snapshot(
            package_name=name,
            pkgbuild_text=new_pkgbuild,
            version=fact.new_version or meta.get("Version", ""),
            last_modified=meta.get("LastModified", 0),
        )

        save_package_profile(
            package_name=name,
            last_score=fact.final_score,
            last_risk=fact.score_breakdown.get("risk_label", ""),
        )

        processed.add(name)

        if (i + 1) % 1000 == 0:
            elapsed = time.time() - batch_start
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            _log(f"Processed {i + 1}/{len(to_process)} packages ({rate:.1f}/s)")
            save_resume_state({"processed": sorted(processed)})

    save_resume_state({"processed": sorted(processed)})
    save_metadata_snapshot(new_meta, _META_SNAPSHOT_PATH)
    clear_resume_state()

    total_elapsed = time.time() - batch_start
    _log(
        f"Baseline build complete: {len(processed)} packages processed "
        f"in {total_elapsed:.0f}s"
    )

    if export_path:
        from .export import build_artifact
        build_artifact(
            export_path=export_path,
            private_key_path=sign_key,
        )



