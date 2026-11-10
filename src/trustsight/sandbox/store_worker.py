"""Store worker for analysis.

The analysis process must not hold a SQLite handle.  This worker owns the
connection and answers a small named read/write API; the parent sends the
operation name plus arguments and receives plain JSON.  Read operations run
with a read-only connection, and write operations are an explicit closed set.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path

from trustsight.sandbox import _linux_sandbox, protocol
from trustsight.sandbox._spawn import core_sandbox_failures

_MEMORY_BYTES = 256 * 1024 * 1024
_CPU_SECONDS = 120
_NOFILE = 32

_WRITE_OPS = {
    "init_db",
    "upsert_package",
    "update_package_version",
    "update_package_maintainer",
    "update_aur_orphan_state",
    "insert_analysis",
    "record_dependency_names",
    "record_observed_domain",
    "record_observed_key",
    "record_added_literals",
    "save_pkgbuild_snapshot",
    "record_recipe_document",
    "record_contact",
    "record_host",
    "record_property_transition",
    "record_alerts",
    "record_cycle_events",
    "save_package_profile",
    "record_upstream_dep_additions",
    "record_gained_hosts",
    "record_adoption_event",
    "set_metadata",
    "bump_observation_seq",
}

_READ_OPS = {
    "effective_observation_count",
    "dependency_observation_count",
    "dependency_observation_counts",
    "dependency_table_populated",
    "top_dependency_names",
    "top_dependency_pairs",
    "is_maintainer_globally_novel",
    "get_package",
    "get_package_id",
    "get_last_analysis",
    "key_observed_before",
    "observed_key_count",
    "domain_first_seen",
    "domain_seen_within",
    "observed_domain_count",
    "maintainer_first_seen",
    "active_campaigns",
    "campaign_state_available",
}

_OPS = _WRITE_OPS | _READ_OPS

_READ_DEFAULTS = {
    "effective_observation_count": 0,
    "dependency_observation_count": 0,
    "dependency_observation_counts": {},
    "dependency_table_populated": False,
    "is_maintainer_globally_novel": False,
    "top_dependency_names": [],
    "top_dependency_pairs": [],
    "get_package": None,
    "get_package_id": None,
    "get_last_analysis": None,
    "key_observed_before": False,
    "observed_key_count": 0,
    "domain_first_seen": None,
    "domain_seen_within": False,
    "observed_domain_count": 0,
    "maintainer_first_seen": None,
    "active_campaigns": [],
    "campaign_state_available": False,
}

_FAILURES: list[str] = []


def _set_mode(write: bool) -> None:
    if write:
        os.environ.pop("TRUSTSIGHT_STORE_READ_ONLY", None)
    else:
        os.environ["TRUSTSIGHT_STORE_READ_ONLY"] = "1"


def _handle(body: bytes) -> dict:
    try:
        request = json.loads(body.decode("utf-8"))
        op = request.get("op")
        if not isinstance(op, str) or op not in _OPS:
            return {"error": f"unknown store op: {op!r}"}
        args = request.get("args") or []
        kwargs = request.get("kwargs") or {}
        if not isinstance(args, list) or not isinstance(kwargs, dict):
            return {"error": "invalid store request"}
        _set_mode(op in _WRITE_OPS)
        import trustsight.db as db

        result = getattr(db, op)(*args, **kwargs)
        return {"result": json.loads(json.dumps(result, default=str))}
    except sqlite3.OperationalError as exc:
        if "unable to open database" not in str(exc):
            return {"error": f"{type(exc).__name__}: {exc}"}
        if op not in _READ_OPS:
            return {"error": "database unavailable for a write operation"}
        return {"result": _READ_DEFAULTS.get(op)}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    from trustsight.sandbox._limits import apply as apply_limits

    db_path = os.environ.get("TRUSTSIGHT_DB_PATH", "")
    if not db_path:
        print("trustsight-store-sandbox-refused: no database path",
              file=sys.stderr, flush=True)
        return 3
    failures = apply_limits(
        memory_bytes=_MEMORY_BYTES, cpu_seconds=_CPU_SECONDS,
        nofile=_NOFILE, fsize=512 * 1024 * 1024)
    sandbox_failures, _proxy_url = _linux_sandbox.apply(
        "store", str(Path(db_path).parent))
    failures.extend(sandbox_failures)
    core = core_sandbox_failures(failures)
    _FAILURES.extend(failures)
    if core:
        print("trustsight-store-sandbox-refused: " + "; ".join(core),
              file=sys.stderr, flush=True)
        return 3
    try:
        os.chdir("/")
    except OSError:
        pass
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    while True:
        try:
            body = protocol.read_frame(stdin)
        except protocol.FrameError:
            return 0
        response = _handle(body)
        if _FAILURES:
            response["degraded"] = list(_FAILURES)
        try:
            stdout.write(protocol.frame(protocol.encode_response(response)))
            stdout.flush()
        except (BrokenPipeError, OSError):
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
