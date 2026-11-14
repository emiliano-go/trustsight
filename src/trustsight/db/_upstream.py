"""Persisted upstream-scan observations (P4).

The server-side lane stores a bounded projection of what it read, keyed by
``(package, repo, version)``.  A signed baseline export turns these into
``upstream_manifest`` IOC entries; the local tool consumes the signed result
without fetching.  The detail is a compact JSON projection, never the raw
manifest texts.
"""

from __future__ import annotations

import json

from ._connection import get_connection

__all__ = [
    "MAX_UPSTREAM_DETAIL_BYTES",
    "get_upstream_observations",
    "save_upstream_observation",
]

#: One observation's detail is a compact projection; anything larger is a
#: defect in the producer, so it is truncated rather than stored whole.
MAX_UPSTREAM_DETAIL_BYTES = 16 * 1024


def _bounded_detail(detail) -> str:
    if detail is None:
        return ""
    if not isinstance(detail, str):
        try:
            detail = json.dumps(detail, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            detail = str(detail)
    raw = detail.encode("utf-8", "replace")
    if len(raw) > MAX_UPSTREAM_DETAIL_BYTES:
        raw = raw[:MAX_UPSTREAM_DETAIL_BYTES]
        return raw.decode("utf-8", "ignore")
    return detail


def save_upstream_observation(
    package: str,
    repo: str,
    version: str = "",
    ref: str = "",
    checksum: str = "",
    detail="",
) -> None:
    """Upsert one ``(package, repo, version)`` observation, bounded."""
    package = str(package or "")[:256]
    repo = str(repo or "")[:256]
    version = str(version or "")[:128]
    ref = str(ref or "")[:128]
    checksum = str(checksum or "")[:256].lower()
    stored = _bounded_detail(detail)
    with get_connection() as conn:
        conn.execute(
            """INSERT INTO upstream_observations
               (package_name, repo, version, ref, checksum, detail, captured_at)
               VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
               ON CONFLICT(package_name, repo, version) DO UPDATE SET
                   ref = excluded.ref,
                   checksum = excluded.checksum,
                   detail = excluded.detail,
                   captured_at = excluded.captured_at""",
            (package, repo, version, ref, checksum, stored),
        )
        conn.commit()


def get_upstream_observations(
    repo: str | None = None,
    package: str | None = None,
    limit: int = 10_000,
) -> list[dict]:
    """Return stored observations, newest first, bounded by *limit*."""
    limit = max(1, min(int(limit), 10_000))
    clauses: list[str] = []
    values: list[object] = []
    if repo:
        clauses.append("repo = ?")
        values.append(str(repo))
    if package:
        clauses.append("package_name = ?")
        values.append(str(package))
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with get_connection() as conn:
        rows = conn.execute(
            f"""SELECT package_name, repo, version, ref, checksum, detail,
                       captured_at
                FROM upstream_observations {where}
                ORDER BY captured_at DESC, id DESC LIMIT ?""",
            (*values, limit),
        ).fetchall()
    return [dict(row) for row in rows]
