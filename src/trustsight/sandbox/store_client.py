"""Parent-side client for the read-only analysis store worker."""

from __future__ import annotations

import atexit
import json
import os
import threading
import time
from pathlib import Path

from . import _worker_io, protocol
from ._spawn import spawn_isolated

WORKER_MODULE = "trustsight.sandbox.store_worker"
#: A full-AUR cycle can queue a large write against a multi-hundred-megabyte
#: corpus; a shorter deadline turns a slow checkpoint into a false failure.
REQUEST_TIMEOUT_SECONDS = 60.0
MAX_REQUESTS_PER_WORKER = 1024
MAX_REQUEST_BYTES = 16 * 1024 * 1024


class StoreUnavailable(RuntimeError):
    """The analysis store could not answer."""


class _Worker:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.proc = None
        self.requests = 0
        self.stderr: list[str] = []

    def start(self) -> None:
        self.proc = spawn_isolated(
            WORKER_MODULE,
            extra_env={
                "TRUSTSIGHT_DB_PATH": self.db_path,
                # The child's root is a private tmpfs; a parent HOME path does
                # not exist there.  Config constants are derived at import
                # time, so pin HOME to the sandbox root.
                "HOME": "/",
            },
        )
        self.requests = 0
        self.stderr = []
        threading.Thread(target=self._drain, daemon=True).start()

    def _drain(self) -> None:
        _worker_io.drain_stderr(
            self.proc,
            lambda text: self.stderr.append(text)
            if len(self.stderr) < 20 else None,
        )

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        proc, self.proc = self.proc, None
        _worker_io.stop_process(proc)

    def request(self, body: bytes) -> bytes:
        if self.proc is None or self.proc.stdin is None or self.proc.stdout is None:
            raise StoreUnavailable("store worker is not running")
        if self.proc.poll() is not None:
            detail = "; ".join(self.stderr) or f"exit {self.proc.returncode}"
            raise StoreUnavailable(f"store worker exited: {detail}")
        deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
        try:
            protocol.write_frame(self.proc.stdin.fileno(), body, deadline)
            header = _worker_io.read_exact(
                self.proc.stdout, protocol.HEADER.size, deadline,
                StoreUnavailable)
            (length,) = protocol.HEADER.unpack(header)
            if length > protocol.MAX_RESPONSE_BYTES:
                raise StoreUnavailable("store response exceeds its cap")
            return _worker_io.read_exact(
                self.proc.stdout, length, deadline, StoreUnavailable)
        except (BrokenPipeError, OSError, protocol.FrameError) as exc:
            detail = "; ".join(self.stderr)
            raise StoreUnavailable(
                f"store worker channel failed: {exc}"
                + (f" ({detail})" if detail else "")) from exc


_lock = threading.Lock()
_worker: _Worker | None = None


def _db_path() -> str:
    from ..db import get_db_path

    return str(Path(get_db_path()))


def _get_worker() -> _Worker:
    global _worker
    path = _db_path()
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        pass
    if _worker is None or _worker.db_path != path or not _worker.alive() \
            or _worker.requests >= MAX_REQUESTS_PER_WORKER:
        if _worker is not None:
            _worker.stop()
        _worker = _Worker(path)
        _worker.start()
    return _worker


def _close() -> None:
    global _worker
    if _worker is not None:
        _worker.stop()
        _worker = None


atexit.register(_close)


def _after_fork() -> None:
    global _worker, _lock
    _worker = None
    _lock = threading.Lock()


os.register_at_fork(after_in_child=_after_fork)


def _call(op: str, *args, **kwargs):
    global _worker
    with _lock:
        worker = _get_worker()
        body = json.dumps(
            {"op": op, "args": list(args), "kwargs": kwargs},
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        if len(body) > MAX_REQUEST_BYTES:
            raise StoreUnavailable(
                f"store request exceeds its {MAX_REQUEST_BYTES}-byte cap")
        try:
            raw = worker.request(body)
            worker.requests += 1
            try:
                response = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise StoreUnavailable(
                    "store worker returned invalid JSON") from exc
            if not isinstance(response, dict) or "result" not in response:
                raise StoreUnavailable(
                    response.get("error", "store worker returned no result")
                    if isinstance(response, dict)
                    else "store worker returned no result")
            return response["result"]
        except StoreUnavailable:
            worker.stop()
            _worker = None
            raise


def _write(op: str, *args, **kwargs):
    return _call(op, *args, **kwargs)


def init_db() -> None:
    _write("init_db")


def upsert_package(name: str, version: str) -> int:
    return int(_write("upsert_package", name, version))


def update_package_version(name: str, version: str):
    return _write("update_package_version", name, version)


def update_package_maintainer(name: str, maintainer: str):
    return _write("update_package_maintainer", name, maintainer)


def update_aur_orphan_state(name: str, orphaned):
    return _write("update_aur_orphan_state", name, orphaned)


def insert_analysis(**kwargs):
    return _write("insert_analysis", **kwargs)


def record_dependency_names(names: list[str]):
    return _write("record_dependency_names", names)


def record_observed_domain(domain: str):
    return _write("record_observed_domain", domain)


def record_observed_key(key: str):
    return _write("record_observed_key", key)


def record_added_literals(package_name: str, literals, observed_at=None):
    return _write("record_added_literals", package_name, literals, observed_at)


def record_recipe_document(package_name: str, scalars, arrays):
    return _write("record_recipe_document", package_name, scalars, arrays)


def save_pkgbuild_snapshot(*args, **kwargs):
    return _write("save_pkgbuild_snapshot", *args, **kwargs)


def save_package_profile(*args, **kwargs):
    return _write("save_package_profile", *args, **kwargs)


def record_gained_hosts(*args, **kwargs):
    return _write("record_gained_hosts", *args, **kwargs)


def record_property_transition(*args, **kwargs):
    return _write("record_property_transition", *args, **kwargs)


def record_upstream_dep_additions(*args, **kwargs):
    return _write("record_upstream_dep_additions", *args, **kwargs)


def set_metadata(key: str, value: str):
    return _write("set_metadata", key, value)


def bump_observation_seq() -> int:
    return int(_write("bump_observation_seq"))


def effective_observation_count() -> int:
    return int(_call("effective_observation_count"))


def dependency_observation_count(name: str) -> int:
    return int(_call("dependency_observation_count", name))


def dependency_observation_counts(names: list[str]) -> dict[str, int]:
    return _call("dependency_observation_counts", names)


def dependency_table_populated() -> bool:
    return bool(_call("dependency_table_populated"))


def is_established_package(name: str) -> bool:
    """Official-repo membership is resolved in the parent; pacman is exec."""
    from ..db import official_package_names

    official = official_package_names()
    if official:
        return name in official
    return len(name) >= 4 and dependency_observation_count(name) >= 10


def is_maintainer_globally_novel(name: str) -> bool:
    return bool(_call("is_maintainer_globally_novel", name))


def top_dependency_names(limit: int = 5000) -> list:
    return _call("top_dependency_names", limit)


def top_dependency_pairs(limit: int = 5000) -> list:
    return _call("top_dependency_pairs", limit)


def get_package(name: str):
    return _call("get_package", name)


def get_package_id(name: str):
    return _call("get_package_id", name)


def get_last_analysis(package_id: int):
    return _call("get_last_analysis", package_id)


def key_observed_before(key: str) -> bool:
    return bool(_call("key_observed_before", key))


def observed_key_count() -> int:
    return int(_call("observed_key_count"))


def domain_first_seen(domain: str):
    return _call("domain_first_seen", domain)


def domain_seen_within(domain: str, days: int) -> bool:
    return bool(_call("domain_seen_within", domain, days))


def observed_domain_count() -> int:
    return int(_call("observed_domain_count"))


def maintainer_first_seen(maintainer: str):
    return _call("maintainer_first_seen", maintainer)


def active_campaigns():
    return _call("active_campaigns")


def campaign_state_available() -> bool:
    return bool(_call("campaign_state_available"))
