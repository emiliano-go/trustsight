"""Parent-side client for the manifest parser sandbox.

One persistent worker is enough for the manifest reads in a review; requests
are serialised and cached by ``(path, text-hash)``.  A worker that dies,
times out, or answers with an error is a named refusal, never a local
fallback: the whole point is that the parent does not parse hostile bytes.
"""

from __future__ import annotations

import atexit
import base64
import hashlib
import json
import os
import threading
import time

from . import _worker_io, protocol
from ._spawn import spawn_isolated

WORKER_MODULE = "trustsight.sandbox.manifest_worker"
REQUEST_TIMEOUT_SECONDS = 10.0
MAX_REQUESTS_PER_WORKER = 1024
MAX_CACHE_ENTRIES = 512

#: A snapshot is base64-encoded inside a framed JSON request.  The protocol
#: caps one frame at ~31 MiB, so 16 MiB of raw bytes is the largest snapshot
#: that fits with its escaping overhead.  A larger archive is a refusal, not
#: an unbounded allocation on the channel.
MAX_SNAPSHOT_PAYLOAD_BYTES = 16 * 1024 * 1024


class ManifestUnavailable(RuntimeError):
    """The manifest sandbox could not answer for this input."""


class _Worker:
    def __init__(self) -> None:
        self.proc = None
        self.requests = 0
        self.degraded: list = []
        self.stderr: list[str] = []
        self._stderr_thread = None

    def start(self) -> None:
        try:
            self.proc = spawn_isolated(WORKER_MODULE)
        except OSError as exc:
            raise ManifestUnavailable(
                f"could not start the manifest sandbox: {exc}") from exc
        self.requests = 0
        self.stderr = []
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, daemon=True)
        self._stderr_thread.start()

    def _drain_stderr(self) -> None:
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
            raise ManifestUnavailable("manifest worker is not running")
        if self.proc.poll() is not None:
            detail = "; ".join(self.stderr) or f"exit {self.proc.returncode}"
            raise ManifestUnavailable(f"manifest worker exited: {detail}")
        deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
        try:
            protocol.write_frame(self.proc.stdin.fileno(), body, deadline)
            header = _worker_io.read_exact(
                self.proc.stdout, protocol.HEADER.size, deadline,
                ManifestUnavailable)
            (length,) = protocol.HEADER.unpack(header)
            if length > protocol.MAX_RESPONSE_BYTES:
                raise ManifestUnavailable("manifest response exceeds its cap")
            return _worker_io.read_exact(
                self.proc.stdout, length, deadline, ManifestUnavailable)
        except (BrokenPipeError, OSError, protocol.FrameError) as exc:
            detail = "; ".join(self.stderr)
            raise ManifestUnavailable(
                f"manifest worker channel failed: {exc}"
                + (f" ({detail})" if detail else "")) from exc


_lock = threading.Lock()
_worker: _Worker | None = None
_cache: dict[tuple, dict | None] = {}
_cache_bytes = 0
MAX_CACHE_BYTES = 32 * 1024 * 1024


def _get_worker() -> _Worker:
    global _worker
    if _worker is None or not _worker.alive()             or _worker.requests >= MAX_REQUESTS_PER_WORKER:
        if _worker is not None:
            _worker.stop()
        _worker = _Worker()
        _worker.start()
    return _worker


def _close() -> None:
    global _worker
    if _worker is not None:
        _worker.stop()
        _worker = None


atexit.register(_close)


def _after_fork() -> None:
    """Drop inherited worker bookkeeping; the child starts its own worker.

    The parent's worker pid is still valid in the child's table, but the
    parent's threads are not, and the inherited lock may have been held at
    fork time.  Replacing both without taking the old lock is what makes the
    first request in a forked corpus worker safe.
    """
    global _worker, _lock, _cache_bytes
    _worker = None
    _lock = threading.Lock()
    _cache.clear()
    _cache_bytes = 0


os.register_at_fork(after_in_child=_after_fork)


def _ask(payload: bytes):
    """Send one frame and decode the result; kill a wedged worker.

    Called with ``_lock`` held.  A timeout, closed channel or invalid reply
    leaves a worker that cannot be trusted for the next request, so it is
    stopped and the caller sees the named refusal.
    """
    global _worker, _cache_bytes
    if len(payload) > protocol.MAX_FRAME_BYTES:
        raise ManifestUnavailable(
            "manifest request exceeds the framed request cap")
    worker = _get_worker()
    try:
        raw = worker.request(payload)
        worker.requests += 1
        try:
            response = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ManifestUnavailable(
                "manifest worker returned invalid JSON") from exc
        if not isinstance(response, dict) or "result" not in response:
            raise ManifestUnavailable(
                response.get("error", "manifest worker returned no result")
                if isinstance(response, dict)
                else "manifest worker returned no result")
        return response["result"]
    except ManifestUnavailable as exc:
        detail = "; ".join(worker.stderr)
        worker.stop()
        _worker = None
        if detail:
            raise ManifestUnavailable(f"{exc} ({detail})") from exc
        raise


def _remember(key: tuple, result) -> None:
    """Cache a projection under a byte budget, not only an entry count."""
    global _cache_bytes
    try:
        size = len(json.dumps(result, separators=(",", ":")))
    except (TypeError, ValueError):
        return
    if size > MAX_CACHE_BYTES:
        return
    if key in _cache:
        return
    if len(_cache) >= MAX_CACHE_ENTRIES or _cache_bytes + size > MAX_CACHE_BYTES:
        _cache.clear()
        _cache_bytes = 0
    _cache[key] = result
    _cache_bytes += size


def parse_srcinfo(text: str) -> dict[str, list[str]]:
    """Parse .SRCINFO in the sandboxed worker."""
    digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
    key = ("__srcinfo__", digest)
    with _lock:
        if key in _cache:
            return _cache[key]
        payload = json.dumps(
            {"path": "__srcinfo__", "text": text}, ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        result = _ask(payload)
        _remember(key, result)
        return result


def request_tokenizer(op: str, value):
    """Run one tokenizer operation in the content worker.

    The analysis path uses this instead of a second tokenizer process: the
    worker already loads the engine locally and has no nested sandbox to
    spawn.  A dead or timed-out worker is a named refusal.  Results are not
    cached here; the tokenizer facade memoises and this avoids retaining
    multi-megabyte resolved diffs.
    """
    with _lock:
        payload = json.dumps(
            {"path": "__tokenizer__", "token_op": op, "input": value},
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        return _ask(payload)


def parse_snapshot(name: str, data: bytes, *, max_members: int = 10_000,
                   max_member_bytes: int = 8 * 1024 * 1024,
                   max_total_bytes: int = 256 * 1024 * 1024) -> dict:
    """Parse an AUR snapshot tarball in the sandboxed worker.

    ``data`` is base64-encoded inside the framed JSON request; the worker
    never opens the network or the filesystem.
    """
    if len(data) > MAX_SNAPSHOT_PAYLOAD_BYTES:
        raise ManifestUnavailable(
            f"snapshot of {len(data)} bytes exceeds the "
            f"{MAX_SNAPSHOT_PAYLOAD_BYTES}-byte worker input cap")
    with _lock:
        payload = json.dumps(
            {"path": "__snapshot__", "text": name,
             "data": base64.b64encode(data).decode("ascii"),
             "max_members": max_members,
             "max_member_bytes": max_member_bytes,
             "max_total_bytes": max_total_bytes},
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        return _ask(payload)


def parse_upstream_archive(name: str, data: bytes, *,
                           max_members: int = 10_000,
                           max_file_bytes: int = 512 * 1024,
                           max_total_bytes: int = 64 * 1024 * 1024,
                           max_files: int = 64) -> dict:
    """Extract manifests from a declared source archive in the sandboxed worker."""
    if len(data) > MAX_SNAPSHOT_PAYLOAD_BYTES:
        raise ManifestUnavailable(
            f"archive of {len(data)} bytes exceeds the "
            f"{MAX_SNAPSHOT_PAYLOAD_BYTES}-byte worker input cap")
    with _lock:
        payload = json.dumps(
            {"path": "__upstream_archive__", "text": name,
             "data": base64.b64encode(data).decode("ascii"),
             "max_members": max_members,
             "max_file_bytes": max_file_bytes,
             "max_total_bytes": max_total_bytes,
             "max_files": max_files},
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        return _ask(payload)


def parse_manifest(path: str, text: str) -> dict | None:
    """Parse one manifest in the sandboxed worker.

    Returns the serialised :class:`ManifestDoc` projection, or ``None`` when
    the path is not a manifest.  A refusal raises :class:`ManifestUnavailable`;
    the caller records a coverage gap.
    """
    digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
    key = (path, digest)
    with _lock:
        if key in _cache:
            return _cache[key]
        payload = json.dumps(
            {"op": "manifest", "path": path, "text": text}, ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        result = _ask(payload)
        _remember(key, result)
        return result


def _cap_text(value: str, limit: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8", "replace")
    if len(encoded) <= limit:
        return value, False
    return encoded[:limit].decode("utf-8", "ignore"), True


def _has_raw_control(value: str) -> bool:
    return any(ord(ch) < 0x20 and ch not in "\t\n\r" for ch in value)


def _bounded_text(value: str, limit: int) -> tuple[str, bool]:
    """Cap without encoding an arbitrarily large string first."""
    candidate = value[:limit]
    if _has_raw_control(candidate):
        raise ManifestUnavailable(
            "artifact manifest strings contain raw control characters")
    capped, byte_cut = _cap_text(candidate, limit)
    return capped, byte_cut or len(value) > limit


def _normalise_declared(declared) -> tuple[dict, bool]:
    from ..analysis.artifact import (
        MAX_DECLARED_DEPENDS,
        MAX_DECLARED_MODE_BYTES,
        MAX_DECLARED_TEXT_BYTES,
        MAX_DECLARED_UNITS,
        MAX_MANIFEST_BYTES,
        MAX_PATH_BYTES,
    )

    if declared is None:
        return {}, False
    if not isinstance(declared, dict):
        raise ManifestUnavailable("artifact declaration must be an object")
    cut = False
    out: dict = {}
    text_total = 0
    for key, maximum in (
            ("depends", MAX_DECLARED_DEPENDS),
            ("units", MAX_DECLARED_UNITS)):
        values = declared.get(key)
        if isinstance(values, str):
            values = (values,)
        if isinstance(values, (list, tuple)):
            safe: list[str] = []
            for index, value in enumerate(values):
                if index >= maximum:
                    cut = True
                    break
                if not isinstance(value, str):
                    raise ManifestUnavailable(
                        f"artifact declaration {key} must contain strings")
                value, item_cut = _bounded_text(value, MAX_PATH_BYTES)
                cut = cut or item_cut
                value_bytes = len(value.encode("utf-8", "replace"))
                if text_total + value_bytes > MAX_MANIFEST_BYTES:
                    cut = True
                    break
                text_total += value_bytes
                safe.append(value)
            out[key] = safe
        elif values:
            raise ManifestUnavailable(
                f"artifact declaration {key} must be an array")
    for key in ("install_text", "built_install_text"):
        value = declared.get(key)
        if isinstance(value, str):
            value, item_cut = _bounded_text(value, MAX_DECLARED_TEXT_BYTES)
            cut = cut or item_cut
            value_bytes = len(value.encode("utf-8", "replace"))
            if text_total + value_bytes > MAX_MANIFEST_BYTES:
                cut = True
            else:
                text_total += value_bytes
                out[key] = value
        elif value is not None:
            raise ManifestUnavailable(
                f"artifact declaration {key} must be a string")
    mode = declared.get("mode_intent")
    if isinstance(mode, str):
        mode, item_cut = _bounded_text(mode, MAX_DECLARED_MODE_BYTES)
        cut = cut or item_cut
        mode_bytes = len(mode.encode("utf-8", "replace"))
        if text_total + mode_bytes > MAX_MANIFEST_BYTES:
            cut = True
        else:
            text_total += mode_bytes
            out["mode_intent"] = mode
    elif mode is not None:
        raise ManifestUnavailable(
            "artifact declaration mode_intent must be a string")
    return out, cut


def _normalise_manifest(manifest) -> tuple[str, bool]:
    from ..analysis.artifact import (
        MAX_CONTENT_BYTES,
        MAX_CONTENT_TOTAL,
        MAX_LINKS_PER_ENTRY,
        MAX_LINKS_TOTAL,
        MAX_MANIFEST_BYTES,
        MAX_MANIFEST_ENTRIES,
        MAX_PATH_BYTES,
        MAX_PATH_TOTAL,
        MAX_RUNPATHS_PER_ENTRY,
        MAX_RUNPATH_TOTAL,
    )

    if not isinstance(manifest, (list, tuple)):
        raise ManifestUnavailable("artifact manifest must be a JSON array")
    cut = False
    entries: list[dict] = []
    path_total = 0
    content_total = 0
    links_total = 0
    runpaths_total = 0
    text_total = 0
    for index, entry in enumerate(manifest):
        if index >= MAX_MANIFEST_ENTRIES:
            cut = True
            break
        if not isinstance(entry, dict):
            raise ManifestUnavailable(
                "every artifact manifest record must be an object")
        raw_path = entry.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            raise ManifestUnavailable(
                "every artifact manifest record needs a string path")
        if path_total >= MAX_PATH_TOTAL:
            cut = True
            continue
        path, item_cut = _bounded_text(raw_path, MAX_PATH_BYTES)
        cut = cut or item_cut
        path_bytes = len(path.encode("utf-8", "replace"))
        if path_total + path_bytes > MAX_PATH_TOTAL:
            cut = True
            continue
        if text_total + path_bytes > MAX_MANIFEST_BYTES:
            cut = True
            continue
        path_total += path_bytes
        text_total += path_bytes

        safe: dict = {"path": path}
        mode = entry.get("mode")
        if isinstance(mode, int) and not isinstance(mode, bool):
            safe["mode"] = mode
        for key in ("setuid", "setgid", "world_writable", "bpf"):
            value = entry.get(key)
            if isinstance(value, bool):
                safe[key] = value

        caps = entry.get("caps")
        if isinstance(caps, str) and caps:
            caps, item_cut = _bounded_text(caps, MAX_PATH_BYTES)
            cut = cut or item_cut
            caps_bytes = len(caps.encode("utf-8", "replace"))
            if text_total + caps_bytes > MAX_MANIFEST_BYTES:
                cut = True
            else:
                text_total += caps_bytes
                safe["caps"] = caps

        raw_elf = entry.get("elf")
        elf = raw_elf if isinstance(raw_elf, dict) else {}
        if raw_elf and not isinstance(raw_elf, dict):
            raise ManifestUnavailable("artifact elf record must be an object")
        safe_elf: dict = {}
        if isinstance(elf.get("packed"), bool):
            safe_elf["packed"] = elf["packed"]
        for key, maximum, total_attr in (
                ("needed", MAX_LINKS_TOTAL, "links"),
                ("rpath", MAX_RUNPATH_TOTAL, "runpaths"),
                ("runpath", MAX_RUNPATH_TOTAL, "runpaths")):
            values = elf.get(key)
            if isinstance(values, str):
                values = (values,)
            if values is None:
                continue
            if not isinstance(values, (list, tuple)):
                raise ManifestUnavailable(
                    f"artifact elf {key} must be an array")
            safe_values: list[str] = []
            for value in values:
                if not isinstance(value, str):
                    raise ManifestUnavailable(
                        f"artifact elf {key} must contain strings")
                if total_attr == "links" and links_total >= maximum:
                    cut = True
                    break
                if total_attr == "runpaths" and runpaths_total >= maximum:
                    cut = True
                    break
                if len(safe_values) >= (
                        MAX_LINKS_PER_ENTRY if total_attr == "links"
                        else MAX_RUNPATHS_PER_ENTRY):
                    cut = True
                    break
                value, item_cut = _bounded_text(value, MAX_PATH_BYTES)
                cut = cut or item_cut
                value_bytes = len(value.encode("utf-8", "replace"))
                if text_total + value_bytes > MAX_MANIFEST_BYTES:
                    cut = True
                    break
                text_total += value_bytes
                safe_values.append(value)
                if total_attr == "links":
                    links_total += 1
                else:
                    runpaths_total += 1
            if safe_values:
                safe_elf[key] = safe_values
        if safe_elf:
            safe["elf"] = safe_elf

        raw_links = entry.get("links")
        if isinstance(raw_links, str):
            raw_links = (raw_links,)
        if raw_links is not None:
            if not isinstance(raw_links, (list, tuple)):
                raise ManifestUnavailable("artifact links must be an array")
            safe_links: list[str] = []
            for value in raw_links:
                if not isinstance(value, str):
                    raise ManifestUnavailable(
                        "artifact links must contain strings")
                if (len(safe_links) >= MAX_LINKS_PER_ENTRY
                        or links_total >= MAX_LINKS_TOTAL):
                    cut = True
                    break
                value, item_cut = _bounded_text(value, MAX_PATH_BYTES)
                cut = cut or item_cut
                value_bytes = len(value.encode("utf-8", "replace"))
                if text_total + value_bytes > MAX_MANIFEST_BYTES:
                    cut = True
                    break
                text_total += value_bytes
                safe_links.append(value)
                links_total += 1
            if safe_links:
                safe["links"] = safe_links

        content = entry.get("content")
        if isinstance(content, str) and content:
            if content_total >= MAX_CONTENT_TOTAL:
                cut = True
            else:
                content, item_cut = _bounded_text(content, MAX_CONTENT_BYTES)
                cut = cut or item_cut
                content_bytes = len(content.encode("utf-8", "replace"))
                if content_total + content_bytes > MAX_CONTENT_TOTAL:
                    cut = True
                elif text_total + content_bytes > MAX_MANIFEST_BYTES:
                    cut = True
                else:
                    content_total += content_bytes
                    text_total += content_bytes
                    safe["content"] = content
        elif content is not None and not isinstance(content, str):
            raise ManifestUnavailable("artifact content must be a string")
        entries.append(safe)

    text = json.dumps(entries, ensure_ascii=False, separators=(",", ":"))
    if len(text.encode("utf-8", "replace")) > MAX_MANIFEST_BYTES:
        raise ManifestUnavailable(
            "artifact manifest request exceeds its byte cap")
    return text, cut


def _validate_artifact_result(result) -> dict:
    from ..analysis.artifact import (
        MAX_FINDING_BYTES,
        MAX_FINDINGS,
        MAX_LIMIT_REASON_BYTES,
        MAX_LIMIT_REASONS,
    )

    if not isinstance(result, dict):
        raise ManifestUnavailable("artifact worker returned no result")
    findings = result.get("findings")
    limits = result.get("limits")
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        raise ManifestUnavailable("artifact worker returned unbounded findings")
    if not isinstance(limits, dict):
        raise ManifestUnavailable("artifact worker returned no limits")
    allowed = {"rule_id", "name", "severity", "category", "match", "file"}
    for finding in findings:
        if not isinstance(finding, dict):
            raise ManifestUnavailable("artifact worker returned a malformed finding")
        if set(finding) - allowed:
            raise ManifestUnavailable(
                "artifact worker returned an unknown finding field")
        rule_id = finding.get("rule_id")
        if (not isinstance(rule_id, str) or len(rule_id) != 4
                or rule_id[0] != "A" or not rule_id[1:].isdigit()):
            raise ManifestUnavailable("artifact worker returned an unknown rule")
        if finding.get("severity") not in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            raise ManifestUnavailable("artifact worker returned an unknown severity")
        for key in ("name", "category", "match", "file"):
            value = finding.get(key)
            if not isinstance(value, str):
                raise ManifestUnavailable(
                    "artifact worker returned a malformed finding")
            if _has_raw_control(value):
                raise ManifestUnavailable(
                    "artifact worker returned a control character")
            if len(value.encode("utf-8", "replace")) > MAX_FINDING_BYTES:
                raise ManifestUnavailable(
                    "artifact worker returned an oversized finding")
    if not isinstance(limits.get("truncated"), bool):
        raise ManifestUnavailable("artifact worker returned malformed limits")
    for key in ("entries_seen", "entries_limit", "links_seen", "links_limit",
                "findings_returned", "findings_limit", "content_bytes",
                "content_limit", "invalid_entries"):
        value = limits.get(key)
        if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 0):
            raise ManifestUnavailable("artifact worker returned malformed limits")
    reasons = limits.get("reasons")
    if (not isinstance(reasons, list) or len(reasons) > MAX_LIMIT_REASONS
            or not all(isinstance(reason, str) for reason in reasons)
            or any(_has_raw_control(reason) for reason in reasons)
            or any(len(reason.encode("utf-8", "replace")) > MAX_LIMIT_REASON_BYTES
                   for reason in reasons)):
        raise ManifestUnavailable("artifact worker returned malformed limits")
    return result


def inspect_artifact_manifest(*, manifest=None, manifest_text=None,
                              declared=None) -> dict:
    """Inspect an L9 artifact manifest in the read-role sandbox.

    The raw-text form is preferred: the parent never parses attacker JSON.
    The list form is kept for API compatibility and is normalised under the
    same bounds before it is serialised.  A dead, timed-out or malformed
    worker is :class:`ManifestUnavailable`; there is no in-process fallback.
    """
    from ..analysis.artifact import MAX_MANIFEST_BYTES

    if manifest is not None and manifest_text is not None:
        raise ManifestUnavailable(
            "pass either manifest or manifest_text, not both")
    declared_payload, declared_cut = _normalise_declared(declared)
    if manifest_text is not None:
        if not isinstance(manifest_text, str):
            raise ManifestUnavailable("artifact manifest text must be a string")
        if len(manifest_text.encode("utf-8", "replace")) > MAX_MANIFEST_BYTES:
            raise ManifestUnavailable("artifact manifest exceeds its byte cap")
        if _has_raw_control(manifest_text):
            raise ManifestUnavailable(
                "artifact manifest text contains raw control characters")
        text = manifest_text
        request_cut = False
    elif manifest is not None:
        text, request_cut = _normalise_manifest(manifest)
    else:
        raise ManifestUnavailable("no artifact manifest was supplied")

    payload = json.dumps(
        {"path": "__artifact_manifest__", "text": text,
         "declared": declared_payload},
        ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    with _lock:
        result = _validate_artifact_result(_ask(payload))
    limits = result["limits"]
    if declared_cut or request_cut:
        limits["truncated"] = True
        reasons = limits.setdefault("reasons", [])
        if "manifest request trimmed" not in reasons:
            reasons.append("manifest request trimmed")
    return result
