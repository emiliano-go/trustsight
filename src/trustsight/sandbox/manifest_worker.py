"""Child entry point for the manifest parser sandbox.

Every byte parsed here (YAML, XML, JSON/JSONC, TOML, INI) is package
controlled.  The parent never imports those loaders on the hostile path: it
sends ``(path, text)`` over the framed protocol and receives a
:class:`ManifestDoc` projection.  The worker is a ``read``-role Linux
sandbox: no network, no writable filesystem, no DB, and a seccomp allowlist.

A worker that cannot apply the sandbox exits before serving.  A parse defect
is an error frame; the parent turns it into a named refusal/coverage gap,
never a clean result.
"""

from __future__ import annotations

import json
import os
import sys

from trustsight.sandbox import _linux_sandbox, protocol
from trustsight.sandbox._spawn import core_sandbox_failures

_FAILURES: list[str] = []

#: The content worker parses both manifests and tokenizer payloads.  The
#: engine's own expansion bounds are far below this, and the manifest walk
#: is bounded per file, so the ceiling is a defect backstop, not a parser
#: input bound.
_WORKER_MEMORY_BYTES = 512 * 1024 * 1024
_WORKER_CPU_SECONDS = 300
_WORKER_NOFILE = 64


def _install_local_tokenizer() -> None:
    """Use the in-process tokenizer engine, not the tokenizer sandbox client.

    A manifest parser calls ``split_lines``.  The parent-side facade would
    spawn the tokenizer worker, which a confined worker cannot do (and should
    not); the manifest worker is already the sandbox, so it loads the engine
    directly.  This is the only second importer besides ``expand_worker``.
    """
    from trustsight import _tokenizer_engine as engine
    import trustsight.tokenizer as facade

    facade.split_lines = engine.split_lines


def _handle(body: bytes) -> dict:
    try:
        request = json.loads(body.decode("utf-8"))
        path = request.get("path")
        text = request.get("text")
        if path == "__tokenizer__":
            from trustsight.sandbox.tokenizer_ops import dispatch
            return {"result": dispatch(
                request.get("token_op"), request.get("input"))}
        if not isinstance(path, str) or not isinstance(text, str):
            return {"error": "invalid manifest request"}
        if path == "__srcinfo__":
            from trustsight.srcinfo import _parse_srcinfo_local
            return {"result": _parse_srcinfo_local(text)}
        if path == "__snapshot__":
            import base64
            from trustsight.analysis.archive_snapshot import parse_snapshot
            data = request.get("data")
            if not isinstance(data, str):
                return {"error": "invalid snapshot request"}
            try:
                raw = base64.b64decode(data, validate=True)
            except Exception:
                return {"error": "invalid snapshot encoding"}
            return {"result": parse_snapshot(
                raw, text,
                max_members=request.get("max_members", 10_000),
                max_member_bytes=request.get("max_member_bytes", 8 * 1024 * 1024),
                max_total_bytes=request.get("max_total_bytes", 256 * 1024 * 1024),
            )}
        from trustsight.analysis.manifests._parse import parse_manifest_local
        doc = parse_manifest_local(path, text)
        return {"result": None if doc is None else doc.to_dict()}
    except Exception as exc:  # a defect is a refusal, not a dead worker
        return {"error": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    _install_local_tokenizer()
    from trustsight.sandbox._limits import apply as apply_limits

    failures = apply_limits(
        memory_bytes=_WORKER_MEMORY_BYTES,
        cpu_seconds=_WORKER_CPU_SECONDS,
        nofile=_WORKER_NOFILE,
    )
    sandbox_failures, _proxy_url = _linux_sandbox.apply("read", "")
    failures.extend(sandbox_failures)
    core = core_sandbox_failures(failures)
    if core:
        print("trustsight-manifest-sandbox-refused: " + "; ".join(core),
              file=sys.stderr, flush=True)
        return 3
    _FAILURES.extend(failures)
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
