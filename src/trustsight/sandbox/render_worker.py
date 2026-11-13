"""Child entry point for the Rich rendering sandbox.

All Rich rendering runs here.  The parent sends a named render operation and
plain JSON data; the worker builds Rich renderables, captures the text, and
returns it.  The worker has no database, network or writable filesystem, so a
defect in Rich cannot reach the review state or the host.
"""

from __future__ import annotations

import contextlib
import importlib
import io
import json
import os
import sys

from trustsight.sandbox import _linux_sandbox, protocol
from trustsight.sandbox._spawn import core_sandbox_failures

_OPS = None

_FAILURES: list[str] = []
_MAX_OUTPUT_BYTES = 8 * 1024 * 1024


class _BoundedOutput(io.StringIO):
    """A capture buffer that refuses to grow past the render output cap."""

    def __init__(self, limit: int = _MAX_OUTPUT_BYTES):
        super().__init__()
        self._limit = limit
        self._size = 0

    def write(self, text: str) -> int:
        self._size += len(text)
        if self._size > self._limit:
            raise ValueError("render output exceeds its byte cap")
        return super().write(text)


_OUT = _BoundedOutput()


def _handle(body: bytes) -> dict:
    try:
        request = json.loads(body.decode("utf-8"))
        op = request.get("op")
        payload = request.get("payload") or {}
        color = bool(request.get("color", False))
        global _OPS
        if _OPS is None:
            from trustsight.render import OPS as render_ops

            _OPS = render_ops
        if op not in _OPS or not isinstance(payload, dict):
            return {"error": f"unknown render op: {op!r}"}
        module_name, function_name = _OPS[op]
        module = importlib.import_module(module_name)
        function = getattr(module, function_name)
        global _OUT
        _OUT = _BoundedOutput()
        from trustsight.render import display as render_display

        render_display.set_output(_OUT, color=color)
        captured = _BoundedOutput()
        with contextlib.redirect_stdout(captured), \
                contextlib.redirect_stderr(captured):
            function(**payload)
        return {
            "result": _OUT.getvalue() + captured.getvalue(),
            "degraded": list(_FAILURES) or None,
        }
    except Exception as exc:  # a render defect is a refusal, not a dead worker
        return {"error": f"{type(exc).__name__}: {exc}"}


def main() -> int:
    from trustsight.render import display as render_display
    from trustsight.sandbox._limits import apply as apply_limits

    render_display.set_output(_OUT)
    failures = apply_limits(
        memory_bytes=256 * 1024 * 1024,
        cpu_seconds=60,
        nofile=32,
    )
    sandbox_failures, _proxy_url = _linux_sandbox.apply("read", "")
    failures.extend(sandbox_failures)
    core = core_sandbox_failures(failures)
    if core:
        print("trustsight-render-sandbox-refused: " + "; ".join(core),
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
        try:
            stdout.write(protocol.frame(protocol.encode_response(response)))
            stdout.flush()
        except (BrokenPipeError, OSError):
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
