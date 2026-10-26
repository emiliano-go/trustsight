"""Child entry point for the sandboxed tokenizer.

Run as ``python <this file>`` by ``trustsight.sandbox.expander``.  It reads
one length-prefixed JSON request per frame on stdin, runs the engine, and
writes one framed response per request on stdout.  It exits on EOF, which
is what happens when the parent's pool is torn down.

The confinement is set here, after the interpreter and the engine have
loaded (a hard ``RLIMIT_AS`` before the imports would kill the import
itself):

* ``RLIMIT_AS`` caps the address space, so a bypass of an expansion bound
  exhausts the child, not the analysis.
* ``RLIMIT_CPU`` and ``RLIMIT_FSIZE`` cap the work and forbid writing.
* ``RLIMIT_NOFILE`` keeps the descriptor table small.
* ``PR_SET_NO_NEW_PRIVS`` makes sure a defect here cannot gain privilege.
* ``unshare(CLONE_NEWNET)`` is attempted best-effort: without privilege it
  fails and the child is still a plain process with no descriptors worth
  having.  The stated trust model already trusts the interpreter, so this
  is hardening, not the guarantee.

A limit that could not be applied is returned to the parent in every
response's ``degraded`` field and logged, rather than swallowed: the
isolation is weaker than the design intends and the operator must be able
to see that.  The core protections are stricter: if address space, CPU or
``PR_SET_NO_NEW_PRIVS`` could not be set, the worker exits before serving,
and the client reports the package as NOT vetted.
"""

import ctypes
import os
import resource
import sys

from trustsight import _tokenizer_engine as engine
from trustsight.sandbox import protocol
from trustsight.sandbox._spawn import core_sandbox_failures

#: Address-space ceiling.  The engine's own bounds are 64 KiB for a line,
#: 8 KiB for a value and 1 MiB for the variable table, so 512 MiB is far
#: above any legitimate expansion and far below the analysis process.
_WORKER_MEMORY_BYTES = 512 * 1024 * 1024

#: CPU seconds before the kernel kills the child.
_WORKER_CPU_SECONDS = 5

#: Descriptors the child may hold.  It needs stdin, stdout, stderr and a
#: little slack; anything more is a defect's access, not the tokenizer's.
_WORKER_NOFILE = 64

_PR_SET_NO_NEW_PRIVS = 38
_CLONE_NEWNET = 0x40000000


_DEGRADED: list[str] = []


class _UnknownOp(Exception):
    """The request named an operation the worker does not implement."""


def _apply_limits() -> list[str]:
    """Bound the child's resources; return what could not be applied.

    A swallowed ``setrlimit`` makes the isolation weaker than the design
    intends, so a failure is reported to the parent (the ``degraded`` field)
    as well as logged.  The git worker works the same way; the two sandboxes
    must not disagree about whether a limit took effect.
    """
    failures: list[str] = []
    names = {
        getattr(resource, name): name
        for name in ("RLIMIT_AS", "RLIMIT_CPU", "RLIMIT_FSIZE", "RLIMIT_NOFILE")
        if hasattr(resource, name)
    }
    for which, value in (
        (resource.RLIMIT_AS, _WORKER_MEMORY_BYTES),
        (resource.RLIMIT_CPU, _WORKER_CPU_SECONDS),
        (resource.RLIMIT_FSIZE, 0),
        (resource.RLIMIT_NOFILE, _WORKER_NOFILE),
    ):
        try:
            resource.setrlimit(which, (value, value))
        except (ValueError, OSError) as exc:
            failures.append(
                f"{names.get(which, str(which))} not applied: "
                f"{type(exc).__name__}"
            )
    no_new_privs = _no_new_privs()
    if not no_new_privs:
        failures.append("PR_SET_NO_NEW_PRIVS not applied: prctl failed")
    _report_isolation(no_new_privs, _drop_network())
    return failures


def _no_new_privs() -> bool:
    """Set PR_SET_NO_NEW_PRIVS; return whether it took effect."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
    except (OSError, AttributeError):
        return False


def _drop_network() -> bool:
    """Best-effort network-namespace removal; return whether it took effect."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.unshare(_CLONE_NEWNET) == 0
    except (OSError, AttributeError):
        return False


def _report_isolation(no_new_privs: bool, network_dropped: bool) -> None:
    """State whether the hardening took effect, on stderr.

    The parent drains this and logs it.  Both are best-effort by design, so
    a failure is not fatal, but a run that silently lost its network
    namespace should not look identical to one that kept it.
    """
    print(
        "trustsight-tokenizer-isolation "
        f"no_new_privs={no_new_privs} network_dropped={network_dropped}",
        file=sys.stderr,
        flush=True,
    )


def _dispatch(op: str, payload: object) -> object:
    """Run one engine operation and return a JSON-serialisable result."""
    if op == "lines":
        return engine.split_lines(payload)
    if op == "join":
        return engine.join_line_continuations(payload)
    if op == "joined_indexed":
        return engine._joined_indexed(payload)
    if op == "resolve_added":
        return engine.resolve_added_lines(payload)
    if op == "resolve_removed":
        return engine.resolve_removed_lines(payload)
    if op == "indexed":
        resolved, unresolved, indices = engine.tokenize_and_resolve_indexed(payload)
        return [resolved, unresolved, indices]
    if op == "variable_table":
        variables, arrays = engine._variable_table(payload)
        return [variables, arrays]
    if op == "variable_table_spans":
        variables, arrays, spans = engine._variable_table_with_spans(payload)
        return [variables, arrays, spans]
    if op == "clean_lines":
        return [
            engine.collapse_traversal(engine.strip_leading_bom(line))
            for line in payload
        ]
    if op == "strip_boms":
        return [engine.strip_leading_bom(line) for line in payload]
    if op == "reconstruct_literals":
        return list(engine.reconstruct_literals(payload))
    if op == "reconstruct_lines":
        from ..line_lex import QuoteState
        from .._tokenizer_engine._quotes import reconstruct_literals_stateful

        state = QuoteState()
        out = []
        for line in payload:
            rebuilt, fully, state, _quoted = reconstruct_literals_stateful(
                line, state,
            )
            out.append([rebuilt, fully])
        return out
    if op == "reconstruct_lines_stateful":
        from ..line_lex import QuoteState
        from .._tokenizer_engine._quotes import reconstruct_literals_stateful

        state = QuoteState()
        out = []
        for line in payload:
            rebuilt, fully, state, quoted = reconstruct_literals_stateful(
                line, state,
            )
            out.append([rebuilt, fully, quoted])
        return out
    raise _UnknownOp(f"unknown op: {op!r}")


def _handle(body: bytes) -> dict:
    import json

    try:
        request = json.loads(body.decode("utf-8"))
        result = _dispatch(request.get("op"), request.get("input"))
        return {"result": result}
    except _UnknownOp as exc:
        return {"error": str(exc)}
    except Exception as exc:  # a defect in the engine is a refusal, not a crash
        return {"error": f"{type(exc).__name__}: {exc}"}


def _attach_degraded(response: dict) -> dict:
    """Attach the startup limit failures to a response, when there are any."""
    if _DEGRADED:
        response["degraded"] = list(_DEGRADED)
    return response


def _encode_response(response: dict) -> bytes:
    """Serialise *response* under the shared response byte cap.

    The parent advertises a response read cap, but by the time it fires the
    child has already built and framed the whole payload.  The cap belongs
    here, while the body is serialised and before it is framed, and it is
    shared with the git worker so the two sandboxes cannot disagree (A4/A14).
    """
    return protocol.encode_response(response)


def main() -> int:
    global _DEGRADED
    failures = _apply_limits()
    core = core_sandbox_failures(failures)
    if core:
        print(
            "trustsight-tokenizer-sandbox-refused: " + "; ".join(core),
            file=sys.stderr,
            flush=True,
        )
        return 3
    _DEGRADED = failures
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
            # EOF or a truncated frame: the parent is done with this worker.
            return 0
        response = _attach_degraded(_handle(body))
        try:
            stdout.write(protocol.frame(_encode_response(response)))
            stdout.flush()
        except (BrokenPipeError, OSError):
            return 1


if __name__ == "__main__":
    sys.exit(main())
