"""Resource limits applied by every content/render worker.

The kernel sandbox bounds reachability; these bounds spend.  A worker that
cannot set a core limit refuses to serve, because the confinement it claims
would be weaker than the one the design names.
"""

from __future__ import annotations

import ctypes
import resource

_PR_SET_NO_NEW_PRIVS = 38


def apply(*, memory_bytes: int, cpu_seconds: int, nofile: int = 64,
          fsize: int = 0) -> list[str]:
    """Set the worker's address-space, CPU, file-size and fd ceilings."""
    failures: list[str] = []
    names = {
        getattr(resource, name): name
        for name in ("RLIMIT_AS", "RLIMIT_CPU", "RLIMIT_FSIZE", "RLIMIT_NOFILE")
        if hasattr(resource, name)
    }
    for which, value in (
        (resource.RLIMIT_AS, memory_bytes),
        (resource.RLIMIT_CPU, cpu_seconds),
        (resource.RLIMIT_FSIZE, fsize),
        (resource.RLIMIT_NOFILE, nofile),
    ):
        try:
            resource.setrlimit(which, (value, value))
        except (ValueError, OSError) as exc:
            failures.append(
                f"{names.get(which, str(which))} not applied: "
                f"{type(exc).__name__}")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise OSError
    except (OSError, AttributeError):
        failures.append("PR_SET_NO_NEW_PRIVS not applied: prctl failed")
    return failures
