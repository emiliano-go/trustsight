"""Shared launch of an isolated sandbox child.

Both sandboxes (the tokenizer worker and the git worker) start the same way:
an isolated interpreter (``-I``: no ``PYTHON*`` environment, no user site, no
cwd on ``sys.path``), a minimal environment (:func:`subproc.minimal_env`), a
new session, and an explicit import of the worker module whose ``main`` is
called.  One implementation, so a fix to the launch (the ``PYTHONPATH``
``sitecustomize`` finding) cannot reach only one of them.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from ..subproc import minimal_env

__all__ = [
    "CORE_SANDBOX_FAILURES",
    "launch_args",
    "core_sandbox_failures",
    "spawn_isolated",
    "WORKER_ROOT",
]


#: The directory a worker inserts on ``sys.path`` to import this package - the
#: tree this process already imported from, not a path an attacker chose.
WORKER_ROOT = str(Path(__file__).resolve().parents[2])

#: A worker that loses one of these is not the populated-by-default subprocess
#: the design assumes.  It refuses to serve rather than analyse a package with
#: weaker confinement than the verdict claims (A6/A16/B2).
CORE_SANDBOX_FAILURES = (
    "RLIMIT_AS",
    "RLIMIT_CPU",
    "PR_SET_NO_NEW_PRIVS",
    "OS sandbox",
)


def core_sandbox_failures(failures: list[str]) -> list[str]:
    """The subset of *failures* that makes a worker refuse to start."""
    return [
        failure for failure in failures
        if failure.startswith(CORE_SANDBOX_FAILURES)
    ]


def launch_args(module: str, role: str | None = None,
                extra_argv: tuple = ()) -> list[str]:
    """The child command line for worker *module* (dotted name).

    ``-I`` is isolated mode.  Isolation also means the child cannot find this
    package through the environment, so the bootstrap inserts the trusted
    source root explicitly and then calls the worker's ``main``.  A *role*
    (and any extra arguments after it) lets the git worker choose fetch or
    read confinement; the tokenizer worker passes neither.
    """
    bootstrap = (
        "import sys;"
        f"sys.path.insert(0, {WORKER_ROOT!r});"
        f"import {module} as _worker;"
        "raise SystemExit(_worker.main())"
    )
    args = [sys.executable, "-I", "-c", bootstrap]
    if role is not None:
        args.append(role)
        args.extend(str(item) for item in extra_argv)
    return args


def spawn_isolated(module: str, cwd: str = "/", role: str | None = None,
                   extra_argv: tuple = (),
                   pass_fds: tuple = ()) -> subprocess.Popen:
    """Start worker *module* with stdio piped, a minimal env, own session."""
    return subprocess.Popen(
        launch_args(module, role, extra_argv),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        pass_fds=pass_fds,
        start_new_session=True,
        cwd=cwd,
        env=minimal_env(),
    )
