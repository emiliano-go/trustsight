"""The environment TrustSight hands to a child process.

A child TrustSight spawns - the sandboxed tokenizer worker, or ``pacman`` and
``vercmp`` - must not receive the parent's environment wholesale.  A whole
class of code-execution bugs lives in process *startup*: variables that name
code the child runs or libraries it maps before its own logic begins.

* ``PYTHONPATH`` makes ``site`` import ``sitecustomize`` from a writable
  directory at interpreter startup (the tokenizer-worker finding).
* ``LD_PRELOAD`` / ``LD_LIBRARY_PATH`` make the dynamic loader map an
  attacker's library into any child, interpreter or not.
* ``PERL5LIB`` / ``RUBYOPT`` / ``BASH_ENV`` / ``ENV`` / ``NODE_OPTIONS`` are
  the per-runtime equivalents.

None are needed by the children TrustSight runs, so the safe default is an
explicit allowlist rather than ``{**os.environ}``.  ``minimal_env`` is that
allowlist, and every ``subprocess`` call in ``src/`` passes it (enforced by
the ``every child process gets an explicit environment`` gate).
"""

from __future__ import annotations

import os

__all__ = ["MINIMAL_ENV_KEYS", "minimal_env"]

#: The variables a child may legitimately need: how to find its binary, and
#: the locale its output is parsed under.  Everything else is dropped -
#: including every startup-hook and loader-injection variable.
MINIMAL_ENV_KEYS: tuple[str, ...] = ("LANG", "LC_ALL", "LC_CTYPE")

#: A fixed, trusted search path.  Inheriting ``PATH`` let a caller's
#: ``PATH=.`` select an attacker's ``pacman`` or ``vercmp``.  Arch's tools
#: live in /usr/bin; /bin is kept for compatibility.
TRUSTED_PATH = "/usr/bin:/bin"


def minimal_env() -> dict:
    """The allowlisted environment for a child process.

    Reads the parent's values but keeps only :data:`MINIMAL_ENV_KEYS`, so no
    ``PYTHON*``, ``LD_*``, ``GIT_*`` or other code-selecting variable can
    reach the child.
    """
    parent = os.environ.copy()
    env = {key: parent[key] for key in MINIMAL_ENV_KEYS if key in parent}
    env["PATH"] = TRUSTED_PATH
    return env
