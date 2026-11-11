"""Git-worker resource-limit failures must be reported, not swallowed.

The worker is a resource-bounded subprocess, not an OS sandbox.  When a
``setrlimit`` or ``PR_SET_NO_NEW_PRIVS`` call fails, the isolation is weaker
than intended, and the loss must be visible to the parent instead of vanishing
into a bare ``except: pass``.
"""

from __future__ import annotations


def test_a_failed_limit_is_reported(monkeypatch):
    from trustsight.sandbox import git_worker

    def boom(which, limits):
        raise OSError("cannot set")

    monkeypatch.setattr(git_worker.resource, "setrlimit", boom)

    def no_libc(*_a, **_k):
        raise AttributeError("no libc")

    monkeypatch.setattr(git_worker.ctypes, "CDLL", no_libc)

    failures = git_worker._apply_limits()
    assert len(failures) == 5  # four rlimits plus NO_NEW_PRIVS
    assert any("RLIMIT_AS" in f for f in failures)
    assert any("PR_SET_NO_NEW_PRIVS" in f for f in failures)


def test_a_healthy_startup_reports_nothing(monkeypatch):
    from trustsight.sandbox import git_worker

    monkeypatch.setattr(git_worker.resource, "setrlimit", lambda _w, _l: None)

    class _Libc:
        def prctl(self, *_a):
            return 0

    monkeypatch.setattr(git_worker.ctypes, "CDLL", lambda *_a, **_k: _Libc())
    assert git_worker._apply_limits() == []


def test_a_libgit2_setting_that_fails_is_reported(monkeypatch):
    """A16: strict verification failing to turn on must not read as on."""
    from trustsight.sandbox import git_worker

    class _RefusingSettings:
        def __setattr__(self, name, value):
            raise ValueError("denied")

        def enable_strict_object_creation(self, value=True):
            raise ValueError("denied")

        def enable_strict_hash_verification(self, value=True):
            raise ValueError("denied")

    monkeypatch.setattr(git_worker.pygit2, "settings", _RefusingSettings())
    monkeypatch.setattr(git_worker.tempfile, "mkdtemp",
                        lambda **_k: "/tmp/trustsight-test-home")
    monkeypatch.setattr(git_worker.atexit, "register", lambda *_a, **_k: None)

    failures = git_worker._harden_libgit2()
    assert len(failures) == 5
    assert any("pack object ceiling" in f for f in failures)
    assert any("strict hash verification" in f for f in failures)
    assert any("http expect-continue" in f for f in failures)


def test_the_response_carries_the_degraded_list(monkeypatch):
    from trustsight.sandbox import git_worker

    monkeypatch.setattr(git_worker, "_DEGRADED", ["RLIMIT_AS not applied: OSError"])
    assert git_worker._attach_degraded({}) == {
        "degraded": ["RLIMIT_AS not applied: OSError"]}
    monkeypatch.setattr(git_worker, "_DEGRADED", [])
    assert git_worker._attach_degraded({}) == {}


def test_a_core_limit_failure_refuses_before_serving(monkeypatch):
    from trustsight.sandbox import git_worker

    monkeypatch.setattr(
        git_worker,
        "_apply_limits",
        lambda: ["RLIMIT_CPU not applied: OSError"],
    )
    assert git_worker.main() == 3


def test_secondary_limit_failures_stay_degraded():
    from trustsight.sandbox import _spawn

    failures = [
        "RLIMIT_FSIZE not applied: OSError",
        "RLIMIT_NOFILE not applied: OSError",
    ]
    assert _spawn.core_sandbox_failures(failures) == []
