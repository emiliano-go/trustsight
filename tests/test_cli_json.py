"""Every ``--json`` surface emits a JSON document, on success and on error.

``inspect --json`` was the one command that did not: the single-result path
returned its body to a caller that discarded it, so it exited 0 with empty
stdout while the ``--last`` path printed its JSON. A test that builds the
expected body directly (as the output-parity suite does) cannot catch that,
because it never runs the command.

So these tests are deliberately structural rather than per-field: whatever a
command prints under ``--json`` must parse as JSON, and the set of commands
covered must equal the set that declares the flag. Add a command with
``--json`` and forget its test, and ``test_every_json_command_is_covered``
fails.
"""

import inspect
import json

import pytest
from typer.testing import CliRunner

from trustsight.cli import app

# Click 8.2+ keeps stderr separate, so `result.stdout` is the document alone;
# the release/seed notices go to stderr and cannot corrupt it.
runner = CliRunner()


# (command path, argv before --json).  Paths must match the flag-declaring
# commands exactly; the coverage test below asserts that.
CASES = [
    ("review", ["review"]),
    ("inspect", ["inspect", "pkg"]),
    ("history", ["history", "pkg"]),
    ("list", ["list"]),
    ("forget", ["forget", "pkg", "--yes"]),
    ("import-baseline", ["import-baseline", "/nonexistent"]),
    ("seed-db", ["seed-db"]),
    ("lint-rules", ["lint-rules"]),
    ("status", ["status"]),
    ("full-aur", ["full-aur"]),
    ("config show", ["config", "show"]),
    ("config set", ["config", "set", "seed.auto_import", "true"]),
    ("config sync-rules", ["config", "sync-rules"]),
    ("override list", ["override", "list"]),
    ("override add", ["override", "add", "H001", "--reason", "test"]),
    ("override rm", ["override", "rm", "H001"]),
    ("db check", ["db", "check"]),
    ("db vacuum", ["db", "vacuum", "--force"]),
    ("db backup", ["db", "backup"]),
    ("baseline build", ["baseline", "build"]),
    ("baseline import", ["baseline", "import", "/nonexistent"]),
    ("corpus pivot", ["corpus", "pivot", "example.com"]),
    ("ioc sources", ["ioc", "sources"]),
    ("ioc import", ["ioc", "import", "/nonexistent"]),
    ("ioc update", ["ioc", "update"]),
    ("ioc list", ["ioc", "list"]),
    ("ioc export", ["ioc", "export"]),
    ("seed info", ["seed", "info"]),
    ("seed fetch", ["seed", "fetch"]),
    ("seed stats", ["seed", "stats"]),
    ("seed migrate", ["seed", "migrate"]),
]


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Point every state path at tmp_path and forbid the network."""
    monkeypatch.setattr("trustsight.config.DATA_DIR", tmp_path)
    monkeypatch.setattr("trustsight.config.CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr("trustsight.config.CACHE_DIR", tmp_path / ".cache")
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    monkeypatch.setenv("TRUSTSIGHT_OFFLINE", "1")
    # Keep discovery off the host's pacman so the run is hermetic: no
    # installed packages, no local repos, no AUR answers.
    monkeypatch.setattr("trustsight.cli.review._discover_packages",
                        lambda **kwargs: (None, 0))
    monkeypatch.setattr("trustsight.discovery.get_installed_foreign", lambda: [])
    monkeypatch.setattr(
        "trustsight.discovery.get_local_repos_from_pacman_conf", lambda: []
    )
    monkeypatch.setattr(
        "trustsight.discovery.get_aur_package_info", lambda *a, **k: {}
    )


@pytest.mark.parametrize("path,argv", CASES, ids=[c[0] for c in CASES])
def test_json_flag_emits_a_document(path, argv, isolated):
    """Whatever the outcome, ``--json`` stdout must parse as JSON.

    A command that ran prints its document; one that could not run prints a
    JSON error. Both are the contract scripting depends on, so both are
    parsed here; the exit code is allowed to be 0 or 2 but never a traceback.
    """
    result = runner.invoke(app, [*argv, "--json"])

    assert result.exit_code in (0, 2), (
        f"{path}: unexpected exit {result.exit_code}\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )
    try:
        json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        pytest.fail(
            f"{path} --json did not print a JSON document: {exc}\n"
            f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
        )


def _json_commands() -> set[str]:
    """Every command path that declares a ``json_output`` parameter."""
    found: set[str] = set()

    def name_of(info):
        return info.name or (
            info.callback.__name__.replace("_", "-") if info.callback else None
        )

    def walk(typer_app, prefix):
        for info in typer_app.registered_commands:
            cb = info.callback
            if cb and "json_output" in inspect.signature(cb).parameters:
                found.add(" ".join(prefix + [name_of(info)]))
        for group in typer_app.registered_groups:
            sub = group.typer_instance
            label = group.name or (sub.info.name if sub else None)
            walk(sub, prefix + [label])

    walk(app, [])
    return found


def test_every_json_command_is_covered():
    """A new ``--json`` command must arrive with a case above."""
    covered = {path for path, _ in CASES}
    declared = _json_commands()

    missing = declared - covered
    stale = covered - declared
    assert not missing, (
        f"these commands declare --json but have no test case: {sorted(missing)}"
    )
    assert not stale, (
        f"these test cases name commands that no longer declare --json: {sorted(stale)}"
    )
