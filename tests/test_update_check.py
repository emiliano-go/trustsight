"""The once-a-command "a newer release exists" notice.

It must warn on an outdated install, never block a pipeline, never pollute
JSON, and never let a network or parse failure break a command.
"""

from __future__ import annotations

import json

import pytest
import typer

from trustsight import release
from trustsight.cli import updates


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    import trustsight.config as config

    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    (tmp_path / "cache").mkdir(parents=True, exist_ok=True)
    monkeypatch.delenv("TRUSTSIGHT_NO_UPDATE_CHECK", raising=False)
    monkeypatch.delenv("TRUSTSIGHT_OFFLINE", raising=False)


# --- version comparison -------------------------------------------------


@pytest.mark.parametrize("latest,current,newer", [
    ("v0.20.0", "0.19.0", True),
    ("0.19.1", "0.19.0", True),
    ("v0.19.0", "0.19.0", False),
    ("v0.18.9", "0.19.0", False),
    ("baseline-2026-09-24", "0.19.0", False),
    ("", "0.19.0", False),
    ("garbage", "0.19.0", False),
])
def test_is_newer(latest, current, newer):
    assert release.is_newer(latest, current) is newer


def test_the_newest_semver_tag_skips_baselines_and_prereleases():
    releases = [
        {"tag_name": "baseline-2026-09-24", "assets": [1]},
        {"tag_name": "v0.19.0"},
        {"tag_name": "v0.20.0-rc1", "prerelease": True},
        {"tag_name": "v0.18.1"},
        {"tag_name": "v0.19.0", "draft": True},
    ]
    assert release._newest_semver_tag(releases) == "v0.19.0"
    assert release._newest_semver_tag([]) is None


# --- the notice ---------------------------------------------------------


def _current(monkeypatch, version="0.19.0"):
    import trustsight

    monkeypatch.setattr(trustsight, "__version__", version, raising=False)


def test_a_newer_release_is_announced(monkeypatch, capsys):
    _current(monkeypatch)
    monkeypatch.setattr(release, "latest_release_tag", lambda: "v0.20.0")
    monkeypatch.setattr(updates, "_interactive", lambda: False)

    updates.check_and_warn()
    err = capsys.readouterr().err
    assert "newer release" in err and "v0.20.0" in err and "0.19.0" in err


def test_an_up_to_date_install_is_silent(monkeypatch, capsys):
    _current(monkeypatch)
    monkeypatch.setattr(release, "latest_release_tag", lambda: "v0.19.0")

    updates.check_and_warn()
    assert capsys.readouterr().err == ""


def test_the_disable_env_is_honoured(monkeypatch, capsys):
    _current(monkeypatch)
    monkeypatch.setenv("TRUSTSIGHT_NO_UPDATE_CHECK", "1")
    called = []
    monkeypatch.setattr(release, "latest_release_tag",
                        lambda: called.append(1) or "v9.9.9")

    updates.check_and_warn()
    assert capsys.readouterr().err == ""
    assert called == []


def test_offline_never_touches_the_network(monkeypatch, capsys):
    _current(monkeypatch)
    monkeypatch.setattr(release, "offline", lambda: True)

    def _boom():
        raise AssertionError("latest_release_tag must not be called offline")

    monkeypatch.setattr(release, "latest_release_tag", _boom)
    updates.check_and_warn()
    assert capsys.readouterr().err == ""


def test_offline_still_uses_a_cached_tag(monkeypatch, capsys):
    """Offline forbids the network, not the notice: a cached tag is local."""
    _current(monkeypatch)
    updates._write_cache("v0.20.0")
    monkeypatch.setattr(release, "offline", lambda: True)
    monkeypatch.setattr(updates, "_interactive", lambda: False)
    monkeypatch.setattr(release, "latest_release_tag",
                        lambda: pytest.fail("no fetch offline"))

    updates.check_and_warn()
    assert "v0.20.0" in capsys.readouterr().err


def test_a_failed_lookup_is_silent(monkeypatch, capsys):
    _current(monkeypatch)

    def _boom():
        raise RuntimeError("rate limited")

    monkeypatch.setattr(release, "latest_release_tag", _boom)
    updates.check_and_warn()
    assert capsys.readouterr().err == ""


# --- the abort path -----------------------------------------------------


def test_abort_prints_the_update_command_and_exits(monkeypatch, capsys):
    _current(monkeypatch)
    monkeypatch.setattr(release, "latest_release_tag", lambda: "v0.20.0")
    monkeypatch.setattr(updates, "_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "y")

    with pytest.raises(typer.Exit) as excinfo:
        updates.check_and_warn()
    assert excinfo.value.exit_code == 2
    err = capsys.readouterr().err
    assert "git pull" in err


def test_declining_the_abort_continues(monkeypatch, capsys):
    _current(monkeypatch)
    monkeypatch.setattr(release, "latest_release_tag", lambda: "v0.20.0")
    monkeypatch.setattr(updates, "_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "n")

    updates.check_and_warn()  # no raise
    assert "newer release" in capsys.readouterr().err


# --- the cache ----------------------------------------------------------


def test_a_fresh_cache_avoids_a_second_lookup(monkeypatch, capsys):
    _current(monkeypatch)
    updates._write_cache("v0.20.0")

    def _boom():
        raise AssertionError("a fresh cache must not refetch")

    monkeypatch.setattr(release, "latest_release_tag", _boom)
    monkeypatch.setattr(updates, "_interactive", lambda: False)

    updates.check_and_warn()
    assert "v0.20.0" in capsys.readouterr().err


def test_a_stale_cache_is_refetched(monkeypatch, tmp_path):
    import time

    _current(monkeypatch)
    path = updates._cache_path()
    path.write_text(json.dumps(
        {"checked_at": time.time() - updates._TTL_SECONDS - 10,
         "latest": "v0.20.0"}))
    monkeypatch.setattr(release, "latest_release_tag", lambda: "v0.20.0")
    monkeypatch.setattr(updates, "_interactive", lambda: False)

    assert updates.newer_version() == ("0.19.0", "0.20.0")
    # The refetch rewrote the cache with the current timestamp.
    assert json.loads(path.read_text())["latest"] == "v0.20.0"
