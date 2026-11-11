"""Parent-owned fetch state is safe from worker-controlled files (A16)."""

from __future__ import annotations

import os
import stat

import pytest

from trustsight.sandbox import fetch_state


def _state(head: str = "a" * 40) -> fetch_state.FetchState:
    return fetch_state.FetchState(
        head=head,
        advertised_head=head,
        fetched_at=1_700_000_000,
        upstream_mtime=1_700_000_000,
        verified=True,
    )


def test_state_round_trips_and_is_parent_only(tmp_path):
    fetch_state.store(tmp_path, "demo", _state())

    loaded = fetch_state.load(tmp_path, "demo")
    assert loaded == _state()
    state_file = fetch_state.state_dir(tmp_path) / "demo.json"
    assert stat.S_IMODE(state_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(fetch_state.state_dir(tmp_path).stat().st_mode) == 0o700


def test_a_symlinked_state_is_not_followed(tmp_path):
    directory = fetch_state.state_dir(tmp_path)
    directory.mkdir(mode=0o700)
    secret = tmp_path / "secret"
    secret.write_text("not state")
    os.symlink(secret, directory / "demo.json")

    assert fetch_state.load(tmp_path, "demo") is None


def test_a_fifo_state_does_not_block(tmp_path):
    directory = fetch_state.state_dir(tmp_path)
    directory.mkdir(mode=0o700)
    os.mkfifo(directory / "demo.json")

    assert fetch_state.load(tmp_path, "demo") is None


def test_an_oversized_state_is_refused(tmp_path):
    directory = fetch_state.state_dir(tmp_path)
    directory.mkdir(mode=0o700)
    (directory / "demo.json").write_bytes(b"x" * 9000)

    assert fetch_state.load(tmp_path, "demo") is None


def test_corrupt_or_incomplete_state_is_ignored(tmp_path):
    directory = fetch_state.state_dir(tmp_path)
    directory.mkdir(mode=0o700)
    (directory / "demo.json").write_text('{"version": 1, "head": ""}')

    assert fetch_state.load(tmp_path, "demo") is None


@pytest.mark.parametrize("name", ["", ".", "..", "a/b", "a\\b"])
def test_invalid_package_names_are_refused(tmp_path, name):
    assert fetch_state.load(tmp_path, name) is None
    with pytest.raises(ValueError):
        fetch_state.store(tmp_path, name, _state())


def test_an_unverified_state_is_ignored(tmp_path):
    directory = fetch_state.state_dir(tmp_path)
    directory.mkdir(mode=0o700)
    document = {
        "version": 1,
        "package": "demo",
        "head": "a" * 40,
        "advertised_head": "a" * 40,
        "fetched_at": 1,
        "upstream_mtime": 1,
        "verified": False,
    }
    import json
    (directory / "demo.json").write_text(json.dumps(document))

    assert fetch_state.load(tmp_path, "demo") is None
