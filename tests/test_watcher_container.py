"""The watcher container must let the startup ruleset sync write.

``full-aur --watch`` syncs ``rules.toml`` to the shipped ruleset once at
startup (covered by ``tests/test_watch.py``), and the guide promises that an
unattended watcher never analyses with a stale ruleset.  A read-only config
mount defeats that: the sync fails open, logs the permission error, and the
watcher keeps the rules the volume was created with.
"""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR_IN_CONTAINER = "/home/ts/.config/trustsight"


def _mode(volume: str) -> str:
    parts = volume.split(":")
    return parts[2] if len(parts) > 2 else "rw"


def test_the_watcher_config_mount_is_writable():
    compose = yaml.safe_load((ROOT / "docker-compose.watcher.yml").read_text())
    volumes = compose["services"]["trustsight-watch"]["volumes"]
    config_mounts = [v for v in volumes if v.split(":")[1] == CONFIG_DIR_IN_CONTAINER]
    assert config_mounts, "the watcher service no longer mounts the config directory"
    for volume in config_mounts:
        assert _mode(volume) != "ro", (
            f"{volume} is read-only, so the startup ruleset sync cannot write "
            "rules.toml; mount it writable"
        )

    guide = (ROOT / "docs" / "guides" / "watching-the-aur.md").read_text()
    assert f"{CONFIG_DIR_IN_CONTAINER}:ro" not in guide, (
        "the docker run example mounts the config directory read-only"
    )


def test_the_watcher_container_is_hardened_and_health_checked():
    compose = yaml.safe_load((ROOT / "docker-compose.watcher.yml").read_text())
    service = compose["services"]["trustsight-watch"]
    assert service["read_only"] is True
    assert service["init"] is True
    assert service["stop_grace_period"] == "2m"
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    assert service["pids_limit"] == 512
    assert service["healthcheck"]["test"][-1] == "--optional"
    assert "full-aur" in service["healthcheck"]["test"]
