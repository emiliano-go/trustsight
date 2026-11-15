"""The watcher deployment's containment invariants.

These are the properties a future compose edit must not silently undo:
no unconfined seccomp, an internal-only fetcher, a networkless signer, no
provider or feed key in the watcher, read-only config, and a digest-pinned
deploy path.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def _compose() -> dict:
    return yaml.safe_load((ROOT / "docker-compose.watcher.yml").read_text())


def test_watcher_and_services_do_not_disable_seccomp():
    services = _compose()["services"]
    for name in ("trustsight-watch", "upstream-fetcher", "egress-proxy",
                 "feed-signer"):
        opts = services[name]["security_opt"]
        assert "seccomp=unconfined" not in opts, name


def test_the_fetcher_is_internal_and_the_signer_is_networkless():
    compose = _compose()
    services = compose["services"]
    assert compose["networks"]["watcher-internal"]["internal"] is True
    assert services["trustsight-watch"]["networks"] == ["watcher-internal"]
    assert services["upstream-fetcher"]["networks"] == ["watcher-internal"]
    assert services["feed-signer"]["network_mode"] == "none"
    assert services["token-broker"]["network_mode"] == "none"
    assert "default" in services["egress-proxy"]["networks"]


def test_the_watcher_routes_its_egress_through_the_proxy():
    watcher = _compose()["services"]["trustsight-watch"]
    assert "egress-proxy:3128" in watcher["environment"]["HTTPS_PROXY"]
    assert "egress-proxy:3128" in watcher["environment"]["HTTP_PROXY"]


def test_the_watcher_holds_neither_a_provider_nor_a_feed_key():
    watcher = _compose()["services"]["trustsight-watch"]
    env = watcher["environment"]
    assert "TRUSTSIGHT_GITHUB_TOKEN_FILE" not in env
    assert "TRUSTSIGHT_FEED_KEY" not in env
    assert "TRUSTSIGHT_FEED_KEY_FILE" not in env
    assert env["TRUSTSIGHT_UPSTREAM_FETCHER_SOCKET"].endswith(".sock")
    assert env["TRUSTSIGHT_FEED_SIGNER_SOCKET"].endswith(".sock")


def test_config_is_read_only_and_tmpfs_is_not_executable():
    watcher = _compose()["services"]["trustsight-watch"]
    config_mount = [v for v in watcher["volumes"] if v.endswith(":/config-src:ro")]
    assert config_mount
    assert all("noexec" in mount for mount in watcher["tmpfs"])
    assert watcher["environment"]["TRUSTSIGHT_CONFIG_DIR"].startswith("/tmp/")


def test_the_pinned_overlay_requires_a_digest():
    text = (ROOT / "docker-compose.watcher.pinned.yml").read_text()
    assert text.count("${TRUSTSIGHT_IMAGE:?") >= 3
    assert "TRUSTSIGHT_REQUIRE_PINNED" in text


def test_the_gvisor_overlay_covers_every_service():
    overlay = yaml.safe_load(
        (ROOT / "docker-compose.watcher.gvisor.yml").read_text())
    services = overlay["services"]
    assert set(services) == {
        "trustsight-watch", "db-writer", "upstream-fetcher", "egress-proxy",
        "feed-signer", "token-broker",
    }
    assert all(item["runtime"] == "runsc" for item in services.values())
    assert all(item["environment"]["TRUSTSIGHT_REQUIRE_GVISOR"] == "1"
               for item in services.values())


def test_the_kata_overlay_puts_the_watcher_in_a_microvm():
    overlay = yaml.safe_load(
        (ROOT / "docker-compose.watcher.kata.yml").read_text())
    assert overlay["services"]["trustsight-watch"]["runtime"] == "kata-runtime"


def test_only_the_watcher_keeps_apparmor_unconfined():
    services = _compose()["services"]
    assert ("apparmor=${TRUSTSIGHT_APPARMOR_PROFILE:-unconfined}"
            in services["trustsight-watch"]["security_opt"])
    for name in ("upstream-fetcher", "egress-proxy", "feed-signer",
                 "token-broker"):
        assert "apparmor=docker-default" in services[name]["security_opt"], name


def test_ci_smoke_uses_the_shipped_security_profiles():
    text = (ROOT / ".github" / "workflows" / "docker.yml").read_text()
    assert "seccomp=unconfined" not in text
    assert "apparmor=unconfined" not in text
    assert "seccomp=\"$PWD/docker/seccomp-watcher.json\"" in text


def test_the_apparmor_overlay_selects_the_shipped_profile():
    overlay = yaml.safe_load(
        (ROOT / "docker-compose.watcher.apparmor.yml").read_text())
    service = overlay["services"]["trustsight-watch"]
    assert "apparmor=trustsight-watcher" in service["security_opt"]
    assert service["environment"]["TRUSTSIGHT_REQUIRE_APPARMOR"] == "1"


def test_the_token_broker_socket_is_not_visible_to_the_watcher():
    services = _compose()["services"]
    watcher_volumes = " ".join(services["trustsight-watch"]["volumes"])
    assert "trustsight-token" not in watcher_volumes
    assert any("trustsight-token" in volume
               for volume in services["upstream-fetcher"]["volumes"])
    assert any("trustsight-token" in volume
               for volume in services["token-broker"]["volumes"])


def test_the_anchor_monitor_is_networkless_and_opt_in():
    service = _compose()["services"]["anchor-monitor"]
    assert service["network_mode"] == "none"
    assert service["profiles"] == ["anchor-monitor"]
    assert any("trustsight-signer-audit" in volume
               for volume in service["volumes"])


def test_the_main_services_require_active_seccomp():
    services = _compose()["services"]
    for name in ("trustsight-watch", "upstream-fetcher", "egress-proxy",
                 "feed-signer", "token-broker"):
        assert services[name]["environment"][
            "TRUSTSIGHT_REQUIRE_SECCOMP"] == "1", name


def test_the_watcher_has_no_writable_database_volume():
    services = _compose()["services"]
    volumes = services["trustsight-watch"]["volumes"]
    assert any(volume.startswith("trustsight-data:") and
               volume.endswith(":ro") for volume in volumes)
    assert services["trustsight-watch"]["environment"][
        "TRUSTSIGHT_DB_WRITER_SOCKET"].endswith("db-writer.sock")


def test_the_database_writer_is_isolated_and_owns_the_volume():
    writer = _compose()["services"]["db-writer"]
    assert writer["network_mode"] == "none"
    assert writer["read_only"] is True
    assert "ALL" in writer["cap_drop"]
    assert any(volume.startswith("trustsight-data:") and
               not volume.endswith(":ro") for volume in writer["volumes"])
