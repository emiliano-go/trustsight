"""The watcher container must let the startup ruleset sync write.

``full-aur --watch`` syncs ``rules.toml`` to the shipped ruleset once at
startup (covered by ``tests/test_watch.py``), and the guide promises that an
unattended watcher never analyses with a stale ruleset.  A read-only config
mount defeats that: the sync fails open, logs the permission error, and the
watcher keeps the rules the volume was created with.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
def _mode(volume: str) -> str:
    parts = volume.split(":")
    return parts[2] if len(parts) > 2 else "rw"


def test_the_watcher_config_mount_is_writable():
    compose = yaml.safe_load((ROOT / "docker-compose.watcher.yml").read_text())
    service = compose["services"]["trustsight-watch"]
    volumes = service["volumes"]
    config_mounts = [v for v in volumes if v.split(":")[1] == "/config-src"]
    assert config_mounts, "the watcher service no longer mounts the config source"
    for volume in config_mounts:
        assert _mode(volume) == "ro", (
            f"{volume} must be read-only; the entrypoint copies it to tmpfs"
        )
    assert service["environment"]["TRUSTSIGHT_CONFIG_SRC"] == "/config-src"
    assert service["environment"]["TRUSTSIGHT_CONFIG_DIR"].startswith("/tmp/")

    entrypoint = (ROOT / "docker" / "entrypoint.sh").read_text()
    assert "cp -R" in entrypoint and "TRUSTSIGHT_CONFIG_SRC" in entrypoint


def test_the_watcher_container_is_hardened_and_health_checked():
    compose = yaml.safe_load((ROOT / "docker-compose.watcher.yml").read_text())
    service = compose["services"]["trustsight-watch"]
    assert service["read_only"] is True
    assert service["init"] is True
    assert service["stop_grace_period"] == "2m"
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    assert "seccomp=./docker/seccomp-watcher.json" in service["security_opt"]
    assert "seccomp=unconfined" not in service["security_opt"]
    assert service["pids_limit"] == 512
    assert "noexec" in " ".join(service["tmpfs"])
    assert service["ulimits"]["core"]["soft"] == 0
    assert service["healthcheck"]["test"][-1] == "--optional"
    assert "full-aur" in service["healthcheck"]["test"]


def test_the_seccomp_profile_allows_worker_namespaces_but_not_dangerous_calls():
    import json

    profile = json.loads((ROOT / "docker" / "seccomp-watcher.json").read_text())
    allowed = {
        name
        for rule in profile["syscalls"]
        if rule.get("action") == "SCMP_ACT_ALLOW" and not rule.get("includes")
        for name in rule.get("names", ())
    }
    denied = {
        name
        for rule in profile["syscalls"]
        if rule.get("action") == "SCMP_ACT_ERRNO"
        for name in rule.get("names", ())
    }
    assert {"unshare", "mount", "pivot_root", "setns"} <= allowed
    assert {"bpf", "perf_event_open", "ptrace", "keyctl"} <= denied


def test_the_watcher_runs_the_deep_walk_with_the_upstream_lane():
    compose = yaml.safe_load((ROOT / "docker-compose.watcher.yml").read_text())
    service = compose["services"]["trustsight-watch"]
    assert service["command"][-2:] == ["--depth", "-1"]
    env = service["environment"]
    assert env["TRUSTSIGHT_UPSTREAM_SCAN_ENABLED"] == "1"
    assert env["TRUSTSIGHT_UPSTREAM_SCAN_ARCHIVE_FETCH"] == "1"


def test_the_fetcher_is_a_separate_service_without_the_watcher_database():
    compose = yaml.safe_load((ROOT / "docker-compose.watcher.yml").read_text())
    services = compose["services"]
    fetcher = services["upstream-fetcher"]
    watcher = services["trustsight-watch"]
    assert fetcher["command"][:2] == ["upstream-fetcher", "--socket"]
    assert "trustsight-data" not in " ".join(fetcher["volumes"])
    assert "./run/trustsight:" in " ".join(fetcher["volumes"])
    assert watcher["environment"]["TRUSTSIGHT_UPSTREAM_FETCHER_SOCKET"].endswith(
        "upstream.sock")
    assert "TRUSTSIGHT_GITHUB_TOKEN_FILE" not in watcher["environment"]
    assert "seccomp=./docker/seccomp-fetcher.json" in fetcher["security_opt"]


def test_the_fetcher_seccomp_profile_denies_namespace_and_mount_calls():
    import json

    profile = json.loads((ROOT / "docker" / "seccomp-fetcher.json").read_text())
    denied = {
        name
        for rule in profile["syscalls"]
        if rule.get("action") == "SCMP_ACT_ERRNO"
        for name in rule.get("names", ())
    }
    assert {"unshare", "mount", "pivot_root", "ptrace", "bpf"} <= denied
    for rule in profile["syscalls"]:
        if rule.get("action") == "SCMP_ACT_ALLOW" and not rule.get("includes"):
            assert "unshare" not in rule.get("names", ())


def test_the_fetcher_has_no_direct_egress_route():
    compose = yaml.safe_load((ROOT / "docker-compose.watcher.yml").read_text())
    services = compose["services"]
    assert services["upstream-fetcher"]["networks"] == ["watcher-internal"]
    assert compose["networks"]["watcher-internal"]["internal"] is True
    proxy = services["upstream-fetcher"]["environment"][
        "TRUSTSIGHT_UPSTREAM_PROXY"]
    assert "egress-proxy:3128" in proxy
    assert "default" in services["egress-proxy"]["networks"]


def _entrypoint(tmp_path, extra):
    src = tmp_path / "cfg"
    src.mkdir()
    (src / "config.toml").write_text("")
    src.chmod(0o555)
    dst = tmp_path / "dst"
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n")
    route6 = tmp_path / "ipv6_route"
    route6.write_text("")
    env = {
        "PATH": "/usr/bin:/bin",
        "TRUSTSIGHT_REQUIRE_HARDENED": "1",
        "TRUSTSIGHT_CONFIG_SRC": str(src),
        "TRUSTSIGHT_CONFIG_DIR": str(dst),
        "TRUSTSIGHT_PROC_NET_ROUTE": str(route),
        "TRUSTSIGHT_PROC_NET_IPV6_ROUTE": str(route6),
    }
    env.update(extra)
    return subprocess.run(
        ["sh", str(ROOT / "docker" / "entrypoint.sh"), "/bin/true"],
        env=env, capture_output=True, text=True, timeout=30)


def test_the_hardened_entrypoint_refuses_a_watcher_token(tmp_path):
    result = _entrypoint(tmp_path, {
        "TRUSTSIGHT_UPSTREAM_FETCHER_SOCKET": "/run/trustsight/upstream.sock",
        "TRUSTSIGHT_GITHUB_TOKEN": "canary",
    })
    assert result.returncode == 2


def test_the_hardened_entrypoint_refuses_a_watcher_feed_key(tmp_path):
    result = _entrypoint(tmp_path, {
        "TRUSTSIGHT_FEED_SIGNER_SOCKET": "/run/trustsight/feed.sock",
        "TRUSTSIGHT_FEED_KEY": "canary",
    })
    assert result.returncode == 2


@pytest.mark.skipif(os.geteuid() == 0, reason="root cannot prove non-root startup")
def test_the_hardened_entrypoint_starts_without_secrets(tmp_path):
    result = _entrypoint(tmp_path, {})
    assert result.returncode == 0, result.stderr


def _pinned_entrypoint(image):
    return subprocess.run(
        ["sh", str(ROOT / "docker" / "entrypoint.sh"), "/bin/true"],
        env={
            "PATH": "/usr/bin:/bin",
            "TRUSTSIGHT_REQUIRE_PINNED": "1",
            "TRUSTSIGHT_IMAGE": image,
        },
        capture_output=True, text=True, timeout=30)


def test_the_pinned_entrypoint_refuses_a_mutable_tag():
    assert _pinned_entrypoint("ghcr.io/o/i:latest").returncode == 2


def test_the_pinned_entrypoint_accepts_a_digest():
    assert _pinned_entrypoint(
        "ghcr.io/o/i@sha256:" + "a" * 64).returncode == 0


def test_the_hardened_entrypoint_refuses_a_default_route(tmp_path):
    route = tmp_path / "default-route"
    route.write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "eth0\t00000000\t0100007F\t0003\t0\t0\t0\t00000000\n")
    result = _entrypoint(tmp_path, {"TRUSTSIGHT_PROC_NET_ROUTE": str(route)})
    assert result.returncode == 2


def test_the_hardened_entrypoint_refuses_a_watcher_token_file(tmp_path):
    result = _entrypoint(tmp_path, {
        "TRUSTSIGHT_UPSTREAM_FETCHER_SOCKET": "/run/trustsight/upstream.sock",
        "TRUSTSIGHT_GITHUB_TOKEN_FILE": "/run/secrets/token",
    })
    assert result.returncode == 2


def _apparmor_entrypoint(attr):
    return subprocess.run(
        ["sh", str(ROOT / "docker" / "entrypoint.sh"), "/bin/true"],
        env={
            "PATH": "/usr/bin:/bin",
            "TRUSTSIGHT_REQUIRE_APPARMOR": "1",
            "TRUSTSIGHT_PROC_SELF_ATTR": str(attr),
        },
        capture_output=True, text=True, timeout=30)


def test_the_apparmor_guard_accepts_the_shipped_profile(tmp_path):
    attr = tmp_path / "current"
    attr.write_text("trustsight-watcher (enforce)\n")
    assert _apparmor_entrypoint(attr).returncode == 0


def test_the_apparmor_guard_refuses_unconfined(tmp_path):
    attr = tmp_path / "current"
    attr.write_text("unconfined\n")
    assert _apparmor_entrypoint(attr).returncode == 2


def test_the_hardened_entrypoint_refuses_a_writable_config_source(tmp_path):
    src = tmp_path / "writable"
    src.mkdir()
    src.chmod(0o755)
    dst = tmp_path / "dst"
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n")
    route6 = tmp_path / "ipv6"
    route6.write_text("")
    result = subprocess.run(
        ["sh", str(ROOT / "docker" / "entrypoint.sh"), "/bin/true"],
        env={
            "PATH": "/usr/bin:/bin",
            "TRUSTSIGHT_REQUIRE_HARDENED": "1",
            "TRUSTSIGHT_REQUIRE_READONLY_CONFIG": "1",
            "TRUSTSIGHT_CONFIG_SRC": str(src),
            "TRUSTSIGHT_CONFIG_DIR": str(dst),
            "TRUSTSIGHT_PROC_NET_ROUTE": str(route),
            "TRUSTSIGHT_PROC_NET_IPV6_ROUTE": str(route6),
        },
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 2


def _gvisor_entrypoint(version):
    return subprocess.run(
        ["sh", str(ROOT / "docker" / "entrypoint.sh"), "/bin/true"],
        env={
            "PATH": "/usr/bin:/bin",
            "TRUSTSIGHT_REQUIRE_GVISOR": "1",
            "TRUSTSIGHT_PROC_VERSION": str(version),
        },
        capture_output=True, text=True, timeout=30)


def test_the_gvisor_guard_accepts_gvisor(tmp_path):
    version = tmp_path / "version"
    version.write_text("Linux version 4.4.0 (gVisor)\n")
    assert _gvisor_entrypoint(version).returncode == 0


def test_the_gvisor_guard_refuses_the_host_kernel(tmp_path):
    version = tmp_path / "version"
    version.write_text("Linux version 6.12.0-generic\n")
    assert _gvisor_entrypoint(version).returncode == 2


def _seccomp_entrypoint(status):
    return subprocess.run(
        ["sh", str(ROOT / "docker" / "entrypoint.sh"), "/bin/true"],
        env={
            "PATH": "/usr/bin:/bin",
            "TRUSTSIGHT_REQUIRE_SECCOMP": "1",
            "TRUSTSIGHT_PROC_SELF_STATUS": str(status),
        },
        capture_output=True, text=True, timeout=30)


def test_the_seccomp_guard_accepts_filter_mode(tmp_path):
    status = tmp_path / "status"
    status.write_text("Name:\tpython\nSeccomp:\t2\n")
    assert _seccomp_entrypoint(status).returncode == 0


def test_the_seccomp_guard_refuses_no_filter(tmp_path):
    status = tmp_path / "status"
    status.write_text("Name:\tpython\nSeccomp:\t0\n")
    assert _seccomp_entrypoint(status).returncode == 2


def test_the_image_normalises_source_permissions():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "chmod -R a+rX /app" in text


def test_the_fetcher_profile_lets_glibc_fall_back_for_threads():
    profile = json.loads((ROOT / "docker" / "seccomp-fetcher.json").read_text())
    rule = next(rule for rule in profile["syscalls"]
                if "clone3" in rule["names"])
    assert rule["action"] == "SCMP_ACT_ERRNO"
    assert rule["errnoRet"] == 38


def _gvisor_seccomp_entrypoint(status, version):
    return subprocess.run(
        ["sh", str(ROOT / "docker" / "entrypoint.sh"), "/bin/true"],
        env={
            "PATH": "/usr/bin:/bin",
            "TRUSTSIGHT_REQUIRE_SECCOMP": "1",
            "TRUSTSIGHT_REQUIRE_GVISOR": "1",
            "TRUSTSIGHT_PROC_SELF_STATUS": str(status),
            "TRUSTSIGHT_PROC_VERSION": str(version),
        },
        capture_output=True, text=True, timeout=30)


def test_the_seccomp_guard_defers_to_gvisor(tmp_path):
    status = tmp_path / "status"
    status.write_text("Seccomp:\t0\n")
    version = tmp_path / "version"
    version.write_text("Linux version 4.4.0 (gVisor)\n")
    assert _gvisor_seccomp_entrypoint(status, version).returncode == 0


def test_the_seccomp_guard_still_fails_without_gvisor(tmp_path):
    status = tmp_path / "status"
    status.write_text("Seccomp:\t0\n")
    version = tmp_path / "version"
    version.write_text("Linux version 6.12.0-generic\n")
    assert _gvisor_seccomp_entrypoint(status, version).returncode == 2
