#!/usr/bin/env python3
"""Validate a running watcher deployment against the containment contract.

Reads ``docker inspect`` JSON (live or from ``--inspect-json``) and names every
departure: writable root, added caps, privileged mode, unconfined seccomp or
AppArmor, a default/bridge network, root user, or missing pid/memory limits.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys


def _labels(container: dict) -> str:
    return container.get("Name", "?").lstrip("/")


def check(container: dict) -> list[str]:
    name = _labels(container)
    host = container.get("HostConfig") or {}
    config = container.get("Config") or {}
    problems: list[str] = []
    if not host.get("ReadonlyRootfs"):
        problems.append(f"{name}: root filesystem is writable")
    if host.get("Privileged"):
        problems.append(f"{name}: container is privileged")
    caps = [str(cap).upper() for cap in host.get("CapAdd") or ()]
    if caps:
        problems.append(f"{name}: added capabilities {caps}")
    drops = {str(cap).upper() for cap in host.get("CapDrop") or ()}
    if "ALL" not in drops:
        problems.append(f"{name}: does not drop ALL capabilities")
    security = " ".join(str(opt) for opt in host.get("SecurityOpt") or ())
    if "no-new-privileges" not in security:
        problems.append(f"{name}: no-new-privileges is missing")
    if "seccomp=unconfined" in security or "apparmor=unconfined" in security:
        problems.append(f"{name}: unconfined seccomp/AppArmor")
    user = str(config.get("User") or "").strip()
    if user in ("", "0", "0:0", "root"):
        problems.append(f"{name}: runs as root")
    if not host.get("PidsLimit"):
        problems.append(f"{name}: no pids limit")
    if not host.get("Memory"):
        problems.append(f"{name}: no memory limit")
    mode = str(host.get("NetworkMode") or "")
    if mode in ("bridge", "host", "default"):
        problems.append(f"{name}: default/host network")
    return problems


def load(path: str | None) -> list[dict]:
    if path:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, list) else [value]
    ids = subprocess.run(
        ["docker", "compose", "-f", "docker-compose.watcher.yml", "ps", "-q"],
        capture_output=True, text=True, check=False)
    if ids.returncode != 0 or not ids.stdout.strip():
        raise RuntimeError("no running watcher containers")
    result = subprocess.run(
        ["docker", "inspect", *ids.stdout.split()],
        capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError("docker inspect failed")
    return json.loads(result.stdout)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inspect-json", help="read docker inspect JSON here")
    args = parser.parse_args(argv)
    try:
        containers = load(args.inspect_json)
    except Exception as exc:  # noqa: BLE001 - one-line refusal
        print(f"validate-containment: {exc}", file=sys.stderr)
        return 2
    problems = [problem for container in containers for problem in check(container)]
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    print(f"ok: {len(containers)} container(s) match the containment contract")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
