"""Optional Docker check: an internal-only network has no direct route.

Skipped unless ``TRUSTSIGHT_DOCKER_TESTS=1``.  It creates a disposable
internal network and proves a process on it cannot reach 1.1.1.1:443.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("TRUSTSIGHT_DOCKER_TESTS") != "1"
    or shutil.which("docker") is None,
    reason="set TRUSTSIGHT_DOCKER_TESTS=1 and install Docker to run",
)


def test_internal_network_has_no_direct_egress():
    network = f"trustsight-test-{uuid.uuid4().hex[:12]}"
    subprocess.run(
        ["docker", "network", "create", "--internal", network],
        check=True, capture_output=True, text=True, timeout=60)
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "--network", network,
             "python:3.12-slim", "python", "-c",
             "import socket; socket.create_connection(('1.1.1.1', 443), 2)"],
            capture_output=True, text=True, timeout=60)
    finally:
        subprocess.run(
            ["docker", "network", "rm", network],
            check=False, capture_output=True, text=True, timeout=60)
    assert result.returncode != 0
