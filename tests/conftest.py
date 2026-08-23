import socket as _socket
import sys
from pathlib import Path

import pytest

_SRC = str(Path(__file__).resolve().parent.parent / "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

SHARED_RULES = [
    {"id": "R001", "name": "Remote Script Execution", "pattern": r"curl.*(?<!\\)\|\s*(bash|sh|python|zsh)", "severity": "CRITICAL", "category": "network_execution", "match_target": "resolved"},
    {"id": "R002", "name": "Wget Pipe to Shell", "pattern": r"wget.*\|\s*(bash|sh|python|zsh)", "severity": "CRITICAL", "category": "network_execution", "match_target": "resolved"},
    {"id": "R003", "name": "Base64 Decode and Execute", "pattern": r"base64.*\-d.*\|", "severity": "CRITICAL", "category": "obfuscation", "match_target": "resolved"},
    {"id": "H001", "name": "Checksum Disabled", "pattern": r"sha256sums\s*=\s*\(?\s*['\"]?(?:SKIP|NONE)['\"]?", "severity": "HIGH", "category": "integrity", "match_target": "raw_line"},
    {"id": "H002", "name": "Checksum Emptied", "pattern": r"sha256sums\s*=\s*\(\s*\)", "severity": "HIGH", "category": "integrity", "match_target": "raw_line"},
    # H003 is now a structural rule (src/trustsight/analysis/structural.py):
    # fires on http:// added sources when no checksum was also added.
    {"id": "R007", "name": "Install File Modification", "pattern": r"^\+.*\.install", "severity": "MEDIUM", "category": "installer", "match_target": "raw_line"},
    {"id": "R008", "name": "Unexpected File Download", "pattern": r"\b(python|ruby|perl)\s+-c\s+https?://", "severity": "HIGH", "category": "network_execution", "match_target": "resolved"},
    # H004 is now a code rule (src/trustsight/analysis/build.py).
    {"id": "R010", "name": "Uses curl in PKGBUILD", "pattern": r"\bcurl\s", "severity": "LOW", "category": "network_usage", "match_target": "raw_line", "scope": ["function_body"]},
    {"id": "R011", "name": "Uses wget in PKGBUILD", "pattern": r"\bwget\s", "severity": "LOW", "category": "network_usage", "match_target": "raw_line", "scope": ["function_body"]},
    # `include_comments` matches the shipped definition: R012's payload is
    # aimed at whoever *reads* the file, and in practice that is always a
    # comment. Without it here the fixture asserted a behaviour the shipped
    # rule gets from a field the fixture did not carry.
    {"id": "R012", "name": "LLM Prompt Injection", "pattern": r"ignore\s+(?:all\s+)?previous\s+(?:instructions|commands|input)", "severity": "FATAL", "category": "injection", "match_target": "resolved", "include_comments": True},
    {"id": "R013", "name": "Unicode Bidi Override", "pattern": r"[\u202A-\u202E\u2066-\u2069\u200B-\u200D\uFEFF]", "severity": "FATAL", "category": "unicode", "match_target": "raw_line"},
]

SHARED_CONFIG = {
    "severity_weights": {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5, "INFO": 0},
    "source_bucket_weights": {"trusted_forge": 0, "official": 0, "raw_hosting": 15, "unknown": 20, "homograph_attack": 30},
    "novelty_weights": {"url_first_globally": 10, "url_first_in_package": 5, "maintainer_first_in_package": 15},
}


# --- outbound network is off during tests -------------------------------
#
# A test that reaches the real AUR does not fail; it *waits*. The metadata
# dump is tens of megabytes behind a 300-second timeout, so a mock that
# silently stops applying turns a one-second unit test into a stalled CI
# job with no failing assertion to point at. That is what happened here:
# `test_watch_stops_cleanly_on_interrupt` patches `run_baseline_build`,
# the patch did not take under a full-suite run, and the suite hung in
# `fetch_metadata` downloading the live corpus.
#
# The guard does not make the mock work. It makes its absence loud: the
# connection raises immediately, naming the address, and the test fails in
# the frame that tried to reach the network.

#: Loopback stays open. Tests that bind a local server are testing the
#: harness around a socket, not the internet.
_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost", ""})


class NetworkAccessDenied(BaseException):
    """A test tried to open a connection to somewhere that is not loopback.

    Deliberately a ``BaseException``. Production code retries around
    ``except Exception``: ``run_watch`` treats a failed cycle as a network
    blip, waits, and tries again - forever, when the cycle count is zero. A
    guard that such a handler can swallow does not stop the run, it turns a
    stall into a spin. This one is not catchable by anything that is not
    reaching for ``BaseException`` deliberately.
    """


@pytest.fixture(autouse=True)
def _offline_by_default(monkeypatch):
    """Pin the suite to what is already on disk.

    TrustSight already supports this: `release.offline()` reads
    ``TRUSTSIGHT_OFFLINE`` so an air-gapped machine or a CI run can forbid
    outbound requests. The tests are such a run, so they declare it rather
    than mocking every call site that might reach the release channel.

    A test that exercises the online path opts back in with
    ``monkeypatch.delenv("TRUSTSIGHT_OFFLINE")``.
    """
    monkeypatch.setenv("TRUSTSIGHT_OFFLINE", "1")


@pytest.fixture(autouse=True)
def _the_aur_rpc_answers_nothing(monkeypatch):
    """Analysing text walks the dependency closure, which asks the AUR.

    `analyze_text` resolves each dependency name against the AUR RPC to
    decide whether it is an AUR package worth walking into. That is a
    network call, and it fires from tests that are about report shape or
    rule behaviour and have no interest in the closure at all - they simply
    call `analyze_text` and get a live lookup.

    An empty answer is what an offline run sees: no name resolves, the walk
    stops, and the report says so through its coverage gaps. A test that is
    actually about dependency resolution patches this with its own data.
    """
    import trustsight.discovery as discovery

    monkeypatch.setattr(discovery, "get_aur_package_info", lambda names: {})


@pytest.fixture(autouse=True)
def _no_outbound_network(monkeypatch):
    real_connect = _socket.socket.connect

    def guarded(self, address, *args, **kwargs):
        # AF_UNIX addresses are filesystem paths, not hosts, and never
        # leave the machine.
        if getattr(self, "family", None) == getattr(_socket, "AF_UNIX", object()):
            return real_connect(self, address, *args, **kwargs)
        host = address[0] if isinstance(address, tuple) else address
        if isinstance(host, (bytes, bytearray)):
            host = host.decode("utf-8", "replace")
        if isinstance(host, str) and host not in _LOOPBACK:
            raise NetworkAccessDenied(
                f"a test tried to connect to {host!r}; the suite must not "
                "reach the network. A mock is missing or stopped applying "
                "- patch the function that fetches, do not let it run."
            )
        return real_connect(self, address, *args, **kwargs)

    monkeypatch.setattr(_socket.socket, "connect", guarded)
