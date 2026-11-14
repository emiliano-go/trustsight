"""Collect upstream manifests for the opt-in scan lane.

The AUR snapshot only carries files committed beside the recipe, so the U-series
is blind to the manifests inside the declared source archive.  This module
closes that gap for the server-side watcher:

* it reads the recipe's ``source=()`` and the strongest checksum per entry;
* for an allowlisted forge entry with a strong checksum it fetches the archive
  through the bounded transport, verifies the checksum, and extracts the
  manifests in the sandboxed manifest worker;
* it returns ``(f"upstream/{path}", text)`` pairs the caller merges into
  ``manifest_texts``, so the existing U-series state/delta path does the rest.

It is off unless ``[upstream_scan] enabled`` and never runs on the local
default analysis path.  A refusal is returned as a note, not hidden.
"""

from __future__ import annotations

import ipaddress
import os
import re
import time

from .upstream_scan import (
    UpstreamScanError,
    choose_fetch_mode,
    checksum_bits,
    configured_hosts,
    verify_archive_checksum,
)
from .analysis.upstream_release import is_ci_workflow_path
from .findings import stamp
from .upstream_fetch import UpstreamFetchError, fetch_bytes

__all__ = ["collect_upstream_manifest_texts"]

_MAX_ARCHIVES = 4
_MAX_SOURCE_ENTRIES = 64
#: A cap on the manifest text one package may add to its state, so a hostile
#: archive cannot turn into a multi-megabyte state document.
_MAX_TEXT_BYTES = 2 * 1024 * 1024
#: Hard ceilings: config can lower these, never raise them.
_HARD_DEADLINE_SECONDS = 300.0
_HARD_MIN_CHECKSUM_BITS = 256
#: The sandboxed worker accepts at most this many base64 bytes in one frame.
_MAX_ARCHIVE_BYTES = 16 * 1024 * 1024

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

#: Strongest first.
_CHECKSUM_ARRAYS = (
    ("b2sums", "b2"),
    ("sha512sums", "sha512"),
    ("sha256sums", "sha256"),
    ("sha1sums", "sha1"),
    ("md5sums", "md5"),
)

_PROVIDER_BY_HOST = {
    "github.com": "github",
    "gitlab.com": "gitlab",
    "codeberg.org": "codeberg",
    "bitbucket.org": "bitbucket",
}

#: Local CI shapes, reported only (U013/U014 are anergic).  A workflow that
#: references a repository secret and sends it to an unknown host, or that
#: materialises full history and greps it for credentials, is the shape the
#: federation channel reports; these are the local equivalents.
_SECRET_REF_RE = re.compile(r"\$\{\{\s*secrets\.", re.IGNORECASE)
_OUTBOUND_RE = re.compile(
    r"(?:curl|wget|Invoke-WebRequest|iwr)\b[^\n]{0,200}?"
    r"https?://([^\s/'\"?#]+)", re.IGNORECASE)
_DEPTH_ZERO_RE = re.compile(r"fetch-depth:\s*['\"]?0", re.IGNORECASE)
_GREP_SECRET_RE = re.compile(
    r"\bgrep\b[^\n]{0,160}(?:token|secret|password|passwd|"
    r"api[_-]?key|credential)", re.IGNORECASE)
_KNOWN_EGRESS = frozenset({
    "github.com", "api.github.com", "codeload.github.com",
    "objects.githubusercontent.com", "raw.githubusercontent.com",
    "uploads.github.com", "pypi.org", "files.pythonhosted.org",
    "registry.npmjs.org", "crates.io", "static.crates.io",
    "deb.debian.org", "archive.ubuntu.com",
})


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _workflow_findings(path: str, text: str) -> list[dict]:
    """U013/U014 over one fetched upstream workflow's text (weight 0)."""
    out: list[dict] = []
    if _SECRET_REF_RE.search(text):
        for match in _OUTBOUND_RE.finditer(text):
            host = match.group(1).strip().lower().rstrip(".")
            if _is_ip_literal(host) or host not in _KNOWN_EGRESS:
                out.append(stamp({
                    "rule_id": "U013",
                    "name": "CI Exfil Shape (Local)",
                    "severity": "MEDIUM",
                    "category": "upstream-ci",
                    "match": (f"{path} pairs a repository secret with an "
                              f"outbound transfer to {host}"),
                    "file": path,
                    "line": None,
                    "params": {"host": host},
                    "weight_override": 0,
                }))
                break
    if _DEPTH_ZERO_RE.search(text) and _GREP_SECRET_RE.search(text):
        out.append(stamp({
            "rule_id": "U014",
            "name": "Git-History Credential Sweep (Local)",
            "severity": "MEDIUM",
            "category": "upstream-ci",
            "match": f"{path} checks out full history and greps it for credentials",
            "file": path,
            "line": None,
            "weight_override": 0,
        }))
    return out


def _checksum_for(recipe, index: int):
    for name, algorithm in _CHECKSUM_ARRAYS:
        values = recipe.arrays.get(name) or ()
        if index >= len(values):
            continue
        value = str(values[index]).strip().lower()
        if value and value not in ("skip", "none") and _HEX_RE.match(value):
            return name, algorithm, value
    return None


def _token_for(host: str):
    provider = _PROVIDER_BY_HOST.get(host)
    if not provider:
        return None
    try:
        from .credentials import CredentialError, resolve_token

        return resolve_token(provider)
    except CredentialError:
        return None


def collect_upstream_manifest_texts(
    recipe_text: str,
    *,
    config: dict | None = None,
    fetcher=None,
    extractor=None,
) -> tuple[list[tuple[str, str]], list[str], list[dict]]:
    """Return upstream manifest texts, refusal notes and local CI findings.

    *fetcher* and *extractor* are injectable for tests; the defaults are the
    real bounded transport and the sandboxed archive worker.
    """
    if not recipe_text:
        return [], [], []
    if config is None:
        from .config import load_config

        config = load_config()
    section = (config or {}).get("upstream_scan") if isinstance(config, dict) else None
    if not isinstance(section, dict) or not section.get("enabled", False):
        return [], [], []
    # The operator's offline switch is absolute: the lane never opens a
    # connection when TRUSTSIGHT_OFFLINE is set, whatever the config says.
    if os.environ.get("TRUSTSIGHT_OFFLINE", "").strip().lower() in (
            "1", "true", "yes"):
        return [], ["upstream_scan_offline"], []

    from .expansion import resolve_text
    from .recipedoc import parse_recipe
    from .sandbox import manifest_client

    try:
        recipe = parse_recipe(recipe_text)
    except Exception:  # noqa: BLE001 - an unparsable recipe yields no upstream reads
        return [], ["upstream_scan_recipe_unparsed"], []

    allowed = configured_hosts(config)
    texts: list[tuple[str, str]] = []
    notes: list[str] = []
    findings: list[dict] = []
    seen = 0
    text_bytes = 0

    def _bounded(value, default: float, ceiling: float) -> float:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return default
        if number <= 0:
            return default
        return min(number, ceiling)

    try:
        minimum = max(
            _HARD_MIN_CHECKSUM_BITS, int(section.get("min_checksum_bits", 256)))
    except (TypeError, ValueError):
        minimum = _HARD_MIN_CHECKSUM_BITS
    deadline_at = time.monotonic() + _bounded(
        section.get("deadline_seconds", 120), 120.0, _HARD_DEADLINE_SECONDS)

    for index, entry in enumerate(recipe.arrays.get("source") or ()):
        if index >= _MAX_SOURCE_ENTRIES:
            break
        if seen >= _MAX_ARCHIVES or time.monotonic() >= deadline_at:
            break
        raw = str(entry)
        url = _resolve(raw, recipe, resolve_text)
        if not url.lower().startswith("https://"):
            continue
        if url.lower().endswith((".sig", ".asc", ".sign")):
            continue
        checksum = _checksum_for(recipe, index)
        if checksum is None:
            continue
        name, algorithm, expected = checksum
        try:
            from .upstream_scan import parse_forge_target

            target = parse_forge_target(url, allowed_hosts=allowed)
        except UpstreamScanError:
            continue
        mode = choose_fetch_mode(
            config,
            declared_checksum_bits=checksum_bits(name),
            archive_on_allowlisted_host=True,
        )
        if mode.mode != "archive":
            continue
        remaining = deadline_at - time.monotonic()
        if remaining <= 0:
            notes.append("upstream_scan_deadline")
            break
        try:
            if fetcher is None:
                data = fetch_bytes(
                    url, allowed_hosts=allowed, token=_token_for(target.host),
                    max_bytes=_MAX_ARCHIVE_BYTES, deadline_seconds=remaining)
            else:
                data = fetcher(url, target)
        except (UpstreamFetchError, UpstreamScanError):
            notes.append("upstream_scan_refused")
            continue
        if not verify_archive_checksum(
                data, expected, algorithm=algorithm, min_bits=minimum):
            notes.append("upstream_scan_checksum")
            continue
        try:
            if extractor is None:
                parsed = manifest_client.parse_upstream_archive(
                    target.slug, data)
            else:
                parsed = extractor(target.slug, data)
        except Exception:  # noqa: BLE001 - a sandbox refusal is a boundary
            notes.append("upstream_scan_refused")
            continue
        if parsed.get("refused") or parsed.get("malformed"):
            notes.append("upstream_scan_partial")
        for path, text in parsed.get("manifest_texts") or ():
            if is_ci_workflow_path(path):
                findings.extend(_workflow_findings(f"upstream/{path}", text))
            size = len(text.encode("utf-8", "replace"))
            if text_bytes + size > _MAX_TEXT_BYTES:
                notes.append("upstream_scan_partial")
                return texts, sorted(set(notes)), _dedupe(findings)
            texts.append((f"upstream/{path}", text))
            text_bytes += size
        seen += 1
    return texts, sorted(set(notes)), _dedupe(findings)


def _dedupe(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for finding in findings:
        key = (str(finding.get("rule_id", "")), str(finding.get("file", "")))
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def _resolve(raw: str, recipe, resolve_text) -> str:
    target = raw.split("::", 1)[-1]
    if "$" not in target:
        return target
    try:
        return resolve_text(target, recipe.scalars)
    except Exception:  # noqa: BLE001 - an unresolved entry stays literal
        return target
