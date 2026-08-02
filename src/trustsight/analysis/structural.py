import re

from ..differ import (
    detect_checksum_removed,
    is_skip_justified,
    source_array_has_command_substitution,
)
from .base import (
    _pkgver_changed_in_diff,
    _url_domain,
)
from .build import _build_findings
from .dependencies import _dependency_findings
from ..findings import stamp

_BINARY_ARTIFACT_RE = re.compile(
    r"\.(?:bin|exe|elf|so|dll|dylib|appimage|deb|rpm|apk|msi|jar|run)"
    r"(?:\?|#|$)",
    re.IGNORECASE,
)

_TRUSTED_BUCKETS = frozenset({"trusted_forge", "official"})

_CHECKSUM_SKIP_RE = re.compile(
    r"sha256sums\s*=\s*\(?\s*[\'\"]?(?:SKIP|NONE)"
)

_CHECKSUM_EMPTIED_RE = re.compile(
    r"sha256sums\s*=\s*\(\s*\)"
)

_CHECKSUM_ADDED_RE = re.compile(
    r"sha256sums\s*=\s*\('[a-fA-F0-9]"
)

_CHECKSUM_REMOVED_LINE_RE = re.compile(
    r"sha256sums"
)


def _find_line_in_diff(diff_text: str, pattern: str, prefix: str = r"\+") -> int | None:
    """Return the 1-based line number of the first ``+``/``-`` line matching *pattern*."""
    full = re.compile(r"^" + prefix + r".*" + pattern, re.IGNORECASE)
    for i, line in enumerate(diff_text.splitlines()):
        if full.search(line):
            return i + 1
    return None


def _structural_findings(
    diff_text: str,
    source_changes,
    source_buckets: dict[str, str] | None = None,
    maintainer_changed: bool = False,
    package_name: str = "",
    config: dict | None = None,
) -> list[dict]:
    source_buckets = source_buckets or {}
    findings: list[dict] = []

    def add(rule_id: str, name: str, severity: str, category: str, match: str, file: str = "PKGBUILD", line: int | None = None, **extra) -> None:
        finding = {
            "rule_id": rule_id, "name": name, "severity": severity,
            "category": category, "match": match,
            "file": file, "line": line,
        }
        if extra:
            finding["params"] = extra
        findings.append(stamp(finding))

    cs_behavior = source_changes.checksum_behavior
    added = source_changes.added_urls
    removed = source_changes.removed_urls
    pkgver_changed = _pkgver_changed_in_diff(diff_text)

    if cs_behavior != "checksum_added_or_changed":
        http_sources = [url for url in added if url.startswith("http://")]
        if http_sources:
            add("R006", "Insecure Download Protocol", "LOW", "integrity",
                f"http:// sources without checksum backing: {http_sources}",
                line=_find_line_in_diff(diff_text, r"http://"),
                http_sources=", ".join(http_sources))

    if cs_behavior == "changed_from_sha256_to_skip":
        skip_reason = is_skip_justified(diff_text)
        suffix = f" ({skip_reason})" if skip_reason else ""
        add("R004", "Checksum Disabled", "INFO" if skip_reason else "HIGH", "integrity",
            f"sha256sums=SKIP ({skip_reason})" if skip_reason else "sha256sums=SKIP",
            line=_find_line_in_diff(diff_text, r"SKIP|NONE"),
            skip_suffix=suffix)
    elif cs_behavior == "checksum_array_emptied":
        add("R005", "Checksum Emptied", "HIGH", "integrity", cs_behavior,
            line=_find_line_in_diff(diff_text, r"sha256sums\s*=\s*\(\s*\)"))

    if cs_behavior == "checksum_added_or_changed" and not added and not removed:
        if not pkgver_changed:
            add("C001", "Checksum Changed Without Source Change With Stable Version",
                "HIGH", "integrity",
                "sha256sums changed but source URLs and pkgver unchanged",
                line=_find_line_in_diff(diff_text, r"""sha256sums\s*=\s*\('"""))
        else:
            add("C002", "Checksum Updated With Version Bump", "INFO", "integrity",
                "sha256sums updated alongside pkgver",
                line=_find_line_in_diff(diff_text, r"""sha256sums\s*=\s*\('"""))

    if removed and added and not pkgver_changed and set(removed) != set(added):
        add("C003", "Source URL Changed Without Version Bump", "INFO", "integrity",
            f"URLs changed: {removed} -> {added}",
            line=_find_line_in_diff(diff_text, r"source(?:_[a-z0-9_]+)?\s*=\s*\("),
            added=str(added), removed=str(removed))

    if detect_checksum_removed(diff_text) and set(removed) == set(added):
        add("C004", "Checksum Removed For Unchanged Source", "CRITICAL", "integrity",
            "checksum array deleted while source URLs stayed the same",
            line=_find_line_in_diff(diff_text, r"sha256sums", prefix=r"\-"))

    for url in added:
        if _BINARY_ARTIFACT_RE.search(url) and source_buckets.get(url) not in _TRUSTED_BUCKETS:
            bucket = source_buckets.get(url, "unknown")
            escaped = re.escape(url)
            add("C005", "Binary Artifact From Untrusted Source", "MEDIUM", "source",
                f"binary artifact from {bucket} bucket: {url}",
                line=_find_line_in_diff(diff_text, escaped[:80]),
                url=url, bucket=bucket)
            break

    if maintainer_changed and added:
        old_domains = {_url_domain(u) for u in removed}
        new_domains = {_url_domain(u) for u in added} - old_domains
        if new_domains:
            add("C006", "Maintainer Change With New Source Domain", "HIGH", "source",
                f"maintainer changed and new domain(s) appeared: {sorted(new_domains)}",
                line=_find_line_in_diff(diff_text, r"#\s*Maintainer"),
                new_domains=", ".join(sorted(new_domains)))

    if source_array_has_command_substitution(diff_text):
        add("C007", "Command Substitution In Source Array", "CRITICAL", "execution",
            "source=() contains $( ) or backtick substitution",
            line=_find_line_in_diff(diff_text, r"\$\(|`"))

    _dependency_findings(diff_text, package_name, config or {}, add)
    _build_findings(diff_text, config or {}, add)

    return findings
