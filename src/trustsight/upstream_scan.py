"""Validation for the optional upstream-scan lane (no transport here).

This module is the safety core the scan lane is built on: it decides whether a
declared upstream may be reached at all, pins the address it resolves to, and
verifies an archive checksum before any parser sees the bytes.  It imports no
transport, so it can be tested and reasoned about without a network, and the
network-confinement gate keeps it that way until the fetch module is wired.

Policy, in one place:

* only an **exact registrable-domain** allowlist (the four forges, plus
  operator additions) is reachable;
* HTTPS only, no userinfo, no non-default port, no ``..`` path segment;
* the resolved address must be routable - a private, loopback, link-local,
  reserved or unspecified answer is refused, which is the DNS-rebinding guard
  the connection then pins to;
* an archive is parsed only after its declared checksum verifies, and a
  checksum below the configured strength is not an anchor.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from dataclasses import dataclass

__all__ = [
    "DEFAULT_ALLOWED_HOSTS",
    "ArchiveBounds",
    "FetchMode",
    "ForgeTarget",
    "UpstreamScanError",
    "choose_fetch_mode",
    "checksum_bits",
    "configured_hosts",
    "is_routable_address",
    "parse_forge_target",
    "pin_target",
    "verify_archive_checksum",
    "ArchiveFetchResult",
    "check_archive_bounds",
    "fetch_archive",
]

#: The forges the lane may reach by default.  An entry is an exact
#: registrable domain, never a suffix or wildcard.
DEFAULT_ALLOWED_HOSTS = (
    "github.com",
    "gitlab.com",
    "codeberg.org",
    "bitbucket.org",
)

_DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

#: Operator allowlist additions are bounded: an allowlist is not a config file
#: to grow without limit, and each entry is still validated.
_MAX_EXTRA_HOSTS = 16


class UpstreamScanError(RuntimeError):
    """The declared upstream cannot be reached under the lane's policy."""


@dataclass(frozen=True)
class ForgeTarget:
    """A validated ``host/owner/repo`` on an allowlisted forge."""

    host: str
    owner: str
    repo: str

    @property
    def slug(self) -> str:
        return f"{self.host}/{self.owner}/{self.repo}"


def _clean_host(value: object) -> str:
    if not isinstance(value, str):
        return ""
    host = value.strip().lower().rstrip(".")
    if not host or "/" in host or ":" in host or "@" in host:
        return ""
    # An operator override is still a host, not a single label or a literal.
    # "localhost", "metadata" and IP literals are not allowlist entries; a
    # dotted name is required and then still has to pass the address policy.
    if "." not in host or ".." in host:
        return ""
    try:
        ipaddress.ip_address(host)
        return ""
    except ValueError:
        pass
    return host if _DOMAIN_RE.match(host) else ""


def configured_hosts(config: dict | None = None) -> frozenset[str]:
    """The allowlist: defaults plus ``allowed_hosts``/``allowed_hosts_extra``.

    A malformed operator entry is ignored rather than allowed, so a typo cannot
    widen the reach.
    """
    hosts = set(DEFAULT_ALLOWED_HOSTS)
    section = (config or {}).get("upstream_scan") if isinstance(config, dict) else None
    if not isinstance(section, dict):
        return frozenset(hosts)
    added = 0
    for key in ("allowed_hosts", "allowed_hosts_extra"):
        values = section.get(key)
        if not isinstance(values, (list, tuple)):
            continue
        for value in values:
            if added >= _MAX_EXTRA_HOSTS:
                break
            host = _clean_host(value)
            if host:
                hosts.add(host)
                added += 1
    return frozenset(hosts)


def parse_forge_target(url: str, *, allowed_hosts=None) -> ForgeTarget:
    """Parse a declared upstream URL into a validated forge target.

    Raises :class:`UpstreamScanError` for a non-HTTPS scheme, userinfo, a
    non-default port, an off-allowlist host, or a path that is not
    ``owner/repo``.
    """
    from urllib.parse import urlsplit

    allowed = frozenset(DEFAULT_ALLOWED_HOSTS if allowed_hosts is None
                        else allowed_hosts)
    if not isinstance(url, str) or not url.strip():
        raise UpstreamScanError("empty upstream URL")
    value = url.strip()
    # A backslash or a control byte is never part of a URL this lane fetches;
    # some parsers normalize them differently, so refuse rather than guess.
    if "\\" in value or any(ch in value for ch in ("\x00", "\n", "\r", "\t")):
        raise UpstreamScanError("upstream URL carries a control character")
    parts = urlsplit(value)
    if parts.scheme.lower() != "https":
        raise UpstreamScanError("upstream URL is not https")
    if parts.username or parts.password:
        raise UpstreamScanError("upstream URL carries userinfo")
    try:
        port = parts.port
    except ValueError as exc:
        raise UpstreamScanError("upstream URL has an invalid port") from exc
    if port not in (None, 443):
        raise UpstreamScanError("upstream URL uses a non-default port")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host or host not in allowed:
        raise UpstreamScanError(f"upstream host is not allowlisted: {host or '?'}")
    segments = [segment for segment in parts.path.split("/") if segment]
    if len(segments) < 2:
        raise UpstreamScanError("upstream URL has no owner/repo path")
    owner, repo = segments[0], segments[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not _SEGMENT_RE.match(owner) or not _SEGMENT_RE.match(repo):
        raise UpstreamScanError("upstream owner/repo contains unsupported characters")
    if owner in (".", "..") or repo in (".", ".."):
        raise UpstreamScanError("upstream owner/repo is not a name")
    return ForgeTarget(host=host, owner=owner, repo=repo)


def is_routable_address(value: str) -> bool:
    """False for a private, loopback, link-local, reserved or unspecified IP."""
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    # ``is_global`` rejects loopback, RFC 1918, link-local, CGNAT
    # (100.64.0.0/10), documentation, benchmarking, reserved, unspecified and
    # metadata ranges in one maintained predicate.
    return address.is_global


def pin_target(target: ForgeTarget, resolver):
    """Resolve *target* and return the routable addresses to connect to.

    *resolver* has ``socket.getaddrinfo``'s shape and is injected so this
    module imports no transport.  Every answer must be routable: a split answer
    carrying one private address is refused rather than raced.
    """
    try:
        infos = resolver(target.host, 443)
    except OSError as exc:
        raise UpstreamScanError(
            f"could not resolve {target.host}: {type(exc).__name__}"
        ) from exc
    addresses = []
    for info in infos or ():
        try:
            address = info[4][0]
        except (TypeError, IndexError):
            continue
        if not is_routable_address(address):
            raise UpstreamScanError(
                f"{target.host} resolves to a non-routable address: {address}"
            )
        addresses.append(str(address))
    if not addresses:
        raise UpstreamScanError(f"{target.host} resolved to no address")
    return tuple(sorted(set(addresses)))


#: Digest name -> strength in bits.
_CHECKSUM_BITS = {
    "md5": 128, "sha1": 160, "sha224": 224, "sha256": 256,
    "sha384": 384, "sha512": 512, "b2": 256,
}
_CHECKSUM_ALGORITHM = {
    "md5": "md5", "sha1": "sha1", "sha224": "sha224", "sha256": "sha256",
    "sha384": "sha384", "sha512": "sha512", "b2": "blake2b",
}


def checksum_bits(name: str) -> int:
    """Strength in bits of a checksum array name (``sha256sums`` -> 256)."""
    base = str(name or "").strip().lower()
    if "sums" in base:
        base = base.split("sums", 1)[0]
    elif base.endswith("sum"):
        base = base[:-3]
    return _CHECKSUM_BITS.get(base, 0)


@dataclass(frozen=True)
class FetchMode:
    """The chosen acquisition mode and why."""

    mode: str  # "clone" or "archive"
    reason: str


def choose_fetch_mode(config: dict | None, *, declared_checksum_bits: int,
                      archive_on_allowlisted_host: bool) -> FetchMode:
    """Pick forge-clone (safer) or a checksum-gated archive read.

    The clone is always preferred: it reaches only an allowlisted forge.  An
    archive is chosen only when the operator enabled ``archive_fetch``, the
    archive host is allowlisted, and a checksum at or above
    ``min_checksum_bits`` pins the bytes.
    """
    section = (config or {}).get("upstream_scan") if isinstance(config, dict) else None
    section = section if isinstance(section, dict) else {}
    if not section.get("archive_fetch", False):
        return FetchMode("clone", "archive fetch is disabled")
    minimum = int(section.get("min_checksum_bits", 256) or 256)
    if declared_checksum_bits < minimum:
        return FetchMode("clone", "no checksum at the configured strength")
    if not archive_on_allowlisted_host:
        return FetchMode("clone", "archive host is not allowlisted")
    return FetchMode("archive", "checksum and allowlist both hold")


@dataclass(frozen=True)
class ArchiveBounds:
    """The ceilings a consumed archive is held to."""

    max_members: int = 10_000
    max_uncompressed_bytes: int = 268_435_456
    max_bytes: int = 67_108_864


def verify_archive_checksum(
    data: bytes,
    expected_hex: str,
    *,
    algorithm: str = "sha256",
    min_bits: int = 256,
) -> bool:
    """True when *data* matches *expected_hex* at or above *min_bits*.

    A weak or malformed expected value is ``False``: it is not an anchor, so
    the caller must not parse the bytes.  The comparison is constant-time.
    """
    expected = str(expected_hex or "").strip().lower()
    if not expected or not _HEX_RE.match(expected):
        return False
    digest_name = _CHECKSUM_ALGORITHM.get(str(algorithm).lower())
    if digest_name is None:
        return False
    if len(expected) * 4 < min_bits:
        return False
    actual = hashlib.new(digest_name, data).hexdigest()
    return hmac.compare_digest(actual, expected)


def check_archive_bounds(
    member_count: int,
    uncompressed_bytes: int,
    bounds: ArchiveBounds,
) -> None:
    """Refuse an archive whose declared shape exceeds *bounds*."""
    if member_count > bounds.max_members:
        raise UpstreamScanError(
            f"archive declares {member_count} members, over {bounds.max_members}")
    if uncompressed_bytes > bounds.max_uncompressed_bytes:
        raise UpstreamScanError(
            f"archive declares {uncompressed_bytes} bytes, over "
            f"{bounds.max_uncompressed_bytes}")


@dataclass(frozen=True)
class ArchiveFetchResult:
    """Bytes that verified against the declared checksum."""

    data: bytes
    target: ForgeTarget


def fetch_archive(
    url: str,
    *,
    expected_hex: str,
    algorithm: str,
    transport,
    allowed_hosts=None,
    min_bits: int = 256,
    max_bytes: int = 67_108_864,
    deadline_seconds: float = 120.0,
):
    """Fetch an archive and return it only after the checksum verifies.

    *transport* is an injected, allowlisted fetch callable
    ``transport(target, max_bytes, deadline_seconds) -> bytes``.  Keeping it
    injected means this module stays free of a raw transport until the reviewed
    egress module is wired; the policy here - target validation, the byte cap,
    and checksum-before-parse - is the half that must never be duplicated or
    skipped.  A mismatch, a weak checksum or an over-cap body is a refusal, so
    no parser ever sees unverified bytes.
    """
    target = parse_forge_target(url, allowed_hosts=allowed_hosts)
    if max_bytes <= 0 or deadline_seconds <= 0:
        raise UpstreamScanError("archive bounds must be positive")
    data = transport(target, max_bytes, deadline_seconds)
    if not isinstance(data, (bytes, bytearray)):
        raise UpstreamScanError("archive transport returned a non-bytes body")
    if len(data) > max_bytes:
        raise UpstreamScanError(
            f"archive is {len(data)} bytes, over the {max_bytes} cap")
    if not verify_archive_checksum(
        bytes(data), expected_hex, algorithm=algorithm, min_bits=min_bits
    ):
        raise UpstreamScanError(
            "archive does not match the declared checksum at the required "
            "strength; refusing to parse it")
    return ArchiveFetchResult(data=bytes(data), target=target)
