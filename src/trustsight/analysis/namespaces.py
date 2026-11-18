"""C035: a declared source occupies an operator-owned namespace."""

from __future__ import annotations

import posixpath
from urllib.parse import unquote, urlparse

from ..findings import stamp

__all__ = ["owned_namespace_findings"]


def _split_owned(value: str) -> tuple[str, str] | None:
    raw = str(value or "").strip().lower().rstrip("/")
    if not raw or "://" in raw:
        return None
    host, _, path = raw.partition("/")
    host = host.strip().lower()
    if path.strip("/"):
        path = "/" + posixpath.normpath(
            "/" + path.strip("/")).lstrip("/").lower()
    else:
        path = ""
    if not host or not path:
        return None
    return host, path


def _urls(recipe_text: str) -> list[str]:
    from ..differ import urls_from_pkgbuild_text
    from ..recipedoc import parse_recipe

    urls = list(urls_from_pkgbuild_text(recipe_text or ""))
    try:
        declared = parse_recipe(recipe_text or "").scalars.get("url")
    except Exception:  # noqa: BLE001 - a broken recipe has no scalar
        declared = None
    if isinstance(declared, str) and declared:
        urls.append(declared)
    return sorted(set(urls))


def owned_namespace_findings(
    recipe_text: str, config: dict, *, package_name: str = "",
) -> list[dict]:
    """Report a source in an owned host but outside the owned path prefix."""
    owned = [
        parsed for parsed in (
            _split_owned(item)
            for item in (config.get("namespaces", {}).get("owned") or ())
        )
        if parsed is not None
    ]
    if not owned:
        return []
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for url in _urls(recipe_text):
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
        except ValueError:
            continue
        raw_path = unquote(parsed.path)
        path = ("/" + posixpath.normpath(raw_path).lower().lstrip("/")
                if raw_path.strip("/") else "")
        if path == "/.":
            path = ""
        for owned_host, owned_path in owned:
            if host != owned_host:
                continue
            if path == owned_path or path.startswith(owned_path + "/"):
                continue
            key = (host, path)
            if key in seen:
                continue
            seen.add(key)
            findings.append(stamp({
                "rule_id": "C035",
                "name": "Owned Namespace Occupied",
                "severity": "HIGH",
                "category": "integrity",
                "match": (f"{host}{path} is outside the operator-owned "
                          f"namespace {owned_host}{owned_path}"),
                "file": "PKGBUILD",
                "line": None,
                "params": {"url": url, "owned": f"{owned_host}{owned_path}"},
            }))
            break
    return findings
