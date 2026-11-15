"""Small JSON webhook used by canary and anchor alerts.

The caller decides whether an alert URL is configured; failures are logged
and swallowed so a dead receiver never masks the security event.
"""

from __future__ import annotations

import json
import logging
import urllib.request

__all__ = ["send"]

log = logging.getLogger(__name__)


def send(url: str, payload: dict, *, timeout: float = 5.0) -> bool:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read(1)
    except Exception as exc:  # noqa: BLE001 - alerting is best effort
        log.warning("alert webhook failed: %s", type(exc).__name__)
        return False
    return True
