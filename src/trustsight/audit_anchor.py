"""Compare the signer's published audit head with an off-host anchor."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

__all__ = ["AnchorError", "check", "watch"]

log = logging.getLogger(__name__)


class AnchorError(RuntimeError):
    pass


def check(head: str, *, expected: str | None = None,
          expected_file: str | None = None) -> str:
    try:
        published = json.loads(Path(head).read_text(encoding="utf-8"))
        actual = published["chain_sha256"]
        if expected_file:
            expected = Path(expected_file).read_text(
                encoding="utf-8").strip()
    except Exception as exc:  # noqa: BLE001 - one-line refusal
        raise AnchorError(type(exc).__name__) from exc
    if not isinstance(actual, str) or len(actual) != 64:
        raise AnchorError("head has no valid chain")
    if expected is not None and actual != expected.strip():
        raise AnchorError("head does not match the anchor")
    return actual


def watch(head: str, *, expected: str | None = None,
          expected_file: str | None = None,
          interval_seconds: float = 300.0,
          notify_url: str | None = None) -> None:
    """Poll forever; any mismatch exits non-zero."""
    while True:
        try:
            chain = check(head, expected=expected,
                          expected_file=expected_file)
        except AnchorError:
            if notify_url:
                from .alerts import send

                send(notify_url, {
                    "event": "trustsight.anchor",
                    "head": head,
                    "ts": int(time.time()),
                })
            log.critical("audit head does not match the anchor")
            raise
        print(chain, flush=True)
        time.sleep(interval_seconds)
