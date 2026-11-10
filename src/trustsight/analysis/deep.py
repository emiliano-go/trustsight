"""Deep analysis mode: escalate expensive passes for a high-score package.

``[deep]`` was reserved.  It now decides whether an inspection escalates:

* deep mode on (config, or an explicit ``--deep``) analyses the full AUR
  dependency closure instead of the default one level; and
* when the static score reaches ``[deep].threshold`` and the optional L9 build
  lane is enabled (``[verify].enabled``), the L9 lane runs and its result is
  reported separately - it never changes the static score.

Nothing here executes package code.  The L9 lane's own container policy
applies; when it is unavailable the caller reports ``l9_unavailable``.
"""

from __future__ import annotations

__all__ = ["deep_decision"]


def _int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def deep_decision(config: dict | None, score, explicit: bool = False) -> dict:
    """The deep-mode decision for one package.

    *explicit* is a user ``--deep`` request.  ``triggered`` means the package
    should be inspected deeply; ``l9_requested`` additionally requires the
    ``[verify]`` lane to be enabled.  A non-numeric score never triggers.
    """
    config = config or {}
    deep = config.get("deep") or {}
    verify = config.get("verify") or {}
    enabled = bool(deep.get("enabled", False))
    threshold = _int(deep.get("threshold", 80), 80)
    verify_enabled = bool(verify.get("enabled", False))
    numeric = isinstance(score, (int, float)) and not isinstance(score, bool)
    triggered = bool(explicit) or (enabled and numeric and score >= threshold)
    return {
        "enabled": enabled,
        "threshold": threshold,
        "verify_enabled": verify_enabled,
        "triggered": triggered,
        "l9_requested": triggered and verify_enabled,
    }
