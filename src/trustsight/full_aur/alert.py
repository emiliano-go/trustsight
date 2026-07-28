"""Alert dispatch via script hook."""

import json
import logging
import subprocess
from typing import Optional

log = logging.getLogger(__name__)


def dispatch_alert(
    hook_command: str,
    package_name: str,
    score: int,
    risk: str,
    verdict: str,
    triggered_rules: list[dict],
) -> None:
    """Fire an alert by invoking the user's hook script.

    The hook receives a JSON payload on stdin:
        {
            "event": "alert",
            "package": "...",
            "score": 35,
            "risk": "Medium",
            "verdict": "...",
            "rules": [{"rule_id": "R004", "severity": "HIGH"}, ...],
            "timestamp": "2026-07-27T..."
        }
    """
    payload = {
        "event": "alert",
        "package": package_name,
        "score": score,
        "risk": risk,
        "verdict": verdict,
        "rules": [
            {"rule_id": r.get("rule_id", ""), "severity": r.get("severity", "")}
            for r in triggered_rules
        ],
        "timestamp": __import__("datetime").datetime.now().isoformat(),
    }
    try:
        proc = subprocess.run(
            hook_command,
            shell=True,
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            timeout=30,
        )
        if proc.returncode != 0:
            log.warning("alert hook exited %d: %s", proc.returncode, proc.stderr.strip())
    except subprocess.TimeoutExpired:
        log.warning("alert hook timed out after 30s")
    except Exception as e:
        log.warning("alert hook failed: %s", e)
