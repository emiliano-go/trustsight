"""Render the GitHub false-positive issue body from a local report."""

import json
from urllib.parse import urlencode

from .release import GITHUB_WEB

__all__ = ["ISSUE_TEMPLATE_URL", "issue_body", "issue_url"]

ISSUE_TEMPLATE_URL = (
    f"{GITHUB_WEB}/emiliano-go/trustsight/issues/new"
    "?template=false_positive.yml"
)

_KINDS = (
    "Bad rule trigger (malicious false positive)",
    "Correct finding, wrong weight or severity (overweighted)",
    "Real finding about a packager practice (benign false positive)",
    "Not sure",
)


def issue_body(
    *,
    package: str,
    report: dict,
    version: str,
    alert_url: str = "",
    command: str = "",
    kind: str = _KINDS[0],
) -> str:
    """Return a Markdown body matching ``false_positive.yml``.

    Every heading is the form's field label, so the text can be pasted into
    the form or filed as a plain issue.  The report is the same JSON
    ``inspect --json`` writes, because a maintainer needs the exact finding
    text and not a paraphrase.
    """
    rule_ids: list[str] = []
    for finding in report.get("findings", ()) or ():
        rule_id = finding.get("rule_id")
        if rule_id and rule_id not in rule_ids:
            rule_ids.append(str(rule_id))

    fields = (
        ("What kind of report is this?", kind),
        ("TrustSight version", f"trustsight {version}".strip()),
        ("AUR package", package),
        ("Feed alert URL", alert_url or "_No response_"),
        ("Rule id", ", ".join(rule_ids) or "_No response_"),
        ("What TrustSight reported", "```json\n"
         + json.dumps(report, indent=2, sort_keys=True) + "\n```"),
        ("Why this is a bad rule trigger",
         "<!-- What did the rule misread? Why is there no bad practice or "
         "malicious behavior behind it? -->"),
        ("PKGBUILD or diff",
         "<!-- Paste the PKGBUILD or the diff here. -->"),
        ("Command or mode", command or f"trustsight inspect {package} --fp-template"),
        ("Config fingerprint", report.get("config_fingerprint") or "_No response_"),
    )
    return "\n".join(f"### {label}\n\n{value}\n" for label, value in fields)


def issue_url(package: str, rule_ids: list[str] | tuple[str, ...] = ()) -> str:
    """Return the new-issue URL with the package and rule ids in the title."""
    title = f"[False positive]: {package}"
    if rule_ids:
        title += " " + " ".join(str(rule_id) for rule_id in rule_ids)
    return f"{ISSUE_TEMPLATE_URL}&{urlencode({'title': title})}"
