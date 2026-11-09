"""A history-exercising corpus.

The locked benign corpus is stateless diffs, so the observation-history
rules (H020/H021/H022, H026/H044, H045/H073, H052/H053/H055/H059/H073/H074,
T008--T012, plus the graph rules) never fire there and their overlap cannot
be measured.
These cycles are the metadata snapshots that exercise them:
``tests/harness/history_replay.py`` runs ``run_corpus_sweep`` over each cycle
and the H-reduction audit joins the result, so the co-fire matrix has
a committed measurement.

Each cycle is ``{name, old, new, prior_history?, maintainer_history?,
source_repos?, edges?, detail?, maintainer_transitions?, prior_rule_history?,
package_cycle_events?, now?, expected}``.  ``expected`` is the rule-id set the
cycle must fire; a replay that drifts fails the parity test in the suite.
"""

from __future__ import annotations


def _pkg(name: str, maintainer: str, version: str = "1.0",
         last_modified: int = 100) -> dict:
    return {
        "Name": name, "PackageBase": name, "Maintainer": maintainer,
        "Version": version, "LastModified": last_modified,
    }


def _bulk(prefix: str, count: int, maintainer: str, version: str = "1.0",
          last_modified: int = 1000) -> dict:
    return {
        f"{prefix}-{i:02d}": _pkg(f"{prefix}-{i:02d}", maintainer, version,
                                  last_modified)
        for i in range(1, count + 1)
    }


#: A prior adoption feed of quiet cycles, the baseline H073/H058 need.
_QUIET_HISTORY = [{"introduced": 0}] * 3

CYCLES: list[dict] = [
    {
        # A handover between two known maintainers: H044 alone, no H026.
        "name": "trusted-handover",
        "old": {"pkg-a": _pkg("pkg-a", "alice"),
                "pkg-b": _pkg("pkg-b", "bob")},
        "new": {"pkg-a": _pkg("pkg-a", "bob"),
                "pkg-b": _pkg("pkg-b", "bob")},
        "expected": ["H044"],
    },
    {
        # A takeover by an account with no other packages: H044 + H026, the
        # audited pair.
        "name": "untrusted-adoption",
        "old": {"pkg-a": _pkg("pkg-a", "alice")},
        "new": {"pkg-a": _pkg("pkg-a", "mallory")},
        "expected": ["H026", "H044"],
    },
    {
        # Ten packages filed by one account in the window, over a quiet
        # baseline: H045 + H073, the audited pair.
        "name": "mass-adoption",
        "old": {"seed": _pkg("seed", "old")},
        "new": {"seed": _pkg("seed", "old"), **_bulk("mal", 10, "mallory")},
        "prior_history": _QUIET_HISTORY,
        "expected": ["H045", "H073"],
    },
    {
        # Three introductions spread across three accounts: H073 fires, H045
        # (one account, ten packages) does not.
        "name": "introduction-deviation",
        "old": {"seed": _pkg("seed", "old")},
        "new": {"seed": _pkg("seed", "old"), **_bulk("dev", 3, "m")},
        "prior_history": _QUIET_HISTORY,
        "expected": ["H073"],
    },
    {
        # Five modified packages by one maintainer within the hour: H055.
        "name": "attribute-burst",
        "old": {f"b-{i}": _pkg(f"b-{i}", "burst") for i in range(5)},
        "new": {f"b-{i}": _pkg(f"b-{i}", "burst", version="2",
                               last_modified=200 + i) for i in range(5)},
        "expected": ["H055"],
    },
    {
        # Three unrelated packages sourcing from one repo: H052.
        "name": "shared-repo",
        "old": {},
        "new": _bulk("sr", 3, "m"),
        "source_repos": {f"sr-{i:02d}": {"https://git.example/shared/repo"}
                         for i in range(1, 4)},
        "expected": ["H052"],
    },
    {
        # An ecosystem name hosted off its canonical host and forge, sharing
        # no token with its repo: H053 + H059, the audited pair.
        "name": "naming-divergence",
        "old": {},
        "new": {"python-obscure-widget":
                _pkg("python-obscure-widget", "m")},
        "source_repos": {"python-obscure-widget":
                         {"https://oddhost.example/zzz/qqq"}},
        "expected": ["H053", "H059"],
    },
    {
        # A takeover plus a version move in one cycle: H074 (and the H044/
        # H026 pair the takeover carries).
        "name": "adopt-then-modify",
        "old": {"pkg-a": _pkg("pkg-a", "alice")},
        "new": {"pkg-a": _pkg("pkg-a", "mallory", version="2",
                              last_modified=200)},
        "expected": ["H026", "H044", "H074"],
    },
    {
        "name": "delayed-post-adoption-payload",
        "old": {"pkg-a": _pkg("pkg-a", "mallory")},
        "new": {"pkg-a": _pkg("pkg-a", "mallory")},
        "now": 1_800_000_000,
        "detail": {"pkg-a": {"rules": ["R001"]}},
        "maintainer_transitions": {"pkg-a": [{
            "observed_at": 1_800_000_000 - 30 * 86400,
            "new_value": "mallory", "property_key": "maintainer",
        }]},
        "expected": ["T008"],
    },
    {
        "name": "high-value-dormant-takeover",
        "old": {"pkg-a": _pkg(
            "pkg-a", "alice", last_modified=1_800_000_000 - 300 * 86400)},
        "new": {"pkg-a": _pkg("pkg-a", "mallory") | {"NumVotes": 150}},
        "now": 1_800_000_000,
        "expected": ["H026", "H044", "T009"],
    },
    {
        "name": "dependency-redirection-to-adopted-node",
        "old": {"consumer": _pkg("consumer", "alice"),
                "target": _pkg("target", "")},
        "new": {"consumer": _pkg("consumer", "alice", version="2"),
                "target": _pkg("target", "mallory")},
        "detail": {"consumer": {
            "dependency_changes": {"depends": ["target"]},
        }},
        "expected": ["H026", "H044", "T010"],
    },
    {
        "name": "recorded-removal-then-reappearance",
        "old": {"seed": _pkg("seed", "alice")},
        "new": {"seed": _pkg("seed", "alice"),
                "returned": _pkg("returned", "mallory")},
        "package_cycle_events": {"returned": [{
            "cycle_time": 4, "status": "removed", "maintainer": "alice",
        }]},
        "expected": ["T011"],
    },
    {
        "name": "cross-window-trust-erosion",
        "old": {"pkg-a": _pkg("pkg-a", "alice")},
        "new": {"pkg-a": _pkg("pkg-a", "alice", version="2")},
        "detail": {"pkg-a": {"rules": ["R001"]}},
        "prior_rule_history": {"pkg-a": [{
            "history_id": 10, "timestamp": "2026-01-01T00:00:00+00:00",
            "rules": ["H049"],
        }]},
        "expected": ["T012"],
    },
]


#: One handover and one shared-repo cycle per Phase-2 stratum.  The shape
#: under test is packaging, not the rule: a stratum's history coverage grows
#: with its diff coverage, so temporal rules track the corpus, not just the
#: eight original cohorts.
_NEW_STRATA = (
    "persist_surface", "signed_sources", "multi_client_fetch",
    "maintainer_churn", "dependency_heavy", "vcs_other",
    "appimage_repack", "lang_deep",
)

for _stratum in _NEW_STRATA:
    CYCLES.append({
        "name": f"{_stratum}-handover",
        "stratum": _stratum,
        "old": {"pkg-a": _pkg("pkg-a", "alice"),
                "pkg-b": _pkg("pkg-b", "bob")},
        "new": {"pkg-a": _pkg("pkg-a", "bob"),
                "pkg-b": _pkg("pkg-b", "bob")},
        "expected": ["H044"],
    })
    CYCLES.append({
        "name": f"{_stratum}-shared-repo",
        "stratum": _stratum,
        "old": {},
        "new": _bulk(f"{_stratum[:3]}", 3, "m"),
        "source_repos": {
            f"{_stratum[:3]}-{i:02d}": {"https://git.example/shared/repo"}
            for i in range(1, 4)
        },
        "expected": ["H052"],
    })
