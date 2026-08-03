"""Phase 3 - kill-chain composition rules (plan §5).

R086 and R089 share one threat model: a PKGBUILD diff that carries a *staged
attack* rather than a single suspicious act.  Both are weight-0 annotations;
neither changes the score.

R086 (host reconnaissance) fires at INFO when a build/install function runs
a host-profiling command from the config-driven ``recon_commands`` list.
Probing "who am I / what machine am I on" has no packaging purpose, but a
single `uname -m` arch check is common and benign, so R086 is deliberately
quiet: it is the recon stage that R089 composes, nothing more.

R089 (attack-chain composition) is computed over the *aggregated*
``triggered_rules`` of a diff scan.  Every rule in the plan maps to a
kill-chain stage; when the hits of one diff span ``[thresholds] r089
attack_chain_stages`` distinct stages, the diff is annotated as a staged
attack.  R089 is an annotation of rule hits, never an additive score, and
its own ``meta`` finding is excluded from every stage count.
"""

import re

from ..config import (
    DEFAULT_RECON_COMMANDS,
    load_patterns,
    load_thresholds,
)
from ..deps import _strip_comment
from ..findings import stamp
from ..rules import _classify_enclosing_function
from ..tokenizer import resolve_added_lines
from .delivery import (
    _SCOPE_FUNCTIONS,
    _find_line,
    _heredoc_body_indices,
)

# ---------------------------------------------------------------------------
# R086 - host reconnaissance
# ---------------------------------------------------------------------------


def _recon_probes(config=None) -> list[re.Pattern]:
    """Compile the R086 recon-command fragments from patterns.toml."""
    patterns = load_patterns().get("patterns", {})
    frags = patterns.get("recon_commands") or DEFAULT_RECON_COMMANDS
    return [re.compile(p, re.IGNORECASE) for p in frags]


def _recon_findings(diff_text, config, add) -> None:
    """A build/install line runs a host-profiling command (R086, INFO).

    The probe list is config-driven (patterns.toml ``recon_commands``).  The
    fragments carry a command-position anchor, so a mention inside a string,
    sed expression or variable value never fires.  Only one finding per line
    is emitted; the first matching probe wins.
    """
    probes = _recon_probes(config)
    if not probes:
        return
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)
    heredoc_body = _heredoc_body_indices(lines)
    for i, line in enumerate(lines):
        if not line.startswith("+") or enclosing.get(i) not in _SCOPE_FUNCTIONS:
            continue
        if i in heredoc_body:
            continue
        body = _strip_comment(line[1:])
        for probe in probes:
            m = probe.search(body)
            if m:
                add("R086", "Host Reconnaissance", "INFO", "recon",
                    f"{enclosing[i]}() profiles the host: {body.strip()[:80]}",
                    line=_find_line(diff_text, m.group(0)),
                    position=enclosing[i],
                    probe=m.group(0)[:60])
                return


# ---------------------------------------------------------------------------
# R089 - attack-chain composition
# ---------------------------------------------------------------------------

# Stage map (plan §5): each rule id belongs to exactly one kill-chain stage.
# Meta rules (R072, R089, R069) are absent - they annotate, they do not
# stage.
_STAGE_OF = {
    "R071": "takeover", "R090": "takeover", "R126": "takeover",
    "R092": "mass_adoption", "R125": "mass_adoption",
    "R068": "install_hook", "R062": "install_hook",
    "R001": "foreign_fetch", "R081": "foreign_fetch", "R118": "foreign_fetch",
    "R120": "payload", "R121": "payload",
    "R082": "obfuscation", "R117": "obfuscation",
    "R119": "anti_analysis",
    "R124": "write_then_exec",
    "R084": "staging",
    "R086": "recon",
    "R085": "persistence", "R114": "persistence",
    "R087": "exfil", "R123": "exfil",
    "R088": "hidden_drop",
    "R080": "foreign_fetch",
}

# Rules that fire on the *same* evidence as a heavier rule and must never be
# counted as extra stages of their own.  No such rule exists today; the plan's
# no-cascade guarantees (R107/R111/R112 never additive) are satisfied because
# those rules are not in the stage map at all.
_CASCADE_ONLY = frozenset()


def _attack_chain_threshold(config=None) -> int:
    """Return the R089 stage threshold from thresholds.toml."""
    thresholds = load_thresholds().get("r089", {})
    return thresholds.get("attack_chain_stages", 3)


def _attack_chain_stages(triggered_rules: list[dict]) -> dict[str, list[str]]:
    """Map the distinct kill-chain stages present in *triggered_rules*.

    Returns ``{stage: [rule_id, ...]}`` in rule-hit order; a rule id appears
    in at most one stage, and meta annotations are never counted.
    """
    stages: dict[str, list[str]] = {}
    for r in triggered_rules:
        rule_id = r.get("rule_id", "")
        if rule_id in _CASCADE_ONLY:
            continue
        stage = _STAGE_OF.get(rule_id)
        if stage and stage not in stages:
            stages[stage] = []
        if stage:
            stages[stage].append(rule_id)
    return stages


def _meta_annotations(triggered_rules: list[dict], config=None) -> list[dict]:
    """Compose the meta annotations of a diff scan (R072, R089).

    R072 keeps its exact historical behavior (distinct categories excluding
    only R072 itself).  R089 is appended when the distinct kill-chain stages
    reach ``[thresholds] r089 attack_chain_stages``.  Both are INFO/weight-0.
    """
    out = []
    categories = {r.get("category", "") for r in triggered_rules
                  if r.get("category") and r["rule_id"] != "R072"}
    if len(categories) >= 3:
        out.append(stamp({
            "rule_id": "R072", "name": "Capability Density Anomaly",
            "severity": "INFO", "category": "meta",
            "match": f"rule hits span {len(categories)} distinct capability categories",
            "params": {"n_categories": len(categories)},
        }))

    stages = _attack_chain_stages(triggered_rules)
    threshold = _attack_chain_threshold(config)
    if len(stages) >= threshold:
        names = ", ".join(sorted(stages))
        out.append(stamp({
            "rule_id": "R089", "name": "Attack-Chain Composition",
            "severity": "INFO", "category": "meta",
            "match": f"rule hits span {len(stages)} distinct kill-chain stages: {names}",
            "params": {"n_stages": len(stages), "stages": names},
        }))
    return out
