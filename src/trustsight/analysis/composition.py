"""Phase 3 - kill-chain composition rules (plan §5).

H040 and H043 share one threat model: a PKGBUILD diff that carries a *staged
attack* rather than a single suspicious act.  Both are weight-0 annotations;
neither changes the score.

H040 (host reconnaissance) fires at INFO when a build/install function runs
a host-profiling command from the config-driven ``recon_commands`` list.
Probing "who am I / what machine am I on" has no packaging purpose, but a
single `uname -m` arch check is common and benign, so H040 is deliberately
quiet: it is the recon stage that H043 composes, nothing more.

H043 (attack-chain composition) is computed over the *aggregated*
``triggered_rules`` of a diff scan.  Every rule in the plan maps to a
kill-chain stage; when the hits of one diff span ``[thresholds] h043
attack_chain_stages`` distinct stages, the diff is annotated as a staged
attack.  H043 is an annotation of rule hits, never an additive score, and
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
# H040 - host reconnaissance
# ---------------------------------------------------------------------------


def _recon_probes(config=None) -> list[re.Pattern]:
    """Compile the H040 recon-command fragments from patterns.toml."""
    patterns = load_patterns().get("patterns", {})
    frags = patterns.get("recon_commands") or DEFAULT_RECON_COMMANDS
    return [re.compile(p, re.IGNORECASE) for p in frags]


def _recon_findings(diff_text, config, add) -> None:
    """A build/install line runs a host-profiling command (H040, INFO).

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
                add("H040", "Host Reconnaissance", "INFO", "recon",
                    f"{enclosing[i]}() profiles the host: {body.strip()[:80]}",
                    line=_find_line(diff_text, m.group(0)),
                    position=enclosing[i],
                    probe=m.group(0)[:60])
                return


# ---------------------------------------------------------------------------
# H043 - attack-chain composition
# ---------------------------------------------------------------------------

# Stage map (plan §5): each rule id belongs to exactly one kill-chain stage.
# Meta rules (H027, H043, H024) are absent - they annotate, they do not
# stage.
_STAGE_OF = {
    "H026": "takeover", "H044": "takeover", "H074": "takeover",
    "H045": "mass_adoption", "H073": "mass_adoption",
    "H023": "install_hook", "H017": "install_hook",
    "R001": "foreign_fetch", "H035": "foreign_fetch", "H066": "foreign_fetch",
    "H068": "payload", "H069": "payload",
    "H036": "obfuscation", "H065": "obfuscation",
    "H067": "anti_analysis", "H080": "anti_analysis",
    "H072": "write_then_exec", "H081": "write_then_exec",
    "H038": "staging",
    "H040": "recon",
    "H039": "persistence", "H062": "persistence", "H076": "persistence",
    "H041": "exfil", "H071": "exfil",
    "H042": "hidden_drop",
    "H034": "foreign_fetch",
    # The map was written when the R-series was the whole ruleset, and it
    # stopped there. A diff carrying nothing but evasion, or nothing but
    # sabotage, could not reach the stage count however many rules fired -
    # which inverts the rule's purpose, because a staged attack spelled in
    # the families designed to *avoid* the R-series is the case H043 is
    # most wanted for.
    "R041": "foreign_fetch", "H082": "write_then_exec",
    "H083": "write_then_exec", "H090": "foreign_fetch",
    "R144": "persistence", "H089": "persistence", "R054": "persistence",
    "H091": "integrity_removed",
    "X001": "obfuscation", "X002": "obfuscation", "X003": "obfuscation",
    "X005": "obfuscation", "X008": "obfuscation", "X018": "obfuscation",
    "X004": "anti_analysis",
    "X006": "foreign_fetch", "X009": "foreign_fetch",
    "X010": "foreign_fetch", "X013": "foreign_fetch",
    "X016": "foreign_fetch",
    "X011": "payload", "X017": "payload",
    "X012": "write_then_exec", "X014": "write_then_exec",
    "X015": "persistence",
    "X019": "exfil",
    "S001": "sabotage", "S002": "sabotage", "S003": "sabotage",
    "S004": "sabotage", "S005": "sabotage", "S006": "sabotage",
    "S007": "sabotage", "S008": "anti_analysis",
}

# Rules that fire on the *same* evidence as a heavier rule and must never be
# counted as extra stages of their own.  No such rule exists today; the plan's
# no-cascade guarantees (H057/H060/H061 never additive) are satisfied because
# those rules are not in the stage map at all.
_CASCADE_ONLY = frozenset()


def _attack_chain_threshold(config=None) -> int:
    """Return the H043 stage threshold from thresholds.toml."""
    thresholds = load_thresholds().get("h043", {})
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
    """Compose the meta annotations of a diff scan (H027, H043).

    H027 keeps its exact historical behavior (distinct categories excluding
    only H027 itself).  H043 is appended when the distinct kill-chain stages
    reach ``[thresholds] h043 attack_chain_stages``.  Both are INFO/weight-0.
    """
    out = []
    categories = {r.get("category", "") for r in triggered_rules
                  if r.get("category") and r["rule_id"] != "H027"}
    if len(categories) >= 3:
        out.append(stamp({
            "rule_id": "H027", "name": "Capability Density Anomaly",
            "severity": "INFO", "category": "meta",
            "match": f"rule hits span {len(categories)} distinct capability categories",
            "params": {"n_categories": len(categories)},
        }))

    stages = _attack_chain_stages(triggered_rules)
    threshold = _attack_chain_threshold(config)
    if len(stages) >= threshold:
        names = ", ".join(sorted(stages))
        out.append(stamp({
            "rule_id": "H043", "name": "Attack-Chain Composition",
            "severity": "INFO", "category": "meta",
            "match": f"rule hits span {len(stages)} distinct kill-chain stages: {names}",
            "params": {"n_stages": len(stages), "stages": names},
        }))
    return out
