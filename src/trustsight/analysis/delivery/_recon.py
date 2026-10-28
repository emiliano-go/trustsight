"""Extracted from delivery.py: _recon."""

import re
from ...config import (
    _SUBCOMMAND_OPTS as _SUBCOMMAND_OPTS,
)
from ...config import DEFAULT_ANTI_ANALYSIS_PROBES
from ...deps import _strip_comment
from ...rules import (
    MAX_RULE_LINE_BYTES,
    ScopeResolver,
    _classify_enclosing_function,
)
from ...tokenizer import resolve_added_lines
from ..base import compile_configured_patterns
from ..build import (
    _recipe_lines,
)
from ._common import _SCOPE_FUNCTIONS, _find_line, _heredoc_body_indices

__all__ = ['_anti_analysis_findings', '_anti_analysis_probes']

def _anti_analysis_probes(config=None) -> list[re.Pattern]:
    """Compile the H067 anti-analysis probe fragments from patterns.toml."""
    return compile_configured_patterns(
        "anti_analysis_probes", DEFAULT_ANTI_ANALYSIS_PROBES)

def _anti_analysis_findings(diff_text, config, add, current_text=None) -> None:
    """A build/install line probing for debuggers, VMs, sandboxes or CI.

    The probe list is config-driven (patterns.toml ``anti_analysis_probes``).
    Legitimate arch/feature checks (`uname -m`, `getconf`) never match a
    probe fragment, which is the whole must-not-fire surface the rule has.
    """
    probes = _anti_analysis_probes(config)
    if not probes:
        return
    lines = resolve_added_lines(diff_text)
    enclosing = _classify_enclosing_function(lines)
    scopes = ScopeResolver(lines, _recipe_lines(current_text))
    heredoc_body = _heredoc_body_indices(lines)
    for i, line in enumerate(lines):
        if not line.startswith("+") or not scopes.within(i, _SCOPE_FUNCTIONS):
            continue
        if i in heredoc_body:
            continue
        # A line the rules engine clamps cannot be read by the pairing
        # passes either; the run already declares `line_truncated`.
        if len(line) > MAX_RULE_LINE_BYTES:
            continue
        body = _strip_comment(line[1:])
        for probe in probes:
            m = probe.search(body)
            if m:
                add("H067", "Anti-Analysis Check", "HIGH", "anti_analysis",
                    f"{enclosing[i]}() probes its environment: {body.strip()[:80]}",
                    line=_find_line(diff_text, m.group(0)),
                    position=enclosing[i],
                    probe=m.group(0)[:60])
                return
