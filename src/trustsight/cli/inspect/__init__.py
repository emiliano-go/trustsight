"""inspect.py facade."""

import json
import sys
import typer
from ...config import ensure_default_configs, load_config
from ...coverage import GAP_REASONS, HISTORY_TRUNCATED
from ...db import (
    init_db,
    maybe_auto_import_seed,
)
from ...fetcher import MAX_HISTORY_DIFFS
from ...scoring import (
    DECLARED_CAVEAT,
    DECLARED_DEFAULT,
    verdict_label,
    verdict_level,
)
from ...safe_text import clean, safe_markup
from ...unicode import describe_fatal_codepoints
from ..completion import installed_packages
from ..display import (
    DEPTH_TRUNCATED_NOTE,
    dependency_lines_plain,
    RISK_COLORS,
    _print_colored,
    finding_where,
    no_aur_change_note,
    use_rich,
    version_transition,
)
from ._render import (
    _explain_lines,
    _failed_history_result,
    _finding_line,
    _inspect_plain,
    _inspect_rich,
    _layers_and_boundaries_line,
    _render_history_panel_plain,
    _render_history_panel_rich,
    _status_text,
)
from .commands import (
    _inspect_history,
    _inspect_one,
    analyze_package,
    register_commands,
)

__all__ = ['DECLARED_CAVEAT', 'DECLARED_DEFAULT', 'DEPTH_TRUNCATED_NOTE', 'GAP_REASONS', 'HISTORY_TRUNCATED', 'MAX_HISTORY_DIFFS', 'RISK_COLORS', '_explain_lines', '_failed_history_result', '_finding_line', '_inspect_history', '_inspect_one', '_inspect_plain', '_inspect_rich', '_layers_and_boundaries_line', '_print_colored', '_render_history_panel_plain', '_render_history_panel_rich', '_status_text', 'analyze_package', 'clean', 'dependency_lines_plain', 'describe_fatal_codepoints', 'ensure_default_configs', 'finding_where', 'init_db', 'installed_packages', 'json', 'load_config', 'maybe_auto_import_seed', 'no_aur_change_note', 'register_commands', 'safe_markup', 'sys', 'typer', 'use_rich', 'verdict_label', 'verdict_level', 'version_transition']
