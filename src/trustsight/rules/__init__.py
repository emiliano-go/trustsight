"""rules.py facade."""

import re
from functools import lru_cache
import threading
import logging
from ..config import load_rules
from ..deps import _strip_comment
from ..diffdoc import parse_diff_lines
from ..file_kinds import shell_lines
from ..findings import stamp
from ..line_lex import lex_lines
from ..tokenizer import (
    clean_lines,
    joined_indexed,
    split_lines,
    strip_boms,
)
from ..regex_safety import (
    BACKTRACK_BUDGET_S,
    backtracking_risk,
    has_nested_quantifier,
    is_superlinear,
)
from ._clamp import (
    _COMMAND_CHAIN_RE,
    _COMMENT_OR_DEP_RE,
    _DEP_DECLARATION_RE,
    _MESSAGE_LINE_RE,
    _PRINTER_LINE_RE,
    _WHITESPACE_RUN_RE,
    MAX_TOKENIZER_LINE_BYTES,
    _has_unquoted_redirect,
    _is_message_line,
    _printer_quote_body_indices,
    _to_pairs,
    bound_tokenizer_lines,
    clamp,
    clamp_diff_lines,
    clamp_text,
    filter_raw_lines,
    get_raw_diff_lines,
    get_raw_diff_lines_indexed,
)
from ._common import (
    MAX_RULE_LINE_BYTES,
    MAX_SCANNED_LINES,
    _log,
)
from ._compiled import (
    GENERATED_PATTERN_RULES,
    _compiled,
    _dynamic_pattern_is_unsafe,
    _dynamic_pattern_verdict,
    _pattern_cache,
    find_line_in_diff,
    precompile_patterns,
    precompile_shipped_patterns,
    precompile_structural_patterns,
    resolve_generated_patterns,
)
from ._scope import (
    ScopeResolver,
    _CLASSIFY_ENTRIES,
    _FUNCTION_CLOSE_RE,
    _FUNCTION_NAME_CLASS,
    _FUNCTION_NAME_RE,
    _FUNCTION_OPEN_RE,
    _blank_quoted,
    _caller_closure_map,
    _classified,
    _classify_caller_closure,
    _classify_enclosing_function,
    _classify_line_context,
    _classify_memo,
    _enclosing_function_map,
    _enclosing_function_map_cached,
    _function_bodies,
    _inline_body,
    _scope_matches,
    _starts_a_new_file,
    apply_rules,
)

__all__ = ['BACKTRACK_BUDGET_S', 'MAX_TOKENIZER_LINE_BYTES', 'bound_tokenizer_lines', 'GENERATED_PATTERN_RULES', 'MAX_RULE_LINE_BYTES', 'MAX_SCANNED_LINES', 'ScopeResolver', '_CLASSIFY_ENTRIES', '_COMMAND_CHAIN_RE', '_COMMENT_OR_DEP_RE', '_DEP_DECLARATION_RE', '_FUNCTION_CLOSE_RE', '_FUNCTION_NAME_CLASS', '_FUNCTION_NAME_RE', '_FUNCTION_OPEN_RE', '_MESSAGE_LINE_RE', '_PRINTER_LINE_RE', '_WHITESPACE_RUN_RE', '_blank_quoted', '_caller_closure_map', '_classified', '_classify_caller_closure', '_classify_enclosing_function', '_classify_line_context', '_classify_memo', '_compiled', '_dynamic_pattern_is_unsafe', '_dynamic_pattern_verdict', '_enclosing_function_map', '_enclosing_function_map_cached', '_function_bodies', '_has_unquoted_redirect', '_inline_body', '_is_message_line', '_log', '_printer_quote_body_indices', '_pattern_cache', '_scope_matches', '_starts_a_new_file', '_strip_comment', '_to_pairs', 'apply_rules', 'backtracking_risk', 'clamp', 'clamp_diff_lines', 'clamp_text', 'clean_lines', 'filter_raw_lines', 'find_line_in_diff', 'get_raw_diff_lines', 'get_raw_diff_lines_indexed', 'has_nested_quantifier', 'is_superlinear', 'joined_indexed', 'lex_lines', 'load_rules', 'logging', 'lru_cache', 'parse_diff_lines', 'precompile_patterns', 'precompile_shipped_patterns', 'precompile_structural_patterns', 're', 'resolve_generated_patterns', 'shell_lines', 'split_lines', 'stamp', 'strip_boms', 'threading']
