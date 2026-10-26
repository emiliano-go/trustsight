"""_tokenizer_engine.py facade."""

import re
from functools import lru_cache
import shlex
import threading
from ._aliases import (
    _ALIAS_DEF_RE,
    _ALIAS_USE_PREFIX,
    _MAX_ALIASES,
    _MAX_ALIAS_LEN,
    _alias_pairs,
    _alias_table,
    _expand_aliases,
)
from ._apply import (
    _TRAVERSAL_RE,
    _joined_indexed,
    _resolve_added_lines,
    _resolve_removed_lines,
    collapse_traversal,
    resolve_added_lines,
    resolve_removed_lines,
    strip_leading_bom,
    tokenize_and_resolve,
    tokenize_and_resolve_indexed,
)
from ._common import (
    _ARRAY_ASSIGNMENT_RE,
    _ASSIGNMENT_RE,
    _MAX_EXPANSION_PASSES,
    _MAX_LINE_LEN,
    _MAX_TABLE_BYTES,
    _MAX_VALUE_LEN,
    _MEMO_ENTRIES,
    _VAR_REF_RE,
    _memo,
    _memoised,
    _split_top_level,
    _tail_continues,
)
from ._expansion import (
    _INNERMOST_RE,
    _REPLACEMENT_ESCAPE_RE,
    _expand_one,
    _strip_affix,
    resolve_expansions,
)
from ._quotes import (
    _ANSI_C_ESCAPES,
    _ANSI_C_OPENER_RE,
    _ANSI_C_QUOTE_RE,
    _EMPTY_QUOTE_CONCAT_RE,
    _ESCAPE_REMOVABLE,
    _PRINTF_LITERAL_RE,
    _STRUCTURAL_METACHARS,
    _WORD_ADJACENT,
    _decode_ansi_c,
    _quotes_removable,
    _strip_shell_quotes,
    reconstruct_literals,
    split_lines,
)
from ._variables import (
    _DIFF_TARGET_LINE_RE,
    _SHELL_SOURCE_FILE_RE,
    _assignments_are_shell,
    _collect_array_entries,
    _join_line_continuations_cached,
    _split_with_lines,
    _strip_outer_quotes,
    _substitute,
    _substitute_with_resolve,
    _table_bytes,
    _variable_table,
    _variable_table_with_spans,
    join_line_continuations,
)

__all__ = ['_ALIAS_DEF_RE', '_ALIAS_USE_PREFIX', '_ANSI_C_ESCAPES', '_ANSI_C_OPENER_RE', '_ANSI_C_QUOTE_RE', '_ARRAY_ASSIGNMENT_RE', '_ASSIGNMENT_RE', '_DIFF_TARGET_LINE_RE', '_EMPTY_QUOTE_CONCAT_RE', '_ESCAPE_REMOVABLE', '_INNERMOST_RE', '_MAX_ALIASES', '_MAX_ALIAS_LEN', '_MAX_EXPANSION_PASSES', '_MAX_LINE_LEN', '_MAX_TABLE_BYTES', '_MAX_VALUE_LEN', '_MEMO_ENTRIES', '_PRINTF_LITERAL_RE', '_REPLACEMENT_ESCAPE_RE', '_SHELL_SOURCE_FILE_RE', '_STRUCTURAL_METACHARS', '_TRAVERSAL_RE', '_VAR_REF_RE', '_WORD_ADJACENT', '_alias_pairs', '_alias_table', '_assignments_are_shell', '_collect_array_entries', '_decode_ansi_c', '_expand_aliases', '_expand_one', '_join_line_continuations_cached', '_joined_indexed', '_memo', '_memoised', '_quotes_removable', '_resolve_added_lines', '_resolve_removed_lines', '_split_top_level', '_split_with_lines', '_strip_affix', '_strip_outer_quotes', '_strip_shell_quotes', '_substitute', '_substitute_with_resolve', '_table_bytes', '_tail_continues', '_variable_table', '_variable_table_with_spans', 'collapse_traversal', 'join_line_continuations', 'lru_cache', 're', 'reconstruct_literals', 'resolve_added_lines', 'resolve_expansions', 'resolve_removed_lines', 'shlex', 'split_lines', 'strip_leading_bom', 'threading', 'tokenize_and_resolve', 'tokenize_and_resolve_indexed']
