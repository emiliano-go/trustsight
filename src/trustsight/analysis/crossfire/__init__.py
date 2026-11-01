"""Crossfire: the evasion technique, not the payload it hides.

Every other family here fires on what a diff *does*. These fire on how it was
*written*. The distinction is not stylistic - it is a response to where the
detection actually failed.

The rules held. The tokenizer that feeds them did not: partial quoting
(``c"u"rl``), array routing (``${A[0]}``), namerefs, and command substitution
(``$(printf '\\x63...')``) all reconstruct an executable name that no pattern
over the resolved text ever sees, because resolution is the step that broke.
Closing each of those in the tokenizer means teaching it to expand more, which
is slow, risky, and trades one bypass for an over-expansion bug.

Crossfire inverts the problem instead. **A word the tokenizer could not
resolve literally is itself the signal.** One rule then covers the evasion
surface of every payload rule at once - R001, H075, H082 and the rest - because
it does not care which payload was being hidden, only that hiding happened.

The failure mode inverts with it. Today a defeated tokenizer produces silence,
which is the worst possible output: the analysis looks clean precisely when it
understood least. Here a defeated tokenizer produces a CRITICAL finding. The
bypass and the alarm become the same event, so cleverness cannot buy quiet.

**What this family is not.** It is not a substitute for fixing the tokenizer,
and it must not become an excuse to stop. A payload written plainly and hidden
by a technique nobody anticipated still gets through; crossfire raises the cost
of evasion, it does not bound it. And it deliberately claims no bytes another
rule already claims: bidi overrides and homoglyphs are absent because
[R013](../../docs/reference/rules/deception.md) is FATAL and already covers
those codepoints, and scoring the same characters twice would corrupt the
calibration the project measures.  X008 exists for the codepoints R013 does
*not* cover - whitespace a shell will not split on - which is a disjoint
set, so it doubles nothing.

Every rule here was measured against the 3,739-diff locked benign corpus
before it was given a weight. The rates are in the reference page; the short
version is that legitimate PKGBUILDs do not do these things.
"""

from __future__ import annotations

import logging
import re
from ...config import (
    DECOMPRESSOR as _DECOMPRESSOR,
    NETWORK_CLIENT as _NETWORK_CLIENT,
    SCRIPT_EXECUTOR,
    STRUCTURED_EXTRACTOR as _STRUCTURED_EXTRACTOR,
    OTHER_FETCH_CLIENT as _OTHER_FETCH_CLIENT,
    PACKAGE_MANAGER_INSTALL as _PACKAGE_MANAGER_INSTALL,
)
from ...coverage import note_stage_failure
from ...deps import _strip_comment
from ...file_kinds import files_at_line, is_shell_file
from ...tokenizer import join_line_continuations, split_lines
from ...rules import clamp_text
from ._common import (
    _ACCOUNT_OPTION_RE,
    _ARRAY_ASSIGN_OPEN_RE,
    _ARRAY_VAR_RE,
    _ASSIGNMENT_RE,
    _CMD,
    _CONFUSABLE_CHARS,
    _DATA_CONSUMER,
    _DECEPTIVE_SPACE_RE,
    _DEP_ARRAY_OPEN_RE,
    _EVALUATION_RE,
    _EXECUTING_SCOPES,
    _EXEC_WRAPPER,
    _FENCE_RE,
    _FIRST_WORD_RE,
    _FOR_LOOP_RE,
    _H032_CLAIMS_RE,
    _HOME_ALIASES,
    _INTERPRETER_DECODE,
    _LITERAL_WORD_RE,
    _NUMERIC_RE,
    _PATH_LOOKUP_ASSIGN_RE,
    _PIPE_WRAPPER_RE,
    _PLAIN_VAR_RE,
    _PRIVILEGE_WRAPPERS,
    _REDIRECT_RE,
    _SHELL,
    _SHELL_CMD,
    _SHELL_NAME,
    _STAGED_RE,
    _WORD_VAR_RE,
    _WRAPPERS,
    _WRITE_COMMAND_RE,
    _WRITE_PREFIX,
    _command_words,
    _confusable_class,
    _continuation_lines,
    _dependency_array_lines,
    _executes,
    _home_alias_hit,
    _loop_variable_names,
    _opens_a_value,
    _path_lookup_names,
    _pipeline_sink,
    _quote_open_at_end,
    _resolved_records,
    _resolves_to_a_literal,
    _split_commands,
    _unquoted_paren_delta,
    _word_around,
    log,
)
from ._dispatch import (
    X007_MIN_TECHNIQUES,
    _NAMES,
    _crossfire_findings,
)
from ._engine import (
    crossfire_techniques,
)
from ._ownership import (
    CROSSFIRE_OWNERSHIP,
    _ownership_yields,
    resolve_ownership,
    resolve_ownership_audit,
)
from ._x01_x08 import (
    X001_RE,
    X002_SHAPES,
    X003_SHAPES,
    X004_SHAPES,
    X006_SHAPES,
)
from ._x09_x16 import (
    X009_RE,
    X010_RE,
    X011_WORD_RE,
    X011_STANDDOWN_RE,
    X012_CONSUMER_RE,
    X012_RE,
    X013_RE,
    X013_STANDDOWN_RE,
    X014_RE,
    X014_STANDDOWN_RE,
    X015_RE,
    X018_RE,
    X019_RE,
    _DISTRO_INSTALL_RE,
    _X009_CLIENT_RE,
    _X016_CONSUMER_RE,
    _X016_FETCH_RE,
    _X016_KNOWN_EXECUTOR_RE,
    _consumer_after_override,
    _consumer_at,
)
from ._x17_x25 import (
    X017_RE,
    X021_RE,
    X024_RE,
    _BUILD_MANIFEST_RE,
    _CONTENT_WRITE_VERB_RE,
    _FUNC_CONTINUATION_BODY_RE,
    _FUNC_CONTINUATION_RE,
    _HEREDOC_OPEN_RE,
    _INDIRECT_VALUE_RE,
    _MANIFEST_ARG_RE,
    _MANIFEST_COMMAND_RE,
    _SENSITIVE_VAR_RE,
    _X017_FIND_RE,
    _X017_SCRIPT_DANGER_RE,
    _X021_RUN_POSITIONAL_RE,
    _X021_SET_GLOB_RE,
    _X022_CONFIG_FLAG_RE,
    _X022_PAYLOAD_RE,
    _X022_WRITE_RE,
    _X024_VALUE_VAR_RE,
    _multiline_function_shadow_lines,
    _normalise_dest,
    _redirect_target,
    _x017_find_runs_a_script,
    _x024_is_passthrough,
)

__all__ = ['CROSSFIRE_OWNERSHIP', 'SCRIPT_EXECUTOR', 'X001_RE', 'X002_SHAPES', 'X003_SHAPES', 'X004_SHAPES', 'X006_SHAPES', 'X007_MIN_TECHNIQUES', 'X009_RE', 'X010_RE', 'X011_WORD_RE', 'X011_STANDDOWN_RE', 'X012_CONSUMER_RE', 'X012_RE', 'X013_RE', 'X013_STANDDOWN_RE', 'X014_RE', 'X014_STANDDOWN_RE', 'X015_RE', 'X017_RE', 'X018_RE', 'X019_RE', 'X021_RE', 'X024_RE', '_ACCOUNT_OPTION_RE', '_ARRAY_ASSIGN_OPEN_RE', '_ARRAY_VAR_RE', '_ASSIGNMENT_RE', '_BUILD_MANIFEST_RE', '_CMD', '_CONFUSABLE_CHARS', '_CONTENT_WRITE_VERB_RE', '_DATA_CONSUMER', '_DECEPTIVE_SPACE_RE', '_DECOMPRESSOR', '_DEP_ARRAY_OPEN_RE', '_DISTRO_INSTALL_RE', '_EVALUATION_RE', '_EXECUTING_SCOPES', '_EXEC_WRAPPER', '_FENCE_RE', '_FIRST_WORD_RE', '_FOR_LOOP_RE', '_FUNC_CONTINUATION_BODY_RE', '_FUNC_CONTINUATION_RE', '_H032_CLAIMS_RE', '_HEREDOC_OPEN_RE', '_HOME_ALIASES', '_INDIRECT_VALUE_RE', '_INTERPRETER_DECODE', '_LITERAL_WORD_RE', '_MANIFEST_ARG_RE', '_MANIFEST_COMMAND_RE', '_NAMES', '_NETWORK_CLIENT', '_NUMERIC_RE', '_OTHER_FETCH_CLIENT', '_PACKAGE_MANAGER_INSTALL', '_PATH_LOOKUP_ASSIGN_RE', '_PIPE_WRAPPER_RE', '_PLAIN_VAR_RE', '_PRIVILEGE_WRAPPERS', '_REDIRECT_RE', '_SENSITIVE_VAR_RE', '_SHELL', '_SHELL_CMD', '_SHELL_NAME', '_STAGED_RE', '_STRUCTURED_EXTRACTOR', '_WORD_VAR_RE', '_WRAPPERS', '_WRITE_COMMAND_RE', '_WRITE_PREFIX', '_X009_CLIENT_RE', '_X016_CONSUMER_RE', '_X016_FETCH_RE', '_X016_KNOWN_EXECUTOR_RE', '_X017_FIND_RE', '_X017_SCRIPT_DANGER_RE', '_X021_RUN_POSITIONAL_RE', '_X021_SET_GLOB_RE', '_X022_CONFIG_FLAG_RE', '_X022_PAYLOAD_RE', '_X022_WRITE_RE', '_X024_VALUE_VAR_RE', '_command_words', '_confusable_class', '_consumer_after_override', '_consumer_at', '_continuation_lines', '_crossfire_findings', '_dependency_array_lines', '_executes', '_home_alias_hit', '_loop_variable_names', '_multiline_function_shadow_lines', '_normalise_dest', '_opens_a_value', '_ownership_yields', '_path_lookup_names', '_pipeline_sink', '_quote_open_at_end', '_redirect_target', '_resolved_records', '_resolves_to_a_literal', '_split_commands', '_strip_comment', '_unquoted_paren_delta', '_word_around', '_x017_find_runs_a_script', '_x024_is_passthrough', 'annotations', 'clamp_text', 'crossfire_techniques', 'files_at_line', 'is_shell_file', 'join_line_continuations', 'log', 'logging', 'note_stage_failure', 're', 'resolve_ownership', 'resolve_ownership_audit', 'split_lines']
