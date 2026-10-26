"""differ.py facade."""

import fnmatch
import re
from collections import Counter
from typing import NamedTuple
from ..changes import ChangeDelta, FileDelta, VersionFacts, change_delta
from ..coverage import unpinned_source_refs
from ..diffdoc import parse_diff_lines, strip_diff_path_prefix
from ..schema import DiffSummary, SourceChanges
from ..line_lex import strip_comment_stateful
from ..tokenizer import split_lines
from ._bounds import (
    MAX_COMPANION_BYTES,
    MAX_COMPANION_FILES,
    MAX_COMPANION_NAME_BYTES,
    MAX_COMPANION_TREE_ENTRIES,
    MAX_DIFF_BYTES,
    MAX_DIFF_PATCHES,
    MAX_DIFF_PATH_BYTES,
    MAX_DIFF_SUMMARY_FILES,
    MAX_GENERATED_DIFF_BYTES,
    MAX_HISTORY_COMMITS,
    MAX_PATCH_BYTES,
    MAX_PATCH_SOURCE_BYTES,
    MAX_PKG_BUILD_BYTES,
    MAX_STREAM_BYTES,
    MAX_URLS_PER_SIDE,
    MAX_URL_TOKEN_BYTES,
)
from ._checksums import (
    _CHECKSUM_ARRAY_RE,
    _CHECKSUM_LINE_RE,
    _CHECKSUM_VARS,
    _CHECKSUM_VAR_NAMES,
    _CHK_DECL_RE,
    _CHK_HASH_CHAR_RE,
    _CHK_SKIP_WORD_RE,
    _ChecksumArray,
    _added_array_items,
    _checksum_items,
    _quoted_items,
    _resolve_checksum_text,
    _text_array_items,
    _touched_checksum_arrays,
    _unquoted_close,
    checksum_array_parity,
    checksum_array_parity_in_text,
    detect_checksum_changes,
    detect_checksum_removed,
    source_array_grew_in_diff,
)
from ._common import (
    _SOURCE_ARRAY_START_RE,
    _SOURCE_ARRAY_START_RE_TEXT,
    _clean_url,
    _is_metadata_path,
    _post_diff_lines,
    _pre_diff_lines,
)
from ._companions import (
    _BINARY_DIFF_MARKER_RE,
    _COMPANION_INCOMPLETE,
    _COMPANION_MAX_BYTES,
    _COMPANION_SKIP,
    _DRAIN_CHUNK_BYTES,
    _PATTERN_REF_RE,
    _TOOL_CONTRACT_FILES,
    _companion_names,
    _is_safe_companion_name,
    _referenced_by_pattern,
    _top_level_blob,
    _tree_blob,
    binary_metadata_in_text,
    binary_metadata_paths,
    changed_opaque_members,
    companion_source_hunks,
    read_blob_head,
)
from ._diff import (
    _bounded_path,
    _diff_file_path,
    diff_summary_from_text,
    generate_diff,
    generate_diff_bounded,
    map_diff_lines,
    truncate_diff,
)
from ._sources import (
    _ARRAY_TOKEN_RE,
    _CMD_SUBST_RE,
    _DKMS_RE,
    _GIT_PKG_RE,
    _SIG_SRC_RE,
    _SKIP_JUSTIFICATION_CHECKS,
    _SOURCE_CMD_SUBST_RE,
    _SOURCE_OPEN_RE,
    _URL_TOKEN_RE,
    _VALIDPGPKEYS_RE,
    _VCS_SOURCE_RE,
    extract_source_array_urls,
    extract_urls_from_diff,
    is_skip_justified,
    local_source_names,
    resolved_source_urls,
    source_array_has_command_substitution,
    urls_from_pkgbuild_text,
)
from ._verification import (
    _GPG_VERIFY_RE,
    _VALIDPGPKEYS_WITH_CONTENT_RE,
    _has_checksum_in_post_diff,
    detect_gpg_verification_removed,
    detect_verification_evidence,
)

__all__ = ['ChangeDelta', 'Counter', 'DiffSummary', 'FileDelta', 'MAX_COMPANION_BYTES', 'MAX_COMPANION_FILES', 'MAX_COMPANION_NAME_BYTES', 'MAX_COMPANION_TREE_ENTRIES', 'MAX_DIFF_BYTES', 'MAX_DIFF_PATCHES', 'MAX_DIFF_PATH_BYTES', 'MAX_DIFF_SUMMARY_FILES', 'MAX_GENERATED_DIFF_BYTES', 'MAX_HISTORY_COMMITS', 'MAX_PATCH_BYTES', 'MAX_PATCH_SOURCE_BYTES', 'MAX_PKG_BUILD_BYTES', 'MAX_STREAM_BYTES', 'MAX_URLS_PER_SIDE', 'MAX_URL_TOKEN_BYTES', 'NamedTuple', 'SourceChanges', 'VersionFacts', '_ARRAY_TOKEN_RE', '_BINARY_DIFF_MARKER_RE', '_CHECKSUM_ARRAY_RE', '_CHECKSUM_LINE_RE', '_CHECKSUM_VARS', '_CHECKSUM_VAR_NAMES', '_CHK_DECL_RE', '_CHK_HASH_CHAR_RE', '_CHK_SKIP_WORD_RE', '_CMD_SUBST_RE', '_COMPANION_INCOMPLETE', '_COMPANION_MAX_BYTES', '_COMPANION_SKIP', '_ChecksumArray', '_DKMS_RE', '_DRAIN_CHUNK_BYTES', '_GIT_PKG_RE', '_GPG_VERIFY_RE', '_PATTERN_REF_RE', '_SIG_SRC_RE', '_SKIP_JUSTIFICATION_CHECKS', '_SOURCE_ARRAY_START_RE', '_SOURCE_ARRAY_START_RE_TEXT', '_SOURCE_CMD_SUBST_RE', '_SOURCE_OPEN_RE', '_TOOL_CONTRACT_FILES', '_URL_TOKEN_RE', '_VALIDPGPKEYS_RE', '_VALIDPGPKEYS_WITH_CONTENT_RE', '_VCS_SOURCE_RE', '_added_array_items', '_bounded_path', '_checksum_items', '_clean_url', '_companion_names', '_diff_file_path', '_has_checksum_in_post_diff', '_is_metadata_path', '_is_safe_companion_name', '_post_diff_lines', '_pre_diff_lines', '_quoted_items', '_referenced_by_pattern', '_resolve_checksum_text', '_text_array_items', '_top_level_blob', '_tree_blob', '_touched_checksum_arrays', '_unquoted_close', 'binary_metadata_in_text', 'binary_metadata_paths', 'change_delta', 'changed_opaque_members', 'checksum_array_parity', 'checksum_array_parity_in_text', 'companion_source_hunks', 'detect_checksum_changes', 'detect_checksum_removed', 'detect_gpg_verification_removed', 'detect_verification_evidence', 'diff_summary_from_text', 'extract_source_array_urls', 'extract_urls_from_diff', 'fnmatch', 'generate_diff', 'generate_diff_bounded', 'is_skip_justified', 'local_source_names', 'map_diff_lines', 'parse_diff_lines', 're', 'read_blob_head', 'resolved_source_urls', 'source_array_grew_in_diff', 'source_array_has_command_substitution', 'split_lines', 'strip_comment_stateful', 'strip_diff_path_prefix', 'truncate_diff', 'unpinned_source_refs', 'urls_from_pkgbuild_text']
