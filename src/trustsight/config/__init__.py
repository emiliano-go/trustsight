"""config.py facade."""

import copy
import logging
import os
import re
from pathlib import Path
import tomllib
from ._default_config import (
    DEFAULT_BASELINE_TAG,
    DEFAULT_CONFIG,
    DEFAULT_HOSTS,
    DEFAULT_IOCS,
    DEFAULT_NAMING,
    DEFAULT_NOVELTY_WEIGHTS,
    DEFAULT_PATTERNS,
    DEFAULT_SOURCE_DIVERGENCE_ALLOW,
    DEFAULT_THRESHOLDS,
    STRUCTURAL_MATCHES,
    STRUCTURAL_SEVERITY_CEILING,
    _STRUCTURAL_CLAMPED,
    _toml_escape_str,
    _toml_str_list,
    _toml_value,
)
from ._default_rules import (
    DEFAULT_DOMAINS,
    DEFAULT_RULES,
    INT_WEIGHT_GROUPS,
    KNOWN_BOOL_KEYS,
    LEGACY_DEFAULT_REVIEW_LIMIT,
    LEGACY_IOCS_STUBS,
    SHIPPED_RULESET_VERSION,
    _SEMANTIC_FIELDS,
)
from ._defaults_executor import (
    ANY_EXECUTOR,
    CATALOGUED_FETCH_ALTERNATIVES,
    DECOMPRESSOR,
    DEFAULT_ANTI_ANALYSIS_PROBES,
    DEFAULT_CONFUSABLE_CHARS,
    DEFAULT_CONFUSABLE_DOMAINS,
    DEFAULT_COVERT_EGRESS_CLIENTS,
    DEFAULT_COVERT_EGRESS_ENDPOINTS,
    DEFAULT_ECOSYSTEM_PREFIXES,
    DEFAULT_FOREIGN_PKG_MANAGERS,
    DEFAULT_FREE_HOSTING_DOMAINS,
    DEFAULT_FREE_REGISTRAR_TLDS,
    DEFAULT_H029_MIN_OBSERVATIONS,
    DEFAULT_H029_PLAIN_MIN_OBSERVATIONS,
    DEFAULT_KNOWN_SUFFIXES,
    DEFAULT_MANIFEST_FILENAMES,
    DEFAULT_NETWORK_TOOLS,
    DEFAULT_OBFUSCATION_INDICATORS,
    DEFAULT_PARSE_TIME_FETCH,
    DEFAULT_PASTE_HOSTS,
    DEFAULT_RECON_COMMANDS,
    DEFAULT_SECURITY_RELEVANT_FLAGS,
    DEFAULT_SECURITY_RELEVANT_LIBRARIES,
    DEFAULT_SOURCE_SCHEMES,
    DEFAULT_STANDARD_PORTS,
    DEFAULT_UPLOAD_FLAGS,
    DEFAULT_VARIANT_SUFFIXES,
    EXEC_WRAPPER,
    NETWORK_CLIENT,
    NETWORK_CLIENT_ALTERNATIVES,
    OTHER_FETCH_CLIENT,
    PACKAGE_MANAGER_INSTALL,
    PAYLOAD_PRODUCER,
    SCRIPT_EXECUTOR,
    SHELL_EXECUTOR,
    STRUCTURED_EXTRACTOR,
    _SUBCOMMAND_OPTS,
)

_log = logging.getLogger(__name__)

CONFIG_DIR = Path.home() / ".config" / "trustsight"

DATA_DIR = Path.home() / ".local" / "share" / "trustsight"

CACHE_DIR = Path.home() / ".cache" / "trustsight" / "repos"

_RULESET_VERSION_RE = re.compile(r"^#\s*ruleset-version:\s*(\d+)", re.MULTILINE)

def local_ruleset_version() -> int:
    """The generation stamped into the user's ``rules.toml`` (0 if absent).

    A missing file reads as current - there is nothing to sync.  A file with
    no marker is a pre-marker install, so it reads as generation 0 and the
    age prompt can fire once.
    """
    path = CONFIG_DIR / "rules.toml"
    if not path.exists():
        return SHIPPED_RULESET_VERSION
    match = _RULESET_VERSION_RE.search(path.read_text(errors="replace"))
    return int(match.group(1)) if match else 0

def ruleset_age_drift(releases: int = 1) -> bool:
    """True when the local ruleset is more than *releases* generations old."""
    return SHIPPED_RULESET_VERSION - local_ruleset_version() > releases

def ensure_dirs():
    """Create config, data, and cache directories if missing.

    Created 0700: the database and the config can carry package names,
    maintainers and analysis history, none of which belong to other local
    users.  An explicit chmod follows the mkdir because the mode argument is
    masked by the umask.
    """
    for d in (CONFIG_DIR, DATA_DIR, CACHE_DIR):
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass

def write_default_file(path: Path, content: str):
    """Write a default file to disk if it does not exist, mode 0600."""
    if not path.exists():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)

def _refresh_legacy_iocs() -> bool:
    """Replace an untouched pre-H056 iocs.toml.  True when rewritten."""
    path = CONFIG_DIR / "iocs.toml"
    try:
        if path.read_text() in LEGACY_IOCS_STUBS:
            path.write_text(DEFAULT_IOCS)
            _toml_cache.pop("iocs.toml", None)
            return True
    except OSError:
        pass
    return False

_LEGACY_REVIEW_LIMIT_RE = re.compile(
    rf"^(\s*default_review_limit\s*=\s*){LEGACY_DEFAULT_REVIEW_LIMIT}(\s*)$"
)

def _refresh_legacy_review_limit() -> bool:
    """Repair the stale shipped ``default_review_limit``.  True when rewritten."""
    path = CONFIG_DIR / "config.toml"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    out: list[str] = []
    section = ""
    changed = False
    for line in text.splitlines(keepends=True):
        newline = "\n" if line.endswith("\n") else ""
        body = line[:-1] if newline else line
        stripped = body.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped
        if section == "[limits]" and _LEGACY_REVIEW_LIMIT_RE.match(body):
            out.append(_LEGACY_REVIEW_LIMIT_RE.sub(r"\g<1>0\g<2>", body) + newline)
            changed = True
        else:
            out.append(line)
    if not changed:
        return False
    path.write_text("".join(out), encoding="utf-8")
    _toml_cache.pop("config.toml", None)
    _log.info("repaired the legacy default_review_limit to 0 (read everything)")
    return True

def ensure_default_configs():
    """Write default config files if they do not exist, and add missing shipped rules."""
    ensure_dirs()
    write_default_file(CONFIG_DIR / "config.toml", DEFAULT_CONFIG)
    write_default_file(CONFIG_DIR / "rules.toml", DEFAULT_RULES)
    write_default_file(CONFIG_DIR / "trusted_domains.toml", DEFAULT_DOMAINS)
    write_default_file(CONFIG_DIR / "hosts.toml", DEFAULT_HOSTS)
    write_default_file(CONFIG_DIR / "patterns.toml", DEFAULT_PATTERNS)
    write_default_file(CONFIG_DIR / "naming.toml", DEFAULT_NAMING)
    write_default_file(CONFIG_DIR / "thresholds.toml", DEFAULT_THRESHOLDS)
    write_default_file(CONFIG_DIR / "iocs.toml", DEFAULT_IOCS)
    _refresh_legacy_iocs()
    _refresh_legacy_review_limit()
    # Append any shipped rules the user's file is missing.  The file is
    # written once at install time, so an older install can lack rules
    # that shipped after it.  Appending is always safe; replacements
    # require an explicit `config sync-rules`.
    added, _updated = sync_rules()
    if added:
        _log.info("added %d missing shipped rule(s) to rules.toml", len(added))

_toml_cache: dict[str, tuple[tuple, dict]] = {}

def load_toml(name: str, copy_result: bool = True) -> dict:
    """Load and parse a TOML file from the config directory.

    *copy_result* may be set False only by an accessor whose callers treat
    the result as read-only.  The deepcopy is not free: the analysis path
    asks for these tables several times per diff, and copying them was
    about 6% of a corpus scan.  ``load_rules`` keeps the copy because
    ``apply_rules`` really does assign to ``rule["pattern"]`` for the three
    generated patterns, and ``load_config`` keeps it because it is handed
    to every caller in the program.
    """
    path = CONFIG_DIR / name
    if not path.exists():
        ensure_default_configs()
    try:
        st = path.stat()
        stamp = (str(path), st.st_mtime_ns, st.st_size)
    except OSError:
        stamp = None
    if stamp is not None:
        cached = _toml_cache.get(name)
        if cached is not None and cached[0] == stamp:
            # Callers treat this as their own dict and some of them edit it
            # (overriding a rule toggle, say), so handing out the cached
            # object itself would let one caller's edit reach every later
            # one.  Copying is still an order of magnitude cheaper than
            # re-reading and re-parsing the file.
            return copy.deepcopy(cached[1]) if copy_result else cached[1]
    with open(path, "rb") as f:
        data = tomllib.load(f)
    if stamp is not None:
        _toml_cache[name] = (stamp, copy.deepcopy(data))
    return data

def set_config(key: str, value: str):
    """Set a config key to a new value in config.toml"""
    if key in KNOWN_BOOL_KEYS:
        if value.strip().lower() in ("true", "1", "yes", "on"):
            value = "true"
        elif value.strip().lower() in ("false", "0", "no", "off"):
            value = "false"
        else:
            raise ValueError(
                f"{key} expects true or false, got {value!r}"
            )
    else:
        section = key.split(".", 1)[0] if "." in key else ""
        if section not in INT_WEIGHT_GROUPS:
            raise ValueError(
                f"unknown config key {key!r}; set seed.auto_import, "
                "rules.experimental, or a weight in "
                + ", ".join(INT_WEIGHT_GROUPS)
            )
        try:
            value = str(int(value))
        except ValueError:
            raise ValueError(
                f"weight {key} expects an integer, got {value!r}"
            ) from None
    path = CONFIG_DIR / "config.toml"
    if not path.exists():
        ensure_default_configs()
    text = path.read_text()
    section_path = key.rsplit(".", 1)
    section = section_path[0] if len(section_path) > 1 else ""
    key_name = section_path[-1] if len(section_path) > 1 else key

    if section:
        header = f"[{section}]"
        if header in text:
            new_text = []
            in_section = False
            replaced = False
            for line in text.splitlines(keepends=True):
                stripped = line.strip()
                if stripped == header:
                    in_section = True
                    new_text.append(line)
                    continue
                if in_section:
                    if stripped.startswith("["):
                        in_section = False
                        if not replaced:
                            new_text.append(f'{key_name} = {_toml_value(value)}\n')
                            replaced = True
                        new_text.append(line)
                        continue
                    if stripped.startswith(f"{key_name} ") or stripped.startswith(f"{key_name}="):
                        new_text.append(f'{key_name} = {_toml_value(value)}\n')
                        replaced = True
                        continue
                    new_text.append(line)
                    continue
                new_text.append(line)
            if not replaced:
                new_text.append(f'{key_name} = {_toml_value(value)}\n')
            text = "".join(new_text)
        else:
            text += f"\n{header}\n{key_name} = {_toml_value(value)}\n"
    else:
        pattern = re.compile(rf"^{re.escape(key_name)}\s*=\s*.*", re.MULTILINE)
        if pattern.search(text):
            text = pattern.sub(f'{key_name} = {_toml_value(value)}', text)
        else:
            text += f'\n{key_name} = {_toml_value(value)}\n'

    path.write_text(text)

def _rule_blocks(toml_text: str) -> dict[str, str]:
    """Map rule id to its raw ``[[rules]]`` block text."""
    blocks: dict[str, str] = {}
    for chunk in toml_text.split("[[rules]]")[1:]:
        block = "[[rules]]" + chunk
        match = re.search(r'^id\s*=\s*["\']([^"\']+)["\']', block, re.MULTILINE)
        if match:
            blocks[match.group(1)] = block.rstrip() + "\n"
    return blocks

LEGACY_RULE_PATTERNS: dict[str, set[str]] = {
    # Pre-0.2.1: fired FATAL on U+200B-U+200D regardless of context, so a
    # localized desktop entry in a benign package scored 100/100.
    "R013": {r"[\u202A-\u202E\u2066-\u2069\u200B-\u200D\uFEFF]"},
    # Pre-2026-08-03: one phrasing of one injection family, and comments -
    # where the payload always lives - were filtered out before matching.
    # It caught 3 of 22 injection fixtures.
    "R012": {r"ignore\s+(?:all\s+)?previous\s+(?:instructions|commands|input)"},
    # Pre-0.13.2: quadratic, and therefore refused by the compile-time
    # safety check once the probe alphabet could see a punctuation-only
    # literal.  A refused pattern does not raise - the rule silently stops
    # matching - so an install-file modification would go unreported on
    # every installation still holding the old text.
    "R007": {r"\+.*\.install.*"},
    # Pre-0.13.3: fired on an escaped pipe, which runs no pipeline. The
    # replacement is strictly narrower, so an install still holding this
    # one loses nothing but the false positive.
    "R001": {
        r"curl.*\|\s*(?:/bin/)?(?:bash|sh|python|zsh|dash|busybox\s+sh|source\s+/dev/stdin)"
    },
    "R002": {
        r"wget.*\|\s*(?:/bin/)?(?:bash|sh|python|zsh|dash|busybox\s+sh|source\s+/dev/stdin)"
    },
    "R003": {r"base64.*(?:\-d|\-\-decode).*\|"},
    "R045": {r"\b(?:xxd|uudecode)\s+[^|]*\|"},
    # The client list R051 names grew (rclone moveto/move/bisync/copyurl,
    # npx), then again in 0.18.0 (git's global options before the verb, for
    # clone/fetch/pull/ls-remote/archive, `git lfs` and `git push`); R057
    # grew the TLS-off flags of the other catalogued clients.  These
    # patterns are shipped, not user-authored, so the old spellings are
    # recorded here and `config sync-rules --update` repairs an install
    # that still carries one.
    "R051": {
        r"\b(?:curl|wget2?|aria2c|axel|lftp|ncftp(?:get)?|snarf|httpie|elinks|links2?|w3m|lynx|browsh|scp|sftp|rsync|ftp|tftp|ssh(?=\s+(?:-\S+\s+)*[\w.@-]+\s+\S)|nc|ncat|netcat|socat|telnet|openssl\s+s_client|dig|host|nslookup|drill|kdig|git\s+(?:clone|fetch|pull|ls-remote|archive)|svn\s+(?:co|checkout|export)|hg\s+(?:clone|pull|unbundle)|bzr\s+(?:branch|pull|export)|darcs\s+get|fossil\s+clone|cvs\s+(?:[-:]\S+\s+)*(?:co|checkout|export)|s3cmd\s+(?:get|sync|cp)|aws\s+s3\s+(?:cp|sync|mv)|gsutil\s+(?:cp|rsync)|az(?:copy)?\s+(?:storage\s+blob\s+download|copy)|rclone\s+(?:copy|sync|cat|copyto)|ipfs\s+(?:get|cat|dag\s+get)|swift\s+download|rados\s+get|git\s+lfs\s+(?:pull|fetch|checkout)|yt-dlp|youtube-dl|transmission-cli|aria2c(?=\s+[^\n;&|]*magnet:)|b2\s+download-file|restic\s+restore|borg\s+extract|lwp-request|lwp-download|git\s+push|fetch(?=\s+[^\n;&|]*\b(?:https?|ftps?)://))\b",
        r"\b(?:curl|wget2?|aria2c|axel|lftp|ncftp(?:get)?|snarf|httpie|elinks|links2?|w3m|lynx|browsh|scp|sftp|rsync|ftp|tftp|ssh(?=\s+(?:-\S+\s+)*[\w.@-]+\s+\S)|nc|ncat|netcat|socat|telnet|openssl\s+s_client|dig|host|nslookup|drill|kdig|git\s+(?:clone|fetch|pull|ls-remote|archive)|svn\s+(?:co|checkout|export)|hg\s+(?:clone|pull|unbundle)|bzr\s+(?:branch|pull|export)|darcs\s+get|fossil\s+clone|cvs\s+(?:[-:]\S+\s+)*(?:co|checkout|export)|s3cmd\s+(?:get|sync|cp)|aws\s+s3\s+(?:cp|sync|mv)|gsutil\s+(?:cp|rsync)|az(?:copy)?\s+(?:storage\s+blob\s+download|copy)|rclone\s+(?:copy|sync|cat|copyto|copyurl|moveto|move|bisync)|ipfs\s+(?:get|cat|dag\s+get)|swift\s+download|rados\s+get|git\s+lfs\s+(?:pull|fetch|checkout)|yt-dlp|youtube-dl|transmission-cli|aria2c(?=\s+[^\n;&|]*magnet:)|b2\s+download-file|restic\s+restore|borg\s+extract|lwp-request|lwp-download|npx|git\s+push|fetch(?=\s+[^\n;&|]*\b(?:https?|ftps?)://))\b",
    },
    "R057": {r"(?:curl\s+(?:[^;&|]*\s)?(?:--insecure|-k)\b|wget\s+(?:[^;&|]*\s)?--no-check-certificate\b)"},
}

def outdated_shipped_rules() -> list[str]:
    """Ids whose on-disk pattern is a superseded shipped pattern."""
    path = CONFIG_DIR / "rules.toml"
    if not path.exists():
        return []
    current = {rid: b for rid, b in _rule_blocks(DEFAULT_RULES).items()}
    outdated = []
    for rule in load_rules():
        rid = rule.get("id")
        if rid not in current or rid not in LEGACY_RULE_PATTERNS:
            continue
        if rule.get("pattern") in LEGACY_RULE_PATTERNS[rid]:
            outdated.append(rid)
    return outdated

def _shipped_rule_fields() -> dict[str, dict[str, str]]:
    """Parse the shipped rule blocks into ``{id: {field: value}}``."""
    parsed: dict[str, dict[str, str]] = {}
    for rid, block in _rule_blocks(DEFAULT_RULES).items():
        fields: dict[str, str] = {}
        for field in _SEMANTIC_FIELDS:
            match = re.search(rf"^{field}\s*=\s*(.+)$", block, re.MULTILINE)
            if not match:
                continue
            value = match.group(1).strip()
            # A list field (`scope`) is compared against the parsed Python
            # value on disk, so normalise it the same way: `str(list)` for
            # `["a", "b"]` is `"['a', 'b']"`, which a bare strip never
            # produced - comparing raw TOML text to that reported a drift on
            # every rule that carries a scope.
            if value.startswith("["):
                try:
                    value = str(tomllib.loads(f"v = {value}")["v"])
                except (tomllib.TOMLDecodeError, KeyError):
                    pass
            fields[field] = value.strip("'\"")
        parsed[rid] = fields
    return parsed

def drifted_shipped_rules() -> list[tuple[str, str, str, str]]:
    """Rules on disk whose semantics differ from the shipped definition.

    Returns ``(rule_id, field, on_disk, shipped)`` tuples.

    ``rules.toml`` is written once, at install time, and only ever gains
    rules afterwards.  A shipped rule that later changes ``match_target``
    therefore keeps its original behaviour forever on an existing install.
    That is not cosmetic: R001 and friends moved to ``match_target =
    "resolved"`` so that a payload assembled from shell variables is
    caught, and an install still holding ``raw_line`` silently misses it.

    Reporting only.  These are not auto-corrected, because a rule whose
    pattern the user has broadened would lose that work if the shipped
    block were written over it.
    """
    path = CONFIG_DIR / "rules.toml"
    if not path.exists():
        return []
    shipped = _shipped_rule_fields()
    drift: list[tuple[str, str, str, str]] = []
    for rule in load_rules():
        rid = rule.get("id")
        expected = shipped.get(rid)
        if not expected:
            continue
        for field in _SEMANTIC_FIELDS:
            if field not in expected:
                continue
            default = "raw_line" if field == "match_target" else ""
            actual = str(rule.get(field, default))
            if actual != expected[field]:
                drift.append((rid, field, actual, expected[field]))
    return drift

def missing_shipped_rules() -> list[str]:
    """Ids present in ``DEFAULT_RULES`` but absent from the user's file.

    ``write_default_file`` only writes when the file does not exist, so an
    install that predates a rule addition never receives it.  Without this
    check, enabling a new rule in ``config.toml`` silently does nothing.
    """
    from ..rule_id_history import RETIRED_RULE_IDS

    path = CONFIG_DIR / "rules.toml"
    if not path.exists():
        return []
    existing = {r.get("id") for r in load_rules()}
    # a retired id is never resurrected by a sync. Its
    # detection now fires under the survivor, so re-adding the old block
    # would double-report; the alias in `survivor_id` is what keeps the id
    # readable.
    return [rid for rid in _rule_blocks(DEFAULT_RULES)
            if rid not in existing and rid not in RETIRED_RULE_IDS]

def _replace_rule_block(text: str, rule_id: str, new_block: str) -> str:
    """Swap the ``[[rules]]`` block for *rule_id* in *text*."""
    parts = text.split("[[rules]]")
    out = [parts[0]]
    for chunk in parts[1:]:
        block = "[[rules]]" + chunk
        match = re.search(r'^id\s*=\s*["\']([^"\']+)["\']', block, re.MULTILINE)
        if match and match.group(1) == rule_id:
            trailing = len(block) - len(block.rstrip())
            out.append(new_block.rstrip() + block[len(block.rstrip()):] if trailing else new_block.rstrip())
        else:
            out.append(block)
    return "".join(out)

def sync_rules(update_outdated: bool = False) -> tuple[list[str], list[str]]:
    """Bring the user's ``rules.toml`` in line with the shipped defaults.

    Appending is always safe, so missing rules are added unconditionally.
    Replacing is not, so a rule is only rewritten when *update_outdated*
    is set **and** either its current pattern is one this project shipped
    before (meaning the user never edited it) **or** its semantic fields
    other than ``pattern`` (match_target, severity, category) differ from
    the shipped definition.

    Rules whose pattern was intentionally edited by the user are never
    overwritten, even if other fields drifted.

    Returns ``(added_ids, updated_ids)``.
    """
    path = CONFIG_DIR / "rules.toml"
    if not path.exists():
        ensure_default_configs()
        return [], []

    blocks = _rule_blocks(DEFAULT_RULES)
    text = path.read_text().rstrip() + "\n"

    updated: list[str] = []
    if update_outdated:
        # Update rules with superseded patterns (legacy shipped versions).
        for rid in outdated_shipped_rules():
            text = _replace_rule_block(text, rid, blocks[rid])
            updated.append(rid)
        # Also update rules whose non-pattern semantic fields drifted from
        # shipped defaults (match_target, severity, category, scope).  A rule
        # whose on-disk pattern is no longer the shipped one is skipped
        # entirely: the user edited it, and replacing the block to fix a
        # *different* field would discard that pattern (the docstring's
        # promise).  Patterns are compared parsed-on-both-sides so a raw-text
        # quirk cannot read as an edit.
        _NON_PATTERN_FIELDS = ("match_target", "severity", "category", "scope")
        on_disk_pattern = {
            r.get("id"): str(r.get("pattern", "")) for r in load_rules()
        }
        shipped_pattern = {
            r.get("id"): str(r.get("pattern", "")) for r in shipped_rules()
        }
        for rid, field, _seen, _shipped in drifted_shipped_rules():
            if rid in updated or field not in _NON_PATTERN_FIELDS:
                continue
            if on_disk_pattern.get(rid, "") != shipped_pattern.get(rid, ""):
                continue
            text = _replace_rule_block(text, rid, blocks[rid])
            updated.append(rid)

    added = missing_shipped_rules()
    for rid in added:
        text += "\n" + blocks[rid]

    # Stamp the current generation: a file with no marker is
    # a pre-marker install and would keep reading as age-drifting after a
    # sync; an old marker is replaced in place.
    before = text
    if _RULESET_VERSION_RE.search(text) is None:
        text = f"# ruleset-version: {SHIPPED_RULESET_VERSION}\n" + text
    else:
        text = _RULESET_VERSION_RE.sub(
            f"# ruleset-version: {SHIPPED_RULESET_VERSION}", text, count=1)
    marker_changed = text != before

    if added or updated or marker_changed:
        path.write_text(text)
    return added, updated

def load_config() -> dict:
    """Load the user config.toml"""
    return load_toml("config.toml")

def configured_baseline_tag() -> str | None:
    """The fallback baseline tag for the release channel, or ``None``.

    Read without creating a config file: the release channel builds a URL
    during a download and must not materialise operator state as a side
    effect of a lookup.  An unreadable or absent file falls back to the
    shipped default; an explicit empty value disables the fallback.
    """
    path = CONFIG_DIR / "config.toml"
    try:
        with open(path, "rb") as f:
            section = tomllib.load(f).get("seed") or {}
    except (OSError, tomllib.TOMLDecodeError):
        section = {}
    # An explicit key wins, including an empty one: setting ``baseline_tag =
    # ""`` turns the fallback off and makes a discovery failure fail closed.
    if "baseline_tag" in section:
        value = str(section["baseline_tag"] or "").strip()
    else:
        value = str(DEFAULT_BASELINE_TAG or "").strip()
    return value or None

_shipped_rules_cache: list[dict] | None = None

def shipped_rules() -> list[dict]:
    """The rule set this build ships, parsed from ``DEFAULT_RULES``.

    Read-only reference: it is what ``rules.toml`` is written from, and
    what the FATAL integrity check compares an on-disk file against.
    """
    global _shipped_rules_cache
    if _shipped_rules_cache is None:
        _shipped_rules_cache = tomllib.loads(DEFAULT_RULES).get("rules", [])
    return _shipped_rules_cache

def shipped_fatal_rule_ids() -> list[str]:
    """Ids of the shipped rules whose severity is FATAL.

    Derived, never hardcoded: a rule promoted to FATAL is protected the
    moment it ships, and the docs and the security gates read this list
    rather than restating it.
    """
    return [r["id"] for r in shipped_rules() if r.get("severity") == "FATAL"]

def enforce_fatal_rules(rules: list[dict]) -> tuple[list[dict], list[str]]:
    """Restore any shipped FATAL rule the on-disk file dropped or downgraded.

    ``rules.toml`` is user-editable, which is the point: an operator must
    be able to tune a noisy pattern.  What they must not be able to do,
    quietly, is switch off the two rules an attacker would most want gone.
    Prompt injection and unicode deception target the *reviewer*, not the
    machine, so a run that skips them is not a tuned run, it is a run whose
    output cannot be trusted at all - and ``override.py`` already refuses
    to suppress a FATAL finding for exactly that reason.  Enforcing it at
    load time closes the other half: deleting the rule instead of
    overriding its finding.

    The restore is in memory only.  Nothing is written back, so a user who
    edited the file still has their file; they just do not get an analysis
    that pretends the rule was never there.  Returns the effective rule
    list and the ids that had to be restored.
    """
    by_id = {r.get("id"): r for r in rules}
    restored: list[str] = []
    effective = list(rules)
    for shipped in shipped_rules():
        if shipped.get("severity") != "FATAL":
            continue
        rid = shipped["id"]
        on_disk = by_id.get(rid)
        if on_disk is None:
            effective.append(dict(shipped))
            restored.append(rid)
        elif on_disk.get("severity") != "FATAL":
            effective[effective.index(on_disk)] = dict(shipped)
            restored.append(rid)
    return effective, restored

def load_rules() -> list[dict]:
    """Load rules from rules.toml, applying per-rule config.toml controls.

    ``[rules.R001]`` controls apply only to rules defined in rules.toml,
    which since the R/H split is every ``R`` id and no other: an ``H`` rule
    is a heuristic emitted from an analysis module, has no TOML definition,
    and intentionally keeps its own configuration paths.
    """
    data = load_toml("rules.toml")
    rules, restored = enforce_fatal_rules(data.get("rules", []))
    controls = load_config().get("rules", {})
    for rule in rules:
        control = controls.get(rule.get("id"), {})
        if not isinstance(control, dict):
            continue
        for key in ("enabled", "weight_override"):
            if key in control:
                rule[key] = control[key]
        if rule.get("severity") == "FATAL" and rule.get("enabled") is False:
            rule["enabled"] = True
            _log.warning("refusing to disable FATAL rule %s", rule["id"])
    if restored:
        _log.warning(
            "rules.toml is missing or has downgraded FATAL rule(s) %s; "
            "the shipped definition is being used instead",
            ", ".join(restored),
        )
    return rules

def clamp_structural_severity(severity: str) -> str:
    """Return *severity* capped at :data:`STRUCTURAL_SEVERITY_CEILING`."""
    return _STRUCTURAL_CLAMPED.get(severity, severity)

def load_structural_rules(on_skip=None) -> list[dict]:
    """Load ``[[structural]]`` recipe rules from rules.toml.

    The table is user-only: it ships empty and is never synced, so the
    entries on disk are the only ones that exist.  A malformed entry is
    skipped and logged rather than failing a whole analysis; ``trustsight
    lint-rules`` reports the same conditions as errors.  ``[rules.R###]``
    controls in ``config.toml`` apply by id, exactly as for a line rule.

    *on_skip* is called with the skipped rule's id when an entry is
    dropped.  An analysis passes a callback that marks the run degraded,
    so an operator's broken rule shrinks the detection surface loudly
    instead of silently.
    """
    raw = load_toml("rules.toml").get("structural", [])
    controls = load_config().get("rules", {})
    rules: list[dict] = []

    def skipped(label: str) -> None:
        if on_skip is not None:
            on_skip(label)

    for entry in raw:
        if not isinstance(entry, dict):
            _log.warning("ignoring non-table structural rule %r", entry)
            skipped("unparsed")
            continue
        rule = dict(entry)
        rid = rule.get("id")
        match = rule.get("match")
        field = rule.get("field")
        pattern = rule.get("pattern")
        if not (isinstance(rid, str) and rid and isinstance(match, str)
                and isinstance(field, str) and field
                and isinstance(pattern, str) and pattern):
            _log.warning("ignoring structural rule with missing fields: %r", rule)
            skipped(str(rid or "unidentified"))
            continue
        if match not in STRUCTURAL_MATCHES:
            _log.warning("ignoring structural rule %s: unknown match %r", rid, match)
            skipped(rid)
            continue
        is_scalar = field.startswith("scalars.")
        if is_scalar != (match == "scalar_changed"):
            _log.warning(
                "ignoring structural rule %s: match %r does not apply to field %r",
                rid, match, field,
            )
            skipped(rid)
            continue
        severity = str(rule.get("severity") or "MEDIUM")
        if severity in _STRUCTURAL_CLAMPED:
            _log.warning(
                "capping structural rule %s severity %s at %s",
                rid, severity, STRUCTURAL_SEVERITY_CEILING,
            )
            severity = _STRUCTURAL_CLAMPED[severity]
        rule["severity"] = severity
        if not rule.get("name"):
            rule["name"] = rid
        if not rule.get("category"):
            rule["category"] = "structural"
        control = controls.get(rid, {})
        if isinstance(control, dict):
            for key in ("enabled", "weight_override"):
                if key in control:
                    rule[key] = control[key]
        rules.append(rule)
    return rules

def _standard_port_pattern() -> str:
    """Generate the R047 non-standard-port exclusion pattern from config."""
    hosts = load_hosts().get("hosts", {})
    cfg = load_config()
    ports = (
        hosts.get("standard_ports")
        or cfg.get("ports", {}).get("standard")
        or DEFAULT_STANDARD_PORTS
    )
    # Escaped: these come from hosts.toml, which is a *list*, not a
    # pattern language.  An unescaped entry silently becomes regex - at
    # best a broken rule, at worst one that matches everything or nothing.
    joined = "|".join(re.escape(str(p)) for p in ports)
    return f'https?://[^/\\s:]+:(?!(?:{joined})(?:[/\\s"\\x27]|$))\\d{{2,5}}'

def _free_registrar_tld_pattern() -> str:
    """Generate the R048 free-registrar-TLD pattern from config."""
    hosts = load_hosts().get("hosts", {})
    cfg = load_config()
    tlds = (
        hosts.get("free_registrar_tlds")
        or cfg.get("domains", {}).get("free_registrar_tlds")
        or DEFAULT_FREE_REGISTRAR_TLDS
    )
    joined = "|".join(re.escape(str(t)) for t in tlds)
    return f'https?://[^/\\s]*\\.(?:{joined})(?:[:/]|["\\x27\\s)]|$)'

def _free_hosting_pattern() -> str:
    """Generate the R152 free-hosting / dynamic-DNS / tunnel pattern.

    The providers are multi-label suffixes (``evil.duckdns.org``), so the
    leading ``\\.`` is what makes this a subdomain match rather than a
    substring one: ``duckdns.org.evil.com`` must not fire.
    """
    hosts = load_hosts().get("hosts", {})
    cfg = load_config()
    domains = (
        hosts.get("free_hosting_domains")
        or cfg.get("domains", {}).get("free_hosting_domains")
        or DEFAULT_FREE_HOSTING_DOMAINS
    )
    joined = "|".join(re.escape(str(d)) for d in domains)
    return f'https?://[^/\\s]*\\.(?:{joined})(?:[:/]|["\\x27\\s)]|$)'

def load_domains() -> dict:
    """Load trusted domains from trusted_domains.toml"""
    return load_toml("trusted_domains.toml", copy_result=False)

def load_patterns() -> dict:
    """Load pattern tables from patterns.toml (H035/H036/D003)."""
    return load_toml("patterns.toml", copy_result=False)

def load_naming() -> dict:
    """Load naming tables from naming.toml (D002/D004/H029)."""
    return load_toml("naming.toml", copy_result=False)

def load_hosts() -> dict:
    """Load host tables from hosts.toml (R047/R048/H041)."""
    return load_toml("hosts.toml", copy_result=False)

def load_thresholds() -> dict:
    """Load thresholds from thresholds.toml (H036/H073/H074)."""
    return load_toml("thresholds.toml", copy_result=False)

def load_iocs() -> dict:
    """Load the versioned indicator list from iocs.toml (H056)."""
    return load_toml("iocs.toml", copy_result=False)

def load_ioc_sources() -> list[str]:
    """Return the configured IOC baseline source names to consult.

    An empty list means "all sources currently imported into the local
    database".  The ``[baselines.ioc]`` table may not exist on legacy
    installs; in that case the baseline stage runs against every source.
    """
    cfg = load_config()
    section = cfg.get("baselines", {}).get("ioc", {})
    sources = section.get("sources", [])
    if not sources:
        return []
    if isinstance(sources, str):
        return [sources]
    return [str(s).strip() for s in sources if str(s).strip()]

def config_fingerprint() -> str:
    """A digest of the instrument: ruleset, thresholds and overrides.

    B1's determinism is *algorithmic*, not configurational.  Two operators
    with different `rules.toml` get different scores by design, so "the
    same input always produces the same score" is only true holding the
    configuration fixed.  Publishing the fingerprint makes that precise:
    same input and same fingerprint must give the same number, and a
    different fingerprint is a different instrument rather than a
    nondeterministic one.

    Covers what can change a score: every rule's id, pattern, severity,
    match target and scope; the scoring weight tables; the thresholds; and
    the active overrides.  Cosmetic fields (a rule's prose description) are
    excluded, because editing a comment is not a different instrument.
    """
    import hashlib
    import json

    def rule_key(rule: dict) -> dict:
        return {
            k: rule.get(k) for k in
            ("id", "pattern", "severity", "category", "match_target",
             "scope", "added_only", "include_comments", "experimental",
              "enabled", "weight_override", "exclude_if_matches",
              "escalates_when")
        }

    def structural_key(rule: dict) -> dict:
        return {
            k: rule.get(k) for k in
            ("id", "field", "match", "pattern", "severity", "category",
             "enabled", "weight_override")
        }

    config = load_config()
    material = {
        "rules": sorted((rule_key(r) for r in load_rules()),
                        key=lambda r: r.get("id") or ""),
        "structural_rules": sorted(
            (structural_key(r) for r in load_structural_rules()),
            key=lambda r: r.get("id") or ""),
        "severity_weights": config.get("severity_weights", {}),
        "source_bucket_weights": config.get("source_bucket_weights", {}),
        "novelty_weights": config.get("novelty_weights", {}),
        # C011's allowlist changes which prebuilt packages are reported, so
        # two operators with different lists are different instruments.
        "source_host_divergence": config.get("source_host_divergence", {}),
        # The selected review policy changes which reports are flagged, even
        # though it deliberately leaves score arithmetic unchanged.
        "review_policy": _review_policy_material(config),
        "thresholds": load_thresholds(),
        "limits": config.get("limits", {}),
        "diff": config.get("diff", {}),
    }
    try:
        from ..override import load_overrides

        # TTL and the indicator cross-check change the effective ruleset (an
        # expired override no longer suppresses), so they belong in the
        # fingerprint beside the rule id and scope.
        material["overrides"] = sorted(
            (o.rule_id, o.package or "", int(o.ttl_observations or 0),
             bool(o.requires_clear_indicators))
            for o in load_overrides()
        )
    except Exception:
        material["overrides"] = []

    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"),
                           default=str).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()

def _review_policy_material(config: dict) -> dict:
    """Return the non-arithmetic policy fields covered by the fingerprint."""
    from ..review_policy import review_policy

    policy = review_policy(config)
    return {"name": policy.name, "threshold": policy.threshold}


__all__ = ['ANY_EXECUTOR', 'CACHE_DIR', 'CATALOGUED_FETCH_ALTERNATIVES', 'CONFIG_DIR', 'DATA_DIR', 'DECOMPRESSOR', 'DEFAULT_ANTI_ANALYSIS_PROBES', 'DEFAULT_BASELINE_TAG', 'DEFAULT_CONFIG', 'DEFAULT_CONFUSABLE_CHARS', 'DEFAULT_CONFUSABLE_DOMAINS', 'DEFAULT_COVERT_EGRESS_CLIENTS', 'DEFAULT_COVERT_EGRESS_ENDPOINTS', 'DEFAULT_DOMAINS', 'DEFAULT_ECOSYSTEM_PREFIXES', 'DEFAULT_FOREIGN_PKG_MANAGERS', 'DEFAULT_FREE_HOSTING_DOMAINS', 'DEFAULT_FREE_REGISTRAR_TLDS', 'DEFAULT_H029_MIN_OBSERVATIONS', 'DEFAULT_H029_PLAIN_MIN_OBSERVATIONS', 'DEFAULT_HOSTS', 'DEFAULT_IOCS', 'DEFAULT_KNOWN_SUFFIXES', 'DEFAULT_MANIFEST_FILENAMES', 'DEFAULT_NAMING', 'DEFAULT_NETWORK_TOOLS', 'DEFAULT_NOVELTY_WEIGHTS', 'DEFAULT_OBFUSCATION_INDICATORS', 'DEFAULT_PARSE_TIME_FETCH', 'DEFAULT_PASTE_HOSTS', 'DEFAULT_PATTERNS', 'DEFAULT_RECON_COMMANDS', 'DEFAULT_RULES', 'DEFAULT_SECURITY_RELEVANT_FLAGS', 'DEFAULT_SECURITY_RELEVANT_LIBRARIES', 'DEFAULT_SOURCE_DIVERGENCE_ALLOW', 'DEFAULT_SOURCE_SCHEMES', 'DEFAULT_STANDARD_PORTS', 'DEFAULT_THRESHOLDS', 'DEFAULT_UPLOAD_FLAGS', 'DEFAULT_VARIANT_SUFFIXES', 'EXEC_WRAPPER', 'INT_WEIGHT_GROUPS', 'KNOWN_BOOL_KEYS', 'LEGACY_DEFAULT_REVIEW_LIMIT', 'LEGACY_IOCS_STUBS', 'LEGACY_RULE_PATTERNS', 'NETWORK_CLIENT', 'NETWORK_CLIENT_ALTERNATIVES', 'OTHER_FETCH_CLIENT', 'PACKAGE_MANAGER_INSTALL', 'PAYLOAD_PRODUCER', 'Path', 'SCRIPT_EXECUTOR', 'SHELL_EXECUTOR', 'SHIPPED_RULESET_VERSION', 'STRUCTURAL_MATCHES', 'STRUCTURAL_SEVERITY_CEILING', 'STRUCTURED_EXTRACTOR', '_LEGACY_REVIEW_LIMIT_RE', '_RULESET_VERSION_RE', '_SEMANTIC_FIELDS', '_STRUCTURAL_CLAMPED', '_SUBCOMMAND_OPTS', '_free_hosting_pattern', '_free_registrar_tld_pattern', '_log', '_refresh_legacy_iocs', '_refresh_legacy_review_limit', '_replace_rule_block', '_review_policy_material', '_rule_blocks', '_shipped_rule_fields', '_shipped_rules_cache', '_standard_port_pattern', '_toml_cache', '_toml_escape_str', '_toml_str_list', '_toml_value', 'clamp_structural_severity', 'config_fingerprint', 'configured_baseline_tag', 'copy', 'drifted_shipped_rules', 'enforce_fatal_rules', 'ensure_default_configs', 'ensure_dirs', 'load_config', 'load_domains', 'load_hosts', 'load_ioc_sources', 'load_iocs', 'load_naming', 'load_patterns', 'load_rules', 'load_structural_rules', 'load_thresholds', 'load_toml', 'local_ruleset_version', 'logging', 'missing_shipped_rules', 'os', 'outdated_shipped_rules', 're', 'ruleset_age_drift', 'set_config', 'shipped_fatal_rule_ids', 'shipped_rules', 'sync_rules', 'tomllib', 'write_default_file']
