"""Parsing, drift detection, and synchronization for shipped rules."""

import re
import tomllib

from ._default_rules import DEFAULT_RULES, _SEMANTIC_FIELDS, SHIPPED_RULESET_VERSION
from ._legacy_shipped_patterns import HISTORICAL_RULE_PATTERNS as _HISTORICAL_RULE_PATTERNS
from ._paths import _RULESET_VERSION_RE


def _config_dir():
    from . import CONFIG_DIR
    return CONFIG_DIR


def load_rules(*args, **kwargs):
    from . import load_rules as _load
    return _load(*args, **kwargs)


def shipped_rules(*args, **kwargs):
    from . import shipped_rules as _load
    return _load(*args, **kwargs)


def ensure_default_configs(*args, **kwargs):
    from . import ensure_default_configs as _ensure
    return _ensure(*args, **kwargs)


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
    "R012": {
        r"ignore\s+(?:all\s+)?previous\s+(?:instructions|commands|input)",
        # Pre-2026-10-16: alternative 8 fired on any model name within 60
        # chars of ignore/approve/skip, so a pkgdesc describing an LLM
        # tool ("local LLM watches sessions and decides what to approve")
        # scored FATAL.  The verb must now take an object.
        r"""\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|the\s+)*(?:previous|above|prior|earlier|preceding|foregoing|existing)\b|^[^\S\n]*(?:#[^\S\n]*)?(?:system|assistant)[^\S\n]*:[^\S\n]*\S|</?(?:system|instructions?|admin|prompt|assistant)\s*>|\byou\s+are\s+(?:an?|the)\s+[^.\n]{0,48}?(?:model|assistant|ai\b)|\bnew\s+instructions?\s*:|\bdo(?:\s+not|n['’]t)\s+(?:flag|warn|analy[sz]e|review|scan)\b|\bdo(?:\s+not|n['’]t)\s+report\s+(?:any\s+|the\s+)?(?:security|issues?|concerns?|problems?|findings?|warnings?|anything)\b|\b(?:mark|classify|report|treat|label|approve)\b[^.\n]{0,24}?\bas\s+(?:safe|benign|clean|harmless|trusted|ok)\b|\b(?:claude|chatgpt|gpt-?[0-9]?|copilot|gemini|llm|ai\s+assistant)\b[^.\n]{0,60}?\b(?:ignore|approve|skip|overlook|flag)\b""",
    },
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
    "R003": {
        r"base64.*(?:\-d|\-\-decode).*\|",
        r"base64.*(?:\-d|\-\-decode).*(?<!\\)\|",
    },
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
    # R046/R047 are generated from config, but an install that predates the
    # loopback/RFC1918/link-local exclusions still carries these older
    # spellings on disk.  Their detection is regenerated before matching, so
    # a stale spelling is inert; listing it lets `config sync-rules --update`
    # rewrite the stored text anyway.
    "R046": {r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"},
    "R047": {r'https?://[^/\s:]+:(?!(?:80|443|8080|8443)(?:[/\s"\x27]|$))\d{2,5}'},
    # R054 was narrowed to writes *outside* the package root.  A `$pkgdir`
    # staged unit is the package's own content (every daemon ships its
    # systemd unit that way); firing HIGH on it flagged ordinary packages.
    # The legacy pattern matched `$pkgdir` too, so it is listed here and
    # `config sync-rules --update` repairs an install that still carries it.
    "R054": {r'(?:\b(?:install|cp|mv|ln|tee|dd|rsync|mkdir|cat|printf|echo)\b|>)[^;&|\n]*?(?:[\s"\x27]|\$\{?pkgdir\}?)(?:(?:/etc/(?:cron\.[a-z]+|cron\.d|systemd/(?:system|user)|profile\.d|bash\.bashrc\.d|zsh(?:/zshrc\.d|rc\.d)|X11/(?:Xsession|xinit/xinitrc)\.d|xdg/autostart|dbus-1/(?:system|session)\.d|sudoers\.d|ld\.so\.conf\.d|pam\.d|security/pam_\w+\.conf|NetworkManager/dispatcher\.d|xinetd\.d|(?:init|rc)\.d|logrotate\.d|tmpfiles\.d|sysusers\.d|binfmt\.d|sysctl\.d|environment\.d|polkit-1/(?:rules|actions)\.d|polkit-1/(?:rules|actions)|skel|update-motd\.d|systemd/(?:system|user)-preset)|/usr/lib/systemd/(?:system|user)|/usr/lib/systemd/(?:system|user)-(?:generators|sleep|shutdown)|/usr/share/dbus-1/(?:system|session)-services|/var/spool/cron)/|(?:/etc/(?:rc\.local|profile|bash\.bashrc|ld\.so\.preload|environment|csh\.cshrc|zsh/(?:zshrc|zprofile|zshenv)|X11/xinit/xinitrc|X11/Xsession))(?![\w./-]))'},
}

# Patterns every earlier release shipped, extracted from the tags by
# scripts/build_legacy_shipped_patterns.py.  The hand-curated entries above
# carry the pre-history cases and their explanations; this closes the gap a
# hand-maintained list kept leaving when a release changed a pattern.
for _rule_id, _patterns in _HISTORICAL_RULE_PATTERNS.items():
    LEGACY_RULE_PATTERNS.setdefault(_rule_id, set()).update(_patterns)

def outdated_shipped_rules() -> list[str]:
    """Ids whose on-disk pattern is a superseded shipped pattern."""
    path = _config_dir() / "rules.toml"
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

    The ``pattern`` field is skipped for the ids in
    :data:`rules._compiled.GENERATED_PATTERN_RULES`: those patterns are
    regenerated before matching, so their on-disk text is inert and a
    difference there is not drift.
    """
    path = _config_dir() / "rules.toml"
    if not path.exists():
        return []
    # R013/R046/R047/R048/R152 carry a placeholder in TOML; their real
    # pattern is regenerated from Unicode data and config before matching
    # (`rules._compiled.resolve_generated_patterns`).  The on-disk `pattern`
    # therefore never affects what they detect, so a difference there is not
    # semantic drift and must not fail the run closed.
    from ..rules._compiled import GENERATED_PATTERN_RULES

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
            if field == "pattern" and rid in GENERATED_PATTERN_RULES:
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

    path = _config_dir() / "rules.toml"
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
    path = _config_dir() / "rules.toml"
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
