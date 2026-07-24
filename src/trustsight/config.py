import re
import tomllib
from pathlib import Path

CONFIG_DIR = Path.home() / ".config" / "trustsight"
DATA_DIR = Path.home() / ".local" / "share" / "trustsight"
CACHE_DIR = Path.home() / ".cache" / "trustsight" / "repos"

DEFAULT_CONFIG = """\
[severity_weights]
FATAL = 0
CRITICAL = 40
HIGH = 25
MEDIUM = 15
LOW = 5
INFO = 0

[source_bucket_weights]
trusted_forge = -10
official = 0
self_hosted = 10
raw_hosting = 15
unknown = 20
homograph_attack = 30

[novelty_weights]
# Calibrated once tier C actually became live.  The previous 10/15/20 was
# set while maturity was permanently 0, so the weights had never been
# exercised: at full maturity a novel URL plus a novel maintainer took a
# borderline 15-point package to 60 (High).  These values keep that case
# in Medium (45) while leaving maintainer novelty the strongest signal,
# since a maintainer change is the xz-utils attack vector.
url_first_in_package = 5
url_first_globally = 10
maintainer_first_in_package = 15

[llm]
provider = "openai"
model = "gpt-4o-mini"
enabled = true
max_tokens = 1024
temperature = 0.3
top_p = 1
seed = 42

[llm.openai]
api_key = ""
base_url = "https://api.openai.com/v1"

[llm.ollama]
url = "http://localhost:11434/v1"

[deep]
enabled = false
threshold = 80

[diff]
max_context_lines = 3
max_diff_chars_for_llm = 2000
max_diff_bytes = 5242880

[limits]
default_review_limit = 20

[seed]
# Import the bundled novelty seed the first time TrustSight runs against
# an empty database.  Without it every source URL looks novel and
# maturity stays at zero, which downgrades every Medium verdict to
# INCONCLUSIVE.  The seed is public AUR data and is additive; it can
# never overwrite something learned from a real analysis.
auto_import = true

[rules]
# Run rules marked experimental in rules.toml.  The R039+ set is now
# calibrated and runs unconditionally; this gates future additions whose
# false-positive rate has not been measured yet.
experimental = false

[verification_evidence]
checksum_present = -10
validpgpkeys_declared = -10
gpg_verify_present = -5

[pinning_weights]
checksum_pinned = -5
tag_pinned = -3
branch_pinned = 0
unpinned = 0
"""

DEFAULT_RULES = """\
[[rules]]
id = "R001"
name = "Remote Script Execution"
pattern = 'curl.*\\|\\s*(?:/bin/)?(?:bash|sh|python|zsh|dash|busybox\\s+sh|source\\s+/dev/stdin)'
severity = "CRITICAL"
category = "network_execution"
match_target = "resolved"

[[rules]]
id = "R002"
name = "Wget Pipe to Shell"
pattern = 'wget.*\\|\\s*(?:/bin/)?(?:bash|sh|python|zsh|dash|busybox\\s+sh|source\\s+/dev/stdin)'
severity = "CRITICAL"
category = "network_execution"
match_target = "resolved"

[[rules]]
id = "R003"
name = "Base64 Decode and Execute"
pattern = 'base64.*(?:\\-d|\\-\\-decode).*\\|'
severity = "CRITICAL"
category = "obfuscation"
match_target = "resolved"

[[rules]]
id = "R006"
name = "Insecure Download Protocol"
pattern = 'https?://.*\\.tar\\.gz.*\\|'
severity = "MEDIUM"
category = "network_execution"
match_target = "resolved"

[[rules]]
id = "R007"
name = "Install File Modification"
pattern = '\\+.*\\.install.*'
severity = "MEDIUM"
category = "installer"
match_target = "raw_line"

[[rules]]
id = "R008"
name = "Unexpected File Download"
pattern = '\\b(python|ruby|perl)\\s+-c\\s+https?://'
severity = "HIGH"
category = "network_execution"
match_target = "resolved"

[[rules]]
id = "R009"
name = "Privilege Escalation"
pattern = '\\bsudo\\b'
severity = "CRITICAL"
category = "privilege"
match_target = "raw_line"
scope = ["function_body"]

[[rules]]
id = "R010"
name = "Uses curl in PKGBUILD"
pattern = '\\bcurl\\s'
severity = "LOW"
category = "network_usage"
match_target = "raw_line"
scope = ["function_body"]

[[rules]]
id = "R011"
name = "Uses wget in PKGBUILD"
pattern = '\\bwget\\s'
severity = "LOW"
category = "network_usage"
match_target = "raw_line"
scope = ["function_body"]

[[rules]]
id = "R012"
name = "LLM Prompt Injection"
pattern = 'ignore\\s+(?:all\\s+)?previous\\s+(?:instructions|commands|input)'
severity = "FATAL"
category = "injection"
match_target = "resolved"

[[rules]]
id = "R013"
name = "Unicode Bidi Override"
# Two alternatives with different rules about context.
#
# 1. Bidi overrides/isolates, invisible operators, and tag characters.
#    None has any legitimate use in a build recipe, so they fire
#    unconditionally.  Covers U+200E/200F and U+2060-2064 and the tag
#    block, which the previous pattern omitted.
#
# 2. Zero-width characters, but only between ASCII neighbours.  U+200B-
#    U+200D are mandatory joiners in Malayalam, Lao, Devanagari and
#    others: a localized 'GenericName[ml]=' line in a browser package
#    legitimately contains U+200D.  Firing FATAL on that scored benign
#    packages 100/100.  Requiring ASCII on both sides keeps the attack
#    (a joiner hidden inside an ASCII command or URL) and drops the
#    false positive.
pattern = '[\\u202A-\\u202E\\u2066-\\u2069\\u2060-\\u2064\\U000E0000-\\U000E007F]|(?<![^\\x00-\\x7F])[\\u200B-\\u200F\\uFEFF](?![^\\x00-\\x7F])'
severity = "FATAL"
category = "unicode"
match_target = "raw_line"

# ---------------------------------------------------------------------
# Expanded ruleset (R039+).
#
# Numbering starts at R039 because R014-R026 are already referenced by
# tests/fixtures/baseline.json and the malicious fixture generators.
# Reusing those ids would silently change what they mean.
#
# Calibrated against a 3322-diff stratified benign corpus.  Fourteen of
# these fire on zero benign diffs; every remaining hit was inspected and
# all but one were true positives (real setuid bits, real network access
# in pkgver(), real writes outside $pkgdir).  Enabling them costs 0.5pp
# of zero-rate and leaves p95 unchanged, so they run by default.
#
# The experimental flag remains supported for future additions: set
# experimental = true on a rule and it is skipped unless
# [rules] experimental = true in config.toml.
#
# raw_line rules set added_only = true.  Raw diff lines include removals,
# so without it a maintainer *deleting* a suspicious line would raise the
# package's score.
# ---------------------------------------------------------------------

# --- Execution and obfuscation ---

[[rules]]
id = "R039"
name = "Eval With Dynamic Content"
pattern = '\\beval\\s+(?:"|\\$\\(|\\$\\{|`|\\$[a-zA-Z_])'
severity = "CRITICAL"
category = "execution"
match_target = "resolved"

[[rules]]
id = "R040"
name = "Shell -c With Dynamic Payload"
pattern = '\\b(?:bash|sh|zsh|dash)\\s+-c\\s+(?:\\$\\(|`|\\$\\{|"[^"]*\\$)'
severity = "CRITICAL"
category = "execution"
match_target = "resolved"

[[rules]]
id = "R041"
name = "Shell Network Redirection"
pattern = '/dev/(?:tcp|udp)/'
severity = "CRITICAL"
category = "network_execution"
match_target = "resolved"

[[rules]]
id = "R042"
name = "Download Then Execute"
pattern = '(?:curl|wget)\\s+[^;&|]*-o\\s*\\S+[^;&|]*(?:&&|;)\\s*(?:chmod\\s+\\+x[^;&|]*(?:&&|;)\\s*)?(?:\\./|/tmp/|bash\\s|sh\\s)'
severity = "CRITICAL"
category = "execution"
match_target = "resolved"

[[rules]]
id = "R043"
name = "Base64 Blob Decode"
pattern = 'base64\\s+(?:-d|--decode)\\s*(?:<<<|<<\\w*|\\$\\{?[a-zA-Z_])'
severity = "CRITICAL"
category = "obfuscation"
match_target = "resolved"

[[rules]]
id = "R044"
name = "Interpreter One-Liner With Network"
pattern = '\\b(?:python3?|perl|ruby)\\s+-e\\s+.*(?:socket|urllib|urlopen|Net::|LWP|open-uri|https?://)'
severity = "HIGH"
category = "network_execution"
match_target = "resolved"

[[rules]]
id = "R045"
name = "Binary Encoding Pipe"
pattern = '\\b(?:xxd|uudecode)\\s+[^|]*\\|'
severity = "MEDIUM"
category = "obfuscation"
match_target = "resolved"

# --- Source provenance ---

[[rules]]
id = "R046"
name = "Source URL Uses IP Address"
pattern = 'https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}'
severity = "MEDIUM"
category = "network"
match_target = "raw_line"
added_only = true

[[rules]]
id = "R047"
name = "Source URL Uses Non-Standard Port"
pattern = 'https?://[^/\\s:]+:(?!(?:80|443|8080|8443)(?:[/\\s"\\x27]|$))\\d{2,5}'
severity = "LOW"
category = "network"
match_target = "raw_line"
added_only = true

[[rules]]
id = "R048"
name = "Source URL On Free Registrar TLD"
pattern = 'https?://[^/\\s]*\\.(?:tk|ml|ga|cf|gq|pw)(?:[:/]|["\\x27\\s)]|$)'
severity = "LOW"
category = "network"
match_target = "raw_line"
added_only = true

# --- Build-time weakening ---

[[rules]]
id = "R049"
name = "Compiler Plugin Or Loader Override"
pattern = '\\b(?:CFLAGS|CXXFLAGS|LDFLAGS)\\s*\\+?=.*(?:-fplugin=|-Wl,--dynamic-linker=)'
severity = "MEDIUM"
category = "build"
match_target = "raw_line"
added_only = true

[[rules]]
id = "R050"
name = "Compiler Hardening Disabled"
pattern = '\\b(?:CFLAGS|CXXFLAGS|LDFLAGS)\\s*\\+?=.*(?:-fno-stack-protector|-z\\s*execstack)'
severity = "MEDIUM"
category = "build"
match_target = "raw_line"
added_only = true

# --- Packaging subterfuge ---

[[rules]]
id = "R051"
name = "Network Access In pkgver"
pattern = '\\b(?:curl|wget|git\\s+(?:clone|fetch|pull|ls-remote)|svn\\s+(?:co|checkout)|hg\\s+pull)\\b'
severity = "HIGH"
category = "packaging"
match_target = "raw_line"
scope = ["pkgver"]
added_only = true

[[rules]]
id = "R052"
name = "Dotfile Written To User Profile"
pattern = '\\b(?:install|cp|mv|tee)\\s+[^;&|]*(?:\\$HOME|~|/root|/home/[^/\\s]+)/\\.\\w+'
severity = "HIGH"
category = "persistence"
match_target = "raw_line"
# Everything except "message": an echo telling the user to run
# `cp ... ~/.zshrc` is an instruction, not a write.
scope = ["function_body", "other"]
added_only = true

[[rules]]
id = "R053"
name = "Setuid Or Setgid Bit Set In Package Root"
# Setuid on a path being staged into the package.  Chromium's sandbox
# helper legitimately needs 4755, so this fires on every Electron
# package; measured across the benign corpus it changes no package's
# risk band at MEDIUM, which keeps the evidence visible without
# reclassifying ordinary updates.
pattern = '\\bchmod\\s+(?:-\\S+\\s+)*(?:[2467][0-7]{3}\\b|[ugoa]*\\+s\\b)\\s+(?!["\\x27]?/)'
severity = "MEDIUM"
category = "privilege"
match_target = "raw_line"
added_only = true

[[rules]]
id = "R059"
name = "Setuid Or Setgid Bit Set Outside Package Root"
# The same operation against an absolute path touches the live
# filesystem rather than $pkgdir, so it is a privilege change on the
# build host and not packaging.
pattern = '\\bchmod\\s+(?:-\\S+\\s+)*(?:[2467][0-7]{3}\\b|[ugoa]*\\+s\\b)\\s+["\\x27]?/'
severity = "HIGH"
category = "privilege"
match_target = "raw_line"
added_only = true

[[rules]]
id = "R054"
name = "Persistence Unit Outside Package Root"
pattern = '[\\s"\\x27](?:/etc/(?:cron\\.[a-z]+|cron\\.d|systemd/system)|/usr/lib/systemd/system|/var/spool/cron)/'
severity = "HIGH"
category = "persistence"
match_target = "raw_line"
scope = ["function_body", "other"]
added_only = true

[[rules]]
id = "R055"
name = "Git Clone With Variable Branch"
pattern = 'git\\s+clone\\s+[^;&|]*(?:--branch|-b)\\s+\\$\\{?[a-zA-Z_]'
severity = "MEDIUM"
category = "source"
match_target = "resolved"

[[rules]]
id = "R056"
name = "Download Then Source"
pattern = '(?:curl|wget)\\s+[^;&|]*-o\\s*\\S+[^;&|]*(?:&&|;)\\s*(?:source|\\.)\\s'
severity = "CRITICAL"
category = "execution"
match_target = "resolved"

# --- Transport security ---

[[rules]]
id = "R057"
name = "TLS Verification Disabled"
pattern = '(?:curl\\s+(?:[^;&|]*\\s)?(?:--insecure|-k)\\b|wget\\s+(?:[^;&|]*\\s)?--no-check-certificate\\b)'
severity = "HIGH"
category = "network"
match_target = "resolved"

[[rules]]
id = "R058"
name = "Write Outside Package Root"
# The command must be the first token on the line, so that an absolute
# path quoted inside an echo string does not count as a write.  The
# lookbehinds require the path to start an argument: this rejects the
# ubiquitous "${pkgdir}"/usr/lib/... idiom, where the quote closing the
# variable would otherwise look like an argument boundary.
pattern = '^\\+?\\s*(?:sudo\\s+)?(?:install|cp|mv|dd|tee)\\s+[^;&|]*(?:(?<=\\s)|(?<=\\s["\\x27]))(?:/etc|/boot|/usr/bin|/usr/lib)/'
severity = "HIGH"
category = "system"
match_target = "raw_line"
added_only = true
"""

DEFAULT_DOMAINS = """\
[trusted_forges]
domains = ["github.com", "gitlab.com", "codeberg.org", "bitbucket.org"]

[official_projects]
domains = [
    "downloads.apache.org",
    "nginx.org",
    "python.org",
    "ftp.gnu.org",
    "kernel.org",
    "dl.google.com",
    "get.videolan.org",
    "download.qt.io",
    "nodejs.org",
    "rubygems.org",
    "pypi.org",
    "crates.io",
    "registry.npmjs.org",
    "archive.archlinux.org",
    "static.rust-lang.org",
]

[raw_hosting]
domains = [
    "raw.githubusercontent.com",
    "pastebin.com",
    "gist.github.com",
    "paste.ee",
    "0x0.st",
    "termbin.com",
    # Ephemeral paste and file-drop services.  These belong here rather
    # than in a detection rule: bucket classification already carries a
    # weight for them, and a rule would double-count the same evidence.
    "hastebin.com",
    "ix.io",
    "transfer.sh",
    "file.io",
    "bashupload.com",
    "temp.sh",
    "anonfiles.com",
    "dpaste.com",
    "sprunge.us",
]
"""


def ensure_dirs():
    for d in (CONFIG_DIR, DATA_DIR, CACHE_DIR):
        d.mkdir(parents=True, exist_ok=True)


def write_default_file(path: Path, content: str):
    if not path.exists():
        path.write_text(content)


def ensure_default_configs():
    ensure_dirs()
    write_default_file(CONFIG_DIR / "config.toml", DEFAULT_CONFIG)
    write_default_file(CONFIG_DIR / "rules.toml", DEFAULT_RULES)
    write_default_file(CONFIG_DIR / "trusted_domains.toml", DEFAULT_DOMAINS)


def load_toml(name: str) -> dict:
    path = CONFIG_DIR / name
    if not path.exists():
        ensure_default_configs()
    with open(path, "rb") as f:
        return tomllib.load(f)


def _toml_value(val: str) -> str:
    if val.lower() in ("true", "false"):
        return val.lower()
    try:
        int(val)
        return val
    except ValueError:
        pass
    escaped = val.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def set_config(key: str, value: str):
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
        import re
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


# Patterns this project shipped in earlier releases, per rule id.  A rule
# on disk whose pattern matches one of these is untouched by the user, so
# replacing it is safe.  A rule whose pattern matches neither the current
# default nor a legacy entry has been customised and is never overwritten.
#
# This exists because rules.toml is written once, at install time.  A
# correctness fix to a shipped pattern otherwise never reaches anyone who
# already has the file.
LEGACY_RULE_PATTERNS: dict[str, set[str]] = {
    # Pre-0.2.1: fired FATAL on U+200B-U+200D regardless of context, so a
    # localized desktop entry in a benign package scored 100/100.
    "R013": {r"[\u202A-\u202E\u2066-\u2069\u200B-\u200D\uFEFF]"},
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


def missing_shipped_rules() -> list[str]:
    """Ids present in ``DEFAULT_RULES`` but absent from the user's file.

    ``write_default_file`` only writes when the file does not exist, so an
    install that predates a rule addition never receives it.  Without this
    check, enabling a new rule in ``config.toml`` silently does nothing.
    """
    path = CONFIG_DIR / "rules.toml"
    if not path.exists():
        return []
    existing = {r.get("id") for r in load_rules()}
    return [rid for rid in _rule_blocks(DEFAULT_RULES) if rid not in existing]


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
    is set **and** its current pattern is one this project shipped before
    (meaning the user never edited it).  Customised rules are left alone.

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
        for rid in outdated_shipped_rules():
            text = _replace_rule_block(text, rid, blocks[rid])
            updated.append(rid)

    added = missing_shipped_rules()
    for rid in added:
        text += "\n" + blocks[rid]

    if added or updated:
        path.write_text(text)
    return added, updated


def load_config() -> dict:
    return load_toml("config.toml")


def load_rules() -> list[dict]:
    data = load_toml("rules.toml")
    return data.get("rules", [])


def load_domains() -> dict:
    return load_toml("trusted_domains.toml")
