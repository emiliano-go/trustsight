import copy
import re
from pathlib import Path

import tomllib

CONFIG_DIR = Path.home() / ".config" / "trustsight"
DATA_DIR = Path.home() / ".local" / "share" / "trustsight"
CACHE_DIR = Path.home() / ".cache" / "trustsight" / "repos"

# ---------------------------------------------------------------------------
# Default data for the pattern/naming tables.  These live in code so the
# shipped .toml can be regenerated from them; an edit on disk overrides the
# code default for a running install.  The accessors in this module and the
# consumers in build.py/deps.py/novelty.py/dependencies.py always fall back
# to these when a config value is absent.
# ---------------------------------------------------------------------------

# R081 — foreign package managers invoked from an install hook.  Each entry
# is a case-insensitive regex fragment matched against reconstructed text.
DEFAULT_FOREIGN_PKG_MANAGERS = [
    r"\b(?:pip|pip3)\s+install\b",
    r"\bnpm\s+(?:install|add)\b",
    r"\bbun\s+(?:install|add)\b",
    r"\bpnpm\s+(?:install|add)\b",
    r"\byarn\s+(?:install|add)\b",
    r"\bcargo\s+install\b",
    r"\bgem\s+install\b",
    r"\bgo\s+install\b",
    r"\bdnf\s+install\b",
    r"\byum\s+install\b",
    r"\bpacman\s+-[SU]\b",
    r"\bapt(?:-get)?\s+install\b",
    r"\bmake\s+install\b(?!\s+DESTDIR)",
]

# R082 — obfuscation indicators counted on a single raw line.  A line
# carrying at least ``[thresholds] r082_obfuscation_density`` distinct
# forms fires; the reconstruction rules (R117) decide whether the line is
# inert or reveals an executable action.
DEFAULT_OBFUSCATION_INDICATORS = [
    r"base64.*(?:-d|--decode)",
    r"printf\s+['\"]\\x",
    r"\$\(|`",
    r"\beval\b",
    r"\|.*(?:bash|sh|zsh)\b",
    r"(?:bit\.ly|t\.co|tinyurl|shorturl|ow\.ly|is\.gd)",
    r"wget\s+-q\s+-O\s*-\s*\|",
    r"\$\{[a-zA-Z_][a-zA-Z0-9_]*\}.*(?:curl|wget|bash|sh)",
    # June-W3 campaign markers (confirmed campaign indicators): ANSI-C
    # quoting, variable indirection, empty-quote concatenation.
    r"\$'",
    r"\$\{!",
    r"(?<=\w)''(?=\w)",
]

# R119 — anti-analysis probes run from a build/install function.  A build
# recipe that checks whether it is being debugged, virtualized, sandboxed, or
# running on CI has no packaging purpose: it is probing its environment to
# decide whether to deploy a payload.  Each entry is a case-insensitive regex
# fragment matched against reconstructed text.  Legitimate arch/feature checks
# (`uname -m`, `getconf`) never match these fragments.
DEFAULT_ANTI_ANALYSIS_PROBES = [
    r"TracerPid",                                   # /proc/self/status debugger marker
    r"\b(?:gdb|strace|lldb|ptrace)\b",              # debugger clients / probe interfaces
    r"systemd-detect-virt",
    r"virt-what",
    r"\bdmidecode\b",
    r"hypervisor",                                  # DMI / /proc/cpuinfo virtualization marker
    r"/\.dockerenv|/run/\.containerenv",            # container sandbox markers
    r"\$\{?(?:CI|GITHUB_ACTIONS|GITLAB_CI|TRAVIS|JENKINS_URL|BUILD_ID|BUILD_NUMBER|CIRCLECI|TF_BUILD|CONTAINER)\}?",
]

# D003 — package names that grant network access from makedepends.
DEFAULT_NETWORK_TOOLS = [
    "curl", "wget", "aria2", "git", "subversion", "mercurial", "rsync",
    "python-requests", "python-httpx", "python-urllib3", "python-aiohttp",
    "ruby-net-http", "nodejs", "npm", "yarn", "cargo", "go",
]

# Suffixes that mark a variant of the same upstream project rather than a
# different project (D002/D004 relatedness).
DEFAULT_VARIANT_SUFFIXES = (
    "-git", "-bin", "-svn", "-hg", "-bzr", "-cvs", "-nightly",
    "-beta", "-stable", "-lts", "-devel",
)

# Prefixes shared by thousands of unrelated packages.  Two names both
# starting with "python-" say nothing about a common project, so these must
# never be treated as evidence of relatedness (D004).
DEFAULT_ECOSYSTEM_PREFIXES = [
    "python", "python2", "python3", "perl", "ruby", "rust", "golang", "go",
    "php", "lua", "nodejs", "node", "js", "haskell", "ocaml", "texlive",
    "r", "vim", "emacs", "ttf", "otf", "font", "fonts", "lib", "lib32",
    "mingw", "aur", "sh",
]

# Suffixes denoting expected package variants (fork, build, packaging mode)
# rather than typosquats.  Stripped before edit-distance comparison so that
# ``foo-git``, ``foo-bin``, ``foo-lts`` are never confused with the real
# ``foo`` (R074).
DEFAULT_KNOWN_SUFFIXES = (
    "-git", "-bin", "-debug", "-lts", "-stable", "-beta",
    "-svn", "-hg", "-bzr", "-cvs",
    "-wine", "-appimage", "-flatpak", "-nightly", "-devel", "-common",
)

# Paste and ephemeral file-drop hosts (R087).  Bucket classification in
# trusted_domains.toml [raw_hosting] already weights these.
DEFAULT_PASTE_HOSTS = [
    "pastebin.com", "gist.github.com", "paste.ee", "0x0.st", "termbin.com",
    "hastebin.com", "ix.io", "transfer.sh", "file.io", "bashupload.com",
    "temp.sh", "anonfiles.com", "dpaste.com", "sprunge.us",
]

# Standard ports excluded from R047 (source URL uses non-standard port).
DEFAULT_STANDARD_PORTS = [80, 443, 8080, 8443]

# Free-registrar TLDs flagged by R048 (source URL on free registrar TLD).
DEFAULT_FREE_REGISTRAR_TLDS = ["tk", "ml", "ga", "cf", "gq", "pw"]

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

[deep]
enabled = false
threshold = 80

[diff]
max_context_lines = 3
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

[discovery]
# Default repositories to scan when no --repo/--foreign/--all-repos CLI
# flags are given.  Only packages found on the AUR are reviewed.
default_repos = []
include_foreign = false
all_repos = false
# When reviewing with --all, include packages not found in the AUR
# metadata snapshot (orphaned, very new, removed from AUR, etc.).
# Set to false to skip unmatched packages entirely.
show_unmatched = true
# Minutes before the AUR RPC response cache expires.  A repeat review
# within this window reuses cached version data instead of re-querying
# the AUR server.  Set to 0 to disable caching entirely.
cache_ttl_minutes = 60

[rules]
# Run rules marked experimental in rules.toml.  The R039+ set is now
# calibrated and runs unconditionally; this gates future additions whose
# false-positive rate has not been measured yet.
experimental = false

[experimental_rules]
# Rules emitted from code rather than rules.toml, so the [rules]
# experimental flag above cannot reach them.  All default to true since
# v0.7.0 after each was measured against the 3246-diff benign corpus
# (see docs/explanation/fire-rates.md).
#
# D001  novel dependency: a name never seen anywhere in the AUR
# D002  typosquatted dependency: a novel name one or two edits from a
#       popular one (refines D001, so enabling it alone is meaningful)
# D003  new network-using makedepends: the build can now fetch code that
#       no checksum covers
# D004  provides/replaces claims an established, unrelated package, which
#       installs this package in front of it
# R061  a download inside build() whose URL is not in source=()
# R062  a .install hook, which runs as root, fetches or executes
# R063  a patch applied from outside the build tree (a URL, an absolute
#       path, or process substitution)
# R064  a source= URL downgraded from https to http
D001 = true
D002 = true
D003 = true
D004 = true
R061 = true
R062 = true
R063 = true
R064 = true

# R060 reports that a critical build function was modified.  It is INFO
# severity, so it carries weight 0 and cannot move a score: it fires on
# 21.4% of benign diffs and is context for a reviewer, not a signal.  That
# is why it is the one rule here safe to leave on.
R060 = true

[verification_evidence]
checksum_present = -10
validpgpkeys_declared = -10
gpg_verify_present = -5

[pinning_weights]
checksum_pinned = -5
tag_pinned = -3
branch_pinned = 0
unpinned = 0

[ports]
# Standard ports excluded from R047 (source URL uses non-standard port).
standard = [80, 443, 8080, 8443]

[domains]
# Free-registrar TLDs flagged by R048 (source URL on free registrar TLD).
free_registrar_tlds = ["tk", "ml", "ga", "cf", "gq", "pw"]

[tools]
# Package names that grant network access in makedepends (D003).
network_makedepends = [
    "curl", "wget", "aria2", "git", "subversion", "mercurial", "rsync",
    "python-requests", "python-httpx", "python-urllib3", "python-aiohttp",
    "ruby-net-http", "nodejs", "npm", "yarn", "cargo", "go",
]
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

# R006 is now a structural rule (src/trustsight/analysis/structural.py):
# fires on http:// added sources when no checksum was also added.

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
scope = ["function_body", "other"]
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
scope = ["function_body", "other"]
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
scope = ["function_body", "other"]
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
    """Create config, data, and cache directories if missing"""
    for d in (CONFIG_DIR, DATA_DIR, CACHE_DIR):
        d.mkdir(parents=True, exist_ok=True)


def write_default_file(path: Path, content: str):
    """Write a default file to disk if it does not exist"""
    if not path.exists():
        path.write_text(content)


def ensure_default_configs():
    """Write default config files if they do not exist"""
    ensure_dirs()
    write_default_file(CONFIG_DIR / "config.toml", DEFAULT_CONFIG)
    write_default_file(CONFIG_DIR / "rules.toml", DEFAULT_RULES)
    write_default_file(CONFIG_DIR / "trusted_domains.toml", DEFAULT_DOMAINS)
    write_default_file(CONFIG_DIR / "hosts.toml", DEFAULT_HOSTS)
    write_default_file(CONFIG_DIR / "patterns.toml", DEFAULT_PATTERNS)
    write_default_file(CONFIG_DIR / "naming.toml", DEFAULT_NAMING)
    write_default_file(CONFIG_DIR / "thresholds.toml", DEFAULT_THRESHOLDS)
    write_default_file(CONFIG_DIR / "iocs.toml", DEFAULT_IOCS)


# Parsed TOML keyed by (path, mtime_ns, size).  load_domains() used to be
# called once per source URL and load_rules() once per analysis, each one
# re-reading and re-parsing the file.  Including the stat in the key means
# an edit on disk is still picked up on the next call.
_toml_cache: dict[str, tuple[tuple, dict]] = {}


def load_toml(name: str) -> dict:
    """Load and parse a TOML file from the config directory"""
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
            return copy.deepcopy(cached[1])
    with open(path, "rb") as f:
        data = tomllib.load(f)
    if stamp is not None:
        _toml_cache[name] = (stamp, copy.deepcopy(data))
    return data


def _toml_escape_str(val: str) -> str:
    """Escape a string for use as a TOML basic string value."""
    escaped = val.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    return f'"{escaped}"'


def _toml_str_list(values) -> str:
    """Render a list of values as a multi-line TOML array."""
    return "[\n" + "".join(f"    {_toml_value(v)},\n" for v in values) + "]"


def _toml_value(val) -> str:
    """format a value for TOML output"""
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, str):
        if val.lower() in ("true", "false"):
            return val.lower()
        try:
            int(val)
            return val
        except ValueError:
            pass
        return _toml_escape_str(val)
    return str(val)


DEFAULT_PATTERNS = (
    "[patterns]\n"
    "# R081 — foreign package managers invoked from an install hook.  A\n"
    "# PKGBUILD that hands installation to another package manager installs\n"
    "# that payload outside pacman's control and its checksums.  Each entry\n"
    "# is a case-insensitive regex fragment matched against reconstructed\n"
    "# text.\n"
    "foreign_pkg_managers = " + _toml_str_list(DEFAULT_FOREIGN_PKG_MANAGERS) + "\n"
    "\n"
    "# R082 — obfuscation indicators counted on a single raw line.  A line\n"
    "# carrying at least [thresholds] r082_obfuscation_density distinct\n"
    "# forms fires; the reconstruction rules (R117) decide whether the\n"
    "# resolved line reveals an executable action.\n"
    "obfuscation_indicators = " + _toml_str_list(DEFAULT_OBFUSCATION_INDICATORS) + "\n"
    "\n"
    "# R119 — anti-analysis probes run from a build/install function.  A build\n"
    "# recipe checking whether it is being debugged, virtualized, sandboxed, or\n"
    "# running on CI has no packaging purpose.  Each entry is a regex fragment\n"
    "# matched against reconstructed text; legitimate arch/feature checks\n"
    "# (uname -m, getconf) never match these.\n"
    "anti_analysis_probes = " + _toml_str_list(DEFAULT_ANTI_ANALYSIS_PROBES) + "\n"
    "\n"
    "# D003 — package names that grant network access from makedepends.  A\n"
    "# new network-capable build dependency is code the checksum array does\n"
    "# not cover.\n"
    "network_tools = " + _toml_str_list(DEFAULT_NETWORK_TOOLS) + "\n"
)

DEFAULT_NAMING = (
    "[naming]\n"
    "# Suffixes that mark a variant of the same upstream project rather than\n"
    "# a different project (D002/D004 relatedness).\n"
    "variant_suffixes = " + _toml_str_list(DEFAULT_VARIANT_SUFFIXES) + "\n"
    "\n"
    "# Prefixes shared by thousands of unrelated packages; never evidence of\n"
    "# a common project (D004).\n"
    "ecosystem_prefixes = " + _toml_str_list(DEFAULT_ECOSYSTEM_PREFIXES) + "\n"
    "\n"
    "# Suffixes denoting expected package variants, stripped before\n"
    "# edit-distance comparison so foo-git is never confused with foo\n"
    "# (R074).\n"
    "known_suffixes = " + _toml_str_list(DEFAULT_KNOWN_SUFFIXES) + "\n"
)

DEFAULT_HOSTS = (
    "[hosts]\n"
    "# Paste and ephemeral file-drop hosts (R087).  Bucket classification\n"
    "# in trusted_domains.toml [raw_hosting] already weights these; this\n"
    "# list backs the dedicated detection rule shipped with R087.\n"
    "paste_hosts = " + _toml_str_list(DEFAULT_PASTE_HOSTS) + "\n"
    "\n"
    "# Standard ports excluded from R047 (source URL uses non-standard port).\n"
    "standard_ports = " + _toml_str_list(DEFAULT_STANDARD_PORTS) + "\n"
    "\n"
    "# Free-registrar TLDs flagged by R048 (source URL on free registrar TLD).\n"
    "free_registrar_tlds = " + _toml_str_list(DEFAULT_FREE_REGISTRAR_TLDS) + "\n"
)

DEFAULT_THRESHOLDS = (
    "[r082]\n"
    "# R082 fires when a single line carries at least this many distinct\n"
    "# obfuscation indicators from [patterns] obfuscation_indicators.\n"
    "obfuscation_density = 3\n"
)

DEFAULT_IOCS = (
    "[iocs]\n"
    "# R106 — exact-match indicators, each with provenance and a confidence\n"
    "# tier.  Populated by the phase that ships R106.\n"
    "version = 1\n"
    "entries = []\n"
)


def set_config(key: str, value: str):
    """Set a config key to a new value in config.toml"""
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


# Fields whose drift from the shipped definition changes what a rule
# detects rather than merely how it reads.
_SEMANTIC_FIELDS = ("match_target", "severity", "category")


def _shipped_rule_fields() -> dict[str, dict[str, str]]:
    """Parse the shipped rule blocks into ``{id: {field: value}}``."""
    parsed: dict[str, dict[str, str]] = {}
    for rid, block in _rule_blocks(DEFAULT_RULES).items():
        fields: dict[str, str] = {}
        for field in _SEMANTIC_FIELDS + ("pattern",):
            match = re.search(rf"^{field}\s*=\s*(.+)$", block, re.MULTILINE)
            if match:
                fields[field] = match.group(1).strip().strip("'\"")
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
    """Load the user config.toml"""
    return load_toml("config.toml")


def load_rules() -> list[dict]:
    """Load rules from rules.toml"""
    data = load_toml("rules.toml")
    return data.get("rules", [])


def _standard_port_pattern() -> str:
    """Generate the R047 non-standard-port exclusion pattern from config."""
    hosts = load_hosts().get("hosts", {})
    cfg = load_config()
    ports = (
        hosts.get("standard_ports")
        or cfg.get("ports", {}).get("standard")
        or DEFAULT_STANDARD_PORTS
    )
    joined = "|".join(str(p) for p in ports)
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
    joined = "|".join(tlds)
    return f'https?://[^/\\s]*\\.(?:{joined})(?:[:/]|["\\x27\\s)]|$)'


def load_domains() -> dict:
    """Load trusted domains from trusted_domains.toml"""
    return load_toml("trusted_domains.toml")


def load_patterns() -> dict:
    """Load pattern tables from patterns.toml (R081/R082/D003)."""
    return load_toml("patterns.toml")


def load_naming() -> dict:
    """Load naming tables from naming.toml (D002/D004/R074)."""
    return load_toml("naming.toml")


def load_hosts() -> dict:
    """Load host tables from hosts.toml (R047/R048/R087)."""
    return load_toml("hosts.toml")


def load_thresholds() -> dict:
    """Load thresholds from thresholds.toml (R082/R125/R126)."""
    return load_toml("thresholds.toml")


def load_iocs() -> dict:
    """Load the versioned indicator list from iocs.toml (R106)."""
    return load_toml("iocs.toml")
