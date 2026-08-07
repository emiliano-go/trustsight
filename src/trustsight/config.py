import copy
import logging
import re
from pathlib import Path

import tomllib

_log = logging.getLogger(__name__)

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

# R081 - foreign package managers invoked from an install hook.  Each entry
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

# R082 - obfuscation indicators counted on a single raw line.  A line
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

# R119 - anti-analysis probes run from a build/install function.  A build
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

# R086 - host-profiling commands run from a build/install function.  Host
# reconnaissance (who am I / what machine am I on) has no packaging purpose;
# it is the recon stage of the kill-chain R089 composes.  Each entry is a
# case-insensitive regex fragment matched against reconstructed text.  The
# leading command-position anchor means only a command invoked at the start
# of a line or after ; / && / || / | fires - bare mentions in strings, sed
# expressions and variable values never do.  `env`, `dmidecode` and
# `systemd-detect-virt` are excluded: `env VAR=val` is overwhelmingly benign,
# and the latter two already belong to R119.  Calibrated to zero benign
# fires across the 3,246-diff corpus.  A lone `uname -m` (arch check) fires
# R086 at INFO by design.
DEFAULT_RECON_COMMANDS = [
    r"(?:\A\s*|[;&|]\s*)uname\b",
    r"(?:\A\s*|[;&|]\s*)whoami\b",
    r"(?:\A\s*|[;&|]\s*)id\b",
    r"(?:\A\s*|[;&|]\s*)logname\b",
    r"(?:\A\s*|[;&|]\s*)getent\b",
    r"(?:\A\s*|[;&|]\s*)hostname\b",
    r"(?:\A\s*|[;&|]\s*)hostnamectl\b",
    r"/etc/machine-id",
    r"(?:\A\s*|[;&|]\s*)lscpu\b",
    r"(?:\A\s*|[;&|]\s*)lsblk\b",
    r"(?:\A\s*|[;&|]\s*)lspci\b",
    r"(?:\A\s*|[;&|]\s*)lsusb\b",
    r"(?:\A\s*|[;&|]\s*)inxi\b",
    r"(?:\A\s*|[;&|]\s*)neofetch\b",
    r"(?:\A\s*|[;&|]\s*)screenfetch\b",
    r"(?:\A\s*|[;&|]\s*)ip\s+addr\b",
    r"(?:\A\s*|[;&|]\s*)ifconfig\b",
    r"(?:\A\s*|[;&|]\s*)iwconfig\b",
    r"/proc/(?:cpuinfo|meminfo|version)",
    r"(?:\A\s*|[;&|]\s*)printenv\b",
]

# R129 - network clients invoked at parse time (top level of the PKGBUILD).
# makepkg sources the recipe before any build step runs, and `makepkg
# --printsrcinfo`, an AUR helper's metadata refresh and a plain `source
# PKGBUILD` all reach these lines.  Each entry is a regex fragment carrying a
# command-position anchor, so a name mentioned in a string, an array element
# or a comment never fires.
DEFAULT_PARSE_TIME_FETCH = [
    r"(?:\A\s*|[;&|]\s*|\$\()\s*curl\b",
    r"(?:\A\s*|[;&|]\s*|\$\()\s*wget\b",
    r"(?:\A\s*|[;&|]\s*|\$\()\s*aria2c\b",
    r"(?:\A\s*|[;&|]\s*|\$\()\s*axel\b",
    r"(?:\A\s*|[;&|]\s*|\$\()\s*lynx\b",
    r"(?:\A\s*|[;&|]\s*|\$\()\s*ncat\b",
    r"(?:\A\s*|[;&|]\s*|\$\()\s*nc\s+-",
    r"(?:\A\s*|[;&|]\s*|\$\()\s*scp\b",
    r"(?:\A\s*|[;&|]\s*|\$\()\s*sftp\b",
    r"(?:\A\s*|[;&|]\s*|\$\()\s*git\s+clone\b",
    r"(?:\A\s*|[;&|]\s*|\$\()\s*git\s+fetch\b",
    r"(?:\A\s*|[;&|]\s*|\$\()\s*svn\s+(?:co|checkout|export)\b",
    r"(?:\A\s*|[;&|]\s*|\$\()\s*hg\s+clone\b",
    r"(?:\A\s*|[;&|]\s*|\$\()\s*pip3?\s+install\b",
    r"(?:\A\s*|[;&|]\s*|\$\()\s*npm\s+(?:install|i|add)\b",
    r"(?:\A\s*|[;&|]\s*|\$\()\s*cargo\s+(?:install|fetch)\b",
    r"(?:\A\s*|[;&|]\s*|\$\()\s*go\s+(?:get|install)\b",
]

# D003 - package names that grant network access from makedepends.
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
# trusted_domains.toml [raw_hosting] already weights these *as source URLs*,
# which is why R087 does not look at source=(): it reads the other
# direction, an upload to one of these hosts from inside a build or install
# function, where no bucket applies and the data is leaving the machine.
DEFAULT_PASTE_HOSTS = [
    "pastebin.com", "gist.github.com", "paste.ee", "0x0.st", "termbin.com",
    "hastebin.com", "ix.io", "transfer.sh", "file.io", "bashupload.com",
    "temp.sh", "anonfiles.com", "dpaste.com", "sprunge.us",
]

# R087 - invocation shapes that *send* a request body rather than fetch one.
# Direction is the whole point of the rule: downloading from a gist is an
# undeclared fetch (R061), while uploading to one is data leaving the build
# machine.  Fragments are matched after the client name on a command-position
# line.
DEFAULT_UPLOAD_FLAGS = [
    r"-F\s",
    r"--form\b",
    r"-T\s",
    r"--upload-file\b",
    r"--data-binary\b",
    r"--data-raw\b",
    r"--data\b",
    r"-d\s",
    r"--post-file\b",
    r"--post-data\b",
    r"--method\s+(?:POST|PUT)\b",
    r"-X\s*(?:POST|PUT)\b",
]

# Source schemes allowed by R080 (source URL uses an exotic protocol).  A
# ``transport+base`` token like ``git+https`` is judged by its base scheme;
# only the base matters here.  Anything outside this allowlist is exotic.
DEFAULT_SOURCE_SCHEMES = [
    "https", "http", "ftp", "ftps", "ssh", "git", "hg", "svn", "bzr",
    "cvs", "file", "dav", "davs",
]

# Covert-egress / tunneling clients flagged by R123 when invoked from a
# build/install function.  These tools exist to move data over channels
# that bypass the normal network surface and have no packaging purpose.
# Kept out: `nc`/`telnet`/`ssh`/`tor` alone are too ambiguous for a static
# rule to call a covert channel with confidence.
DEFAULT_COVERT_EGRESS_CLIENTS = [
    r"(?:torsocks|torify|proxychains4?)\b",
    r"(?:ncat|socat|openvpn|wireguard)\b",
    r"(?:ngrok|frpc|frps|chisel|revsocks)\b",
    r"(?:iodine|dnscat2?)\b",
]

# DoH endpoints flagged by R123 (covert egress).  Encrypted DNS-over-HTTPS
# in a build/install function is a covert channel: it moves DNS queries, the
# one channel a build is not supposed to touch, out of the resolver's sight.
DEFAULT_COVERT_EGRESS_ENDPOINTS = [
    "dns.google", "cloudflare-dns.com", "dns.quad9.net",
    "doh.opendns.com", "dns.hostux.net", "mozilla.cloudflare-dns.com",
]

# Popular domains that R013b treats as homoglyph targets.  A script-mixed
# label is only a homoglyph when it is confusable with a configured target;
# a script-mixed label that reads as nothing configured is a real IDN, not
# an attack.
DEFAULT_CONFUSABLE_DOMAINS = [
    "github.com", "gitlab.com", "bitbucket.org", "google.com", "gmail.com",
    "youtube.com", "facebook.com", "twitter.com", "paypal.com", "amazon.com",
    "microsoft.com", "sourceforge.net", "archlinux.org", "aur.archlinux.org",
    "python.org", "npmjs.com", "crates.io", "mozilla.org", "debian.org",
    "gnu.org", "kernel.org", "stackoverflow.com", "wikipedia.org",
]

# Standard ports excluded from R047 (source URL uses non-standard port).
DEFAULT_STANDARD_PORTS = [80, 443, 8080, 8443]

# Free-registrar TLDs flagged by R048 (source URL on free registrar TLD).
DEFAULT_FREE_REGISTRAR_TLDS = ["tk", "ml", "ga", "cf", "gq", "pw"]

# R094 - security-relevant build flags, matched against the tokenized
# ``configure_flags`` property (full_aur/properties.py).  A hardening flag
# appearing or disappearing after a long-stable build is an attack-surface
# change the diff alone would not surface.
DEFAULT_SECURITY_RELEVANT_FLAGS = [
    "-fno-stack-protector",
    "-fstack-protector-strong",
    "-fstack-protector-all",
    "-fno-pie",
    "-no-pie",
    "-fno-pic",
    "-fno-PIC",
    "-fcf-protection",
    "-fstack-clash-protection",
    "-D_FORTIFY_SOURCE",
]

# R095 - security-relevant libraries.  Vendoring one of these (dropping the
# system dependency and pulling a source copy whose name matches) bypasses
# the distribution's security updates.
DEFAULT_SECURITY_RELEVANT_LIBRARIES = [
    "openssl", "libssl", "libcrypto", "openssl-1.1", "libressl",
    "gnutls", "nss", "nspr", "libgcrypt", "libsodium", "libcurl",
    "curl", "zlib", "libpng", "libjpeg", "libjpeg-turbo", "libtiff",
    "libxml2", "expat", "pcre", "pcre2", "sqlite", "libsqlite3",
    "icu", "libicu", "dbus", "libdbus", "pam", "libpam", "libsystemd",
    "libudev", "liblzma", "zstd", "libzstd",
]

DEFAULT_CONFIG = """\
[severity_weights]
FATAL = 0
CRITICAL = 40
HIGH = 25
MEDIUM = 15
LOW = 5
INFO = 0

[source_bucket_weights]
trusted_forge = 0
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
# Seconds libgit2 may spend connecting to, and waiting for data from, the
# AUR before it aborts a clone/fetch.  These are enforced inside libgit2's
# transport; without them a silently stalled connection hangs a worker
# thread forever, because the progress callbacks that carry TrustSight's
# own deadline only run while bytes are arriving.
network_connect_timeout = 10
network_transfer_timeout = 30
# Seconds the review prefetch phase waits for the whole batch.  What has
# not arrived by then is abandoned and fetched again during analysis.
prefetch_timeout = 120
# Seconds between cycles of `trustsight full-aur --watch`.  The AUR's own
# metadata dump is regenerated every few minutes, so anything under a
# minute only re-downloads the same snapshot; the floor is enforced.
watch_interval = 3600
watch_min_interval = 60

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

# R009 is now a code rule (src/trustsight/analysis/build.py): sudo at a
# command position inside a build/install function.  The regex form fired on
# any `sudo` mention in a function body - optdepends names, path segments
# and echo strings - which the code rule's position scoping eliminates.

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
# A PKGBUILD is increasingly read by a model, not only by a person, and
# text addressed to that reader has no packaging purpose whatsoever.
#
# The previous pattern matched one phrasing ("ignore previous
# instructions") and missed every other form the generator produces:
# role markers, tag-like injections, personas, suppression orders and
# pre-declared verdicts.  Eight alternatives now cover the family:
#
#   1. override    - ignore/disregard/forget the previous instructions
#   2. role        - a line that opens with 'system:' / 'assistant:'
#                    ('user:' is deliberately absent: a comment can
#                    legitimately open 'user: nobody', and a question
#                    addressed to a model carries no instruction)
#   3. tag         - <system>, <instructions>, <admin> markup
#   4. persona     - 'you are a helpful model that ...'
#   5. instruction - 'new instruction:'
#   6. suppress    - 'do not flag/warn/analyze/scan/review', and
#                    'do not report' only when the object is a finding
#                    ('do not report bugs to Arch' is ordinary prose)
#   7. verdict     - 'mark/classify/report ... as safe/benign/clean'
#   8. addressed   - a named model told to ignore/approve/skip
#
# include_comments is essential and not incidental: the payload is
# always a comment, and comment lines are filtered out for every rule
# that describes what the shell *executes*.
#
# Calibrated: 22/22 injection fixtures, 0 fires across 3,246 benign
# corpus diffs (every alternative measured separately).
pattern = '''\\b(?:ignore|disregard|forget|override|bypass)\\s+(?:all\\s+|any\\s+|the\\s+)*(?:previous|above|prior|earlier|preceding|foregoing|existing)\\s+(?:\\w+\\s+){0,2}(?:instructions?|commands?|input|context|rules?|prompts?|guidelines?|checks?)|^[^\\S\\n]*(?:#[^\\S\\n]*)?(?:system|assistant)[^\\S\\n]*:[^\\S\\n]*\\S|</?(?:system|instructions?|admin|prompt|assistant)\\s*>|\\byou\\s+are\\s+(?:an?|the)\\s+[^.\\n]{0,48}?(?:model|assistant|ai\\b)|\\bnew\\s+instructions?\\s*:|\\bdo(?:\\s+not|n['’]t)\\s+(?:flag|warn|analy[sz]e|review|scan)\\b|\\bdo(?:\\s+not|n['’]t)\\s+report\\s+(?:any\\s+|the\\s+)?(?:security|issues?|concerns?|problems?|findings?|warnings?|anything)\\b|\\b(?:mark|classify|report|treat|label|approve)\\b[^.\\n]{0,24}?\\bas\\s+(?:safe|benign|clean|harmless|trusted|ok)\\b|\\b(?:claude|chatgpt|gpt-?[0-9]?|copilot|gemini|llm|ai\\s+assistant)\\b[^.\\n]{0,60}?\\b(?:ignore|approve|skip|overlook|flag)\\b'''
severity = "FATAL"
category = "injection"
match_target = "resolved"
include_comments = true

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
#
# 3. Comments are scanned too (include_comments).  Hiding text from the
#    reader is the entire attack, and a comment is the one place in a
#    PKGBUILD whose only audience is a reader - excluding it left the
#    rule blind to its own threat model.
pattern = '[\\u202A-\\u202E\\u2066-\\u2069\\u2060-\\u2064\\U000E0000-\\U000E007F]|(?<![^\\x00-\\x7F])[\\u200B-\\u200F\\uFEFF](?![^\\x00-\\x7F])'
severity = "FATAL"
category = "unicode"
match_target = "raw_line"
include_comments = true

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


# The iocs.toml this project shipped before R106 existed: a placeholder with
# no schema, no tiers and no warning that a miss is uninformative.  An
# install that still carries it byte-for-byte has never been edited, so
# replacing it costs the user nothing and is the only way the documented
# schema reaches anyone who installed earlier.
LEGACY_IOCS_STUBS = frozenset({
    "[iocs]\n"
    "# R106 - exact-match indicators, each with provenance and a confidence\n"
    "# tier.  Populated by the phase that ships R106.\n"
    "version = 1\n"
    "entries = []\n"
})


def _refresh_legacy_iocs() -> bool:
    """Replace an untouched pre-R106 iocs.toml.  True when rewritten."""
    path = CONFIG_DIR / "iocs.toml"
    try:
        if path.read_text() in LEGACY_IOCS_STUBS:
            path.write_text(DEFAULT_IOCS)
            _toml_cache.pop("iocs.toml", None)
            return True
    except OSError:
        pass
    return False


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
    _refresh_legacy_iocs()


# Parsed TOML keyed by (path, mtime_ns, size).  load_domains() used to be
# called once per source URL and load_rules() once per analysis, each one
# re-reading and re-parsing the file.  Including the stat in the key means
# an edit on disk is still picked up on the next call.
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
    "# R081 - foreign package managers invoked from an install hook.  A\n"
    "# PKGBUILD that hands installation to another package manager installs\n"
    "# that payload outside pacman's control and its checksums.  Each entry\n"
    "# is a case-insensitive regex fragment matched against reconstructed\n"
    "# text.\n"
    "foreign_pkg_managers = " + _toml_str_list(DEFAULT_FOREIGN_PKG_MANAGERS) + "\n"
    "\n"
    "# R082 - obfuscation indicators counted on a single raw line.  A line\n"
    "# carrying at least [thresholds] r082_obfuscation_density distinct\n"
    "# forms fires; the reconstruction rules (R117) decide whether the\n"
    "# resolved line reveals an executable action.\n"
    "obfuscation_indicators = " + _toml_str_list(DEFAULT_OBFUSCATION_INDICATORS) + "\n"
    "\n"
    "# R119 - anti-analysis probes run from a build/install function.  A build\n"
    "# recipe checking whether it is being debugged, virtualized, sandboxed, or\n"
    "# running on CI has no packaging purpose.  Each entry is a regex fragment\n"
    "# matched against reconstructed text; legitimate arch/feature checks\n"
    "# (uname -m, getconf) never match these.\n"
    "anti_analysis_probes = " + _toml_str_list(DEFAULT_ANTI_ANALYSIS_PROBES) + "\n"
    "\n"
    "# R086 - host-profiling commands run from a build/install function.  Host\n"
    "# reconnaissance (who am I / what machine am I on) has no packaging\n"
    "# purpose; it is the recon stage of the kill-chain R089 composes.  Each\n"
    "# entry is a regex fragment matched against reconstructed text.  Fragments\n"
    "# carry a command-position anchor so bare mentions in strings, sed\n"
    "# expressions or variable values never fire; `env`, `dmidecode` and\n"
    "# systemd-detect-virt are deliberately absent (they belong to R119 or\n"
    "# produce benign false positives).  A lone `uname -m` fires R086 at INFO.\n"
    "recon_commands = " + _toml_str_list(DEFAULT_RECON_COMMANDS) + "\n"
    "\n"
    "\n"
    "# R087 - curl/wget invocation shapes that send a request body.  An\n"
    "# upload to a paste or file-drop host from a build or install function\n"
    "# is the exfil direction; a download from one is R061's undeclared\n"
    "# fetch.  Matched after the client name on a command-position line.\n"
    "upload_flags = " + _toml_str_list(DEFAULT_UPLOAD_FLAGS) + "\n"
    "\n"
    "# R129 - network clients invoked at parse time (the top level of the\n"
    "# PKGBUILD, outside every function).  makepkg sources the recipe before\n"
    "# any build step runs, so these lines execute on a metadata refresh, not\n"
    "# only on a build.  Fragments carry a command-position anchor.\n"
    "parse_time_fetch = " + _toml_str_list(DEFAULT_PARSE_TIME_FETCH) + "\n"
    "\n"
    "# D003 - package names that grant network access from makedepends.  A\n"
    "# new network-capable build dependency is code the checksum array does\n"
    "# not cover.\n"
    "network_tools = " + _toml_str_list(DEFAULT_NETWORK_TOOLS) + "\n"
    "\n"
    "# R094 - security-relevant build flags.  A hardening flag dropping out of\n"
    "# (or appearing in) a long-stable configure_flags set is an attack-surface\n"
    "# change that the diff alone would not surface.\n"
    "security_relevant_flags = " + _toml_str_list(DEFAULT_SECURITY_RELEVANT_FLAGS) + "\n"
    "\n"
    "# R095 - security-relevant libraries.  When a package stops depending on\n"
    "# one of these and starts vendoring a matching source copy, it bypasses\n"
    "# the distribution's security updates.\n"
    "security_relevant_libraries = " + _toml_str_list(DEFAULT_SECURITY_RELEVANT_LIBRARIES) + "\n"
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
    "# Source schemes allowed by R080 (source URL uses exotic protocol).\n"
    "source_schemes = " + _toml_str_list(DEFAULT_SOURCE_SCHEMES) + "\n"
    "\n"
    "# Covert-egress / tunneling clients invoked in build/install (R123).\n"
    "covert_egress_clients = " + _toml_str_list(DEFAULT_COVERT_EGRESS_CLIENTS) + "\n"
    "\n"
    "# DoH endpoints flagged by R123 (covert egress).\n"
    "covert_egress_endpoints = " + _toml_str_list(DEFAULT_COVERT_EGRESS_ENDPOINTS) + "\n"
    "\n"
    "# Popular domains that R013b treats as homoglyph targets.\n"
    "confusable_domains = " + _toml_str_list(DEFAULT_CONFUSABLE_DOMAINS) + "\n"
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
    "\n"
    "[r089]\n"
    "# R089 annotates a diff whose rule hits span at least this many distinct\n"
    "# kill-chain stages from the R089 stage map (recon, staging, persistence,\n"
    "# foreign_fetch, payload, install_hook, write_then_exec, obfuscation,\n"
    "# anti_analysis, hidden_drop, exfil, takeover, mass_adoption).\n"
    "attack_chain_stages = 3\n"
    "\n"
    "[r116]\n"
    "# R116 fires when a diff newly claims a provides/replaces entry naming a\n"
    "# package the corpus shows this many packages depend on (established,\n"
    "# official-repo membership fires regardless).\n"
    "widely_provided_observations = 25\n"
    "\n"
    "[r092]\n"
    "# R092 (mass adoption) fires when a single maintainer submits at least\n"
    "# this many packages with the whole cluster landing within this many days.\n"
    "# The no-baseline gate keeps it silent on a first bootstrap.\n"
    "min_packages = 10\n"
    "window_days = 7\n"
    "\n"
    "[r100]\n"
    "# R100 (shared source repo cluster) fires when at least this many\n"
    "# unrelated packages (distinct package bases) declare the same normalized\n"
    "# upstream source URL.\n"
    "min_packages = 3\n"
    "\n"
    "[r105]\n"
    "# R105 (attribute burst) fires when at least this many packages by one\n"
    "# maintainer are modified within this many hours.  Added packages are\n"
    "# excluded: R092 already claims the adoption clusters.\n"
    "min_packages = 5\n"
    "window_hours = 24\n"
    "\n"
    "[r125]\n"
    "# R125 (introduction-rate deviation) compares a cycle's new-package count\n"
    "# to the prior cycles; it only fires once this many prior cycles exist and\n"
    "# the rate exceeds the mean by at least this many standard deviations.\n"
    "min_history_cycles = 3\n"
    "z_score = 3.0\n"
    "min_introduced = 3\n"
    "\n"
    "[r126]\n"
    "# R126 (adopt-then-modify) fires on a package adopted this cycle whose\n"
    "# modify time still falls within this many days.\n"
    "window_days = 14\n"
    "\n"
    "[r107]\n"
    "# R107 (transitive exposure) only reports a package whose transitive\n"
    "# dependency closure reaches an adopted-from-orphan package at this many\n"
    "# hops or deeper.  Context only; weight 0.\n"
    "min_hops = 2\n"
    "\n"
    "[r111]\n"
    "# R111 (transitive orphan risk) only reports a package whose transitive\n"
    "# dependency closure reaches a currently-orphaned package at this many\n"
    "# hops or deeper.  Context only; weight 0.\n"
    "min_hops = 2\n"
    "\n"
    "[r112]\n"
    "# R112 (dependency centrality) flags a package depended on by at least\n"
    "# this many AUR packages.  Prioritisation only; weight 0.\n"
    "min_dependents = 50\n"
    "\n"
    "[r108]\n"
    "# R108 (maintainer baseline deviation) is maturity- and z-gated like R125,\n"
    "# but per maintainer against that maintainer's own prior activity.\n"
    "min_history_cycles = 3\n"
    "z_score = 2.0\n"
    "min_activity = 3\n"
    "\n"
    "[longitudinal]\n"
    "# R094-R098/R102/R083 gate on a property holding at least this many\n"
    "# consecutive observations before its break is reported.  Below it the\n"
    "# stability_weight is 0 and no PropertyBreak is emitted, so a cold or\n"
    "# immature database never fires the longitudinal rules.\n"
    "stability_floor = 10\n"
)

DEFAULT_IOCS = (
    "# R106 - Class E indicators of compromise.\n"
    "#\n"
    "# An entry is a confirmed artefact of a real incident: a package name\n"
    "# that was published as malware, a host a payload was fetched from, the\n"
    "# digest of a dropped binary.  R106 matches by exact equality and\n"
    "# nothing else - 'evil.example' does not match 'notevil.example' or\n"
    "# 'cdn.evil.example', and a truncated digest matches nothing.\n"
    "#\n"
    "# A MISS IS UNINFORMATIVE.  This list records what has already been\n"
    "# reported; it says nothing about a package it does not name.  An\n"
    "# attacker with fresh infrastructure is not on it by definition.\n"
    "#\n"
    "# The list ships empty: TrustSight does not invent indicators.  Add\n"
    "# entries from an advisory you can cite, and keep the provenance with\n"
    "# them - the confidence tier decides the severity, so an unsourced\n"
    "# entry must not sit at 'confirmed'.\n"
    "\n"
    "[meta]\n"
    "# Bump when the entry list changes; reports name the version they were\n"
    "# matched against.\n"
    "version = 1\n"
    "\n"
    "# Each indicator is one [[entries]] table:\n"
    "#\n"
    "# [[entries]]\n"
    "# type = \"domain\"              # domain | package | hash\n"
    "# value = \"malicious.example\"  # matched exactly, case-insensitively\n"
    "# confidence = \"confirmed\"     # confirmed -> FATAL, high -> CRITICAL,\n"
    "#                              # medium -> HIGH (an entry with no known\n"
    "#                              # tier still matches, at MEDIUM)\n"
    "#                              # 'confirmed' scores the package 100 on\n"
    "#                              # its own - use it only for an artefact\n"
    "#                              # a report you can cite named as malware\n"
    "# provenance = \"https://security.archlinux.org/ASA-...\"\n"
    "# campaign = \"2026-06-aur-install-hook\"\n"
    "# added = \"2026-08-03\"\n"
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
    # Pre-2026-08-03: one phrasing of one injection family, and comments -
    # where the payload always lives - were filtered out before matching.
    # It caught 3 of 22 injection fixtures.
    "R012": {r"ignore\s+(?:all\s+)?previous\s+(?:instructions|commands|input)"},
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
    """Load rules from rules.toml, with the shipped FATAL set re-asserted."""
    data = load_toml("rules.toml")
    rules, restored = enforce_fatal_rules(data.get("rules", []))
    if restored:
        _log.warning(
            "rules.toml is missing or has downgraded FATAL rule(s) %s; "
            "the shipped definition is being used instead",
            ", ".join(restored),
        )
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


def load_domains() -> dict:
    """Load trusted domains from trusted_domains.toml"""
    return load_toml("trusted_domains.toml", copy_result=False)


def load_patterns() -> dict:
    """Load pattern tables from patterns.toml (R081/R082/D003)."""
    return load_toml("patterns.toml", copy_result=False)


def load_naming() -> dict:
    """Load naming tables from naming.toml (D002/D004/R074)."""
    return load_toml("naming.toml", copy_result=False)


def load_hosts() -> dict:
    """Load host tables from hosts.toml (R047/R048/R087)."""
    return load_toml("hosts.toml", copy_result=False)


def load_thresholds() -> dict:
    """Load thresholds from thresholds.toml (R082/R125/R126)."""
    return load_toml("thresholds.toml", copy_result=False)


def load_iocs() -> dict:
    """Load the versioned indicator list from iocs.toml (R106)."""
    return load_toml("iocs.toml", copy_result=False)


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
             "scope", "added_only", "include_comments", "experimental")
        }

    config = load_config()
    material = {
        "rules": sorted((rule_key(r) for r in load_rules()),
                        key=lambda r: r.get("id") or ""),
        "severity_weights": config.get("severity_weights", {}),
        "source_bucket_weights": config.get("source_bucket_weights", {}),
        "novelty_weights": config.get("novelty_weights", {}),
        "thresholds": load_thresholds(),
        "limits": config.get("limits", {}),
        "diff": config.get("diff", {}),
    }
    try:
        from .override import load_overrides

        material["overrides"] = sorted(
            (o.rule_id, o.package or "") for o in load_overrides()
        )
    except Exception:
        material["overrides"] = []

    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"),
                           default=str).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()
