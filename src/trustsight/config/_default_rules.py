"""Extracted from config.py: _default_rules."""

from ._defaults_executor import ANY_EXECUTOR, NETWORK_CLIENT, SHELL_EXECUTOR

__all__ = ['DEFAULT_DOMAINS', 'DEFAULT_RULES', 'INT_WEIGHT_GROUPS', 'KNOWN_BOOL_KEYS', 'LEGACY_DEFAULT_REVIEW_LIMIT', 'LEGACY_IOCS_STUBS', 'SHIPPED_RULESET_VERSION', '_SEMANTIC_FIELDS']

SHIPPED_RULESET_VERSION = 18

DEFAULT_RULES = """\
# ruleset-version: 18
[[rules]]
id = "R001"
name = "Remote Script Execution"
# The pipe must not be escaped.  An escaped pipe passes a literal bar to
# curl as an argument and runs no pipeline at all, and this rule fired on
# it: a false positive on the highest-severity, highest-recall rule in the
# set.  The tokenizer deliberately keeps that escape intact (see
# tokenizer._ESCAPE_REMOVABLE) precisely so the distinction survives here.
pattern = 'curl.*(?<!\\\\)\\|\\s*(?:@@EXEC@@)'
severity = "CRITICAL"
category = "network_execution"
match_target = "resolved"

[[rules]]
id = "R002"
name = "Wget Pipe to Shell"
# Unescaped, for the reason R001 above gives: an escaped bar is an
# argument to wget, not a pipeline.
pattern = 'wget.*(?<!\\\\)\\|\\s*(?:@@EXEC@@)'
severity = "CRITICAL"
category = "network_execution"
match_target = "resolved"

[[rules]]
id = "R003"
name = "Base64 Decode and Execute"
# The trailing bar must be a real pipe; escaped, the decode goes to
# stdout and nothing consumes it.
pattern = 'base64.*(?:\\-d|\\-\\-decode).*(?<!\\\\)\\|'
severity = "CRITICAL"
category = "obfuscation"
match_target = "resolved"

# H003 is now a structural rule (src/trustsight/analysis/structural.py):
# fires on http:// added sources when no checksum was also added.

[[rules]]
id = "R007"
name = "Install File Modification"
# Anchored, and with no trailing wildcard.  Unanchored, the previous form
# was quadratic: the search retries at every offset and the wildcard
# rescans the line from each one.  A raw line is capped at
# MAX_RULE_LINE_BYTES, where that cost is measurable.  On an added line -
# the only line this is aimed at, since a diff marker sits at position 0 -
# the anchored form matches exactly the same text.
pattern = '^\\+.*\\.install'
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

# H004 is now a code rule (src/trustsight/analysis/build.py): sudo at a
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
# Calibrated: 22/22 injection fixtures, 0 fires across 3,739 benign
# corpus diffs (every alternative measured separately).
pattern = '''\\b(?:ignore|disregard|forget|override|bypass)\\s+(?:all\\s+|any\\s+|the\\s+)*(?:previous|above|prior|earlier|preceding|foregoing|existing)\\b|^[^\\S\\n]*(?:#[^\\S\\n]*)?(?:system|assistant)[^\\S\\n]*:[^\\S\\n]*\\S|</?(?:system|instructions?|admin|prompt|assistant)\\s*>|\\byou\\s+are\\s+(?:an?|the)\\s+[^.\\n]{0,48}?(?:model|assistant|ai\\b)|\\bnew\\s+instructions?\\s*:|\\bdo(?:\\s+not|n['’]t)\\s+(?:flag|warn|analy[sz]e|review|scan)\\b|\\bdo(?:\\s+not|n['’]t)\\s+report\\s+(?:any\\s+|the\\s+)?(?:security|issues?|concerns?|problems?|findings?|warnings?|anything)\\b|\\b(?:mark|classify|report|treat|label|approve)\\b[^.\\n]{0,24}?\\bas\\s+(?:safe|benign|clean|harmless|trusted|ok)\\b|\\b(?:claude|chatgpt|gpt-?[0-9]?|copilot|gemini|llm|ai\\s+assistant)\\b[^.\\n]{0,60}?\\b(?:ignore|approve|skip|overlook|flag)\\b'''
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
# Numbering starts at R039 because H005-R026 are already referenced by
# tests/fixtures/baseline.json and the malicious fixture generators.
# Reusing those ids would silently change what they mean.
#
# Calibrated against a 3739-diff stratified benign corpus.  Fourteen of
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
# `bash -c "$E"` where `E` was assigned on an earlier line is the same
# dynamic payload as `bash -c "$(...)"`; only the substitution moved.  A
# bare `$NAME` argument is therefore dynamic too - the tokenizer resolves
# the ones it can, so what reaches this pattern unresolved is precisely
# what could not be read.
pattern = '\\b(?:@@SHELL@@)\\s+-c\\s+(?:\\$\\(|`|\\$\\{|["\\x27]?\\$[A-Za-z_]|"[^"]*\\$)'
severity = "CRITICAL"
category = "execution"
match_target = "resolved"

[[rules]]
id = "R041"
name = "Shell Network Redirection"
# The literal spelling was the whole rule, and `/dev/t?p/` opens the same
# socket: bash expands the glob when the redirect runs, and the diff never
# contains the word the pattern looks for. A `/dev/` path whose protocol
# component is not a literal is claimed on that basis - there is no benign
# reason to glob or interpolate the name of a device node.
pattern = '/dev/(?:tcp|udp)/|/dev/[a-z]*[?*\\[][a-z?*\\]\\[]*/|/dev/\\$\\{?\\w+\\}?/'
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
pattern = '\\b(?:xxd|uudecode)\\s+[^|]*(?<!\\\\)\\|'
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

[[rules]]
id = "R152"
name = "Source URL On Free-Hosting Or Dynamic-DNS Host"
# Generated at load from hosts.toml free_hosting_domains (then the
# config.toml [domains] fallback, then the shipped list); the text here is the
# shipped-default expansion so an ungenerated copy stays coherent.
pattern = 'https?://[^/\\s]*\\.(?:duckdns\\.org|no\\-ip\\.org|noip\\.com|no\\-ip\\.biz|ddns\\.net|hopto\\.org|zapto\\.org|sytes\\.net|dynu\\.com|dynv6\\.net|afraid\\.org|changeip\\.com|dyndns\\.org|ngrok\\.io|ngrok\\.app|ngrok\\-free\\.app|trycloudflare\\.com|localtunnel\\.me|loca\\.lt|serveo\\.net|bore\\.pub|pinggy\\.io|localhost\\.run|lhr\\.life|pagekite\\.me|portmap\\.io|pages\\.dev|workers\\.dev|r2\\.dev|github\\.io|gitlab\\.io|codeberg\\.page|vercel\\.app|netlify\\.app|web\\.app|firebaseapp\\.com|surge\\.sh|render\\.com|onrender\\.com|glitch\\.me|replit\\.dev|herokuapp\\.com|deno\\.dev|railway\\.app)(?:[:/]|["\\x27\\s)]|$)'
severity = "MEDIUM"
category = "network"
match_target = "raw_line"
# Everything except "message": a `docs: https://x.github.io/...` line in an
# install banner is a link the reader clicks, not a source the recipe fetches
# (sysc-shell).  The URL is what the user is told to visit, not a build input.
scope = ["function_body", "other"]
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
# The client list is the shared one.  `pkgver()` runs before any review
# step, so "which binary fetched" is the least interesting property of a
# fetch there - and `openssl s_client`, `lftp` and `wget2` all walked past
# a five-verb list.
pattern = '\\b(?:@@NETCLIENT@@)\\b'
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
# `setcap cap_setuid+ep` grants the same power the setuid bit does, by a
# different mechanism, and was claimed by neither rule: a file capability
# is not a mode.
pattern = '\\bchmod\\s+(?:-\\S+\\s+)*(?:(?:--mode=)?(?:[2467][0-7]{3}\\b|[ugoa]*\\+s\\b))(?:\\s+--\\s+(?!["\\x27]?/)|\\s+(?!--\\s)(?!["\\x27]?/))|\\bsetcap\\s+(?:-\\S+\\s+)*["\\x27]?cap_\\w+[^\\s]*\\s+(?!["\\x27]?/)|\\binstall\\s+(?:-\\S+\\s+)*(?:--mode=|-m\\s*)[2467][0-7]{3}\\b[^;\\n&|]*?\\$\\{?(?:pkgdir|DESTDIR)\\}?'
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
pattern = '\\bchmod\\s+(?:-\\S+\\s+)*(?:(?:--mode=)?(?:[2467][0-7]{3}\\b|[ugoa]*\\+s\\b))(?:\\s+--\\s+["\\x27]?/|\\s+(?!--\\s)["\\x27]?/)|\\bsetcap\\s+(?:-\\S+\\s+)*["\\x27]?cap_\\w+[^\\s]*\\s+["\\x27]?/|\\binstall\\s+(?:-\\S+\\s+)*(?:--mode=|-m\\s*)[2467][0-7]{3}\\b[^;\\n&|]*?(?<![\\w$}])["\\x27]?/'
severity = "HIGH"
category = "privilege"
match_target = "raw_line"
scope = ["function_body", "other"]
added_only = true

[[rules]]
id = "R017"
name = "Setuid/Setgid Permission"
# R053/R059 provide the more useful package-root versus live-filesystem
# finding when a target is present.  This generic form remains the fallback
# for an otherwise unclassified chmod command.
pattern = 'chmod.*\\+s'
severity = "HIGH"
category = "privilege"
match_target = "raw_line"
scope = ["function_body", "other"]
added_only = true
exclude_if_matches = ["R053", "R059"]

[[rules]]
id = "R054"
name = "Persistence Unit Outside Package Root"
# The path anchor used to be [\\s"'] alone, which only reaches the
# idiomatic "${pkgdir}"/usr/lib/systemd/system/ form.  The merged-quote
# "${pkgdir}/usr/lib/systemd/system/" and unquoted $pkgdir/usr/lib/...
# forms stage the identical root-level unit (pacman installs what the
# recipe staged), so a $pkgdir prefix in any quoting style is an anchor
# too.  This rule reads raw added lines, independently of tokenizer
# quote handling.
# The path list is the *autostart surface*, not just cron and system
# units.  Everything here runs code with nobody asking it to: a `.desktop`
# in `xdg/autostart` starts with the session, a systemd **user** unit starts
# with the user's login, `profile.d`, `bash.bashrc.d` and `zshrc.d` run in
# every new shell, `Xsession.d` and `xinitrc.d` run at graphical login, a
# D-Bus policy grants a service the right to be activated on demand, and
# `sudoers.d` decides who may become root.
#
# `pam.d`, `dispatcher.d`, `xinetd.d`, `init.d`/`rc.d` and `logrotate.d`
# join on the same test: a PAM line runs on every authentication, a
# dispatcher script on every network change, an xinetd entry on every
# connection, and a logrotate `postrotate` block on every rotation. Each
# appears in *zero* of the 3,739 benign diffs - an AUR package that needs
# one of these ships it as a declared source file, which R054 reads either
# way.
#
# `ld.so.conf.d` is here on its own measurement: a directory added to the
# loader search path is code loaded into every process that starts
# afterwards, and it appears in *zero* of the 3,739 benign diffs.  It was
# excluded in a first pass that measured five paths together and read the
# aggregate as if it applied to each.
#
# Deliberately *not* here: `/usr/share/applications`, which is where every
# GUI package on the system puts its menu entry - it runs when the user
# clicks it, which is not persistence - and `tmpfiles.d`, `sysusers.d`,
# `udev/rules.d` and `modprobe.d`, which ordinary driver and library
# packages ship as a matter of course (modprobe.d alone is 0.28% of the
# corpus).  Including that group fired on 30 benign packages and would have
# made the rule mean "this package installs files".
#
# A *write*, not a mention.  The path alone matched
# `if [[ -f /etc/profile.d/cuda.sh ]]`, which tests for a file rather than
# planting one - and a rule that reads "persistence unit installed" must not
# fire on a package checking whether one exists.
pattern = '(?:\\b(?:install|cp|mv|ln|tee|dd|rsync|mkdir|cat|printf|echo)\\b|>)[^;&|\\n]*?(?:[\\s"\\x27]|\\$\\{?pkgdir\\}?)(?:(?:/etc/(?:cron\\.[a-z]+|cron\\.d|systemd/(?:system|user)|profile\\.d|bash\\.bashrc\\.d|zsh(?:/zshrc\\.d|rc\\.d)|X11/(?:Xsession|xinit/xinitrc)\\.d|xdg/autostart|dbus-1/(?:system|session)\\.d|sudoers\\.d|ld\\.so\\.conf\\.d|pam\\.d|security/pam_\\w+\\.conf|NetworkManager/dispatcher\\.d|xinetd\\.d|(?:init|rc)\\.d|logrotate\\.d|tmpfiles\\.d|sysusers\\.d|binfmt\\.d|sysctl\\.d|environment\\.d|polkit-1/(?:rules|actions)\\.d|polkit-1/(?:rules|actions)|skel|update-motd\\.d|systemd/(?:system|user)-preset)|/usr/lib/systemd/(?:system|user)|/usr/lib/systemd/(?:system|user)-(?:generators|sleep|shutdown)|/usr/share/dbus-1/(?:system|session)-services|/var/spool/cron)/|(?:/etc/(?:rc\\.local|profile|bash\\.bashrc|ld\\.so\\.preload|environment|csh\\.cshrc|zsh/(?:zshrc|zprofile|zshenv)|X11/xinit/xinitrc|X11/Xsession))(?![\\w./-]))'
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
id = "R144"
name = "Packaged File Points At A World-Writable Path"
# A file staged into $pkgdir that names a program under /tmp, /var/tmp or
# /dev/shm.  Those directories are world-writable, so whatever the config
# names can be replaced by any local user between the package being
# installed and the config being read - and the config is read as root for
# a unit, a PAM line or a cron entry.
#
# It is both halves at once: an attacker who ships this is arranging for
# their own planted file to run, and a maintainer who ships it by accident
# has handed the same lever to anyone with a shell on the machine.  The
# target is never in the diff, which is why every rule that looks for a
# payload found nothing here.
#
# Order-free: the recipe may write the config and then name the path
# (`printf SCRIPT=/tmp/e.sh > "$pkgdir/etc/conf.d/x"`) or the reverse.
# Zero occurrences in the 3,739-diff benign corpus - a package pointing
# its own config at /tmp is not something the ecosystem does.
#
# Anchored at `^` so each lookahead runs once.  Unanchored, `search` retries
# both from every position and the audit refuses the pattern outright.
pattern = '^\\+?(?=[^\\n]*\\$\\{?pkgdir\\}?)(?=[^\\n]*(?:/tmp/|/var/tmp/|/dev/shm/))\\S'
severity = "HIGH"
category = "persistence"
match_target = "raw_line"
scope = ["function_body", "other"]
added_only = true

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
# The client list is deliberate and closed: every entry is a documented
# flag that turns verification off for that client.  `--no-verify` is
# deliberately absent - for bun and cargo it skips lifecycle scripts, not
# TLS, and claiming it would describe the wrong thing.  bun/node ship no
# TLS flag of their own; the ecosystem switch is the Node compatibility
# env var below, and cargo's transport is git (`http.sslVerify`) already
# covered.
pattern = '(?:curl\\s+[^;&|]*?(?:--insecure|-k)\\b|wget\\s+[^;&|]*?--no-check-certificate\\b|git\\s+-c\\s+http\\.sslVerify=false\\b|GIT_SSL_NO_VERIFY\\s*=|pip\\s+[^;&|]*?--trusted-host\\b|npm\\s+[^;&|]*?--strict-ssl=false\\b|deno\\s+[^;&|]*?--unsafely-ignore-certificate-errors\\b|NODE_TLS_REJECT_UNAUTHORIZED\\s*=\\s*[\"\\x27]?0\\b)'
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

# --- Build environment overrides ---

[[rules]]
id = "R078"
name = "Compression Command Override"
# COMPRESS* variables control makepkg's archive compression command.
# Overriding them can pipe decompressed content through an arbitrary binary.
pattern = '(?:^|\\s|\\+)(?:export\\s+|declare\\s+-x\\s+)?COMPRESS(?:ZST|XZ|GZ|BZ2|LZ4|LRZ|LZO|LZ|Z)\\s*\\+?='
severity = "MEDIUM"
category = "build"
match_target = "raw_line"
added_only = true

[[rules]]
id = "R091"
name = "Privilege Escalation Override"
# PACMAN_AUTH controls how pacman gains elevated privileges during
# makepkg -S.  Overriding it in a PKGBUILD means the package is trying
# to control privilege escalation on the builder's machine.
pattern = '(?:^|\\s|\\+)(?:export\\s+|declare\\s+-x\\s+)?PACMAN_AUTH\\s*\\+?='
severity = "HIGH"
category = "build"
match_target = "raw_line"
added_only = true

[[rules]]
id = "R104"
name = "Error Handling Suppressed"
# trap empty-string ERR suppresses error handling, hiding build failures
# from the reviewer.  trap empty-string DEBUG hides trace output.  These
# are subsets of R099 but carry higher severity because they actively
# conceal activity.  Only the single-quote form is common; the double-
# quote form is rare and already caught by R099.
# Must come before R099 so the more specific match fires first.
# Pattern avoids backslash escapes to stay compatible with
# _shipped_rule_fields() which extracts via regex, not TOML parsing.
pattern = "trap '' (?:ERR|DEBUG)(?:[^a-zA-Z]|$)"
severity = "HIGH"
category = "build"
match_target = "raw_line"
added_only = true

[[rules]]
id = "R099"
name = "Trap Statement"
# trap registers signal handlers.  In a PKGBUILD it can suppress errors
# (trap '' ERR) or run code on build completion (trap 'payload' EXIT).
# Legitimate cleanup traps exist but are uncommon enough to flag.
# Excludes when R104 already claimed the more specific form.
pattern = '^(?:\\+)?\\s*trap\\s+'
severity = "MEDIUM"
category = "build"
match_target = "raw_line"
added_only = true
exclude_if_matches = ["R104"]
"""

DEFAULT_RULES = (
    DEFAULT_RULES
    .replace("@@EXEC@@", ANY_EXECUTOR)
    .replace("@@SHELL@@", SHELL_EXECUTOR)
    .replace("@@NETCLIENT@@", NETWORK_CLIENT)
)

DEFAULT_DOMAINS = """\
[trusted_forges]
domains = [
    "github.com",
    "gitlab.com",
    "codeberg.org",
    "bitbucket.org",
    "sourceforge.net",
    "freedesktop.org",
]

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

LEGACY_IOCS_STUBS = frozenset({
    "[iocs]\n"
    "# H056 - exact-match indicators, each with provenance and a confidence\n"
    "# tier.  Populated by the phase that ships H056.\n"
    "version = 1\n"
    "entries = []\n"
})

LEGACY_DEFAULT_REVIEW_LIMIT = 20

INT_WEIGHT_GROUPS = ("severity_weights", "source_bucket_weights", "novelty_weights")

KNOWN_BOOL_KEYS = ("seed.auto_import", "rules.experimental")

_SEMANTIC_FIELDS = ("match_target", "severity", "category", "pattern", "scope")
