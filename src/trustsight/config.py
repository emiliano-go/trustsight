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

# H035 - foreign package managers invoked from an install hook.  Each entry
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

# H036 - obfuscation indicators counted on a single raw line.  A line
# carrying at least ``[thresholds] h036_obfuscation_density`` distinct
# forms fires; the reconstruction rules (H065) decide whether the line is
# inert or reveals an executable action.
# ---------------------------------------------------------------------------
# The executor vocabulary
# ---------------------------------------------------------------------------
#
# One list, because there were six and they disagreed.  R001/R002 knew
# `bash|sh|python|zsh|dash|busybox sh`; H075 knew `bash|sh|zsh|dash`;
# `network._PIPE_TO_SHELL_RE` knew `bash|sh|zsh|dash|ksh|python3?|perl|ruby`;
# crossfire knew all of them.  The disagreement was not cosmetic - H016
# *stands down* when it believes R001 owns the line, and it made that
# decision with the wider list, so `curl url | ksh -s` silenced H016 and
# then fell through R001, which had never heard of ksh.  A CRITICAL became
# a LOW because two lists that had to agree were edited separately.
#
# Defined here, in the lowest layer, so the rule TOML below and the Python
# analysers can share one definition without `config` importing `analysis`.
SHELL_EXECUTOR = r"(?:ba|z|da|k|mk|pdk|ya|po|a)?sh|busybox\s+(?:ash|sh)"

#: Shells plus the interpreters that read a script from stdin just as well.
#: `curl url | php` is a remote shell as surely as `curl url | bash` - php,
#: lua, tclsh and the alternative shells all execute standard input when
#: given no script argument.  Leaving them out did not make the list
#: conservative, it made it an allowlist one rename wide.
#:
#: `awk` is deliberately absent: awk reads its *program* from an argument
#: and its stdin is data, so `curl url | awk '{print}'` executes nothing.
SCRIPT_EXECUTOR = SHELL_EXECUTOR + (
    r"|python3?|perl|ruby|node|php|lua(?:jit)?|tclsh|wish"
    r"|fish|tcsh|csh|rc|es|elvish|xonsh|nu|osh"
)

#: A wrapper may carry its own flags before the executor: `env -i bash`.
EXEC_WRAPPER = (
    # Two shapes, because wrappers take their arguments differently.
    #
    # The plain ones carry flags and at most a duration: `env -i bash`,
    # `timeout 5 bash`, `nice -n 10 bash`.
    # A terminal emulator's `-e` is "run this command", which makes it a
    # wrapper in exactly the sense `env` and `timeout` are: the executor
    # and its argument follow, and every rule that reads an execution
    # should see through it. Bare `st` is deliberately absent - two
    # characters match `stat(` and `static` in committed C.
    r"(?:(?:env|exec|command|sudo|doas|nohup|setsid|nice|ionice|stdbuf"
    r"|timeout|unbuffer|script"
    r")"
    r"(?:\s+-[-\w]+)*(?:\s+\d+[smhd]?)?\s+"
    # The sandboxes take *positional* arguments - `chroot /tmp/root bash`,
    # `bwrap --ro-bind / / bash` - so a flags-only form cannot reach the
    # executor past them.  Bounded to four tokens: enough for the real
    # invocations, short enough that the span cannot wander off looking for
    # an executor several commands away.
    # Terminals sit in the *positional* group, not the flag group: the
    # command may follow a subcommand rather than a flag (`wezterm start
    # bash x.sh`), which is the same shape `chroot DIR cmd` has.
    r"|(?:xterm|u?rxvt|konsole|gnome-terminal|alacritty|kitty|wezterm|foot"
    r"|terminator|xfce4-terminal|lxterminal|tilix|ttyd|zellij"
    r"|chroot|bwrap|firejail|nsjail|unshare|proot|fakeroot|fakechroot"
    r"|systemd-nspawn|toolbox|distrobox-enter"
    # `screen -dmS name bash s.sh` and `runuser -u u -- bash s.sh` put the
    # command after their own positional arguments too.
    r"|screen|dtach|abduco|runuser|setpriv|nohup)"
    r"(?:\s+[^\s;&|]+){0,4}\s+"
    r")"
)

#: Programs that bring bytes onto the machine from somewhere else.
#:
#: R001/R002 claim `curl` and `wget`; H016 and H082 knew a slightly longer
#: list; `_PIPE_TO_SHELL_RE` knew a third.  Every one of them was an
#: allowlist, and the interesting property of a downloader is not its name -
#: `lftp -c "cat URL" | bash`, `nc host 80 | bash` and
#: `openssl s_client -connect h:443 | bash` are the same operation with the
#: same result.  Listed once so that adding a client adds it everywhere.
#: Kept as a tuple, not a pre-joined string: consumers need to subtract the
#: clients R001/R002 already claim, and splitting a joined pattern on `|`
#: tears alternation groups (`git\s+(?:clone|fetch)`) into fragments.
NETWORK_CLIENT_ALTERNATIVES = (
    r"curl", r"wget2?", r"aria2c", r"axel", r"lftp", r"ncftp(?:get)?", r"snarf",
    r"httpie",
    r"elinks", r"links2?", r"w3m", r"lynx", r"browsh",
    r"scp", r"sftp", r"rsync", r"ftp", r"tftp",
    # `ssh host cat /srv/p.sh | sh` is a fetch with a shell attached, and
    # `ssh` was never on this list. It read as covered because the audit's
    # own probe used `host` as the hostname, which collides with the
    # `host` DNS client below - the chain fired for the wrong reason and
    # any other hostname scored nothing.
    #
    # Anchored on a remote command so the bare word cannot match: `ssh` at
    # a command position followed by a target and something to run there.
    # Neither `ssh` nor `scp` appears anywhere in the benign corpus.
    r"ssh(?=\s+(?:-\S+\s+)*[\w.@-]+\s+\S)",
    r"nc", r"ncat", r"netcat", r"socat", r"telnet",
    r"openssl\s+s_client",
    r"dig", r"host", r"nslookup", r"drill", r"kdig",
    r"git\s+(?:clone|fetch|pull|ls-remote|archive)",
    r"svn\s+(?:co|checkout|export)",
    r"hg\s+(?:clone|pull|unbundle)",
    r"bzr\s+(?:branch|pull|export)",
    r"darcs\s+get", r"fossil\s+clone",
    # `cvs -d :pserver:host:/repo checkout p` puts the root between the
    # verb and the command, and it is not a flag.
    r"cvs\s+(?:[-:]\S+\s+)*(?:co|checkout|export)",
    # Object and content stores.  The bytes still arrive from off the
    # machine; only the address notation differs - `s3://`, a content
    # identifier, a magnet link, an LFS pointer.  A client whose transport
    # is not HTTP is not a client the recipe can be trusted to have
    # declared.
    r"s3cmd\s+(?:get|sync|cp)",
    r"aws\s+s3\s+(?:cp|sync|mv)",
    r"gsutil\s+(?:cp|rsync)",
    r"az(?:copy)?\s+(?:storage\s+blob\s+download|copy)",
    r"rclone\s+(?:copy|sync|cat|copyto)",
    r"ipfs\s+(?:get|cat|dag\s+get)",
    r"swift\s+download",
    r"rados\s+get",
    r"git\s+lfs\s+(?:pull|fetch|checkout)",
    r"yt-dlp|youtube-dl",
    # A lookahead, for the reason the BSD `fetch` arm needs one: consuming
    # the magnet link as part of the client token leaves no address behind
    # for the address matcher, so the fetch is recognised and scores
    # nothing.
    r"transmission-cli|aria2c(?=\s+[^\n;&|]*magnet:)",
    r"b2\s+download-file",
    r"restic\s+restore|borg\s+extract",
    # libwww-perl ships a CLI, and it is the one a Perl recipe reaches for
    # when it wants a download without a shell-out to curl.
    #
    # `GET`, `POST` and `HEAD` are its aliases and are deliberately absent:
    # matching is case-insensitive here, so they would claim every `get`
    # in the ecosystem. `lwp-request` is what the alias runs and cannot be
    # confused with an English word.
    r"lwp-request", r"lwp-download",
    # `git push` sends bytes *out*. The inventory had clone/fetch/pull -
    # every way to bring code in and no way to send it - so a recipe
    # exfiltrating through a push looked like nothing at all.
    r"git\s+push",
    # BSD `fetch(1)`. Anchored on a URL argument because `fetch` on its own
    # is a word `git fetch` and a hundred build scripts already use.
    # A lookahead, not a match: consuming the URL as part of the client
    # token left no address behind for the address matcher to pair with,
    # so the client was recognised and the fetch still scored nothing.
    r"fetch(?=\s+[^\n;&|]*\b(?:https?|ftps?)://)",
)

NETWORK_CLIENT = "|".join(NETWORK_CLIENT_ALTERNATIVES)

#: HTTPie's binary really is called `http`, and a bare `http` alternative
#: matches the scheme of every URL in the recipe.  A client name that fires
#: on its own argument is not a client name.

#: The subset R001/R002 already claim.  X009 covers the remainder, so one
#: fetch-and-execute is scored once however it was spelled.
CATALOGUED_FETCH_ALTERNATIVES = (r"curl", r"wget2?")

#: Everything else, for X009.
OTHER_FETCH_CLIENT = "|".join(
    alt for alt in NETWORK_CLIENT_ALTERNATIVES
    if alt not in CATALOGUED_FETCH_ALTERNATIVES
)

#: Package managers that resolve a dependency and then *run* code from it -
#: `pip` runs setup.py and PEP 517 hooks, `npm` runs lifecycle scripts,
#: `cargo` compiles build.rs in-process, `gem` runs extconf, `go` builds the
#: module.  Fetching and executing third-party code is what these commands
#: are for, which is why the recipe naming one is the whole signal.
PACKAGE_MANAGER_INSTALL = (
    r"(?:pip[23]?|pipx|uv(?:\s+pip)?|poetry|conda|mamba|micromamba)\s+(?:pip\s+)?"
    r"(?:install|add|sync)"
    r"|(?:npm|pnpm|yarn|bun)\s+(?:install|add|ci|exec)"
    r"|cargo\s+(?:install|add)"
    r"|go\s+(?:install|get)"
    r"|gem\s+(?:install|build)"
    r"|composer\s+(?:require|install|update)"
    r"|opam\s+(?:install|pin)"
    r"|luarocks\s+(?:install|build|make)"
    r"|cpanm?\s+|nimble\s+install|dub\s+fetch|stack\s+install"
    # The distribution's own tools.  `pacman -U ./evil.pkg.tar.zst` inside
    # `build()` installs a package as root, scriptlets and all, and
    # `pacman -S` downloads one first.  H035 claims *foreign* package
    # managers in install hooks; pacman is not foreign and a build function
    # is not a hook, so this fell between the two.  A recipe has no business
    # installing packages: makepkg resolves `depends` for that.
    r"|pacman\s+-(?:U|S(?![a-z]*[yq])|S[a-z]*y)"
    r"|makepkg\s+(?:-\S*i|--install)"
    r"|(?:apt-get|apt|dnf|yum|zypper|apk|emerge)\s+(?:install|add)"
    # The one-shot runners.  `npx evilpkg` resolves a package from the
    # registry and executes it in a single word - no install step to notice,
    # no lockfile, nothing left behind.  It is the install class with the
    # install elided, which is a weaker signal to a reader and an identical
    # one to the machine.
    r"|(?:npx|bunx|pnpx|yarn\s+dlx)\b"
    r"|(?:uv|pipx|conda|mamba|poetry|pdm|hatch|rye)\s+run\b"
    r"|deno\s+(?:run|install|cache)"
    # Run-a-remote-module verbs.  `cargo script <url>`, `bun x <url>` and
    # `pkgx <url>` fetch and execute in a single word with no install step
    # to notice - the one-shot runner class again, one ecosystem further on.
    r"|cargo\s+script|bun\s+x\b|pkgx\b|nix\s+run\b|uvx\b"
    # Container and image stores.  `docker pull evil/img && docker run
    # evil/img` fetches a filesystem and executes its entrypoint; `snap`
    # and `flatpak` install and then run confined applications; `helm`
    # applies charts that carry hooks.  None of them names a URL, which is
    # why the fetch inventory never saw them, but "resolve a name from a
    # registry and run what comes back" is exactly X011's claim.
    r"|(?:docker|podman|nerdctl|ctr)\s+(?:run|pull|exec|compose\s+up|build)"
    r"|(?:lxc|incus)\s+(?:launch|init|exec|image\s+(?:copy|import))"
    r"|snap\s+(?:install|run|refresh)"
    r"|flatpak\s+(?:install|run|remote-add)"
    r"|helm\s+(?:install|upgrade|pull)"
    r"|(?:kubectl|oc)\s+(?:apply|run|create)"
    r"|(?:go|cargo)\s+run\b"
)

#: Query tools that pull a *value* out of a structured file.
#:
#: The same shape as a decoder, with a query instead of an algorithm:
#: `jq -r .cmd cfg.json | bash` runs whatever that field holds, and the
#: field is in a JSON file no rule reads.  A reviewer looking at the recipe
#: sees a config lookup; what executes is chosen by the data.
STRUCTURED_EXTRACTOR = (
    r"\b(?:jq|gojq|jaq|yq|tomlq|xq|dasel|fx)\b[^\n|;&]*?-[^\n|;&]*?r"
    r"|\b(?:jq|gojq|jaq|yq|tomlq|xq|dasel)\s+[^\n|;&]*?[.\[]"
    r"|\bxmlstarlet\s+sel\b|\bxmllint\b[^\n|;&]*?--xpath"
    r"|\bsqlite3\b[^\n|;&]*?(?:\.read\b|select\b)"
    # `[^\n|&]` for the interpreter arm, not `[^\n|;&]`: a shell command
    # ends at `;`, but `python3 -c 'import json;print(...)'` puts one inside
    # a quoted argument as a matter of Python syntax.  The same distinction
    # the interpreter fetch arm needed.
    r"|\b(?:python[23]?|ruby|perl|node)\b[^\n|&]*?"
    r"(?:json\.loads?|yaml\.safe_load|tomllib?\.loads?|JSON\.parse"
    r"|Marshal\.load|msgpack|pickle\.loads?)"
    r"|\bplutil\b[^\n|;&]*?-extract"
    r"|\bgit\s+config\s+--get\b"
    r"|\bcrudini\s+--get\b|\bawk\b[^\n|;&]*?/[^/\n]*/[^\n|;&]*?print"
)

#: Commands that turn a file the reviewer cannot read into bytes.  X001
#: already claimed base32/basenc/uudecode/openssl/xxd/tr on the reasoning
#: that they "decode the same payload into the same shell"; compression is
#: the same sentence.  `gzip -dc payload.gz | bash` needs no encoder alphabet
#: at all, and a `.gz` in `source=()` with `SKIP` is unremarkable to read.
DECOMPRESSOR = (
    r"\b(?:gzip|bzip2|xz|lzma|lzip|plzip|clzip|zstd|lz4|brotli|compress"
    r"|lrzip|rzip|7zr)\s+[^\n|;&]*?-[^\n|;&]*?[dc]"
    # `uncompress -c p.Z` and `iconv -f UCS-2 -t UTF-8 p.uc2` both turn bytes
    # a reviewer cannot read into a script.  iconv is a transcoder rather
    # than a decompressor, which is a distinction about the algorithm, not
    # about what reaches the shell.
    r"|\buncompress\b|\biconv\b[^\n|;&]*?-[ft]\b"
    r"|\b(?:gunzip|bunzip2|unxz|unlzma|unzstd|unlz4|zcat|bzcat|xzcat|lzcat"
    r"|zstdcat|lz4cat)\b"
    # `-xOf` is one cluster: the O is not at a word boundary, which is how
    # the most natural spelling of this slipped the first version.
    r"|\b(?:bsd)?tar\s+[^\n|;&]*?(?:-[A-Za-z]*O[A-Za-z]*|--to-stdout)\b"
    # `7za?` misses `7zz`, the binary 7-Zip ships as of 23.x - one
    # character past the pattern that named it. The suffix is open-ended
    # for the same reason the executor list was inverted: the next
    # spelling is the packager's to choose.
    r"|\b7z[a-z0-9]*\s+[^\n|;&]*?-so\b"
    # squashfs images are an archive family the list did not have at all.
    r"|\bunsquashfs\s+[^\n|;&]*?(?:-cat|-stdout)\b"
    r"|\bcpio\s+[^\n|;&]*?--to-stdout\b"
    # The zip family reads a member to stdout with its own verbs, none of
    # which look like a decompressor flag.  `unzip -p p.zip | bash` is the
    # same operation as `gzip -dc p.gz | bash` and was claimed by nobody.
    r"|\bunzip\s+[^\n|;&]*?-[A-Za-z]*p[A-Za-z]*\b"
    r"|\b(?:funzip|zipcat)\b"
    r"|\bunrar\s+[^\n|;&]*?\bp\b"
    r"|\b(?:ar|7zr)\s+[^\n|;&]*?\bp\b"
    # Decryption is decoding: the reviewer cannot read the input either way.
    # `gpg -d` and `gpg --decrypt` write the plaintext to stdout by default.
    r"|\bgpg2?\s+[^\n|;&]*?(?:-[A-Za-z]*d[A-Za-z]*|--decrypt)\b"
    r"|\bage\s+[^\n|;&]*?(?:-[A-Za-z]*d[A-Za-z]*|--decrypt)\b"
)

#: Commands whose output is a *payload*: they turn bytes the reviewer cannot
#: read into bytes a shell can run.  Used both for the piped form (X001) and
#: for the redirect form, where the same producer writes a file that a later
#: line executes.
PAYLOAD_PRODUCER = (
    DECOMPRESSOR
    + r"|\b(?:base64|base32|basenc|uudecode|uudeview)\b"
    r"|\bxxd\s+[^\n|;&]*?-[A-Za-z]*r"
    r"|\bod\s+[^\n|;&]*?-A"
    r"|\bopenssl\s+(?:enc|base64|zlib)\b"
    r"|\bcertutil\s+[^\n|;&]*?-decode"
)

#: Anything that will execute text handed to it, in any of its spellings.
ANY_EXECUTOR = (
    # A brace group or subshell is a pipe target whose body runs a shell:
    # `curl url | { bash; }` and `curl url | ( sh )` execute exactly what
    # `curl url | bash` does, and the literal after-the-bar arm saw a `{`.
    r"[({]\s*(?:" + EXEC_WRAPPER + r")?(?:/(?:usr/)?bin/)?(?:" + SCRIPT_EXECUTOR + r")\b"
    r"|(?:/(?:usr/)?bin/)?(?:" + SCRIPT_EXECUTOR + r")\b"
    r"|" + EXEC_WRAPPER + r"(?:/(?:usr/)?bin/)?(?:" + SCRIPT_EXECUTOR + r")\b"
    # `source /dev/stdin` and `. /dev/stdin` read the pipe as a script.
    r"|(?:source|\.)\s+/dev/stdin\b"
)


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

# H067 - anti-analysis probes run from a build/install function.  A build
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

# H040 - host-profiling commands run from a build/install function.  Host
# reconnaissance (who am I / what machine am I on) has no packaging purpose;
# it is the recon stage of the kill-chain H043 composes.  Each entry is a
# case-insensitive regex fragment matched against reconstructed text.  The
# leading command-position anchor means only a command invoked at the start
# of a line or after ; / && / || / | fires - bare mentions in strings, sed
# expressions and variable values never do.  `env`, `dmidecode` and
# `systemd-detect-virt` are excluded: `env VAR=val` is overwhelmingly benign,
# and the latter two already belong to H067.  Calibrated to zero benign
# fires across the 3,246-diff corpus.  A lone `uname -m` (arch check) fires
# H040 at INFO by design.
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

# H077 - network clients invoked at parse time (top level of the PKGBUILD).
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
# ``foo`` (H029).
DEFAULT_KNOWN_SUFFIXES = (
    "-git", "-bin", "-debug", "-lts", "-stable", "-beta",
    "-svn", "-hg", "-bzr", "-cvs",
    "-wine", "-appimage", "-flatpak", "-nightly", "-devel", "-common",
)

# Paste and ephemeral file-drop hosts (H041).  Bucket classification in
# trusted_domains.toml [raw_hosting] already weights these *as source URLs*,
# which is why H041 does not look at source=(): it reads the other
# direction, an upload to one of these hosts from inside a build or install
# function, where no bucket applies and the data is leaving the machine.
DEFAULT_PASTE_HOSTS = [
    "pastebin.com", "gist.github.com", "paste.ee", "0x0.st", "termbin.com",
    "hastebin.com", "ix.io", "transfer.sh", "file.io", "bashupload.com",
    "temp.sh", "anonfiles.com", "dpaste.com", "sprunge.us",
]

# H041 - invocation shapes that *send* a request body rather than fetch one.
# Direction is the whole point of the rule: downloading from a gist is an
# undeclared fetch (H016), while uploading to one is data leaving the build
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

# Source schemes allowed by H034 (source URL uses an exotic protocol).  A
# ``transport+base`` token like ``git+https`` is judged by its base scheme;
# only the base matters here.  Anything outside this allowlist is exotic.
DEFAULT_SOURCE_SCHEMES = [
    "https", "http", "ftp", "ftps", "ssh", "git", "hg", "svn", "bzr",
    "cvs", "file", "dav", "davs",
]

# Covert-egress / tunneling clients flagged by H071 when invoked from a
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

# DoH endpoints flagged by H071 (covert egress).  Encrypted DNS-over-HTTPS
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

# H047 - security-relevant build flags, matched against the tokenized
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

# H048 - security-relevant libraries.  Vendoring one of these (dropping the
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

[review]
# Controls which scored packages enter the review workload. This does not
# change score arithmetic or risk bands. A package is flagged above its
# selected profile's threshold.
profile = "default"

[review.profiles]
default = 20
quiet = 40
strict = 10

[deep]
enabled = false
threshold = 80

[depth]
# How far into a package's AUR dependency closure to analyse.  0 disables
# it, 1 (the default) analyses direct AUR dependencies, n analyses n levels,
# and -1 walks every level there is - bounded by depth.MAX_DEPTH_LEVELS and
# depth.MAX_DEPTH_NODES, because the dependency graph is written by the
# party under review.  Overridden per run by --depth.
levels = 1

[diff]
max_context_lines = 3
max_diff_bytes = 5242880

[limits]
# How many packages `trustsight review` reads when no --limit is given.
# 0 means all of them, which is the default because a review that stops
# early has not looked at the rest, and this tool does not report on what
# it did not read.  Any other value is honoured and the packages left over
# are named in the summary rather than dropped quietly.
#
# This key shipped set to 20 and was never read by anything: the flag's own
# default (0) won every time, so the documented setting did nothing.
default_review_limit = 0
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
# Import the novelty seed the first time TrustSight runs against
# an empty database.  The seed is a signed release asset
# (baseline-seed.tar.gz) fetched from the release channel; the fetch
# is verified against the pinned key and skipped silently when
# offline.  Without it every source URL looks novel and maturity stays
# at zero, which downgrades every Medium verdict to INCONCLUSIVE.  The
# seed is public AUR data and is additive; it can never overwrite
# something learned from a real analysis.
auto_import = true

[baselines.ioc]
# IOC Federation baselines (v0.12.0).  ``enabled`` gates the match stage
# during analysis; ``sources`` is a list of baseline source names to
# consult.  An empty list means "all imported sources".  Baselines are
# imported with ``trustsight ioc import <dir>``.
enabled = true
sources = []

[[baselines.ioc.feeds]]
# Example feed entry.  TrustSight ships with no default feeds; operators
# add trusted sources here and import them explicitly.  A feed whose url
# is a release-channel URL is updated by `trustsight ioc update`, which
# downloads baseline-ioc-<asset>-manifest.json/-iocs.jsonl, verifies the
# distribution signature, and imports with the curator-key check.  Any
# other url is refused.  `asset` defaults to `name`.
name = "example-feed"
url = "https://example.org/trustsight/ioc-baseline/"
enabled = false

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
# Minutes before the offline AUR metadata snapshot is refetched.  A
# snapshot older than this reports every installed package as current,
# so `review` downloads a fresh dump (~60 MB) before comparing.  Set to
# 0 to never refresh automatically, which means version comparisons are
# only as current as the last snapshot on disk.
metadata_ttl_minutes = 60

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
# H016  a download inside build() whose URL is not in source=()
# H017  a .install hook, which runs as root, fetches or executes
# H018  a patch applied from outside the build tree (a URL, an absolute
#       path, or process substitution)
# H019  a source= URL downgraded from https to http
D001 = true
D002 = true
D003 = true
D004 = true
H016 = true
H017 = true
H018 = true
H019 = true

# H015 reports that a critical build function was modified.  It is INFO
# severity, so it carries weight 0 and cannot move a score: it fires on
# 21.4% of benign diffs and is context for a reviewer, not a signal.  That
# is why it is the one rule here safe to leave on.
H015 = true

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
# Calibrated: 22/22 injection fixtures, 0 fires across 3,246 benign
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
pattern = '\\bchmod\\s+(?:-\\S+\\s+)*(?:(?:--mode=)?(?:[2467][0-7]{3}\\b|[ugoa]*\\+s\\b))(?:\\s+--\\s+(?!["\\x27]?/)|\\s+(?!--\\s)(?!["\\x27]?/))|\\bsetcap\\s+(?:-\\S+\\s+)*["\\x27]?cap_\\w+[^\\s]*\\s+(?!["\\x27]?/)'
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
pattern = '\\bchmod\\s+(?:-\\S+\\s+)*(?:(?:--mode=)?(?:[2467][0-7]{3}\\b|[ugoa]*\\+s\\b))(?:\\s+--\\s+["\\x27]?/|\\s+(?!--\\s)["\\x27]?/)|\\bsetcap\\s+(?:-\\S+\\s+)*["\\x27]?cap_\\w+[^\\s]*\\s+["\\x27]?/'
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
# appears in *zero* of the 3,246 benign diffs - an AUR package that needs
# one of these ships it as a declared source file, which R054 reads either
# way.
#
# `ld.so.conf.d` is here on its own measurement: a directory added to the
# loader search path is code loaded into every process that starts
# afterwards, and it appears in *zero* of the 3,246 benign diffs.  It was
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
# Zero occurrences in the 3,246-diff benign corpus - a package pointing
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

# The executor list is substituted rather than written out, so R001, R002
# and R040 cannot drift from the list H016 stands down on.  See
# SHELL_EXECUTOR above for what that drift cost.
DEFAULT_RULES = (
    DEFAULT_RULES
    .replace("@@EXEC@@", ANY_EXECUTOR)
    .replace("@@SHELL@@", SHELL_EXECUTOR)
    .replace("@@NETCLIENT@@", NETWORK_CLIENT)
)

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


# The iocs.toml this project shipped before H056 existed: a placeholder with
# no schema, no tiers and no warning that a miss is uninformative.  An
# install that still carries it byte-for-byte has never been edited, so
# replacing it costs the user nothing and is the only way the documented
# schema reaches anyone who installed earlier.
LEGACY_IOCS_STUBS = frozenset({
    "[iocs]\n"
    "# H056 - exact-match indicators, each with provenance and a confidence\n"
    "# tier.  Populated by the phase that ships H056.\n"
    "version = 1\n"
    "entries = []\n"
})


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
    "# H035 - foreign package managers invoked from an install hook.  A\n"
    "# PKGBUILD that hands installation to another package manager installs\n"
    "# that payload outside pacman's control and its checksums.  Each entry\n"
    "# is a case-insensitive regex fragment matched against reconstructed\n"
    "# text.\n"
    "foreign_pkg_managers = " + _toml_str_list(DEFAULT_FOREIGN_PKG_MANAGERS) + "\n"
    "\n"
    "# H036 - obfuscation indicators counted on a single raw line.  A line\n"
    "# carrying at least [thresholds] h036_obfuscation_density distinct\n"
    "# forms fires; the reconstruction rules (H065) decide whether the\n"
    "# resolved line reveals an executable action.\n"
    "obfuscation_indicators = " + _toml_str_list(DEFAULT_OBFUSCATION_INDICATORS) + "\n"
    "\n"
    "# H067 - anti-analysis probes run from a build/install function.  A build\n"
    "# recipe checking whether it is being debugged, virtualized, sandboxed, or\n"
    "# running on CI has no packaging purpose.  Each entry is a regex fragment\n"
    "# matched against reconstructed text; legitimate arch/feature checks\n"
    "# (uname -m, getconf) never match these.\n"
    "anti_analysis_probes = " + _toml_str_list(DEFAULT_ANTI_ANALYSIS_PROBES) + "\n"
    "\n"
    "# H040 - host-profiling commands run from a build/install function.  Host\n"
    "# reconnaissance (who am I / what machine am I on) has no packaging\n"
    "# purpose; it is the recon stage of the kill-chain H043 composes.  Each\n"
    "# entry is a regex fragment matched against reconstructed text.  Fragments\n"
    "# carry a command-position anchor so bare mentions in strings, sed\n"
    "# expressions or variable values never fire; `env`, `dmidecode` and\n"
    "# systemd-detect-virt are deliberately absent (they belong to H067 or\n"
    "# produce benign false positives).  A lone `uname -m` fires H040 at INFO.\n"
    "recon_commands = " + _toml_str_list(DEFAULT_RECON_COMMANDS) + "\n"
    "\n"
    "\n"
    "# H041 - curl/wget invocation shapes that send a request body.  An\n"
    "# upload to a paste or file-drop host from a build or install function\n"
    "# is the exfil direction; a download from one is H016's undeclared\n"
    "# fetch.  Matched after the client name on a command-position line.\n"
    "upload_flags = " + _toml_str_list(DEFAULT_UPLOAD_FLAGS) + "\n"
    "\n"
    "# H077 - network clients invoked at parse time (the top level of the\n"
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
    "# H047 - security-relevant build flags.  A hardening flag dropping out of\n"
    "# (or appearing in) a long-stable configure_flags set is an attack-surface\n"
    "# change that the diff alone would not surface.\n"
    "security_relevant_flags = " + _toml_str_list(DEFAULT_SECURITY_RELEVANT_FLAGS) + "\n"
    "\n"
    "# H048 - security-relevant libraries.  When a package stops depending on\n"
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
    "# (H029).\n"
    "known_suffixes = " + _toml_str_list(DEFAULT_KNOWN_SUFFIXES) + "\n"
)

DEFAULT_HOSTS = (
    "[hosts]\n"
    "# Paste and ephemeral file-drop hosts (H041).  Bucket classification\n"
    "# in trusted_domains.toml [raw_hosting] already weights these; this\n"
    "# list backs the dedicated detection rule shipped with H041.\n"
    "paste_hosts = " + _toml_str_list(DEFAULT_PASTE_HOSTS) + "\n"
    "\n"
    "# Source schemes allowed by H034 (source URL uses exotic protocol).\n"
    "source_schemes = " + _toml_str_list(DEFAULT_SOURCE_SCHEMES) + "\n"
    "\n"
    "# Covert-egress / tunneling clients invoked in build/install (H071).\n"
    "covert_egress_clients = " + _toml_str_list(DEFAULT_COVERT_EGRESS_CLIENTS) + "\n"
    "\n"
    "# DoH endpoints flagged by H071 (covert egress).\n"
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
    "[h036]\n"
    "# H036 fires when a single line carries at least this many distinct\n"
    "# obfuscation indicators from [patterns] obfuscation_indicators.\n"
    "obfuscation_density = 3\n"
    "\n"
    "[h043]\n"
    "# H043 annotates a diff whose rule hits span at least this many distinct\n"
    "# kill-chain stages from the H043 stage map (recon, staging, persistence,\n"
    "# foreign_fetch, payload, install_hook, write_then_exec, obfuscation,\n"
    "# anti_analysis, hidden_drop, exfil, takeover, mass_adoption).\n"
    "attack_chain_stages = 3\n"
    "\n"
    "[h064]\n"
    "# H064 fires when a diff newly claims a provides/replaces entry naming a\n"
    "# package the corpus shows this many packages depend on (established,\n"
    "# official-repo membership fires regardless).\n"
    "widely_provided_observations = 25\n"
    "\n"
    "[h045]\n"
    "# H045 (mass adoption) fires when a single maintainer submits at least\n"
    "# this many packages with the whole cluster landing within this many days.\n"
    "# The no-baseline gate keeps it silent on a first bootstrap.\n"
    "min_packages = 10\n"
    "window_days = 7\n"
    "\n"
    "[h052]\n"
    "# H052 (shared source repo cluster) fires when at least this many\n"
    "# unrelated packages (distinct package bases) declare the same normalized\n"
    "# upstream source URL.\n"
    "min_packages = 3\n"
    "\n"
    "[h055]\n"
    "# H055 (attribute burst) fires when at least this many packages by one\n"
    "# maintainer are modified within this many hours.  Added packages are\n"
    "# excluded: H045 already claims the adoption clusters.\n"
    "min_packages = 5\n"
    "window_hours = 24\n"
    "\n"
    "[h073]\n"
    "# H073 (introduction-rate deviation) compares a cycle's new-package count\n"
    "# to the prior cycles; it only fires once this many prior cycles exist and\n"
    "# the rate exceeds the mean by at least this many standard deviations.\n"
    "min_history_cycles = 3\n"
    "z_score = 3.0\n"
    "min_introduced = 3\n"
    "\n"
    "[h074]\n"
    "# H074 (adopt-then-modify) fires on a package adopted this cycle whose\n"
    "# modify time still falls within this many days.\n"
    "window_days = 14\n"
    "\n"
    "[h057]\n"
    "# H057 (transitive exposure) only reports a package whose transitive\n"
    "# dependency closure reaches an adopted-from-orphan package at this many\n"
    "# hops or deeper.  Context only; weight 0.\n"
    "min_hops = 2\n"
    "\n"
    "[h060]\n"
    "# H060 (transitive orphan risk) only reports a package whose transitive\n"
    "# dependency closure reaches a currently-orphaned package at this many\n"
    "# hops or deeper.  Context only; weight 0.\n"
    "min_hops = 2\n"
    "\n"
    "[h061]\n"
    "# H061 (dependency centrality) flags a package depended on by at least\n"
    "# this many AUR packages.  Prioritisation only; weight 0.\n"
    "min_dependents = 50\n"
    "\n"
    "[h058]\n"
    "# H058 (maintainer baseline deviation) is maturity- and z-gated like H073,\n"
    "# but per maintainer against that maintainer's own prior activity.\n"
    "min_history_cycles = 3\n"
    "z_score = 2.0\n"
    "min_activity = 3\n"
    "\n"
    "[longitudinal]\n"
    "# H047-H051/H054/H037 gate on a property holding at least this many\n"
    "# consecutive observations before its break is reported.  Below it the\n"
    "# stability_weight is 0 and no PropertyBreak is emitted, so a cold or\n"
    "# immature database never fires the longitudinal rules.\n"
    "stability_floor = 10\n"
)

DEFAULT_IOCS = (
    "# H056 - Class E indicators of compromise.\n"
    "#\n"
    "# An entry is a confirmed artefact of a real incident: a package name\n"
    "# that was published as malware, a host a payload was fetched from, the\n"
    "# digest of a dropped binary.  H056 matches by exact equality and\n"
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


INT_WEIGHT_GROUPS = ("severity_weights", "source_bucket_weights", "novelty_weights")
KNOWN_BOOL_KEYS = ("seed.auto_import", "rules.experimental")


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
#
# `pattern` belongs here for the same reason the others do, and its absence
# was the more expensive omission: this function already parsed it and then
# compared everything except it, so a shipped *pattern* fix was invisible on
# every existing install and nothing said so.  The escape guard that stopped
# R001 firing on `curl \| grep` and the executor list that stopped `curl |
# ksh` slipping past both landed that way.  `outdated_shipped_rules` covers
# the same ground only for patterns a human remembered to add to
# LEGACY_RULE_PATTERNS, which is a list that has to be maintained to work.
_SEMANTIC_FIELDS = ("match_target", "severity", "category", "pattern")


def _shipped_rule_fields() -> dict[str, dict[str, str]]:
    """Parse the shipped rule blocks into ``{id: {field: value}}``."""
    parsed: dict[str, dict[str, str]] = {}
    for rid, block in _rule_blocks(DEFAULT_RULES).items():
        fields: dict[str, str] = {}
        for field in _SEMANTIC_FIELDS:
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
              "enabled", "weight_override", "exclude_if_matches")
        }

    config = load_config()
    material = {
        "rules": sorted((rule_key(r) for r in load_rules()),
                        key=lambda r: r.get("id") or ""),
        "severity_weights": config.get("severity_weights", {}),
        "source_bucket_weights": config.get("source_bucket_weights", {}),
        "novelty_weights": config.get("novelty_weights", {}),
        # The selected review policy changes which reports are flagged, even
        # though it deliberately leaves score arithmetic unchanged.
        "review_policy": _review_policy_material(config),
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


def _review_policy_material(config: dict) -> dict:
    """Return the non-arithmetic policy fields covered by the fingerprint."""
    from .review_policy import review_policy

    policy = review_policy(config)
    return {"name": policy.name, "threshold": policy.threshold}
