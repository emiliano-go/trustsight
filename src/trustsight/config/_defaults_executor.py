"""Extracted from config.py: _defaults_executor."""


__all__ = ['ANY_EXECUTOR', 'GETENT_ENUMERATION_FRAGMENT', 'CATALOGUED_FETCH_ALTERNATIVES', 'DECOMPRESSOR', 'DEFAULT_ANTI_ANALYSIS_PROBES', 'DEFAULT_CONFUSABLE_CHARS', 'DEFAULT_CONFUSABLE_DOMAINS', 'DEFAULT_COVERT_EGRESS_CLIENTS', 'DEFAULT_COVERT_EGRESS_ENDPOINTS', 'DEFAULT_ECOSYSTEM_PREFIXES', 'DEFAULT_FOREIGN_PKG_MANAGERS', 'DEFAULT_FREE_HOSTING_DOMAINS', 'DEFAULT_FREE_REGISTRAR_TLDS', 'DEFAULT_H029_MIN_OBSERVATIONS', 'DEFAULT_H029_PLAIN_MIN_OBSERVATIONS', 'DEFAULT_KNOWN_SUFFIXES', 'DEFAULT_MANIFEST_FILENAMES', 'DEFAULT_NETWORK_TOOLS', 'DEFAULT_OBFUSCATION_INDICATORS', 'DEFAULT_PARSE_TIME_FETCH', 'DEFAULT_PASTE_HOSTS', 'DEFAULT_RECON_COMMANDS', 'DEFAULT_SECURITY_RELEVANT_FLAGS', 'DEFAULT_SECURITY_RELEVANT_LIBRARIES', 'DEFAULT_SOURCE_SCHEMES', 'DEFAULT_STANDARD_PORTS', 'DEFAULT_UPLOAD_FLAGS', 'DEFAULT_VARIANT_SUFFIXES', 'EXEC_WRAPPER', 'LEGACY_FOREIGN_PKG_MANAGER_LISTS', 'LEGACY_NETWORK_TOOL_LISTS', 'LEGACY_NETWORK_TOOLS', 'NETWORK_CLIENT', 'NETWORK_CLIENT_ALTERNATIVES', 'OTHER_FETCH_CLIENT', 'PACKAGE_MANAGER_INSTALL', 'PAYLOAD_PRODUCER', 'SCRIPT_EXECUTOR', 'SHELL_EXECUTOR', 'STRUCTURED_EXTRACTOR', '_SUBCOMMAND_OPTS']

LEGACY_FOREIGN_PKG_MANAGER_LISTS = [
    (
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
    ),
]

DEFAULT_FOREIGN_PKG_MANAGERS = list(LEGACY_FOREIGN_PKG_MANAGER_LISTS[0]) + [
    # One-shot runners resolve and execute a package with no install step.
    r"\bnpx\s+", r"\bbunx\s+", r"\bpnpx\s+",
    r"\bpipx\s+", r"\buvx\s+", r"\bpython3?\s+-m\s+pip3?\s+install\b",
    r"\bpkgx\s+", r"\bnix\s+run\b",
    r"\bdeno\s+(?:run|install|cache)\b",
    # Container runtimes and the run-a-remote-module verbs.
    r"\b(?:docker|podman)\s+(?:run|pull)\b",
    r"\bcargo\s+script\b", r"\bbun\s+x\b", r"\buv\s+run\b",
    r"\bpoetry\s+run\b", r"\bpipenv\s+run\b", r"\bconda\s+run\b",
]

SHELL_EXECUTOR = r"(?:ba|z|da|k|mk|pdk|ya|po|a)?sh|busybox\s+(?:ash|sh)"

SCRIPT_EXECUTOR = SHELL_EXECUTOR + (
    r"|python3?|perl|ruby|node|php|lua(?:jit)?|tclsh|wish"
    r"|fish|tcsh|csh|rc|es|elvish|xonsh|nu|osh"
)

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

_SUBCOMMAND_OPTS = (
    r"(?:\s+(?:--[^\s;&|]+|-[^-\s;&|][^\s;&|]*))*"
    r"(?:\s+[^-\s;&|][^\s;&|]*)*"
)

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
    # FreeBSD's fetch.  `fetch -o "$srcdir"/stage URL` is the same download
    # as curl's; the `(?!\()` keeps a local `fetch()` helper function from
    # reading as the client.
    r"fetch(?!\()",
    r"openssl\s+s_client",
    r"dig", r"host", r"nslookup", r"drill", r"kdig",
    # `git -C "$srcdir/x" pull` puts the repository path between the verb
    # and the subcommand, and the straight `git\s+(?:clone|...)` spelling
    # saw no client at all - exactly the spelling a build helper uses.
    # Global options may precede the subcommand.
    r"git(?:\s+(?:-C\s*\S+|-c\s*\S+|--\S+))*\s+(?:clone|fetch|pull|ls-remote|archive)",
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
    r"s3cmd" + _SUBCOMMAND_OPTS + r"\s+(?:get|sync|cp)",
    r"aws\s+s3" + _SUBCOMMAND_OPTS + r"\s+(?:cp|sync|mv)",
    # `aws s3api get-object` is the API-level spelling of the same transfer
    # and was never in the inventory at all; the wave-3/5 probes fetched
    # through it and scored nothing.
    r"aws\s+s3api" + _SUBCOMMAND_OPTS + r"\s+get-object",
    r"gsutil" + _SUBCOMMAND_OPTS + r"\s+(?:cp|rsync)",
    r"az(?:copy)?" + _SUBCOMMAND_OPTS + r"\s+(?:storage\s+blob\s+download|copy)",
    r"rclone" + _SUBCOMMAND_OPTS + r"\s+(?:copy|sync|cat|copyto|copyurl|moveto|move|bisync)",
    r"ipfs" + _SUBCOMMAND_OPTS + r"\s+(?:get|cat|dag\s+get)",
    r"swift" + _SUBCOMMAND_OPTS + r"\s+download",
    r"rados" + _SUBCOMMAND_OPTS + r"\s+get",
    r"git(?:\s+(?:-C\s*\S+|-c\s*\S+|--\S+))*\s+lfs\s+(?:pull|fetch|checkout)",
    r"yt-dlp|youtube-dl",
    # A lookahead, for the reason the BSD `fetch` arm needs one: consuming
    # the magnet link as part of the client token leaves no address behind
    # for the address matcher, so the fetch is recognised and scores
    # nothing.
    r"transmission-cli|aria2c(?=\s+[^\n;&|]*magnet:)",
    r"b2\s+download-file",
    # The Backblaze CLI v1 spelling `b2 download` (v2 is `download-file`).
    # The validator kept the v1 alias while core listed only v2, and a
    # payload fetching through `b2 download` scored 0 in core while the
    # validator certified the chain intact - each half consistent against
    # its own list, wrong together.  The v2 alternative above stays pinned
    # verbatim (the harness drift test whitelists it by exact spelling);
    # `\b` keeps this arm from claiming `download-file` by prefix.
    r"b2\s+download\b",
    r"restic\s+restore|borg\s+extract",
    # libwww-perl ships a CLI, and it is the one a Perl recipe reaches for
    # when it wants a download without a shell-out to curl.
    #
    # `GET`, `POST` and `HEAD` are its aliases and are deliberately absent:
    # matching is case-insensitive here, so they would claim every `get`
    # in the ecosystem. `lwp-request` is what the alias runs and cannot be
    # confused with an English word.
    r"lwp-request", r"lwp-download",
    # `npx` runs a package fetched from the registry in one step; the
    # harness's validator listed it while the engine's client vocabulary
    # did not, so a chain through it was unmeasurable and unwatched.
    r"npx",
    # `git push` sends bytes *out*. The inventory had clone/fetch/pull -
    # every way to bring code in and no way to send it - so a recipe
    # exfiltrating through a push looked like nothing at all.
    r"git(?:\s+(?:-C\s*\S+|-c\s*\S+|--\S+))*\s+push",
    # BSD `fetch(1)`. Anchored on a URL argument because `fetch` on its own
    # is a word `git fetch` and a hundred build scripts already use.
    # A lookahead, not a match: consuming the URL as part of the client
    # token left no address behind for the address matcher to pair with,
    # so the client was recognised and the fetch still scored nothing.
    r"fetch(?=\s+[^\n;&|]*\b(?:https?|ftps?)://)",
)

NETWORK_CLIENT = "|".join(NETWORK_CLIENT_ALTERNATIVES)

CATALOGUED_FETCH_ALTERNATIVES = (r"curl", r"wget2?")

OTHER_FETCH_CLIENT = "|".join(
    alt for alt in NETWORK_CLIENT_ALTERNATIVES
    if alt not in CATALOGUED_FETCH_ALTERNATIVES
)

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

PAYLOAD_PRODUCER = (
    DECOMPRESSOR
    + r"|\b(?:base64|base32|basenc|uudecode|uudeview)\b"
    r"|\bxxd\s+[^\n|;&]*?-[A-Za-z]*r"
    r"|\bod\s+[^\n|;&]*?-A"
    r"|\bopenssl\s+(?:enc|base64|zlib)\b"
    r"|\bcertutil\s+[^\n|;&]*?-decode"
)

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
    r"\|[^|\n]*\b(?:bash|sh|zsh)\b",
    r"(?:bit\.ly|t\.co|tinyurl|shorturl|ow\.ly|is\.gd)",
    r"wget\s+-q\s+-O\s*-\s*\|",
    r"\$\{[a-zA-Z_][a-zA-Z0-9_]*\}.*(?:curl|wget|bash|sh)",
    # June-W3 campaign markers (confirmed campaign indicators): ANSI-C
    # quoting, variable indirection, empty-quote concatenation.
    r"\$'",
    r"\$\{!",
    r"(?<=\w)''(?=\w)",
]

#: The udev/chroot guard an install scriptlet legitimately runs to decide
#: whether udev is present.  It is not an analysis probe, so it is excluded
#: by a negative lookahead on the command; `systemd-detect-virt -q`, `--vm`
#: and `--container` still fire.
H067_SYSTEMD_DETECT_VIRT_PROBE = r"systemd-detect-virt(?!\s+--chroot\b)"
H067_LEGACY_SYSTEMD_DETECT_VIRT = r"systemd-detect-virt"

DEFAULT_ANTI_ANALYSIS_PROBES = [
    r"TracerPid",                                   # /proc/self/status debugger marker
    r"\b(?:gdb|strace|lldb|ptrace)\b",              # debugger clients / probe interfaces
    H067_SYSTEMD_DETECT_VIRT_PROBE,
    r"virt-what",
    r"\bdmidecode\b",
    r"hypervisor",                                  # DMI / /proc/cpuinfo virtualization marker
    r"/\.dockerenv|/run/\.containerenv",            # container sandbox markers
    r"\$\{?(?:CI|GITHUB_ACTIONS|GITLAB_CI|TRAVIS|JENKINS_URL|BUILD_ID|BUILD_NUMBER|CIRCLECI|TF_BUILD|CONTAINER)\}?",
]

#: The H040 getent fragment, named because config/__init__ repairs legacy
#: patterns.toml files by substituting it for the pre-narrowing fragment.
#: `getent <db>` with no key enumerates the database (account/hosts dump -
#: recon); `getent passwd <name>` is a targeted lookup and the standard
#: provisioning step before useradd, so it must not fire.
GETENT_ENUMERATION_FRAGMENT = r"(?:\A\s*|[;&|]\s*)getent\s+\w+\s*(?=$|[;&|])"

DEFAULT_RECON_COMMANDS = [
    r"(?:\A\s*|[;&|]\s*)uname\b",
    r"(?:\A\s*|[;&|]\s*)whoami\b",
    r"(?:\A\s*|[;&|]\s*)id\b",
    r"(?:\A\s*|[;&|]\s*)logname\b",
    GETENT_ENUMERATION_FRAGMENT,
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

DEFAULT_PARSE_TIME_FETCH = [
    r"(?:\A|[;&|]|\$\()\s*curl\b",
    r"(?:\A|[;&|]|\$\()\s*wget\b",
    r"(?:\A|[;&|]|\$\()\s*aria2c\b",
    r"(?:\A|[;&|]|\$\()\s*axel\b",
    r"(?:\A|[;&|]|\$\()\s*lynx\b",
    r"(?:\A|[;&|]|\$\()\s*fetch(?!\()",
    r"(?:\A|[;&|]|\$\()\s*w3m\b",
    r"(?:\A|[;&|]|\$\()\s*elinks\b",
    r"(?:\A|[;&|]|\$\()\s*links\b",
    r"(?:\A|[;&|]|\$\()\s*browsh\b",
    r"(?:\A|[;&|]|\$\()\s*http\b",
    r"(?:\A|[;&|]|\$\()\s*snarf\b",
    r"(?:\A|[;&|]|\$\()\s*yt-dlp\b",
    r"(?:\A|[;&|]|\$\()\s*rclone\b",
    r"(?:\A|[;&|]|\$\()\s*s3cmd\b",
    r"(?:\A|[;&|]|\$\()\s*swift\b",
    r"(?:\A|[;&|]|\$\()\s*ipfs\b",
    r"(?:\A|[;&|]|\$\()\s*rsync\b",
    r"(?:\A|[;&|]|\$\()\s*restic\b",
    r"(?:\A|[;&|]|\$\()\s*borg\b",
    r"(?:\A|[;&|]|\$\()\s*ncftpget?\b",
    r"(?:\A|[;&|]|\$\()\s*ftp\b",
    r"(?:\A|[;&|]|\$\()\s*tftp\b",
    r"(?:\A|[;&|]|\$\()\s*lftp\b",
    r"(?:\A|[;&|]|\$\()\s*rados\b",
    r"(?:\A|[;&|]|\$\()\s*lwp-(?:request|download)\b",
    r"(?:\A|[;&|]|\$\()\s*telnet\b",
    r"(?:\A|[;&|]|\$\()\s*socat\b",
    r"(?:\A|[;&|]|\$\()\s*openssl\s+s_client\b",
    r"(?:\A|[;&|]|\$\()\s*ncat\b",
    r"(?:\A|[;&|]|\$\()\s*nc\s+-",
    r"(?:\A|[;&|]|\$\()\s*scp\b",
    r"(?:\A|[;&|]|\$\()\s*sftp\b",
    r"(?:\A|[;&|]|\$\()\s*git\s+clone\b",
    r"(?:\A|[;&|]|\$\()\s*git\s+fetch\b",
    r"(?:\A|[;&|]|\$\()\s*svn\s+(?:co|checkout|export)\b",
    r"(?:\A|[;&|]|\$\()\s*hg\s+clone\b",
    r"(?:\A|[;&|]|\$\()\s*pip3?\s+install\b",
    r"(?:\A|[;&|]|\$\()\s*npm\s+(?:install|i|add)\b",
    r"(?:\A|[;&|]|\$\()\s*cargo\s+(?:install|fetch)\b",
    r"(?:\A|[;&|]|\$\()\s*go\s+(?:get|install)\b",
]

DEFAULT_NETWORK_TOOLS = [
    "curl", "wget", "aria2", "axel", "lftp", "ftp", "tftp", "socat",
    "netcat", "ncat", "nc", "telnet", "sshpass", "openssh",
    "git", "subversion", "mercurial", "rsync",
    "python-requests", "python-httpx", "python-urllib3", "python-aiohttp",
    "python-pip", "python-uv", "ruby-net-http", "nodejs", "npm", "pnpm",
    "yarn", "bun", "uv", "cargo", "go",
]

#: Lists shipped before the transfer-client expansion.  ``patterns.toml`` is
#: written once at install and never synced, so an existing install keeps its
#: old list forever; the repair swaps an exact shipped table for the new one
#: and leaves any user edit alone.  Oldest first.
LEGACY_NETWORK_TOOL_LISTS = (
    [
        "curl", "wget", "aria2", "git", "subversion", "mercurial", "rsync",
        "python-requests", "python-httpx", "python-urllib3", "python-aiohttp",
        "ruby-net-http", "nodejs", "npm", "yarn", "cargo", "go",
    ],
    [
        "curl", "wget", "aria2", "git", "subversion", "mercurial", "rsync",
        "python-requests", "python-httpx", "python-urllib3", "python-aiohttp",
        "python-pip", "python-uv", "ruby-net-http", "nodejs", "npm", "pnpm",
        "yarn", "bun", "uv", "cargo", "go",
    ],
)

LEGACY_NETWORK_TOOLS = LEGACY_NETWORK_TOOL_LISTS[-1]

DEFAULT_VARIANT_SUFFIXES = (
    "-git", "-bin", "-svn", "-hg", "-bzr", "-cvs", "-nightly",
    "-beta", "-stable", "-lts", "-devel",
)

DEFAULT_ECOSYSTEM_PREFIXES = [
    "python", "python2", "python3", "perl", "ruby", "rust", "golang", "go",
    "php", "lua", "nodejs", "node", "js", "haskell", "ocaml", "texlive",
    "r", "vim", "emacs", "ttf", "otf", "font", "fonts", "lib", "lib32",
    "mingw", "aur", "sh",
]

DEFAULT_KNOWN_SUFFIXES = (
    "-git", "-bin", "-debug", "-lts", "-stable", "-beta",
    "-svn", "-hg", "-bzr", "-cvs",
    "-wine", "-appimage", "-flatpak", "-nightly", "-devel", "-common",
)

DEFAULT_CONFUSABLE_CHARS = (
    "0oO", "1lIi", "2zZ", "3eE", "4aA", "5sS",
    "6bBG", "7tT", "8bB", "9gq",
)

DEFAULT_H029_MIN_OBSERVATIONS = 100

DEFAULT_H029_PLAIN_MIN_OBSERVATIONS = 1000

DEFAULT_PASTE_HOSTS = [
    "pastebin.com", "gist.github.com", "paste.ee", "0x0.st", "termbin.com",
    "hastebin.com", "ix.io", "transfer.sh", "file.io", "bashupload.com",
    "temp.sh", "anonfiles.com", "dpaste.com", "sprunge.us",
]

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

DEFAULT_SOURCE_SCHEMES = [
    "https", "http", "ftp", "ftps", "ssh", "git", "hg", "svn", "bzr",
    "cvs", "file", "dav", "davs",
]

DEFAULT_COVERT_EGRESS_CLIENTS = [
    r"(?:torsocks|torify|proxychains4?)\b",
    r"(?:ncat|socat|openvpn|wireguard)\b",
    r"(?:ngrok|frpc|frps|chisel|revsocks)\b",
    r"(?:iodine|dnscat2?)\b",
]

DEFAULT_COVERT_EGRESS_ENDPOINTS = [
    "dns.google", "cloudflare-dns.com", "dns.quad9.net",
    "doh.opendns.com", "dns.hostux.net", "mozilla.cloudflare-dns.com",
]

DEFAULT_CONFUSABLE_DOMAINS = [
    "github.com", "gitlab.com", "bitbucket.org", "google.com", "gmail.com",
    "youtube.com", "facebook.com", "twitter.com", "paypal.com", "amazon.com",
    "microsoft.com", "sourceforge.net", "archlinux.org", "aur.archlinux.org",
    "python.org", "npmjs.com", "crates.io", "mozilla.org", "debian.org",
    "gnu.org", "kernel.org", "stackoverflow.com", "wikipedia.org",
]

DEFAULT_STANDARD_PORTS = [80, 443, 8080, 8443]

DEFAULT_FREE_REGISTRAR_TLDS = ["tk", "ml", "ga", "cf", "gq", "pw"]

DEFAULT_FREE_HOSTING_DOMAINS = [
    # Dynamic DNS
    "duckdns.org", "no-ip.org", "noip.com", "no-ip.biz", "ddns.net",
    "hopto.org", "zapto.org", "sytes.net", "dynu.com", "dynv6.net",
    "afraid.org", "changeip.com", "dyndns.org",
    # Tunnels
    "ngrok.io", "ngrok.app", "ngrok-free.app", "trycloudflare.com",
    "localtunnel.me", "loca.lt", "serveo.net", "bore.pub", "pinggy.io",
    "localhost.run", "lhr.life", "pagekite.me", "portmap.io",
    # Free / static hosting
    "pages.dev", "workers.dev", "r2.dev", "github.io", "gitlab.io",
    "codeberg.page", "vercel.app", "netlify.app", "web.app",
    "firebaseapp.com", "surge.sh", "render.com", "onrender.com",
    "glitch.me", "replit.dev", "herokuapp.com", "deno.dev", "railway.app",
]

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

DEFAULT_SECURITY_RELEVANT_LIBRARIES = [
    "openssl", "libssl", "libcrypto", "openssl-1.1", "libressl",
    "gnutls", "nss", "nspr", "libgcrypt", "libsodium", "libcurl",
    "curl", "zlib", "libpng", "libjpeg", "libjpeg-turbo", "libtiff",
    "libxml2", "expat", "pcre", "pcre2", "sqlite", "libsqlite3",
    "icu", "libicu", "dbus", "libdbus", "pam", "libpam", "libsystemd",
    "libudev", "liblzma", "zstd", "libzstd",
]

DEFAULT_MANIFEST_FILENAMES = (
    "cargo::Cargo.toml",
    "cargo::Cargo.lock",
    "cargo::cargo/config.toml",
    "cargo::.cargo/config.toml",
    "cargo::cargo/config",
    "cargo::.cargo/config",
    "npm::package.json",
    "npm::package-lock.json",
    "npm::npm-shrinkwrap.json",
    "npm::yarn.lock",
    "npm::pnpm-lock.yaml",
    "npm::.npmrc",
    "npm::.yarnrc.yml",
    "pip::pyproject.toml",
    "pip::requirements.txt",
    "pip::requirements*.txt",
    "pip::requirements/*.txt",
    "pip::*-requirements.txt",
    "pip::requirements*.in",
    "pip::constraints.txt",
    "pip::constraints*.txt",
    "pip::Pipfile",
    "pip::Pipfile.lock",
    "pip::poetry.lock",
    "pip::uv.lock",
    "pip::uv.toml",
    "pip::pdm.lock",
    "pip::pylock.toml",
    "pip::pylock.*.toml",
    "pip::setup.py",
    "pip::setup.cfg",
    "pip::tox.ini",
    "pip::noxfile.py",
    "pip::pip.conf",
    "pip::pip.ini",
    "pip::.pip/pip.conf",
    "pip::.config/pip/pip.conf",
    "pip::.pypirc",
    "conda::environment.yml",
    "conda::environment.yaml",
    "conda::meta.yaml",
    "conda::pixi.toml",
    "conda::pixi.lock",
    "conda::conda-lock.yml",
    "conda::*.conda-lock.yml",
    "go::go.mod",
    "go::go.sum",
    "go::go.work",
    "go::go.work.sum",
    "gem::Gemfile",
    "gem::Gemfile.lock",
    "gem::*.gemspec",
    "composer::composer.json",
    "composer::composer.lock",
    "npm::deno.json",
    "npm::deno.jsonc",
    "npm::bun.lock",
    "jvm::pom.xml",
    "jvm::build.gradle",
    "jvm::build.gradle.kts",
    "jvm::settings.gradle",
    "jvm::settings.gradle.kts",
    "jvm::gradle/libs.versions.toml",
    "dotnet::*.csproj",
    "dotnet::*.fsproj",
    "dotnet::*.vbproj",
    "dotnet::packages.config",
    "dotnet::NuGet.config",
    "dotnet::Directory.Packages.props",
    "dart::pubspec.yaml",
    "dart::pubspec.lock",
    "crystal::shard.yml",
    "crystal::shard.lock",
    "julia::Project.toml",
    "julia::Manifest.toml",
    "cpp::vcpkg.json",
    "cpp::conanfile.txt",
    "haskell::*.cabal",
    "ocaml::*.opam",
    "elixir::mix.exs",
    "elixir::mix.lock",
    "r::DESCRIPTION",
    "r::renv.lock",
    "perl::cpanfile",
    "fortran::fpm.toml",
    "gleam::gleam.toml",
    "swift::Package.resolved",
    "swift::Package.swift",
    "swift::Podfile",
    "swift::Cartfile",
    "swift::Cartfile.resolved",
    "zig::build.zig.zon",
    "d::dub.json",
    "nim::*.nimble",
    "lua::*.rockspec",
    "clojure::deps.edn",
    "clojure::project.clj",
    "ocaml::dune-project",
    "elixir::rebar.config",
    "elixir::rebar.lock",
    "haskell::cabal.project",
    "haskell::cabal.project.freeze",
    "haskell::stack.yaml",
    "haskell::stack.yaml.lock",
    "haskell::package.yaml",
    "cpp::CMakeLists.txt",
    "cpp::meson.build",
    "bazel::MODULE.bazel",
    "perl::META.json",
    "perl::META.yml",
)
