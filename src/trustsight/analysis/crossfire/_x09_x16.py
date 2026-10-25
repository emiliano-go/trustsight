"""Extracted from crossfire.py: _x09_x16."""

from __future__ import annotations
import re
from ...config import (
    NETWORK_CLIENT as _NETWORK_CLIENT,
    SCRIPT_EXECUTOR,
    OTHER_FETCH_CLIENT as _OTHER_FETCH_CLIENT,
    PACKAGE_MANAGER_INSTALL as _PACKAGE_MANAGER_INSTALL,
)
from ...deps import _strip_comment
from ._common import _DATA_CONSUMER, _EXEC_WRAPPER, _SHELL

__all__ = ['X009_RE', 'X010_RE', 'X011_RE', 'X011_STANDDOWN_RE', 'X012_CONSUMER_RE', 'X012_RE', 'X013_RE', 'X013_STANDDOWN_RE', 'X014_RE', 'X014_STANDDOWN_RE', 'X015_RE', 'X018_RE', 'X019_RE', '_DISTRO_INSTALL_RE', '_X009_CLIENT_RE', '_X016_CONSUMER_RE', '_X016_FETCH_RE', '_X016_KNOWN_EXECUTOR_RE', '_consumer_after_override', '_consumer_at']

X009_RE = re.compile(
    r"\b(?:" + _OTHER_FETCH_CLIENT + r")\b[^\n|;&]*+"
    r"(?<!\\)\|\s*(?:" + _SHELL + r")",
    re.IGNORECASE,
)

X010_RE = re.compile(
    r"\b(?:python[23]?|perl|ruby|node|php|lua)\s+(?:-\S++\s++)*?-[ceEr]\b"
    r"[^\n]{0,400}?"
    r"(?:https?://"
    r"|urlopen|urlretrieve|urllib|requests\.(?:get|post)|httpx"
    r"|file_get_contents|fsockopen|curl_exec"
    r"|Net::HTTP|LWP|getstore|open-uri|URI\.(?:open|parse)"
    r"|https?\.get|fetch\s*\(|socket\.(?:create_)?connect)",
    re.IGNORECASE,
)

X018_RE = re.compile(
    r"\b(?:python[23]?|perl|ruby|node|deno|bun|php|lua)\s+(?:-\S++\s++)*?-[ceEr]\b"
    r"[^\n]{0,400}?(?:"
    # Reflection: the name is a value, not a token.
    r"__import__\s*\(|importlib\.import_module|getattr\s*\(|__dict__\s*\["
    r"|Object\[|eval\s*\(|exec\s*\(|Function\s*\(|instance_eval"
    r"|const_get|send\s*\(:|call_user_func|\$\$\w+"
    # Or the name is glued together from pieces no list can hold.
    r"|[\"'][A-Za-z_][\w.]*[\"']\s*\+\s*[\"'][\w.]*[\"']"
    r"|[\"'][\w.]*[\"']\s*\.\s*[\"'][\w.]*[\"']"
    # Or the one-liner simply hands a build-tree path to the language's
    # own exec primitive: `ruby -e 'exec "bash", "$srcdir/x.sh"'`. No name
    # is assembled and no module is imported, so neither the reflection
    # arms above nor X010's network list has anything to match.
    # Ruby writes `exec "bash", "x"` with no parentheses at all, so the
    # call is recognised by the name followed by *either* a paren or
    # whitespace.
    r"|(?:exec|system|spawn|popen|execv?p?e?|posix_spawn|Process\.\w+"
    r"|subprocess\.\w+|os\.exec\w*|open[23]|IPC::Open[23])\s*[\s(][^\n]{0,120}?"
    r"\$\{?(?:srcdir|startdir|PWD|BUILDDIR)\}?/"
    r")",
    re.IGNORECASE,
)

X019_RE = re.compile(
    # A query name or ICMP payload the recipe computes.
    # Command position, not anywhere: `host` is also an English word, and
    # `echo "Host: $(uname -rn)"` is a build script printing a banner.
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:dig|drill|kdig|host|nslookup)\s"
    r"[^\n;&|]*\$[({]"
    r"|(?:\A\s*|[;&|(]\s*|&&\s*)ping6?\s[^\n;&|]*\s-p\s*[\"']?\$[({]"
    # Host material written into the package.
    r"|(?:\A\s*|[;&|(]\s*|&&\s*)(?:env|printenv|set|hostname|id|uname)\b"
    r"[^\n;&|]*>\s*[\"']?[^\"'\s;&|]*\$\{?pkgdir\}?"
    r"|(?:/etc/(?:machine-id|hostname|shadow|hosts)"
    r"|\$\{?HOME\}?/\.(?:ssh|aws|gnupg|docker|netrc)"
    r"|~/\.(?:ssh|aws|gnupg|docker|netrc)"
    r"|\.(?:bash_history|zsh_history))"
    r"[^\n;&|]*>\s*[\"']?[^\"'\s;&|]*\$\{?pkgdir\}?",
    re.IGNORECASE,
)

X011_STANDDOWN_RE = re.compile(
    r"--ignore-scripts|--no-index|--offline|--no-deps"
    r"|--frozen-lockfile\b[^\n]*--offline"
    # `--prefix "$srcdir"` is a destination, not a target, and matching any
    # occurrence of `$srcdir` stood the rule down on
    # `npm install evilpkg --prefix "$srcdir"` - a registry fetch with a
    # local install prefix, which is the opposite of what the flag means.
    # A relative target (`npm install ./pkg`) is decided after the match by
    # `_x011_local_target`, so a `./` in the manager's own path stays a
    # registry fetch.
    r"|(?<!prefix=)(?<!prefix\s)(?<!prefix=\")(?<!root=)\s\$\{?(?:srcdir|startdir)\}?/"
    # A *local* artifact only, and the whole argument must be local: anchored
    # to a whitespace-preceded token so the match cannot start part-way
    # through `https://e/x.tgz`, which is a remote target that happens to
    # end in an archive suffix.  Standing down on that would be reading the
    # extension instead of the address.
    r"|(?<=\s)(?!\S*://)[\w.-]+(?:/[\w.-]+)*\.(?:whl|tgz|gem|crate)\b",
    re.IGNORECASE,
)

_DISTRO_INSTALL_RE = re.compile(
    r"\b(?:pacman\s+-|makepkg\s+(?:-\S*i|--install)"
    r"|(?:apt-get|apt|dnf|yum|zypper|apk|emerge)\s+(?:install|add))",
    re.IGNORECASE,
)

X011_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*|\|\|\s*)"
    r"(?:" + _EXEC_WRAPPER + r")?"
    # A vendored toolchain runs the manager through a path: `v/bin/pip` and
    # `./tools/node/bin/npm` are the same command to the shell as `pip` and
    # `npm`, and both resolve from the registry.
    r"(?:/?(?:[\w.$~{}-]+/)+)?"
    # `python3 -m pip install` and `node --require ... npm` reach the same
    # manager through the interpreter that ships it.
    r"(?:(?:python[23]?|py|node|ruby|perl)\s+-\S+\s+)?"
    r"(?:" + _PACKAGE_MANAGER_INSTALL + r")\b",
    re.IGNORECASE,
)

X012_RE = re.compile(
    r"\b(?:export\s+)?"
    r"(?P<var>CC|CXX|LD|AR|RANLIB|NM|OBJCOPY|STRIP|CPP|HOSTCC"
    r"|PATH|LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT|PERL5LIB|PYTHONPATH"
    r"|NODE_OPTIONS|RUSTC_WRAPPER|MAKEFLAGS|CARGO)\s*=\s*"
    r"[\"']?[^\n\"']*?"
    # `PATH="$srcdir:$PATH"` prepends the build directory itself, with no
    # path component after it, and requiring a `/` meant the plainest
    # spelling of the plainest case matched nothing.
    r"\$\{?(?:srcdir|startdir|pkgdir)\}?(?:[/:\"']|\s|$)",
    re.IGNORECASE,
)

X012_CONSUMER_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:" + _EXEC_WRAPPER + r")?"
    r"(?:g?make|cmake|ninja|meson|configure|\./configure|autoreconf|gcc|g\+\+"
    r"|clang|cargo|go|rustc|python[23]?\s+setup\.py|scons|waf|bazel)\b",
    re.IGNORECASE,
)

X013_STANDDOWN_RE = re.compile(
    r"(?:gpg2?|pacman-key)\b(?![^\n;&|]*--recv-keys)"
    r"[^\n;&|]*\$\{?srcdir\}?/",
    re.IGNORECASE,
)

X013_RE = re.compile(
    r"--(?:proxy|preproxy|socks[45]a?|proxy1\.0|noproxy|doh-url"
    r"|resolve|connect-to|cacert|capath|proxy-cacert|proxy-insecure"
    r"|pinnedpubkey)\b"
    r"|\b(?:export\s+)?(?:HTTPS?_PROXY|https?_proxy|ALL_PROXY|all_proxy"
    r"|NO_PROXY|no_proxy|SSL_CERT_FILE|SSL_CERT_DIR|CURL_CA_BUNDLE"
    r"|GIT_SSL_CAINFO|GIT_SSL_NO_VERIFY|REQUESTS_CA_BUNDLE|NODE_EXTRA_CA_CERTS"
    r"|PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|npm_config_registry)\s*=" 
    r"|\bgit\b[^\n;&|]*?-c\s+(?:http|https)\.(?:proxy|sslCAInfo|sslVerify)"
    r"|\bnpm\s+config\s+set\s+(?:registry|cafile|strict-ssl)"
    # A keyring is a trust root too.  `gpg --import k.asc` on a key this
    # recipe fetched, or `--recv-keys` from a keyserver it names, makes
    # every later signature check pass against the attacker's key - the
    # same substitution as replacing a CA bundle, with verification left
    # switched on so it reads as diligence.  `--verify` is untouched: that
    # is the check, not the trust.
    r"|\bgpg2?\b[^\n;&|]*?--(?:import\b|recv-keys|keyserver|import-ownertrust)"
    r"|\bpacman-key\b[^\n;&|]*?--(?:add|recv-keys|lsign-key|populate)"
    r"|\bapt-key\s+add|\brpm\s+--import"
    r"|\bpip\s+config\s+set\b[^\n;&|]*?index-url",
    re.IGNORECASE,
)

X014_RE = re.compile(
    r"\b(?:export\s+|declare\s+-x\s+)?"
    r"(?P<var>BASH_ENV|ENV|PROMPT_COMMAND|PS0|PS4"
    r"|SHELLOPTS|BASHOPTS|BASH_FUNC_\w+%%"
    r"|GIT_SSH_COMMAND|GIT_EXTERNAL_DIFF|GIT_PAGER|GIT_EDITOR"
    r"|LESSOPEN|LESSCLOSE|PAGER|EDITOR|VISUAL"
    r"|LD_AUDIT|GCONV_PATH|LOCPATH|HOSTALIASES"
    # The per-interpreter equivalents of BASH_ENV: each names code the
    # interpreter runs before the program it was asked to run.
    #
    # `PERL5LIB` and `PYTHONPATH` are deliberately absent. They name a
    # place to *look for* modules, not code to run, and `perl-*` and
    # `python-*` recipes set them as a matter of course - five benign
    # packages fired the moment they were included. X012 already claims
    # them, and claims the thing that actually matters about them: a
    # library path pointed into the source tree.
    r"|RUBYOPT|PERL5OPT|PYTHONSTARTUP|NODE_REPL_EXTERNAL_MODULE"
    r"|LUA_INIT|R_PROFILE_USER|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS)"
    r"\s*=\s*(?![\s;]*$)"
    # A command-line hook flag carries code the same way an environment
    # variable does: `restic --option pre-exec=...`, `borg --pre-hook ...`,
    # `rsync -e "ssh -o ProxyCommand=..."`, `--exec`, `--on-failure`.  The
    # tool runs the value; the recipe only names it.
    r"|--(?:pre|post)-?(?:exec|hook|command|script|backup|run)\b"
    r"|\b(?:pre|post)-(?:exec|hook|command|script)\s*="
    r"|\bProxyCommand\s*=|\bLocalCommand\s*=|\bPermitLocalCommand\b"
    # git's own documented exec-bearing configuration keys. A bounded
    # list, because git publishes it: each of these names a program git
    # runs, and `git -c key=cmd <verb>` or `git config key cmd` sets one
    # without any of it looking like a command.
    r"|\bcore\.(?:fsmonitor|pager|editor|sshCommand|hooksPath|askPass)\b"
    r"|\bdiff\.(?:external|[\w-]+\.(?:command|textconv))\b"
    # `submodule.<n>.update` takes `checkout|rebase|merge|none|!command`
    # and a git alias is a git subcommand unless it is prefixed with `!`.
    # Only the bang form runs a shell, and `git config
    # submodule.lib/googletest.update "none"` - disabling a submodule - is
    # ordinary enough to appear in the benign corpus twice.
    r"|\bsubmodule\.[^\s=]*\.update\b\s*[= ]\s*[\"']?!"
    r"|\balias\.[\w-]+\b\s*[= ]\s*[\"']?!"
    r"|\bfilter\.[\w-]+\.(?:clean|smudge|process)\b"
    r"|\bcredential\.(?:helper|[\w:/.]+\.helper)\b"
    r"|\buploadpack\.packObjectsHook\b|\bprotocol\.[\w-]+\.command\b"
    r"|\bsequence\.editor\b|\bgpg\.program\b"
    # `rsync -e`/`--rsh` names the transport program rsync executes.
    r"|\brsync\b[^\n;&|]*?\s--?(?:e|rsh)[=\s]"
    # `filter` is deliberately absent: pnpm/yarn `--filter @scope/pkg` and
    # rsync `--filter` rules select work, they do not name a program.
    r"|--(?:exec|command|on-failure|on-success|use-compress-program)"
    r"\s*[=\s]\s*[\"']?[^\s\"';]*/"
    # Flag-agnostic, and bounded on the *value* rather than the name.
    # `--reloadcmd`, `--callback`, `--ssh-keys`, `-c`: the list of flags
    # that carry a command is as open-ended as the list of daemons that
    # define them, and the audit's own answer was a 60-name catalogue. A
    # value that *begins with an executor and names a build directory* is
    # a command whatever flag holds it, and no package in the benign
    # corpus passes one.
    # The flag prefix is gone and the build path is asserted rather than
    # walked to. `--?[\w-]+[=\s]+` retried its character run at every
    # position and the lazy span behind it re-scanned from each - together
    # 1522 ms on a full-length line, which the safety audit refuses. A
    # quoted value that *starts* with an executor is rare enough to anchor
    # on, and the lookahead then runs once per such value.
    # A leading `|` keeps mutt's `push "|bash"` in scope: the value is a
    # pipeline the host runs, and the bar is part of it.
    r"|[\"']\|?\s*(?:(?:/(?:usr/)?bin/)?(?:ba|z|da|k|)sh"
    r"|python3?|perl|ruby|node|php|lua)\s"
    r"(?=[^\"'\n]{0,120}\$\{?(?:srcdir|startdir|PWD|BUILDDIR)\}?/)"
    # A flag whose value is a *script* in the build tree. `--callback
    # "$PWD/x.sh"` names something the tool will run; `--prefix
    # "$srcdir/out"` names a directory, which is why the extension is
    # required. `install -Dm755 "$srcdir/x.sh" "$pkgdir/..."` is packaging
    # and was every one of this arm's benign matches.
    # A quoted value that *is* a pipeline into a shell. A mutt macro
    # spelled `push "|bash"` hands the message to a shell, and there is no
    # build path anywhere in it - the payload is what the tool feeds in.
    # The quotes may be backslash-escaped, because the value is nested
    # inside another quoted argument: `mutt -e "push \"|bash\""`.
    r"|\\?[\"']\s*\|\s*(?:/(?:usr/)?bin/)?(?:ba|z|da|k|)sh\s*\\?[\"']"
    # The flag token is anchored so it cannot retry mid-word, and the value
    # is asserted rather than walked to. Written as a plain span the flag
    # run and the path run re-scanned each other: 1542 ms on a full-length
    # line, which the safety audit refuses.
    r"|(?<![\w-])-{1,2}[\w-]{1,24}"
    r"(?==?\s?[\"']?\$\{?(?:srcdir|startdir|PWD|BUILDDIR)\}?/"
    r"[\w./-]{0,80}\.(?:sh|bash|py|pl|rb|js|lua|php)(?![\w.]))",
    re.IGNORECASE,
)

X014_STANDDOWN_RE = re.compile(
    # `install`, `cp`, `mv` and `ln` name paths to copy; their arguments
    # are not exec slots. `rsync` is deliberately absent - its `-e` names
    # the transport program it runs.
    # A normal interpreter invocation (`python -P "$srcdir/test.py"`) is a
    # command, not a flag whose value the tool will execute.  The flag arm
    # below is flag-agnostic, so without this it read Python's `-P` as an
    # exec slot whenever a build-tree script followed.
    r"(?:\A\s*|[;&|(]\s*|&&\s*)(?:[A-Za-z_]\w*=\S+\s+)*"
    r"(?:python3?|pypy3?)\b[^\n;&|]*?\s-\S+\s+[\"']?\$\{?(?:srcdir|startdir|PWD|BUILDDIR)\}?/"
    r"|(?:\A\s*|[;&|(]\s*|&&\s*)(?:install|cp|mv|ln)\s"
    r"|=\s*[\"']?(?:cat|true|false|:|/bin/true|/usr/bin/true|less|more|vi|vim"
    r"|nano|/dev/null)[\"']?\s*(?:;|$)",
    re.IGNORECASE,
)

X015_RE = re.compile(
    r"(?:\A\s*|[;&|(]\s*|&&\s*|\|\|\s*)"
    r"(?:" + _EXEC_WRAPPER + r")?"
    # `batch` takes its command on stdin and needs no argument at all, so
    # requiring one meant the plainest spelling matched nothing.
    r"(?:crontab\b|at\s+(?:-\S+\s+)*(?:now|\+|[0-9])|batch\b"
    r"|systemd-run\b|incrontab\b|entr\b|inotifywait\b|inotifywatch\b"
    # `udevadm control --reload-rules` was listed here, but a config reload
    # schedules nothing: in a hook it is the documented-required step after
    # installing udev rules (logibar, linux-g13-driver-git), and in a build
    # it is a no-op the builder cannot even perform.
    # `enable --now` starts the unit; excluding `enable` outright let the
    # one spelling that both installs and runs it through.
    r"|systemctl\s+(?:--user\s+)?(?:start\b|enable\s+[^\n;&|]*--now\b))"
    r"|\bcrontab\s+-\b|\bcrontab\s+[^\n;&|]*\|"
    r"|(?<![\w-])RUN\+?=\s*[\"']",
    re.IGNORECASE,
)

_X009_CLIENT_RE = re.compile(r"\b(?:" + _OTHER_FETCH_CLIENT + r")", re.IGNORECASE)

_X016_FETCH_RE = re.compile(r"(?:" + _NETWORK_CLIENT + r")", re.IGNORECASE)

_X016_CONSUMER_RE = re.compile(r"\A(?:" + _DATA_CONSUMER + r")\Z", re.IGNORECASE)

_X016_KNOWN_EXECUTOR_RE = re.compile(
    r"\A(?:/(?:usr/)?bin/)?(?:" + SCRIPT_EXECUTOR + r")\Z", re.IGNORECASE)

def _consumer_after_override(body: str, override: re.Match) -> bool:
    """True when a compile/configure step follows the override on its line.

    ``CC="$srcdir/mcc" make`` is the shell's ``VAR=value command`` form: the
    override and the step it redirects share a line, so looking for the
    consumer from the *next* line never saw it.  The scan resumes at the
    first token boundary after the matched value, which skips the rest of
    the path and its closing quote.
    """
    tail = body[override.end():]
    boundary = re.search(r"[;&|]|\s", tail)
    if boundary is None:
        return False
    return bool(X012_CONSUMER_RE.search(tail[boundary.start():]))

def _consumer_at(lines: list[str], index: int) -> bool:
    """True when a compile or configure step runs at or after *index*.

    The scan reads added lines only, which is right for asking what a diff
    introduced and wrong for asking what an override redirects. An `export
    CC="$srcdir/mcc"` added directly above an *unchanged* `make` is the
    most suspicious shape the rule has - the attacker supplies one line and
    the existing recipe supplies the rest - and it was the one shape the
    rule could not see, because the consumer never carried a `+`.

    Context lines are therefore consulted for the consumer half only. The
    override still has to be an addition: an unchanged build that has
    always set `CC` is not a finding.
    """
    for line in lines[index:]:
        if line.startswith("-") or line.startswith("+++"):
            continue
        if not (line.startswith("+") or line.startswith(" ")):
            continue
        body = _strip_comment(line[1:])
        if X012_CONSUMER_RE.search(body):
            return True
    return False
