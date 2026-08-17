# Crossfire

The evasion technique, not the payload it hides.

Every other family on these pages fires on what a diff *does*. These fire on
how it was *written*, and the difference is a response to where detection
actually fails.

The payload rules hold. The tokenizer that feeds them is what gets defeated:
partial quoting (`c"u"rl`), array routing (`${A[0]}`), namerefs, and command
substitution (`$(printf '\x63\x75\x72\x6c')`) each assemble an executable name
that no pattern over the resolved text ever sees, because resolution is the
step that broke. Teaching the tokenizer to expand more closes one bypass at a
time and risks an over-expansion bug in exchange.

Crossfire inverts the problem. **A word the tokenizer could not reduce to a
literal is itself the signal.** One rule then covers the evasion surface of
every payload rule at once - R001, R127, R137 and the rest - because it does
not care which payload was hidden, only that hiding happened.

The failure mode inverts with it, and that is the point worth keeping. Today a
defeated tokenizer produces silence, which is the worst available output: the
analysis reads clean exactly when it understood least. Here a defeated
tokenizer produces a CRITICAL finding, so the bypass and the alarm are the same
event and cleverness cannot buy quiet.

## What this family is not

It is not a replacement for fixing the tokenizer. A payload written plainly and
hidden by a technique nobody anticipated still gets through; crossfire raises
the cost of evasion, it does not bound it.

It also claims no bytes another rule already claims. Three of the obvious
candidates were dropped for that reason rather than because they were hard:

| Dropped | Already claimed by |
|---|---|
| Base64 decoded to a shell | [R003](obfuscation.md#r003) and [R043](obfuscation.md#r043), both CRITICAL |
| BiDi and homoglyph codepoints | [R013](deception.md#r013) at **FATAL**, plus R013b for confusable domains |
| A write whose target starts with `~/` or `$HOME/` | [R077](install-and-persist.md#r077) |

X001 and X005 exist as the *remainder* of the first and third: the encodings
R003 does not cover, and the home directories R077 cannot see because they are
spelled another way. There is no X008 - R013 leaves it nothing to do, and
scoring the same characters twice would corrupt the calibration.

The home case also changed R077 itself. A write into a user's home from an
**install scriptlet** is now CRITICAL rather than HIGH, because pacman runs
scriptlets as root during the transaction, and root reaching into somebody's
home is categorical rather than suspicious. The same write during `build()`
stays HIGH.

Two further candidates were dropped on measurement rather than overlap. Domain
reputation and upstream-owner matching are absent from X006 because the novelty
tier already scores a globally-first-seen URL and an owner heuristic is too
brittle for a decentralised repository. Bare `2>/dev/null` is absent from X004
because it fires on 0.481% of the benign corpus as ordinary defensive shell -
small, but noise rather than signal.

## Measured before weighted

Every rule here was run against the locked benign corpus before it was given a
severity. The figures below are the corpus as `tests/fixtures/corpus.lock`
records it in the historical baseline - **3,246** diffs, generated 2026-07-16. The current aggregate calibration baseline is 3,739 diffs; this page's legacy per-rule measurement is retained for traceability:

| Rule | Benign diffs | Rate |
|---|---|---|
| X001 | 0 | 0.000% |
| X002 | 0 | 0.000% |
| X003 | 0 | 0.000% |
| X004 | 0 | 0.000% |
| X005 | 0 | 0.000% |
| X006 | 0 | 0.000% |
| X007 | 0 | 0.000% |

The ceiling is 30%. The whole family is now at zero, which is what makes
CRITICAL affordable here: legitimate recipes do not assemble command names out
of parts.

X002 read 0.695% when the family shipped (26 diffs, against a corpus of 3,739
at the time) and 0.678% on today's locked set. The number is worth keeping in
view because of what closing it turned up. The hits were not marginal calls
about which shape counts as evasion. Every one was a rule looking in the wrong
place:

- **Function scope leaked across files.** A hunk shows part of a file, so a
  `package() {` whose closing brace fell outside it left the brace counter
  raised for the rest of the diff, putting every *following file* inside that
  function. A `.desktop` file's translated `Name[be]=` line was read as shell
  and matched the homoglyph shape - Cyrillic in a translation impersonates
  nothing. Seven diffs. Fixed in the shared classifier, so every scoped rule
  gets the correction.
- **A modified continuation tail lost its head.** The joiner joins lines
  carrying the same diff marker; editing the tail of a `\`-continued command
  separates the halves with the removed version, so the `+` line arrived alone
  and its first word - an argument - read as a command name.
- **`eval` was scored twice.** R039 already claims eval-of-dynamic-content.
  Treating `eval` as a wrapper walked into its argument and drew a second
  CRITICAL on the same bytes, which is the thing this family says it never
  does.
- **A variable naming a *directory* is not a hidden command.**
  `"$srcdir/calibre-release/calibre-debug"` spells its executable out; only the
  path prefix came from a variable. The shape matched it because the variable
  name was allowed to match a prefix of itself.
- **`CMD=$(which x)` names its executable literally**, one line up, where every
  payload rule reads it. Exempted as the discovery idiom - not assignment in
  general, since `CMD=$(printf '\x63\x75\x72\x6c')` assembles a name that
  appears nowhere and stays an evasion.

None of those made the rule stricter about what counts as an evasion; the
bypasses closed in the same pass ([below](#evasions-closed)) made it looser
about where it looks. Rate and recall moved in opposite directions,
which is the only combination worth having.

---

### X001: Encoded Payload Decoded To A Shell {#x001}

- **Severity:** CRITICAL (weight 40)
- **Category:** `evasion`
- **Condition:** A hex or octal escape blob, a reversed hex dump (`xxd -r`, `od -An`, `hexdump`), a non-base64 decoder (`base32 -d`, `basenc`, `openssl enc -d`, `uudecode`), an ANSI-C `$'...'` blob, or a `tr` rotation, piped into a shell or handed to `eval`, inside an executing scope.

Base64 is deliberately absent - R003 and R043 claim it. What is left is every
other encoding, and the Atomic Arch second wave used hex.

The decoder list is the rule's whole surface, so a decoder missing from it is a
one-word bypass. `base32 -d`, `openssl enc -d` and `uudecode` decode the same
payload into the same shell and were claimed by nobody until they were added.

### X002: Non-Literal Executable Name {#x002}

- **Severity:** CRITICAL (weight 40)
- **Category:** `evasion`
- **Condition:** A word in command position that is not a literal: a variable (`$cmd`, `${A[0]}`, `${!ref}`, `${c//X/}`), a substitution (`$(...)`, backticks), an intra-word quote break (`c"u"rl`), an ANSI-C string (`$'\x63...'`), a brace expansion (`cur{l,}`), or a character that impersonates ASCII (`сurl`).

The rule that pays for the family. Every tokenizer bypass found so far works by
assembling a command name the parser cannot read, so all of them produce this
one shape.

Three exclusions keep it precise, and each was derived from the corpus rather
than guessed:

- **An assignment is not a command.** `font=$(grep ...)` names no executable.
- **A variable that resolves is not an evasion.** If the tokenizer reduced the
  name to a literal from an assignment in the diff or its context, the word is
  a spelling choice.
- **Quotes and parentheses bound the split.** A `|` inside `sed 's|a|b|'`, and
  an `&&` inside `(( a && b ))`, do not start a new command. Both produced
  false positives before the splitter respected them.
- **A homoglyph impersonates; other non-ASCII does not.** The shape uses the curated confusable map `buckets` already applies to domains, not "any non-ASCII character". The broader form fired on ordinary English prose carrying a typographic apostrophe, which names no command.
- **An expression is not a command.** `(( ... ))` and `[[ ... ]]` evaluate
  rather than execute, and a leading flag means the line continues a previous
  one (`sed \` then `  -i "${dir}/x"`), so neither offers a command position.

The scan walks *past* prefixes rather than reading the first token, because a
command word is not always first. An assignment (`FOO=1 ${A[0]}`), a wrapper
(`env`, `exec`, `sudo`, `nohup`, `timeout 5`), a conditional keyword
(`if ${A[0]}; then`), a redirect (`>out ${A[0]}`) and a subshell opener
(`( ${A[0]} )`) each displace it, and every one of them defeated an earlier
version of this rule. They are pinned as regressions in
`tests/test_crossfire.py`.

`eval` is deliberately *not* a wrapper here, though it runs another command
like the rest: R039 already claims eval-of-dynamic-content, and this family
never scores bytes another rule scores - the same reason X008 does not exist
beside R013.

## Evasions closed {#evasions-closed}

Ten, in the pass that took the family to zero, plus one closed in the
tokenizer instead ([below](#the-one-that-was-fixed-in-the-tokenizer-instead)).
Each defeated the shipped rule and is now a regression test:

| Evasion | Rule | Why it worked |
|---|---|---|
| `package_libfoo() { ... }` | all | A **split package**. makepkg calls `package_$pkgname()` for each name in a split recipe, and the scope gate was an allowlist of the five standard function names. |
| `package_google-chrome-bin()` | all | Worse than the above: a pkgname may hold a hyphen, and the shared classifier's `\w+` does not match one, so the function never opened at all and its body classified as `other` - invisible to every rule with a scope, not just this family. |
| `_helper() { ... }`, called from `build()` | all | An ordinary helper. The name is the author's to choose, which is the whole problem with matching on it. |
| a payload at **top level** | all | Top-level code runs when makepkg *sources* the recipe, before any build step. The gate only read inside functions. |
| `if ${A[0]} x; then` | X002 | A conditional keyword takes a command and tests its status. The scan stopped at the keyword. |
| `elif`, `while`, `until` | X002 | Same shape, three more keywords. |
| `set +o xtrace` | X004 | The long spelling of `set +x`. The pattern required the `x` to end the option cluster. |
| `base32 -d \| sh` | X001 | Not `base64`, so R003 and R043 did not claim it, and the decoder list did not carry it. |
| `openssl enc -d \| sh` | X001 | As above. |
| `uudecode \| sh` | X001 | As above. |
| `cp payload /home/alice` | X005 | Every alias pattern required a trailing separator. |
| `cp payload /root` | X005 | As above. |
| `cp payload ~alice` | X005 | As above. |

### The one that was fixed in the tokenizer instead

`c\url` is `curl` to the shell, which drops a backslash before an ordinary
character. The tokenizer did not, so the name never reconstructed and **no rule
saw it at all** - not R001, not anything. It was the only bypass in this family
that reached nothing.

It was closed here first, as an `escaped-character` shape, and then closed
properly: `tokenizer._ESCAPE_REMOVABLE` now drops the escape during quote
removal, so every rule that reads a command name sees through it rather than
only this one. The shape was retired in the same change, because with the name
resolved it would score one command twice - the same reason `curl""`, which
always folded, never had a shape either.

That is the progression this family's [own warning](#what-this-family-is-not) asks
for: crossfire is not a substitute for fixing the tokenizer, and a shape
retired because the tokenizer caught up is the arrangement working. Both halves
are pinned in `test_an_escaped_name_is_the_tokenizer_s_now`, so a fold that
silently stopped working cannot leave the payload uncovered.

The escapes that *mean* something are deliberately left alone. `\|` is a
literal pipe, not a pipeline: unescaping it would build a pipe-to-shell out of
`curl x \| sh`, which runs nothing of the sort. `\ ` holds one word together,
`\$` is what stops an expansion, and `\\` is a literal backslash. Bash removes
every backslash; going that far here would not be more faithful, it would
invent syntax the line did not have.

### X003: Obfuscated Command Argument {#x003}

- **Severity:** HIGH (weight 25)
- **Category:** `evasion`
- **Condition:** A `curl`/`wget` long option truncated to a unique prefix (`--upload-f`), a shell invoked with options stuffed before `-c` (`bash -lc`, `sh -ec`), or a URL whose host is an octal, hex or integer-encoded IP.

`sh -c` is ordinary and does not fire; `sh -lc` is a login shell obtained
without saying so.

### X004: Build Output Suppressed {#x004}

- **Severity:** MEDIUM (weight 15)
- **Category:** `evasion`
- **Condition:** `TERM=dumb`, `set +x` or `set +o xtrace`, or `exec >/dev/null` / `exec 2>&-` inside an executing scope.

MEDIUM because hiding output is weak evidence alone: its value is
compositional, in X007. Bare `2>/dev/null` is excluded as noise.

### X005: Home Reached By An Alternative Spelling {#x005}

- **Severity:** HIGH (weight 25)
- **Category:** `evasion`
- **Condition:** A write command or redirect whose target reaches a home directory by a spelling [R077](install-and-persist.md#r077) does not match: `/home/alice`, `/home/$USER/...`, `~alice`, `/root`, `${HOME:-/home/alice}/...`, or a traversal that names `home` or `root`. The trailing separator is optional - `cp payload /home/alice` writes into the same directory as `/home/alice/` did.

R077 matches a target that *starts with* `~/` or `$HOME/`. That is the obvious
spelling, and the obvious spelling is the one an attacker will not use. Every
form above reaches the same directory and none of them carries that prefix.

This is the family's thesis applied to a path rather than to a command name.
Writing `/home/$USER/bin` when `$HOME/bin` exists is a choice, and the only
thing the choice buys is getting past a check.

It **defers** rather than doubles: a target R077 already claims is skipped
here, so one write is scored once. Staging paths are exempt outright -
`$pkgdir/home/...` is packaging, not a write into anybody's home.

### X006: Source Points Somewhere Unexpected {#x006}

- **Severity:** HIGH (weight 25)
- **Category:** `evasion`
- **Condition:** A URL shortener, or a raw-IP URL, anywhere in the diff.

Both forms are never legitimate in a `source=` array: a shortener hides the
destination from the reader, and a raw IP has no name to check. Domain
reputation is deliberately not attempted here.

### X007: Multiple Evasion Techniques {#x007}

- **Severity:** CRITICAL (weight 40)
- **Category:** `evasion`
- **Condition:** Two or more of X001-X006 in the same diff.

One technique can be an accident of style. Two in one diff is a method. The
threshold is `crossfire.X007_MIN_TECHNIQUES`, and the cluster fires on **zero**
benign diffs - co-occurrence is the strongest single signal in this family.

Unlike [R089](composition.md#r089), which annotates kill-chain stages at weight
0, X007 scores: the stages R089 counts are each independently evidenced, while
co-occurring *evasion* is evidence about intent that none of its members carry
alone.
