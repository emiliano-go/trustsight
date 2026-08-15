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

Every rule here was run against the 3,739-diff locked benign corpus before it
was given a severity:

| Rule | Benign diffs | Rate |
|---|---|---|
| X001 | 0 | 0.000% |
| X002 | 26 | 0.695% |
| X003 | 0 | 0.000% |
| X004 | 0 | 0.000% |
| X005 | 0 | 0.000% |
| X006 | 0 | 0.000% |
| X007 | 0 | 0.000% |

The ceiling is 30%. These sit two orders of magnitude under it, which is what
makes CRITICAL affordable here: legitimate recipes do not assemble command
names out of parts.

X002's 26 are worth naming rather than rounding away. Most are plain variables
used as commands - `$DKMS add -m ...` - where the assignment lives outside the
diff, so the tokenizer cannot see that the name reduces to a literal. A
variable that *does* resolve is suppressed already. The rest are
`eval "$(cmd)"`, which is genuinely dynamic execution: R039 is documented for
that shape but does not fire on it, so X002 is covering rather than
duplicating.

That makes the rate an artifact of reading a diff rather than a property of the
rule. On whole-file input - the shape a first-seen package presents, where the
assignment is visible - the same `$DKMS` recipe is silent and `${A[0]}` still
fires. X002 is therefore *more* accurate on the first-seen path than the 0.374%
suggests, and the number above should be read as the worst case rather than the
expected one.

---

### X001: Encoded Payload Decoded To A Shell {#x001}

- **Severity:** CRITICAL (weight 40)
- **Category:** `evasion`
- **Condition:** A hex or octal escape blob, a reversed hex dump (`xxd -r`, `od -An`, `hexdump`), an ANSI-C `$'...'` blob, or a `tr` rotation, piped into a shell or handed to `eval`, inside an executing scope.

Base64 is deliberately absent - R003 and R043 claim it. What is left is every
other encoding, and the Atomic Arch second wave used hex.

### X002: Non-Literal Executable Name {#x002}

- **Severity:** CRITICAL (weight 40)
- **Category:** `evasion`
- **Condition:** A word in command position that is not a literal: a variable (`$cmd`, `${A[0]}`, `${!ref}`), a substitution (`$(...)`, backticks), an intra-word quote break (`c"u"rl`), an ANSI-C string (`$'\x63...'`), a brace expansion (`cur{l,}`), or a character that impersonates ASCII (`сurl`).

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
(`env`, `exec`, `sudo`, `nohup`, `timeout 5`), a redirect (`>out ${A[0]}`) and
a subshell opener (`( ${A[0]} )`) each displace it, and every one of them
defeated an earlier version of this rule. They are pinned as regressions in
`tests/test_crossfire.py`.

### X003: Obfuscated Command Argument {#x003}

- **Severity:** HIGH (weight 25)
- **Category:** `evasion`
- **Condition:** A `curl`/`wget` long option truncated to a unique prefix (`--upload-f`), a shell invoked with options stuffed before `-c` (`bash -lc`, `sh -ec`), or a URL whose host is an octal, hex or integer-encoded IP.

`sh -c` is ordinary and does not fire; `sh -lc` is a login shell obtained
without saying so.

### X004: Build Output Suppressed {#x004}

- **Severity:** MEDIUM (weight 15)
- **Category:** `evasion`
- **Condition:** `TERM=dumb`, `set +x`, or `exec >/dev/null` / `exec 2>&-` inside an executing scope.

MEDIUM because hiding output is weak evidence alone: its value is
compositional, in X007. Bare `2>/dev/null` is excluded as noise.

### X005: Home Reached By An Alternative Spelling {#x005}

- **Severity:** HIGH (weight 25)
- **Category:** `evasion`
- **Condition:** A write command or redirect whose target reaches a home directory by a spelling [R077](install-and-persist.md#r077) does not match: `/home/alice/...`, `/home/$USER/...`, `~alice/...`, `/root/...`, `${HOME:-/home/alice}/...`, or a traversal that names `home` or `root`.

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
