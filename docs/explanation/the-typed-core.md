<!-- description: The typed core: DiffDoc and RecipeDoc, array_diff and array_alignment, first-class provenance and unresolved values, the shared line lexer, and the parity harnesses that gate a change to any of them. -->

# The Typed Core

Every analysis stage used to re-walk the raw diff text and re-decide, per
module, which lines are headers, what `+`/`-`/context means, what file a line
belongs to, and what its new-file line number is. Each walker made those
decisions slightly differently, and the differences were a recurring bug class:
a finding attributed to the wrong file, a post-state that dropped a content
line, an array state machine that flushed on the wrong line. The typed core is
the fix: parse once into a document, then every reader is a projection or a
query over it, so the structural decisions exist exactly once.

## `DiffDoc`: the diff, parsed once

`trustsight.diffdoc.parse_diff` reads a unified diff into a `DiffDoc`: files,
hunks, and classified lines. Each line carries its side (`add`, `remove`,
`context`, or `other`), the file it belongs to, and both line numbers - the
old-file position and the new-file position. Header recognition and path
capping mirror the legacy walkers byte for byte, and each hunk carries
`expected_lines`/`actual_lines`, which is how a cut hunk (`partial_hunk`) is
detected rather than guessed at.

A line that is not diff content (`diff --git`, `index`, `Binary files`, `\ No
newline`, junk) is classified `other`: it stays in the document so a migrating
state machine sees exactly the lines its legacy walk saw, but no projection
feeds it anywhere as content.

## `RecipeDoc`: the PKGBUILD, read once

`trustsight.recipedoc.parse_recipe` reads a PKGBUILD into a `RecipeDoc`:
resolved scalars, collected arrays, function bodies, and a first-class
`unresolved` list for the assignments the sandboxed tokenizer refused to guess
at (a command substitution, an expansion it will not resolve). A rule reading
an unresolved field treats it as "not seen", which is what the coverage gaps
report; a typed model that guesses would be a regression in the one place
guessing is forbidden.

Backslash continuations are joined before reading, and provenance maps a joined
line back to its first physical line, so `pkgver=\` and `install=\`
continuations resolve instead of reading as a bare backslash. `RecipeDoc`
carries spans: a scalar's assignment line, each array entry's first line, a
function's header. When the recipe was rebuilt from a diff, a span names the
real file, line and side, so a finding cites the line the rule is about rather
than the first text match anywhere in the diff.

## `array_diff` and `array_alignment`

`array_diff(old, new)` answers "how did this array change" as a multiset:
`gained` and `lost` keep duplicate occurrences and their order, so adding an
entry twice is two gains and removing one copy of a duplicate is a loss.
`reordered` compares only the matched occurrences, so a multiplicity change is
not a reorder. Nine modules each used to make their own opener/closer
decisions; the question is now one query with no state machine to get wrong.

`array_alignment(old, new)` is the positional view, for arrays whose index
pairing matters: `pairs`, `inserted` and `deleted`, matched by identical value,
longest block first, so an entry inserted or removed mid-array does not mispair
the entries after it. The matcher is quadratic and refuses an old x new pair
past `MAX_ALIGNMENT_CELLS`, because an honest refusal beats a truncated
alignment that misreports moves.

## `line_lex`: one lexical scanner

Function-body detection and rule-scope classification both count braces, and
both used to count them on the raw line: `echo "}"` was wrong in one reader and
`# }` in the other. `trustsight.line_lex` is the one place that decides which
text is code. It is a lexical scan, not a shell parser: it resolves nothing and
blanks only what shell would not execute as written. Braces in quotes, comments
and heredoc bodies do not count; `$(...)` and backticks inside double quotes
stay code because they execute. A partial diff fragment resets quote state each
line and ends a heredoc at a file or hunk header, so a hunk whose closer sits
outside the fragment cannot blank the rest of the file.

Both Bash function spellings - `name()` and `function name`, with or without
parentheses - and hyphenated names such as `package_google-chrome-bin` are
recognised, pinned by a differential test against the tree-sitter-bash grammar.

## The parity harnesses

The migration is gated, not asserted:

- `tests/harness/diffdoc_parity.py` compares every `DiffDoc` projection against
  the legacy `differ` walker it replaces, over the locked benign corpus and the
  labelled malicious fixtures. The calibration CI job runs it.
- `tests/harness/finding_parity.py` and `tests/harness/typed_core_parity.py`
  replay the corpus through `scan_diff` and compare every emitted finding
  (rule, severity, weight, file, line, params) and the scope-scanner outputs
  against a pre-migration baseline. They are migration tools, run locally, and
  retire with the last legacy walker.
- A suite guard pins the remaining raw text loops, so a new diff walker outside
  the typed core fails review.

The migration changed no finding, score, file or line: 3,919 corpus diffs
replay byte-identical, and the 23 known line/file corrections are the
provenance fixes described above, recorded against the baseline rather than
smoothed over.

## See also

- [Recipe-Targeted User Rules](structural-user-rules.md): the operator surface
  that queries `RecipeDoc` directly.
- [Cross-File Consistency](cross-file-consistency.md): H092 and H103 read
  `.SRCINFO` and the typed recipe together.
- [Sandboxing the Tokenizer](sandboxing-the-tokenizer.md): the resolver
  `RecipeDoc` is built on.
