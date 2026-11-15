<!-- description: How the typed core, the single read of diff and recipe, and cross-file consistency produce anchored findings without guessing. -->

# Architecture and Pipeline


This page explains the structural decisions that make every finding
anchorable: how the diff and the recipe are read once into a typed document,
what is reported when the structure cannot be read, and how the recipe is
compared against the files that describe or ship with it.

## The Typed Core

TrustSight reads attacker-controlled text, and its output is evidence: a rule
id, a severity, and the file and line the finding is about. The input's own
formatting can make those anchors ambiguous - a content line whose text begins
`++ `, a `}` inside `echo "}"` or a comment, an array whose closing parenthesis
sits outside the hunk, a `pkgver=` continued onto the next line. If two readers
resolve the ambiguity differently, one of them reports a finding against the
wrong file, drops a content line, or reads a partially shown array as a whole
one. For a tool whose job is telling a reviewer where to look, that is not a
cosmetic error.

The typed core is the single place those decisions are made. A unified diff is
parsed once into a `DiffDoc`, and a PKGBUILD is read once into a `RecipeDoc`.
Every stage that needs the diff's structure - which line is content, which file
and line it belongs to - is a projection or a query over that document, so each
structural decision exists exactly once. What the analysis cannot read is never
guessed at - it is recorded as an unresolved value or a named coverage gap -
because a guess in this pipeline becomes a finding the reviewer cannot
distinguish from a fact.

### `DiffDoc`: one reading of the diff

`trustsight.diffdoc.parse_diff` reads a unified diff into files, hunks and
classified lines. Each line carries its side (`add`, `remove`, `context` or
`other`), the file it belongs to, and, for a content line inside a hunk, the
line number it holds on each side (the old-file position for a removal, the
new-file position for an addition, both for context). Every stage that needs
to know where a change sits reads that, instead of re-walking the raw text and
deciding again.

A line that is not diff content (`diff --git`, `index`, `Binary files`, `\ No
newline`, junk) is classified `other`. It stays in the document, so malformed
input still yields classified data, but the content projections all filter on
side: it is never read as recipe text.

Header recognition is prefix-based, matching how diff spells a header line: a
content line that begins `++ ` or `--- ` produces the same bytes as a file
header and is read as one. The document also carries each hunk's declared and
actual line counts, and a hunk shorter than its header claims is reported as
the `partial_hunk` coverage gap.
A cut hunk is therefore a declared gap, not a short array silently read as a
complete one.

### `RecipeDoc`: one reading of the recipe

`trustsight.recipedoc.parse_recipe` reads a PKGBUILD into resolved scalars,
collected arrays and function bodies. It is built on the sandboxed tokenizer,
and `unresolved` is first-class: an assignment the tokenizer never resolved to
a value - a command substitution, an arithmetic expansion or a backtick in the
value - is listed there, and a rule reading an unresolved field treats it as
"not seen", which is what the coverage gaps report. A typed model that guessed
would be a regression in the one place guessing is forbidden.

Backslash continuations are joined before reading, and provenance maps a
joined line back to its first physical line, so `pkgver=\` and `install=\`
continuations resolve instead of reading as a bare backslash. The document
carries spans: a scalar's assignment line, each array entry's first line, a
function's header. When the recipe was rebuilt from a diff, a span names the
real file, line and side, so a finding cites the line the rule is about rather
than the first text match anywhere in the diff. Both Bash function spellings -
`name()` and `function name`, with or without parentheses - and hyphenated
names such as `package_google-chrome-bin` are recognised, pinned by a
differential test against the tree-sitter-bash grammar.

### `array_diff` and `array_alignment`

`array_diff(old, new)` answers "how did this array change" as a multiset:
`gained` and `lost` keep duplicate occurrences and their order, so adding an
entry twice is two gains and removing one copy of a duplicate is a loss.
`reordered` compares only the matched occurrences, so a multiplicity change is
not a reorder. Array changes are one query with no per-module opener/closer
state machine to get wrong - the shape that once let the hex sums of a checksum
array be scored as dependencies.

`array_alignment(old, new)` is the positional view, for arrays whose index
pairing matters: `pairs`, `inserted` and `deleted`, matched by identical value,
longest block first, so an entry inserted or removed mid-array does not mispair
the entries after it. The matcher is quadratic and refuses an old x new pair
past `MAX_ALIGNMENT_CELLS`, because an honest refusal beats a truncated
alignment that misreports moves.

### `line_lex`: one lexical opinion on what is code

Function-body detection and rule-scope classification both count braces, and
both once counted them on the raw line: `echo "}"` was wrong in one reader and
`# }` in the other. `trustsight.line_lex` is the one place that decides which
text is code. It is a lexical scan, not a shell parser: it resolves nothing and
blanks only what shell would not execute as written. Braces in quotes, comments
and heredoc bodies do not count; `$(...)` and backticks inside double quotes
stay code because they execute. A fragment mode exists for partial diffs:
quote state resets each line and a heredoc ends at a file or hunk header, so a
hunk whose closer sits outside the fragment cannot blank the lines that follow.

### How the guarantee is held

The claim "one parse, many projections" is gated, not asserted. A projection
baseline pins the parse over the locked benign corpus and the labelled
malicious fixtures: every diff's file attribution, sides, line numbers and
hunk arithmetic is hashed, and the calibration CI job checks the whole corpus,
so a parse change fails until the baseline is deliberately regenerated (see
[re-baselining](../contributing/re-baselining.md)). A finding replay compares
every emitted finding - rule, severity, weight, file, line, params - against a
baseline recorded before the typed core existed, so a change that moves a
finding anywhere fails the comparison. A suite guard pins the remaining raw
text loops, so a new diff walker outside the typed core fails review. Where a
reader legitimately reads the text differently - an unresolved-regex
extraction is not a resolved-value read - the divergence is documented, not
smoothed over. The exact figures live in the [changelog](../changelog.md).

### What it does not do

- The line lexer is a lexical scan, not a shell parser. It does not resolve
  expansions, follow command substitution or evaluate conditionals; it only
  decides which characters are code.
- Header recognition is prefix-based, so a hunk whose content begins `++ ` is
  read as a file header; the count mismatch is surfaced as `partial_hunk`
  rather than guessed away.
- Alignment past `MAX_ALIGNMENT_CELLS` refuses rather than truncates.
- A partial document is partial. A diff shows hunks, not files, and a rule
  that compares pre and post states anchors on changed lines rather than trust
  an array whose closer was never shown.

### See also

- [Security Model](../security-design/security-model.md): why nothing here guesses, and how an
  incomplete analysis fails closed.
- [Recipe-Targeted User Rules](static-analysis-and-resolution.md): the operator surface
  that queries `RecipeDoc` directly.
- [Cross-File Consistency](architecture-and-pipeline.md): H092 and H103 read
  `.SRCINFO` and the typed recipe together.
- [Sandboxing the Tokenizer](static-analysis-and-resolution.md): the resolver
  `RecipeDoc` is built on.

## Cross-File Consistency

A package is more than a `PKGBUILD`. The same facts are stated again in
`.SRCINFO`, committed files are named by the recipe, and an `install=`
declaration points at a scriptlet that ships beside it. An analysis that
reads one document can be misled by another that says something different:
the recipe fetches one host while the metadata names another, a build
executes a committed file the recipe never mentions, or a declared hook is
not in the tree at all. These are cross-file questions, and no single-line
regex can ask them.

### What is checked today

| Check | Rule or gap | Compares |
|-------|-------------|----------|
| Metadata names a source the recipe does not | H092 | `.SRCINFO` hosts against PKGBUILD hosts |
| Metadata and recipe disagree on a security-relevant field | H103 | `install=`, checksum arrays and `depends` between the two documents |
| A named hook is not in the committed tree | `tree_not_analyzed` | `install=` against the snapshot manifest |
| A committed file is executed without being declared | H081 | build commands against committed file names |
| A downloaded source file is executed | H083 | `source=()` entries against execution sites |
| A committed payload is inspected | H066-tree | the snapshot manifest against the rule's own reading |
| The hook script ships with the declaration | H100 | `install=` against the diff's file list |

The most important property is the one all of these share: the analysis
prefers the document it trusts least. The PKGBUILD is what `makepkg`
runs, `.SRCINFO` is a generated convenience that makepkg does not read,
and a committed file is only as good as the recipe that names it. When
they disagree, the disagreement itself is the signal.

### How H103 compares

H103 is the value-level comparison this page used to record as open. It
compares `install=`, the checksum arrays and `depends`, and only when both
documents carry the field and neither side has an unresolved variable:
anything else reads as "not seen", never as a divergence. A stale `pkgver`
alone is silent because it changes nothing the build does, and reordering
is silent because the comparison is a set. That conservatism is what keeps
a stale `.SRCINFO` - the ordinary shape of an AUR package whose maintainer
forgot `makepkg --printsrcinfo` - from firing.

### Residual gaps

- **H092 is one-directional and host-only.** It reports a host `.SRCINFO`
  names and the recipe does not. H103 compares its fields symmetrically,
  but a host only the recipe names is not reported by H092, and a URL path
  or checksum *value* difference is invisible to it.
- **H103 compares a short field list.** `install=`, the checksum arrays and
  `depends`; `license`, `provides`, `conflicts` and the rest stay
  uncompared, and a field carrying an unresolved variable is skipped.
- **Richer-side reads are still uncompared outside H103.** Property
  extraction and the review path prefer `.SRCINFO` for `depends` and
  `license`; H103 compares `depends`, but `license` is read from one side
  only.
- **A caller-supplied `.SRCINFO` need not match the PKGBUILD.** The API's
  text path takes both as arguments, so the pair may describe different
  revisions; the review and corpus paths read both from the same commit.

The per-line `source = value` spelling is no longer accepted inside
PKGBUILD text: it is honoured only in a `.SRCINFO` section, where it is a
real generated declaration, so a line makepkg never reads can no longer
mark a download as declared.

### See also

- [What TrustSight Cannot See](limitations-and-uncertainty.md): the general limit this page narrows.
- [Evidence Tiers](../reference/evidence-tiers.md): how declared facts are reported.
- [Rules Reference](../rules/index.md): H081, H083, H092, H103 and the rest.
