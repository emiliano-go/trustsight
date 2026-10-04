<!-- description: Recipe-targeted user rules: a second kind of rules.toml entry that matches typed recipe structure instead of diff lines, with five match primitives, a changed-line partial-diff rule, and a HIGH severity cap. -->

# Recipe-Targeted User Rules

A line regex cannot see structure. "A source array gained an entry whose host
matches X" is the natural way to describe a supply-chain move, and no R-series
pattern states it cleanly: the array may be formatted across lines, the same
text may sit in a comment, and an edit that keeps an entry but rewrites its
line matches or not depending on whitespace. The typed core exists to make
that question structural, and this page defines a second rule kind that asks
it directly. The kind ships with zero rules and is an operator surface, not a
shipped detection family.

## The surface

Structural rules live in `rules.toml` in their own top-level array, beside
the R-series `[[rules]]` entries:

```toml
[[structural]]
id = "R900"
field = "source"
match = "host_added"
pattern = "^(.*\\.)?example\\.com$"
severity = "MEDIUM"
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | **Required.** Rule identifier; `lint-rules` warns when it does not follow the `R###` convention and errors when it names a rule the code already emits. |
| `field` | `string` | **Required.** An array name (`source`, `depends`, `sha256sums`) or `scalars.` plus a scalar name (`scalars.install`). |
| `match` | `string` | **Required.** One of the five primitives below. |
| `pattern` | `string` | **Required.** Python regex searched against the value the primitive selects, never against a raw line. |
| `severity` | `string` | Optional, defaults to `MEDIUM`. `FATAL` and `CRITICAL` clamp to `HIGH`. |
| `name` | `string` | Optional, defaults to the id. |
| `category` | `string` | Optional, defaults to `structural`. |

An entry missing any required field is skipped at load and logged; `lint-rules`
reports the same condition as an error.

`[rules.R###]` controls in `config.toml` (`enabled`, `weight_override`) apply
to a structural entry exactly as they do to a line rule. A rule refused by the
pattern gate is skipped and logged, and `trustsight lint-rules` reports the
same condition as an error.

## Matching values, not lines

The pattern is searched, not matched in full, against the value the primitive
selects: an array entry, an extracted host, a scalar value, or a local name.
It never sees a diff line, so a `#` comment, a `pkgdesc` string or a
`sha256sums` hash cannot satisfy a rule aimed at a source entry unless the
primitive selected it.

Compilation goes through the same gate as an R-series rule (`rules.py`): a
nested quantifier, a probe over the backtracking budget, or superlinear cost
growth refuses the pattern. Matching is case-insensitive, like the R-series.

## What a partial diff means

A diff shows hunks, not files, and the pre and post recipes reconstructed
from it are partial documents. Parsing a partial array is not safe on its own:
the tokenizer returns the entries it can see for an array whose closing
parenthesis sits outside the hunk, and a rule comparing those entries with
the post state would call every invisible old entry newly added. The rule is
changed-line anchored instead.

An entry is **gained** only when `array_diff(pre, post)` reports it gained
AND the diff carries it on an added line. It is **lost** only when the diff
carries it on a removed line. The delta is a multiset: an entry added twice
counts twice and a duplicate removal is a loss, so multiplicity is never
silently dropped. An unchanged entry appears on an added line
only when its line was rewritten, and then the removed counterpart is in the
pre state, so it is not reported as gained. An entry the diff never shows at
all cannot be reported in either direction, which is the intended silence:
the diff is the evidence, and it does not contain the claim.

When the post-state text is available (the review path reads the head
PKGBUILD, the corpus path reads the new one), the post array is complete by
construction; the changed-line anchor still applies, so a rule reports the
edit the diff shows and not the array's whole history.

## Primitives

| `match` | `field` | Fires when | Pattern sees |
|---------|---------|------------|--------------|
| `entry_added` | array | an entry is gained and appears on an added line | the entry literal |
| `entry_removed` | array | an entry is lost and appears on a removed line | the entry literal |
| `host_added` | array | a gained entry on an added line yields a host | the extracted host |
| `scalar_changed` | `scalars.x` | both sides resolve `x` and the values differ | the new value |
| `renamed` | source array | a URL visible on both sides keeps the URL and changes its local name | the new local name |

A `field` the recipe does not carry never matches; an array name with an
architecture suffix (`source_x86_64`) works the same as its base. `host_added`
extracts the host with the same normalization the bucket classifier uses, so a
`name::url` rename keys on the URL's host. `renamed` is the reverse fact: the
URL stayed and the local name moved, which is how a download file is relabelled
without changing where it comes from.

## First-seen packages

A package observed for the first time has no pre state, so the change
primitives degrade to presence checks: `entry_added`, `host_added` and
`scalar_changed` fire on the complete post-state recipe, and `entry_removed`
and `renamed` stay silent. An operator can therefore write a standing rule
("any new package whose source fetches from this host") and every package is
evaluated once from its full text.

## The HIGH cap

A structural primitive is a weaker claim than a content match. "The source
array gained an entry whose host matches this pattern" is true of a
legitimate mirror move as easily as of a swap, and a user-authored pattern
has not been measured against the locked corpus the way a shipped rule has.
`FATAL` and `CRITICAL` therefore clamp to `HIGH` at load time, with a warning,
and `lint-rules` reports the clamp. The rule still runs; the cap bounds what
one pattern about structure may claim without corpus evidence.

## What it does not do

- No cross-field conjunctions. A rule describes one field and one primitive;
  composing several findings is what H098 and H102 do in code.
- No function-body structure. The primitives read the variable tables, not the
  shell inside `build()` or `package()`; the R-series already matches those
  lines and the X-series reads their execution.
- No arbitrary keyed arrays. `renamed` and `host_added` understand the source
  entry forms (`name::url`, plain URLs, VCS entries) that the source rewriters
  and H099 already key on; other arrays have no key semantics.
- No ids the code already emits. The loader accepts any non-empty id, but
  `lint-rules` warns when it does not follow `R###` and errors when it names a
  programmatic rule, because one id would then mean two different things. An
  `R###` id in the line-rule range is the convention for the same reason.
- No score above `HIGH`, and no FATAL short-circuit.

## See also

- [Customization](why-static-analysis.md#customization): where `rules.toml` sits in the design.
- [R-series and H-series](../reference/rules/system.md#r-series): the line-regex fields these entries sit beside.
- [Writing a Rule](../contributing/writing-a-rule.md): the code-rule path, for structure this surface cannot express.
- [lint-rules](../reference/cli.md#trustsight-lint-rules): the static checks a structural entry gets.
