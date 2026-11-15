<!-- description: Migration audit of the documentation rework against master: what was compared, what was preserved, and every intentional difference. -->

# Documentation Migration Audit

This report records the check that the information-architecture rework did
not lose documentation. It compares every Markdown page on `master` with the
reworked tree and lists the differences that are intentional.

## Method

- **Page inventory**: every `docs/**/*.md` on `master` was compared with the
  current tree. Master has 119 pages; the rework has 94, because 22 Rule
  System plus 22 Rule Nature pages became 22 canonical category pages, and 22
  explanation pages became 7 conceptual pages.
- **Rule definitions**: every `### <ID>:` body was extracted from both trees
  and compared after normalising Markdown links, headings and whitespace.
- **Prose**: every paragraph was checked for an exact match or a high-overlap
  match in the current tree. Missing paragraphs were inspected individually.
- **Tables**: every table row was compared as a normalised row, not as an
  opaque block, so a moved table with updated link paths would not read as a
  loss.
- **Code samples**: every fenced block was compared verbatim.
- **Links**: all internal links and anchors are also enforced by
  `tests/test_docs.py`; `zensical build --strict` reports no issues.

## Rule definitions

| Check | Result |
|---|---|
| Old catalog IDs | 301 |
| Current catalog IDs | 301 |
| IDs missing from the current catalog | 0 |
| Rule section bodies changed | 4 of 301 |
| Nature prose sections changed | 0 of 44 |
| Category pages with both mechanics and interpretation | 22 of 22 |

The four changed rule bodies differ only in link targets:

- `H015`, `H016`: `../configuration.md#code_rules` became
  `../reference/configuration.md#code_rules`.
- `H029`, `D002`: "see Rule Nature" became "see Rule Interpretation", because
  the Nature tab no longer exists.

Every rule pattern, severity, target, condition and limitation is otherwise
unchanged. `tests/test_docs.py` still pins every quoted pattern to the shipped
`rules.toml`, and `tests/test_generated_docs.py` pins the generated pages to
their sources.

## Explanation pages

The 22 explanation pages were merged into 7 canonical pages. Each body was
checked against its destination page; all body content is present. The merged
pages add a short framing introduction, which is why a byte-for-byte page
comparison shows an insertion rather than a deletion.

`docs/explanation/seed-provenance.md` had shell comments starting with `##`
that the heading-demotion step briefly changed to `###`. The audit caught it,
and the block is restored verbatim in
[threat-intelligence.md](docs/explanation/threat-intelligence.md).

## Homepage and overview content

The homepage was deliberately shortened. Its substantive material was moved,
not discarded:

- The three platform and ecosystem paragraphs now lead the
  [What is TrustSight?](docs/start-here/what-is-trustsight.md)
  page.
- The "instrument, not a judge" wording and the security-model boundary are
  preserved on the same page.
- The rule-family inventory is now generated from the catalog in
  [rules/index.md](docs/rules/index.md): per-series
  counts and the 301 total, of which 277 score.
- The evidence-layer table lives in
  [Evidence Categories](docs/reference/evidence-categories.md),
  and the detection/coverage explanation lives in
  [Assurance Layers](docs/security-design/assurance-layers.md).
- The "Ready to get started?" pointer is preserved on the homepage.

The old homepage page-directory tables were replaced by the section landings
and the sidebar. They contained no information beyond a title, a link and a
one-line scope, all of which the destination page still states.

## Fire rates

The old `system.md` measured-fire-rate table had 43 rows. It was initially
summarised as a link to the canonical Fire Rates page, which did not carry all
43 rows. The audit found this and the full table is now restored under
[Measured code-emitted rules](docs/explanation/historical-and-behavioral-analysis.md#measured-code-emitted-rules),
including every rule id, hit count, rate and note.

All 43 rule/rate pairs are present. The 5.95% to 0.15% D001 extractor-fix
narrative is preserved in the same page.

## Intentional differences

These old passages have no current equivalent by design. None carried
technical information that is absent elsewhere:

| Old passage | Why it is not verbatim |
|---|---|
| "Mechanics live on the ... system page" | The System/Nature split was merged; the mechanics are on the same page now. |
| "Where these rules come from and what a finding means: Rule Nature" | The Nature tab was merged into each category page. |
| "System page and Nature page are not labels..." | Replaced by "One canonical page per subject", which describes the new contract. |
| "Each category also has a page on the Rule Nature tab..." | Replaced by instructions for `docs_src/nature/`, the merged page's source. |
| "This page is the map. The rule system reference explains..." | The overview now routes to the split mechanics pages directly. |
| Old homepage section tables (`Tutorial`, `Explanation`, `Guides`) | Replaced by the sidebar and section landings; every page and scope is still present. |
| Old rule index catalog table | Regenerated in `rules/definitions.md`; all 301 rows and IDs are present. |
| Old security stubs pointing at another page | Rewritten as "See ..." links to the page that owns the part. |

## Residual risk

- Two prose paragraphs from the old homepage are represented by equivalent
  wording on other pages rather than verbatim: the evidence-layer paragraph
  and the detection/coverage paragraph. Their claims, tables and examples are
  in Assurance Layers and Evidence Categories.
- The one-line category descriptions from the old Rule Nature index are
  shorter in the new category list; the full "where it comes from" and "what a
  finding means" sections remain on each category page.

No technical definition, rule, configuration field, security guarantee,
example or table row was found missing after these checks.
