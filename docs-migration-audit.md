<!-- description: Migration audit of the documentation rework against master: what was compared, what was preserved, and every intentional difference. -->

# Documentation Migration Audit

This report records the check that the information-architecture rework did
not lose documentation. It compares every Markdown page on `master` with the
reworked tree and lists the differences that are intentional.

## Method

- **Page inventory**: every `docs/**/*.md` on `master` was compared with the
  current tree. Master has 120 pages; the rework has 95, because 22 Rule
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

## Per-file audit

Every Markdown page on `master` (120 files) is listed below with its current
destination and result. "Moved" means the page kept its content and only its
links changed; "merged" means its prose lives on a consolidated page;
"split" means its sections now live on more than one focused page; "rewritten"
means the page was replaced by a new landing or policy page.

| Result | Files |
|---|---:|
| Unchanged | 4 |
| Updated in place (links or wording) | 21 |
| Moved, content preserved | 30 |
| Merged into a consolidated page | 38 |
| Canonical rule category pages (all definitions and nature prose) | 22 |
| Split across focused pages | 2 |
| Rewritten as an entry point or policy page | 3 |
| **Total** | **120** |

| Master file | Destination | Audit result |
|---|---|---|
| `docs/assurance-layers.md` | `docs/security-design/assurance-layers.md` | Moved; content preserved and links updated (93% paragraphs verbatim) |
| `docs/assurance-layers/diversity.md` | `docs/security-design/assurance-layers/diversity.md` | Moved; content preserved and links updated (92% paragraphs verbatim) |
| `docs/assurance-layers/enforcement.md` | `docs/security-design/assurance-layers/enforcement.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/assurance-layers/evidence-categories.md` | `docs/reference/evidence-categories.md` | Moved; content preserved and links updated (91% paragraphs verbatim) |
| `docs/assurance-layers/reporting.md` | `docs/security-design/assurance-layers/reporting.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/changelog.md` | `docs/changelog.md` | Unchanged; version link definitions added |
| `docs/contributing/blinded-evaluation.md` | `docs/contributing/blinded-evaluation.md` | Updated in place; 100% of paragraphs verbatim, remainder link or navigation updates |
| `docs/contributing/development-setup.md` | `docs/contributing/development-setup.md` | Unchanged |
| `docs/contributing/index.md` | `docs/contributing/index.md` | Updated in place; 100% of paragraphs verbatim, remainder link or navigation updates |
| `docs/contributing/publishing-baselines.md` | `docs/contributing/publishing-baselines.md` | Updated in place; 100% of paragraphs verbatim, remainder link or navigation updates |
| `docs/contributing/re-baselining.md` | `docs/contributing/re-baselining.md` | Unchanged |
| `docs/contributing/releasing.md` | `docs/contributing/releasing.md` | Updated in place; 100% of paragraphs verbatim, remainder link or navigation updates |
| `docs/contributing/security-review.md` | `docs/contributing/security-review.md` | Updated in place; 90% of paragraphs verbatim, remainder link or navigation updates |
| `docs/contributing/writing-a-rule.md` | `docs/contributing/writing-a-rule.md` | Updated in place; the obsolete Rule Nature instructions replaced with the merged-page workflow, all rule-authoring guidance preserved |
| `docs/explanation/alert-budget.md` | `docs/explanation/detection-and-evidence.md` | Merged; prose preserved |
| `docs/explanation/benchmarks-and-methodology.md` | `docs/explanation/detection-and-evidence.md` | Merged; prose preserved |
| `docs/explanation/campaign-alert-mode.md` | `docs/explanation/detection-and-evidence.md` | Merged; prose preserved |
| `docs/explanation/cold-start-and-maturity.md` | `docs/explanation/scoring-and-verdicts.md` | Merged; prose preserved |
| `docs/explanation/corpus-and-priors.md` | `docs/explanation/historical-and-behavioral-analysis.md` | Merged; prose preserved |
| `docs/explanation/cross-file-consistency.md` | `docs/explanation/architecture-and-pipeline.md` | Merged; prose preserved |
| `docs/explanation/escalation-licensing.md` | `docs/explanation/scoring-and-verdicts.md` | Merged; prose preserved |
| `docs/explanation/fire-rates.md` | `docs/explanation/historical-and-behavioral-analysis.md` | Moved; content preserved and links updated (96% paragraphs verbatim) |
| `docs/explanation/immune-inspired-design.md` | `docs/explanation/detection-and-evidence.md` | Merged; prose preserved |
| `docs/explanation/index.md` | `docs/security-design/how-it-works.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/explanation/kinds-of-alerts.md` | `docs/explanation/detection-and-evidence.md` | Merged; prose preserved |
| `docs/explanation/neighborhood-elevation.md` | `docs/explanation/detection-and-evidence.md` | Merged; prose preserved |
| `docs/explanation/override-tolerance.md` | `docs/explanation/scoring-and-verdicts.md` | Merged; prose preserved |
| `docs/explanation/reducing-the-h-series.md` | `docs/explanation/detection-and-evidence.md` | Merged; prose preserved |
| `docs/explanation/rule-taxonomy.md` | `docs/rules/interpretation.md` | Moved; the System/Nature section replaced by One canonical page per subject, all label sections preserved |
| `docs/explanation/sandboxing-the-parsers.md` | `docs/explanation/static-analysis-and-resolution.md` | Merged; prose preserved |
| `docs/explanation/sandboxing-the-tokenizer.md` | `docs/explanation/static-analysis-and-resolution.md` | Merged; prose preserved |
| `docs/explanation/scoring-philosophy.md` | `docs/explanation/scoring-and-verdicts.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/explanation/seed-provenance.md` | `docs/explanation/threat-intelligence.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/explanation/structural-user-rules.md` | `docs/explanation/static-analysis-and-resolution.md` | Merged; prose preserved |
| `docs/explanation/state-and-lifecycles.md` | `docs/explanation/state-and-lifecycles.md` | Added on master after the rework branched; preserved in full, links updated to the new security paths, and nested under How TrustSight Works |
| `docs/explanation/the-typed-core.md` | `docs/explanation/architecture-and-pipeline.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/explanation/what-trustsight-cannot-see.md` | `docs/explanation/limitations-and-uncertainty.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/explanation/why-static-analysis.md` | `docs/explanation/static-analysis-and-resolution.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/guides/acting-on-a-flag.md` | `docs/workflows/acting-on-a-flag.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/guides/auditing-before-update.md` | `docs/workflows/auditing-before-update.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/guides/configuring-rules-and-weights.md` | `docs/workflows/configuring-rules-and-weights.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/guides/gating-yay-paru.md` | `docs/workflows/integrating-yay-and-paru.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/guides/index.md` | `docs/workflows/index.md` | Updated in place; intro reworded for Workflows, page table preserved with new links |
| `docs/guides/reducing-blast-radius.md` | `docs/workflows/reducing-blast-radius.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/guides/tuning-false-positives.md` | `docs/workflows/tuning-false-positives.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/guides/using-in-ci.md` | `docs/workflows/using-in-ci.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/guides/watching-the-aur.md` | `docs/workflows/watching-the-aur-continuously.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/index.md` | `docs/index.md`, `docs/start-here/what-is-trustsight.md` | Rewritten as an entry point; platform paragraphs and report description moved to the listed pages, inventories to Rules and Security & Design |
| `docs/license.md` | `docs/license.md` | Unchanged |
| `docs/reference/baseline-keys.md` | `docs/reference/baseline-keys.md` | Updated in place; 100% of paragraphs verbatim, remainder link or navigation updates |
| `docs/reference/cli.md` | `docs/reference/cli.md` | Updated in place; 100% of paragraphs verbatim, remainder link or navigation updates |
| `docs/reference/configuration.md` | `docs/reference/configuration.md` | Updated in place; 100% of paragraphs verbatim, remainder link or navigation updates |
| `docs/reference/evidence-tiers.md` | `docs/reference/evidence-tiers.md` | Updated in place; 100% of paragraphs verbatim, remainder link or navigation updates |
| `docs/reference/exit-codes.md` | `docs/reference/exit-codes.md` | Updated in place; 100% of paragraphs verbatim, remainder link or navigation updates |
| `docs/reference/glossary.md` | `docs/reference/glossary.md` | Updated in place; 95% of paragraphs verbatim, remainder link or navigation updates |
| `docs/reference/index.md` | `docs/reference/index.md` | Updated in place; one bullet added (Evidence Categories), every prior entry unchanged |
| `docs/reference/ioc.md` | `docs/reference/ioc.md` | Updated in place; 100% of paragraphs verbatim, remainder link or navigation updates |
| `docs/reference/nature/artifact.md` | `docs/rules/artifact.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/composition.md` | `docs/rules/composition.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/corpus-behavioral.md` | `docs/rules/corpus-behavioral.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/correlation.md` | `docs/rules/correlation.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/count-based.md` | `docs/rules/count-based.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/crossfire.md` | `docs/rules/crossfire.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/deception.md` | `docs/rules/deception.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/entropy.md` | `docs/rules/entropy.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/fetch-and-execution.md` | `docs/rules/fetch-and-execution.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/index.md` | `docs/rules/categories.md` | Merged; prose preserved |
| `docs/reference/nature/indicator.md` | `docs/rules/indicator.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/install-and-persist.md` | `docs/rules/install-and-persist.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/integrity.md` | `docs/rules/integrity.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/maintainer-and-metadata.md` | `docs/rules/maintainer-and-metadata.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/meta.md` | `docs/rules/meta.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/naming-and-dependency.md` | `docs/rules/naming-and-dependency.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/obfuscation.md` | `docs/rules/obfuscation.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/sabotage.md` | `docs/rules/sabotage.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/staging-and-recon.md` | `docs/rules/staging-and-recon.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/temporal.md` | `docs/rules/temporal.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/unverifiable.md` | `docs/rules/unverifiable.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/upstream-manifests.md` | `docs/rules/upstream-manifests.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/nature/upstream-release.md` | `docs/rules/upstream-release.md` | Merged into the category page; 2/2 prose sections preserved, routing line and self-link removed |
| `docs/reference/python-api.md` | `docs/reference/python-api.md` | Updated in place; 100% of paragraphs verbatim, remainder link or navigation updates |
| `docs/reference/report-schema.md` | `docs/reference/report-schema.md` | Updated in place; 100% of paragraphs verbatim, remainder link or navigation updates |
| `docs/reference/rules/artifact.md` | `docs/rules/artifact.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/composition.md` | `docs/rules/composition.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/corpus-behavioral.md` | `docs/rules/corpus-behavioral.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/correlation.md` | `docs/rules/correlation.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/count-based.md` | `docs/rules/count-based.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/crossfire.md` | `docs/rules/crossfire.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/deception.md` | `docs/rules/deception.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/entropy.md` | `docs/rules/entropy.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/fetch-and-execution.md` | `docs/rules/fetch-and-execution.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/index.md` | `docs/rules/index.md`, `docs/rules/definitions.md`, `docs/rules/categories.md`, `docs/rules/identifiers.md` | Split: catalog moved to definitions.md (301/301 rows), taxonomy to categories.md and interpretation, identifiers to identifiers.md, overview rewritten |
| `docs/reference/rules/indicator.md` | `docs/rules/indicator.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/install-and-persist.md` | `docs/rules/install-and-persist.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/integrity.md` | `docs/rules/integrity.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/maintainer-and-metadata.md` | `docs/rules/maintainer-and-metadata.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/meta.md` | `docs/rules/meta.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/naming-and-dependency.md` | `docs/rules/naming-and-dependency.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/nature.md` | `docs/rules/series.md` | Moved to Series; See also links updated |
| `docs/reference/rules/obfuscation.md` | `docs/rules/obfuscation.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/sabotage.md` | `docs/rules/sabotage.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/staging-and-recon.md` | `docs/rules/staging-and-recon.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/system.md` | `docs/rules/scoring.md`, `docs/rules/matching.md`, `docs/rules/configuration.md`, `docs/rules/identifiers.md`, `docs/rules/series.md`, `docs/reference/rules/system.md` | Split by responsibility; every table, anchor and 43-row fire table preserved; compatibility anchors retained |
| `docs/reference/rules/temporal.md` | `docs/rules/temporal.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/unverifiable.md` | `docs/rules/unverifiable.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/upstream-manifests.md` | `docs/rules/upstream-manifests.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reference/rules/upstream-release.md` | `docs/rules/upstream-release.md` | Rule category page; all rule sections and nature prose preserved |
| `docs/reports/2026-10-14-aur-name-clone-waves.md` | `docs/reports/2026-10-14-aur-name-clone-waves.md` | Updated in place; 100% of paragraphs verbatim, remainder link or navigation updates |
| `docs/reports/hot-path-baseline.md` | `docs/reports/hot-path-baseline.md` | Updated in place; 100% of paragraphs verbatim, remainder link or navigation updates |
| `docs/reports/in-the-wild.md` | `docs/reports/in-the-wild.md` | Updated in place; 100% of paragraphs verbatim, remainder link or navigation updates |
| `docs/security.md` | `docs/security-design/security-model.md` | Moved; content preserved and links updated (96% paragraphs verbatim) |
| `docs/security/enforcement-map.md` | `docs/security-design/enforcement-map.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/security/program-under-attack.md` | `docs/security-design/security-boundaries.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/security/release-signing.md` | `docs/security-design/release-signing.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/security/vulnerability-reporting.md` | `docs/security-design/vulnerability-reporting.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/security/what-a-result-claims.md` | `docs/security-design/what-a-result-claims.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/standards.md` | `docs/standards.md` | Updated in place; 99% of paragraphs verbatim, remainder link or navigation updates |
| `docs/tutorial/installation.md` | `docs/start-here/installation.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/tutorial/quickstart.md` | `docs/start-here/quickstart.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
| `docs/tutorial/reading-a-report.md` | `docs/start-here/understanding-your-first-report.md` | Moved; content preserved and links updated (100% paragraphs verbatim) |
