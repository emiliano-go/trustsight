# Changelog

## [Unreleased]

## [0.2.2] - 2026-07-24

This release fixes a critical false positive in R013 that could score benign
packages 100/100, restores the novelty engine (Tier C) which had been inert
since v0.1, and ships a pre-seeded database of 178,491 AUR source URLs to
eliminate cold-start INCONCLUSIVE verdicts.

**Existing users must run `trustsight config sync-rules --update`** to receive
the corrected detection patterns. `rules.toml` is written only when absent, so
a package upgrade alone does not update it. The command is additive and never
overwrites a rule you have edited.

Note: `v0.2.1` was already tagged at the previous commit, and the `[0.3.0]`
section below is recorded in this changelog but was never tagged. This release
takes the next free patch number; the 0.3.0 discrepancy is left for a separate
reconciliation.

### Fixed

- R013 (FATAL) fired on legitimate localized text. U+200B-U+200D are mandatory joiners in Malayalam, Lao and other scripts, so a `GenericName[ml]=` line in a browser package scored 100/100; measured on two packages in the benign corpus. Zero-width characters now require ASCII neighbours; bidi overrides, invisible operators and tag characters still fire unconditionally. The pattern also gains U+200E/U+200F, U+2060-U+2064 and the tag block, which `unicode.py` already listed and which account for the documented recall gap.
- R058 fired on `"${pkgdir}"/usr/lib/...`, where the quote closes before the path, and on absolute paths quoted inside `echo` strings. It now requires the command to be the first token on the line and the path to start an argument.
- The maintainer was read from `.SRCINFO`, which does not carry one; checked against the AUR mirror, 0 of 200 `.SRCINFO` files have a `maintainer =` line, while every PKGBUILD opens with `# Maintainer:`. `get_maintainer_from_commit()` therefore always returned `None`, silently disabling `maintainer_changed`, the highest novelty weight (20), and C006. Now read from the PKGBUILD comment, with `.SRCINFO` as a fallback.
- `scan_diff` tracked novelty differently from the live path in three ways: it compared raw URLs instead of `normalize_url`-d ones (so every version bump read as novel), it derived "first seen globally" from the per-package set (making it identical to per-package), and it overwrote rather than OR-ed the flags across multiple URLs (so a familiar URL masked a novel one).
- Tier C novelty was inert: `observation_count` was never populated outside tests, so `maturity()` always read 0 and every novelty weight scored zero. Now sourced from `count_observations()`.
- Homograph detection missed Cyrillic confusables. `has_homograph()` only matched codepoints named `LATIN*`, while the `CONFUSABLES` table it sits beside is Cyrillic; so `github.cоm` classified as `unknown` (+20) rather than `homograph_attack` (+30). Replaced with mixed-script-per-label detection, plus punycode decoding to close the `xn--` bypass. Legitimate single-script IDNs (`.рф`, Japanese, Korean) are not flagged.
- `cli.py` called `set_config` without importing it, so `trustsight config set` raised `NameError`.
- `scripts/build_corpus.py` had a 600s timeout on the AUR bare clone, which the repository cannot meet, so the script could never complete on a fresh machine. Partial clones were also left on disk and reused silently, since `rev-parse --git-dir` succeeds on an interrupted clone.

### Added

- Novelty seed database. `scripts/generate_seed.py` builds it from the AUR git mirror by parsing `.SRCINFO` (including the arch-suffixed `source_x86_64` arrays); `trustsight seed-db` imports it. Without a seed, a fresh install has an empty `source_urls` table, so `url_first_globally` fires for github.com and every other ordinary host, and `maturity()` returns 0 because there is no analysis history; leaving every Medium verdict downgraded to INCONCLUSIVE. Import is additive and idempotent, and never overwrites a row learned from a real analysis.
- `metadata` and `maintainer_counts` tables, and `effective_observation_count()`: maturity falls back to a seed-supplied bootstrap count, and real analyses take over as soon as they outnumber it, so the tool never depends on external data permanently.
- `trustsight lint-rules` (`--file` for CI): detects unreachable, over-broad, and malformed rules. Errors on empty patterns, duplicate ids, ids owned by `analysis.py`, comment-shadowed rules, and scope contradictions; warns on rules that fire on ordinary packaging.
- Expanded ruleset R039-R059 (21 rules), calibrated against a 3322-diff stratified benign corpus and enabled by default. Fourteen fire on zero benign diffs; every remaining hit was inspected individually and all but one were true positives. R053 was split by target: setuid inside `$pkgdir` is MEDIUM (Chromium's sandbox helper legitimately needs 4755, and at MEDIUM this changes no package's risk band), while setuid on an absolute path is a separate HIGH rule, R059. The `experimental` flag remains supported for future additions.
- Programmatic rules C004 (checksum removed for unchanged source), C005 (binary artifact from untrusted source), C006 (maintainer change with new source domain), C007 (command substitution in source array).
- Rule scopes may name a PKGBUILD function (`scope = ["pkgver"]`), not just a line context.
- `added_only` rule field: match only added lines, so deleting a suspicious line no longer raises a package's score.
- Ephemeral paste and file-drop services added to the `raw_hosting` bucket.

### Changed

- Novelty weights recalibrated now that tier C is live: `url_first_globally` 15 → 10, `url_first_in_package` 10 → 5, `maintainer_first_in_package` 20 → 15. The previous values had never been exercised, because `observation_count` was never populated and the maturity multiplier was permanently 0. At full maturity they took a borderline 15-point package with a novel URL and a novel maintainer to 60 (High); the new values keep that case at 45 (Medium). Maintainer novelty remains the strongest signal.
- `_structural_findings()` is now shared by `analyze_package()` and `scan_diff()`, removing ~110 lines duplicated between the live and offline pipelines.

## [0.3.0] - 2026-07-18

- Score column renamed to "Risk Score"
- Rich progress output during review
- AUR RPC batching for performance
- Handle empty AUR repos gracefully
- FATAL severity with hard stop at 100
- Verification evidence detection and scoring
- Source pinning classification
- Code rules C001-C003 for structural anomalies
- URL normalization for novelty dedup
- Maturity-based novelty gating with Inconclusive risk level
- Scope-based rule matching (function_body context)
- R012 (prompt injection) and R013 (unicode bidi) rules
- LLM verdict integrity assertions
- scan_diff offline pipeline for benchmark use
- is_skip_justified analysis for SKIP checksums
- Fix: SKIP checksums no longer count as verification evidence
- Removed R004/R005 from TOML rules (now programmatic, context-aware)
- Default LLM provider changed to openai
- CI workflows for corpus drift monitoring
- 267 tests (was 218)

## [0.2.0] - 2026-07-15

- R004/R005 rule hardening with quote bypass fix
- Tokenizer iteration fix
- Forge classification cap
- IDN detection
- Shell variant coverage
- base64 --decode detection

## [0.1.0] - 2026-07-12

- Initial release
- R001-R011 rules
- AUR diff analysis pipeline
- Deterministic scoring
- SQLite novelty tracking
- LLM verdict integration
- Basic CLI (review, inspect, history, config)
