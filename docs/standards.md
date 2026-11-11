<!-- description: The normative detection, output, evidence, calibration, configuration, engineering, operations, release and process standards every TrustSight change is held to, and where each one is enforced. -->

# Standards

TrustSight's usefulness depends on its limits being explicit, consistent and enforced. These are the project's normative standards. They are not style preferences: each one has a test, a gate, or a documented policy behind it.

The long-form explanations live on the linked pages. This page is the canonical index of what a change is allowed to do. Security is one part of the standard; the rest covers how the instrument is built, calibrated, documented, released and operated.

## False-positive vocabulary

### Benign false positive

A benign false positive is a rule hit on a genuine bad practice by the packager, where the package itself is not malicious. The finding is real: the practice is undesirable, and the rule is doing its job. The fix belongs with the packager, or the finding is documented as a known false positive; it does not belong in a package-specific rule branch.

### Malicious false positive

A malicious false positive is a bad rule trigger: the rule fired with no bad practice or malicious behaviour behind it. A misread option, an allowlist gap, or a counting or grouping error is a malicious false positive. The fix belongs in the detection shape, and it ships with the true-positive twin.

The term names a false positive of the maliciousness claim, not a malicious false positive. See [Tuning False Positives](guides/tuning-false-positives.md#two-kinds-of-false-positive). The glossary defines both terms once: [Glossary](reference/glossary.md).

## Detection standards

### Never tune for a package

No package name, maintainer, or individual recipe may appear in detection logic. If a rule fires on a real property, the finding stays. Change the shape or document the false positive; never add a package-specific branch or allowlist entry to spare one package. A package-specific exemption is a gap an attacker can rename their way into.

Operator overrides are different. They are explicit, scoped, require a reason, and expire; they are an operator's local decision, not a hidden branch in the instrument. A package-specific branch in shipped code is forbidden.

**Enforced by:** [Tuning False Positives](guides/tuning-false-positives.md#known-false-positives) and review of every rule change.

### False-positive fixes include the true-positive twin

A change that only stops a rule firing is not a fix. The malicious case must still fire, and the regression suite must pin both sides of the change.

**Enforced by:** `tests/test_false_positive_fixes.py` and [Writing a Rule](contributing/writing-a-rule.md#tests).

### New rules start report-only

A new detection ships at weight 0 (INFO) until the benign corpus calibrates it. Being useful is not the same as being calibrated.

**Enforced by:** [Scoring Philosophy](explanation/scoring-philosophy.md) and `tests/test_calibration_gates.py`.

### Anergy is a standing state, not a silent omission

A report-only rule is listed in the shipped anergy ledger. The ledger names the signal that is missing, and scoring reads it: an anergic rule reports its findings at weight 0 whatever severity it declares. Promotion removes the entry and names the release and the changelog bullet that records the measured outcome. A release cannot silently score a rule that is still anergic.

A `conditional` entry records the narrower case: the rule scores normally except where a signed corroboration applies (C001 is weight 0 only for a checksum the signed `upstream_hash` baseline names). It is reviewed by the weekly calibration and is never globally muted.

**Enforced by:** `trustsight.anergy`, `scripts/gates/_process.py` and `trustsight admin anergic`.

### Scored rules pass the fire-rate gate

A rule firing on at least 30% of the benign corpus is describing a census, not detecting an anomaly. It must be INFO and weight 0.

**Enforced by:** [Writing a Rule](contributing/writing-a-rule.md#fire-rate-gate).

### Rule identity is permanent

A rule carries a permanent uid and a permanent id. Retired ids resolve to their survivor and are never re-issued; renamed ids keep an alias so old suppressions still resolve. Rule ids are immutable even when the taxonomy later looks wrong.

**Enforced by:** `registry_uids.json`, `rule_id_history.py`, `registry.py` and [Rule System](reference/rules/system.md).

### Rule intake names five things

A proposed rule names its mechanism (series), its subject (category), its evidence layer, its shared dependencies, and the attack variation existing rules miss. If another rule already covers the same shape, the change is filed as an instance of that rule or must argue complementary coverage. Complementary is not the same as independent: two rules that share the tokenizer or history database can fail together.

**Enforced by:** [Writing a Rule](contributing/writing-a-rule.md), [How to Add a Useful Detector](assurance-layers/diversity.md) and the intake review.

### Rules must be able to fire

A rule that can never fire is a defect, not a harmless extra. Lint rejects comment-only patterns, duplicate ids, unknown scope values, uncompilable regexes and structural patterns that can never see a diff line.

**Enforced by:** `src/trustsight/lint.py` and `tests/test_lint_cmd.py`.

### Every rule maps to one layer and one composition stage

A rule belongs to exactly one evidence layer and one composition stage. A new rule that cannot name its layer or stage is not integrated.

**Enforced by:** `layers.py`, `analysis/composition.py` (`_STAGE_OF`) and the layer gates.

### Positive evidence is reported, never credited

Declared checksums, PGP keys, pins and trusted hosts are INFO findings at weight 0. There are no subtractive weights, because a claim an attacker can assert for free must not buy back score.

**Enforced by:** [What a Result Claims](security/what-a-result-claims.md#b10-positive-evidence-is-reported-never-credited).

### Known false positives are documented

When the same shape is a real signal elsewhere, keep the finding and document why it stays. Do not add a package to an allowlist to silence it.

**Enforced by:** [Tuning False Positives](guides/tuning-false-positives.md#known-false-positives).

### Fixtures are executable claims

Every scored rule needs a benign case and a malicious case. Entries carry `must_fire`, `must_not_fire`, `min_score` or `max_score`, and every diff is referenced by the group's `expected.json`; `verify_fixtures.py` checks that neither half drifts. Fixtures are regenerated, not hand-edited, and a known-gap record is updated when another rule starts catching the shape.

**Enforced by:** `scripts/verify_fixtures.py`, `scripts/gen_malicious_fixtures.py`, `scripts/calibration/_core.py` and [Writing a Rule](contributing/writing-a-rule.md#fixtures).

## Shared machinery and the typed core

### One resolver, one implementation

Path, host and URL decisions go through the shared helpers rather than being re-derived in each rule. `_raw_targets`, `canonical_host`, `normalize_url` and the typed parsers are the single implementation; a rule that re-invents one is a future inconsistency.

**Enforced by:** `analysis/persistence.py` (`_raw_targets`), `buckets.py` (`canonical_host`), `novelty.py` (`normalize_url`) and review.

### No new raw line loops outside the typed core

New code reads diffs through `DiffDoc` and recipes through `RecipeDoc`. A legitimate raw `split_lines` loop is pinned with a reason in `tests/test_typed_core_adoption.py`; an unpinned new loop fails the suite.

**Enforced by:** `tests/test_typed_core_adoption.py` and [The Typed Core](explanation/the-typed-core.md).

### Findings go through stamp and templates

Every finding is built with `stamp` and rendered through `TEMPLATES`. A rule does not hand-build its rendered form or omit the template and evidence contract.

**Enforced by:** `findings.stamp`, `verdict.py` and `tests/test_output_parity.py`.

## Output, determinism and reporting

### Every emitted order is explicit

Findings, changes, alert titles, report keys and release members are sorted rather than left to dict or set iteration order. Two runs over the same input cannot produce a different order.

**Enforced by:** `changes.py`, `reporting.py`, `contract.py` and `scripts/gates/_integrity.py`.

### Alert names and release outputs are deterministic

Alert cycle names are ordered by score, count and id. Release tarballs use sorted members and a fixed mtime, and the checksum describes the worktree being tagged, not `HEAD`.

**Enforced by:** `notify.py`, `scripts/build_release_tarball.py` and `tests/test_release_workflow.py`.

### CLI and API share one body

Every report key is present on every path, the API and CLI share one analysis, and the score is withheld from default bodies.

**Enforced by:** `reporting.py` and the API/CLI parity gates in `scripts/security_gates.py`.

### Exit code is not a verdict

Exit 0 means the analysis completed; exit 2 means it could not. A package that flags is reported in the output, not in the exit status.

**Enforced by:** [What a Result Claims](security/what-a-result-claims.md#b6-what-a-result-does-not-claim) and `tests/test_exit_codes.py`.

### Alert counts reconcile and weight-zero annotations are reported

Shown findings plus grouped findings equal the rendered count. Weight-0 annotations are reported but never scored.

**Enforced by:** the alert-count and weight-zero gates in `scripts/security_gates.py`.

### Alert volume is capped and reported

The terminal cap is always announced, and the JSON report is never filtered. Volume is not evidence about any single package.

**Enforced by:** [Alert Budget](explanation/alert-budget.md).

## Evidence and verdict standards

### Instrument, not judge

A flag is a prompt to look, not a verdict to obey. An unflagged result is a detection outcome, not a certificate of safety.

**Enforced by:** [Acting on a Flag](guides/acting-on-a-flag.md) and [What a Result Claims](security/what-a-result-claims.md#b6-what-a-result-does-not-claim).

### Fail closed

Incomplete coverage forbids a clean verdict. A truncated diff, a partial file or an unread manifest is INCONCLUSIVE, never unflagged.

**Enforced by:** `coverage.fail_closed` and [Security Model](security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete).

### Unresolved is not seen

A construct the analyzer could not resolve is reported as a boundary. It is never treated as absent, and it is never treated as benign.

**Enforced by:** `W008`/`X026` and [Security Model](security.md).

### Evidence over assertion

TrustSight never fetches a URL a package declares. It reports what it could read and what it could not, rather than confirming an attacker's claim for them.

**Enforced by:** [Security Model](security.md#part-a-trustsight-as-a-program-under-attack) and the W-series.

### A failed query is not an empty result

A failed lookup degrades to an explicit failure or a declared boundary, never to “none found”. A cache miss is a miss; a query failure is not evidence of absence.

**Enforced by:** `discovery.py` and the coverage boundary rules.

### Refuse rather than truncate for state

An over-cap seed or baseline aborts its import. Diff and history truncation is allowed only as a declared coverage gap; it never becomes a complete-looking result.

**Enforced by:** `bounded_io.py`, `docs/security/program-under-attack.md` and `coverage.py`.

### Suppression is always visible

A suppressed finding is returned and reported, never silently discarded. Overrides expire, and indicator corroboration can make a suppressed finding visible again.

**Enforced by:** [What a Result Claims](security/what-a-result-claims.md#b5-suppression-is-always-visible) and [Override Tolerance](explanation/override-tolerance.md).

### FATAL cannot be switched off

The FATAL rules protect the reviewer, not just the machine. No tuning justification can disable them.

**Enforced by:** [What a Result Claims](security/what-a-result-claims.md#b4-fatal-cannot-be-switched-off) and `config.enforce_fatal_rules`.

### Report what changed, not only what fired

Every result carries a change summary beside its findings, including the no-change case. Absence of alerts must not read as absence of change.

**Enforced by:** [What a Result Claims](security/what-a-result-claims.md#b7-a-result-reports-what-changed-not-only-what-fired).

### Findings are checkable

Content findings carry a file and line. Non-content findings declare an evidence class instead of silently omitting a location.

**Enforced by:** [What a Result Claims](security/what-a-result-claims.md#b8-a-finding-is-checkable) and `findings.NON_CONTENT_RULES`.

### No output grants permission to skip review

No rendered output says or implies “safe”, “clean”, or “nothing to review”. The terminal always ends with a direction to review.

**Enforced by:** [What a Result Claims](security/what-a-result-claims.md#b9-no-output-grants-permission-to-skip-review).

## Calibration standards

### Separation gate

Benign p95 must stay below malicious p5. A change that moves both populations is not a detection improvement.

**Enforced by:** `scripts/calibration/_gates.py` and [Benchmarks and Methodology](explanation/benchmarks-and-methodology.md).

### CRITICAL recall stays at 100%

Every known malicious fixture must still fire. Losing a critical detection to reduce noise is not a trade the project accepts.

**Enforced by:** `tests/test_calibration_gates.py`.

### Cold start is zero-fire

Novelty and history rules decline while the database is cold. They do not guess from an empty observation set.

**Enforced by:** [Cold Start and Maturity](explanation/cold-start-and-maturity.md).

### Determinism under a fixed fingerprint

The same input and the same config fingerprint must produce the same score. A different fingerprint is a different instrument, by design.

**Enforced by:** `config.config_fingerprint` and `tests/test_calibration_gates.py`.

### Published figures move with the measurement

A scoring change updates the published distribution and the calibration baseline in the same change.

**Enforced by:** `scripts/rebaseline.py` and [Re-baselining](contributing/re-baselining.md).

### Rule and scoring changes run full calibration

Targeted tests are not enough for a rule or scoring change. The full calibration job is part of the change, not a follow-up.

**Enforced by:** [CONTRIBUTING](contributing/index.md) and `.github/workflows/calibration.yml`.

### Corpus checks use the parallel worker pool

Do not hand-roll a serial `for path: analyze_diff(...)` loop. Use `scripts/scan_benign.py` or the calibration worker pool so a corpus check stays a measured pass rather than a multi-hour serial walk.

**Enforced by:** [Writing a Rule](contributing/writing-a-rule.md) and `scripts/scan_benign.py`.

### Blinded evaluation material stays out of fixtures

Externally labelled material goes through the blinded-evaluation intake, not into `tests/fixtures/` before evaluation. Adding it early contaminates the only independent measurement the project has.

**Enforced by:** [Blinded Evaluation](contributing/blinded-evaluation.md) and [CONTRIBUTING](contributing/index.md).

## Configuration and compatibility

### New shipped defaults are not migrations

`write_default_file` only writes when a file is absent. A behavior that depends on a new shipped default must also fall back in code so an existing install receives it; changing `DEFAULT_*` alone changes only fresh installs.

**Enforced by:** `config.write_default_file` and the runtime fallbacks in `buckets.py` (`_confusable_targets`, `_declared_sibling_groups`).

### Config sync appends, never overwrites

Missing shipped rules are appended to an existing `rules.toml`. Replacing a changed rule requires explicit `config sync-rules --update`; user customization is never silently rewritten.

**Enforced by:** `config.ensure_default_configs`, `config.sync_rules` and [Configuration Reference](reference/configuration.md).

### Overrides require a reason and stay visible

An override is scoped, reason-bearing, expiring and visible in the result. It cannot suppress FATAL or hide indicator corroboration.

**Enforced by:** `override.py` and [Override Tolerance](explanation/override-tolerance.md).

### Default config files are private

Default config files are written mode 0600.

**Enforced by:** `config.write_default_file`.

## Engineering standards

### No interpreter or shell execution

Analysis never executes package content. There is no sandbox that makes running a PKGBUILD safe, so the project does not run one.

**Enforced by:** `scripts/security_gates.py`.

### No package-controlled network

TrustSight connects only to its declared hosts, and never fetches a URL a package names. This removes the SSRF primitive entirely.

**Enforced by:** `scripts/security_gates.py` and [Security Model](security.md).

### All inputs are bounded and regexes are audited

Diff size, line size, history walk, stream reads, tokenizer work and regex matching all have source-level bounds. A package cannot decide how much CPU or memory the process spends, and shipped patterns pass an adversarial audit for catastrophic backtracking.

**Enforced by:** `scripts/security_gates.py` and A14.

### No path-based archive extraction

Archive handling never trusts a path taken from package content.

**Enforced by:** `scripts/security_gates.py`.

### Manifest parsers refuse, not hang

Hostile TOML, JSON, YAML and line input returns a refusal instead of hanging or exhausting the process. YAML is only ever `safe_load`.

**Enforced by:** `tests/test_manifest_syntax.py` and A4b/A5.

### Tokenizer and git are sandboxed

They run in isolated workers, not in the analysis process. A tokenizer failure must not blind the whole analysis silently, and libgit2 stays behind the git worker.

**Enforced by:** `sandbox/`, `scripts/security_gates.py` and [Sandboxing the Tokenizer](explanation/sandboxing-the-tokenizer.md).

### Every child process gets an explicit environment

Children do not inherit `PYTHON*` or loader-injection variables. The environment is built explicitly for the worker.

**Enforced by:** `subproc.py`, `sandbox/client.py` and the child-environment gate.

### SQL is parameterised and output is sanitised

Package-controlled text never becomes SQL and never becomes a terminal control sequence.

**Enforced by:** `scripts/security_gates.py` and `safe_text.clean`.

### The cache is an optimization, never an authority

A miss, version mismatch, malformed entry or oversized entry falls back to a fresh parse. The cache never answers in place of the parser, and it never chooses how much the read allocates: entries are read through `read_file_capped` under `MAX_DOC_CACHE_BYTES` (16 MiB), and a payload over that cap is not stored.

**Enforced by:** `doc_cache.py`, `diffdoc.from_dict` and the bounded-read gate.

### Only JSON, never pickle

Caches and documents are JSON. Attacker-derived data is never deserialized into code.

**Enforced by:** `diffdoc.py` and `doc_cache.py`.

### Heavy imports are lazy

`tldextract`, `rich`, `importlib.metadata` and similar are imported at point of use to keep CLI startup fast. A module-level import that costs startup time needs a reason.

**Enforced by:** `buckets.py`, `notify.py`, `fetcher.py` and `cli/display.py`.

### Privacy: hashed maintainers, no package names to the AUR

Seeds and exports carry salted hashes of maintainer identities, never plaintext. Package names are public and stored as written. Private lookups must not send package names to `aur.archlinux.org`.

**Enforced by:** `seed_build.py`, `full_aur/export.py`, `watchlist.py` and `discovery.py`.

### A seed or baseline supplies state, not rules

A baseline may add observations, never detection rules.

**Enforced by:** `full_aur/export.import_baseline` and the baseline gate.

### Templates are code-owned; fields are package-owned

Gates check template text, never substituted field values. A package legitimately named `safe-rs` must not trip a permission-denial check.

**Enforced by:** [What a Result Claims](security/what-a-result-claims.md#b9-no-output-grants-permission-to-skip-review) and the reporting gates.

## Operational resilience

### Optional operator aids must not break analysis

A malformed or missing watchlist, cache or optional config is empty or a miss, never an error that aborts an analysis.

**Enforced by:** `watchlist.py`, `doc_cache.py` and the analysis entry points.

### Notification failure never kills the watcher

Sinks are independent; a failed POST is logged and swallowed. The request has a bounded timeout, and the response body is drained rather than read for content.

**Enforced by:** `notify.py` and `tests/test_notify.py`.

### Alerts are not urgent by default

The urgent notification tier pages at night, so ordinary alerts never carry it. Urgency is reserved for the one campaign class that must wake a reviewer.

**Enforced by:** `notify.py`.

### Volume degrades to top-K, not silence

The stored JSON keeps every package. Only the notification is capped, and the cap is reported.

**Enforced by:** `notify.py` and [Alert Budget](explanation/alert-budget.md).

## Release and process standards

### Release from a clean tree

The release tarball refuses a worktree with untracked files and names what it found. A checksum over unreviewed files is silently wrong; being in the index is the operator's statement that a file belongs in the release.

**Enforced by:** `scripts/build_release_tarball.py` and [Releasing](contributing/releasing.md).

### A baseline release ships the whole signed family

A `baseline-*` release is not a place for one convenient asset. It ships `baseline-seed.tar.gz`, `baseline-corpus.tar.zst` and `baseline-manifest.json`, each with its detached `.sig` under the pinned distribution key. The manifest records every asset's SHA-256 and size, and the tool refuses a download whose signature does not verify. The CI-only calibration corpus (`baseline-benign-corpus.tar.gz`) is the one deliberate exception: it is unsigned because the tool never consumes it, and its bytes are anchored by `corpus_content_sha256` in `baseline.json`. Publishing a partial or unsigned family is a release defect, not a shortcut.

**Enforced by:** `scripts/build_release_baselines.py`, `scripts/pack_calibration_corpus.py`, `.github/workflows/baselines.yml` and [Publishing Baselines](contributing/publishing-baselines.md).

### Gates report measured values

A gate returns what it measured, not just pass or fail. A gate that cannot name its measurement is not a gate.

**Enforced by:** `scripts/gates/_core.py` and `scripts/security_gates.py`.

### Every behaviour change carries evidence

A behaviour change ships with true-positive and false-positive tests, calibration, documentation and a changelog entry.

**Enforced by:** [Writing a Rule](contributing/writing-a-rule.md) and [CONTRIBUTING](contributing/index.md).

### Changelog entries carry measured outcomes

A fix names the live case and records the before/after distribution when the figure moved. “Improved detection” without a measurement is not a changelog entry.

**Enforced by:** `docs/changelog.md` and review.

### Discuss first for security-shaped changes

New rules, severity changes, tokenizer or resolver changes, network targets, dependencies, schema changes and public API changes need a design discussion before implementation.

**Enforced by:** [CONTRIBUTING](contributing/index.md).

### Docs have one source of truth

Rule prose lives in `docs_src/`; generated pages are regenerated, never hand-edited.

**Enforced by:** `tests/test_generated_docs.py` and `scripts/build_rules_index.py`.

### Docs prose is not hard-wrapped mid-sentence

Write paragraphs as paragraphs and let the renderer wrap them. A forced newline mid-sentence makes the source harder to edit and the diff noisier.

**Enforced by:** review and the docs conventions.

### Regression tests name the case they pin

A regression test names the package, feed date or incident it protects, so the next reader knows what would break if the test were removed.

**Enforced by:** review and the false-positive regression suites.

### Comments explain why and cite the case

A non-obvious guard names the failure or package that motivated it. A comment that repeats the code is not documentation.

**Enforced by:** review and the existing incident comments in `buckets.py`, `notify.py` and `persistence.py`.

### Public API docstrings are complete

The supported API is documented in reST fields on every public method parameter.

**Enforced by:** [CONTRIBUTING](contributing/index.md).

### Critical paths are signed and CI installs from the lock

Commits touching the critical set carry the pinned signing key, and every workflow uses the locked dependency set.

**Enforced by:** `scripts/critical_paths.py`, `uv.lock` and the CI workflows.

## Applying a standard

When a watcher alert or a bug report points at a rule, the question is never “which package should we exclude?”. It is: what general shape did the rule match, is that shape a real signal elsewhere, and can the rule be narrowed without losing its true-positive case? If the answer is “this package is special”, the change is not ready. Fix the shape, or leave the finding and document why it stays.
