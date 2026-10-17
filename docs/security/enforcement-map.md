<!-- description: The enforcement map: every security invariant mapped to the gate that fails the build when it stops being true. -->

# Part C: The enforcement map

Each row is one invariant, the gate that proves it, and where the behaviour lives. Run them all with:

```bash
python scripts/security_gates.py
```

`scripts/security_gates.py` returns exit code 1 when any gate fails (and 0 when all pass), so an exit code of 1 means a claim on this page has stopped being true. That is the same non-zero exit the CI job keys on to fail the build.

| Gate | Invariant | Implementation |
|------|-----------|----------------|
| `no interpreter or shell execution` | A1 | source-wide AST scan, with explicit UTF-8 reads |
| `version arguments are shape-checked` | A1 | `discovery._VERSION_ARG_RE` |
| `network confined to the fetch modules` | A2, A3 | `discovery.py`, `fetcher.py`, `full_aur/fetch.py`, `full_aur/metadata.py`, `release.py` |
| `declared source URLs are never fetched` | A2 | no raw transport in `src/trustsight/analysis/`, and every fetch helper it imports is name-keyed |
| `every JSON report carries the fingerprint` | B1 | `schema.fact_to_dict`, `reporting.report_body` |
| `suppression is never hidden by a flag` | B5 | `suppressed_rules` outside any verbosity branch in `cli/review.py` |
| `alert grouping is reported` | B5, B11 | `analysis/meta.alert_volume_finding`; W010 becomes a SATURATED boundary |
| `alert counts reconcile` | B5 | `shown + grouped == rendered`; the JSON is never filtered |
| `campaign state is instrument state` | B1 | the config fingerprint carries no campaign or observation state |
| `campaign expiry is structural` | A11 | an expired campaign is never returned by `active_campaigns` |
| `campaign points are attributed` | B1 | every campaign bonus is a `G007` entry carrying `campaign_id` |
| `elevation is attributed` | B1/B10 | `G006` is weight-0 INFO and names the campaign whose scope it touched |
| `escalation is one notch` | B10 | licensing moves a band one step, never more |
| `escalation never reaches fatal` | B4/B10 | no escalation or bonus path reaches FATAL |
| `escalation chains are rejected` | B10 | a rule that is itself licensed cannot license a third |
| `expired overrides are reported` | B5 | a lapsed override stops suppressing and its id is named |
| `corroborated suppression is terminal-visible` | B5 | a visible-only suppression renders in the terminal |
| `overrides never hide indicator corroboration` | B5 | a clear-indicator override cannot hide a match the run made |
| `the default output is not headline-shaped` | Guarantees | the default inspect render volunteers no score |
| `one network host, declared` | A3 | endpoint constants: `aur.archlinux.org` everywhere, `api.github.com` and `github.com` only in `release.py` |
| `every request has a timeout` | A4 | `urlopen` call sites |
| `every stream read is bounded` | A4, A14 | source-wide AST scan for a `read()` with no size |
| `artifact reads are bounded before verification` | A4 | `db.py`, `ioc_baseline.py`, `seed_build.py`, `full_aur/export.py` |
| `rule matching is bounded on hostile input` | A5 | `rules.MAX_RULE_LINE_BYTES` |
| `H-series intake is frozen` | internal | `categories.RULE_CATEGORIES` |
| `H-series reduction residue` | internal | `categories.RULE_CATEGORIES`, target 55-65 |
| `retired ids resolve to live survivors` | internal | `rule_id_history.RETIRED_RULE_IDS` |
| `docs layer mapping matches the registry` | internal | `scripts/build_layers_doc.py`, `trustsight.layers` |
| `layer detection and coverage are independent` | internal | `trustsight.layers._layer_coverage` |
| `every rule names its shared dependencies` | internal | `trustsight.detectors`, `SERIES_DEPENDENCIES` |
| `layer overrides stay within the closed set` | internal | `trustsight.layers.parse_overrides`, `LAYER_VALUES` |
| `boundaries are the coverage view` | B2 | `trustsight.boundaries`, `coverage.GAPS` |
| `every report body key is documented` | B11, report schema | `reporting.REPORT_KEYS`, `docs/reference/report-schema.md` |
| `transcendence table names real series` | internal | `docs/assurance-layers/diversity.md`, `layers.SERIES_LAYER` |
| `every rule carries exactly one layer` | internal | `trustsight.layers.layer_of`, `categories.RULE_CATEGORIES` |
| `boundaries forbid clean exactly when coverage gaps exist` | B2 | `trustsight.boundaries`, `coverage_gaps` |
| `the indicator tier mirrors ioc_matches` | B1 | `reporting.report_body`, `PackageFact.ioc_matches` |
| `the layer profile is gap-precise and additive` | internal | `trustsight.layers.layer_profile` |
| `differ hostile input is bounded` | A4b | `differ` parser limits and hostile extraction gate |
| `generated diff is bounded before assembly` | A4b, B2 | `sandbox/git_project.generate_diff_bounded`, `MAX_DIFF_PATCHES`, `MAX_PATCH_BYTES` |
| `companion reads are bounded before data` | A4b | `sandbox/git_project.companion_source_hunks`, `MAX_PKG_BUILD_BYTES`, `MAX_COMPANION_TREE_ENTRIES` |
| `differ output is deterministic` | Guarantees | sorted differ summaries and URL extraction |
| `API inputs are bounded before initialization` | A4c | `trustsight.api` input validators |
| `expansion is bounded and never indirect` | A6 | `tokenizer.py` |
| `tokenizer hostile-input smoke is deterministic` | A6, A14 | `tokenizer.py` and fixed hostile-input smoke cases |
| `tokenizer module is isolated` | A6 | no `src/` module imports `_tokenizer_engine` except `sandbox/expand_worker.py` |
| `tokenizer worker startup is isolated` | A6 | the worker launches `-I` with no `PYTHON*` environment, so no `sitecustomize` runs at startup |
| `git worker startup is isolated` | A16 | the git worker launches `-I` with a minimal environment, so no `sitecustomize` runs at startup |
| `git worker limit failures are reported` | A16 | `sandbox/git_worker._apply_limits` returns the limits that could not be set, and the client surfaces `degraded` rather than swallowing them; this is a **resource-bounded subprocess boundary, not an OS sandbox** (no separate UID, network namespace or seccomp) |
| `every child process gets an explicit environment` | A6 | every `subprocess` call in `src/` passes `env=minimal_env()`, so no inherited startup-hook or loader-injection variable (`PYTHONPATH`, `LD_PRELOAD`, ...) reaches a child |
| `tokenizer pool waits are bounded` | A6, A14 | `sandbox/client.py` refuses a saturated pool at a finite deadline rather than blocking forever |
| `a dead tokenizer child fails the package` | A6, B2 | `sandbox/client.py` raises `TokenizerUnavailable`; the batch runner reports the package as NOT vetted |
| `regex patterns pass adversarial audit` | A5, A14 | configured and source regex patterns |
| `untrusted text is sanitised where it is rendered` | A1, B7 | every CLI render path: `safe_text.clean` rather than the weaker `unicode.strip_ansi`, and values wrapped rather than passed to Rich as bare strings |
| `every live regex is audited` | A5, A14 | every compiled pattern reachable from an imported module, including patterns assembled from parts rather than written as literals |
| `report rendering is data-driven` | A7 | `verdict.py`, `findings.py` |
| `no path-based archive extraction` | A8 | `full_aur/fetch.py`, `db._extract_v2_archive` |
| `release artifacts and tags use the verified commit` | release consistency | `.github/workflows/publishing.yml` builds from the checked-out target and refuses a tag that points elsewhere; `scripts/verify_release.py` rebuilds `HEAD` |
| `SQL is parameterised` | A9 | `db.py` |
| `terminal output is inert` | A10 | `safe_text.py`, `cli/` |
| `freshness uses local marker` | A11 | `sandbox/git_project._is_current`, `sandbox/git_project.last_fetch_time` |
| `a seed cannot rewrite the database` | A12 | `db.import_seed` |
| `hashed maintainers protect privacy` | P1 | `db.maintainers_hashed`, `seed_meta.salt` |
| `the seed hash is deterministic` | P1 | `seed_build._hash_value` |
| `an IOC match carries its source` | A13b | `ioc_baseline.IocMatch.source`, `analysis/ioc_match.py` |
| `IOC matches never contribute to the score` | B1 | `PackageFact.ioc_matches` separate from `score_breakdown` |
| `an expired IOC is never silent` | IOC expiration | `ioc_baseline.active_iocs`, `cli/ioc.py` `[EXPIRED]` label |
| `IOCs are not in the rule config layer` | config separation | no `ioc` table in `rules.toml`, `patterns.toml`, `thresholds.toml` |
| `a pattern IOC that risks ReDoS is refused` | A13b pattern safety | `iocs.compile_ioc_pattern` static nested-quantifier and quantified-alternation checks |
| `reserved names are refused by every writer` | A12, A13 | `db.upsert_package`, `db.save_package_profile`, `db.save_pkgbuild_snapshot` |
| `a baseline supplies state, not rules` | A13 | `full_aur/export.import_baseline` |
| `incomplete coverage fails closed` | B2 | `coverage.fail_closed` |
| `a truncated diff cannot read as unflagged` | B2 | `analysis/pipeline.py`, `full_aur/analyze.py` |
| `an unpinned build dependency is a declared gap` | B2, A14 | `analysis/buildfetch.py`, `coverage.UNPINNED_BUILD_DEPS` |
| `a coverage gap is always shown with the band` | B2 | `coverage.qualified_band`, `scoring.verdict_label` |
| `every result declares its coverage` | B2 | every `PackageFact(...)` construction |
| `a result reports what changed` | B7 | `changes` on every `PackageFact` |
| `change entries carry no severity` | B7 | `changes` is a list of plain strings |
| `content findings carry a location` | B8 | `findings.NON_CONTENT_RULES` |
| `no template grants permission to skip` | B9 | denylist over `verdict.py`, `findings.py` |
| `positive evidence never changes the score` | B10 | every `P` finding is INFO, weight 0 |
| `every render reports the same information` | B11, B2, B5, B7 | all four renderers in `cli/review.py`, `cli/inspect.py` |
| `the API and CLI emit the same JSON body` | B11 | `reporting.report_body`, `REPORT_KEYS` |
| `the score is withheld from every default body` | B11, Guarantees | `reporting.SCORE_KEYS`, `Report.to_dict` |
| `the API and CLI share one analysis` | B11 | `api.py` imports the CLI's analysis entry points |
| `positive evidence cannot lower a FATAL` | B10, B4 | maximal declared evidence plus one FATAL |
| `declared findings fire under the shipped config` | B10 | every `P` finding reachable with the config that ships |
| `a critical finding never reads medium` | B4, bands | `scoring.CRITICAL_BAND_FLOOR`, `calculate_score` |
| `a fatal finding names itself in the label` | B4, bands | `scoring.verdict_label`, `_fatal_label` |
| `the flag threshold is derived, not copied` | B2 | `scoring.FLAG_THRESHOLD` |
| `the maturity numbers are derived, not copied` | B3 | `scoring._MATURITY_THRESHOLD` |
| `FATAL rules cannot be switched off` | B4 | `config.enforce_fatal_rules` |
| `FATAL findings survive every override` | B4, B5 | `override.filter_triggered_rules` |
| `doc cross-references resolve` | this page, and every page linking to it | every `docs/**` link and anchor |
| `the score is deterministic under a fixed fingerprint` | B1 | `config.config_fingerprint`, two-run comparison |
| `every input bound is a source constant` | A14 | bound constants are module-level literals |
| `every result render ends with a direction to review` | B9 | `verdict.DIRECTIONS`, structural |
| `no git filters or hooks are configured` | A3 | clone configuration |
| `libgit2 stays behind the git sandbox` | A16 | only `sandbox/git_project.py` and `sandbox/git_worker.py` import `pygit2`; the parent reaches every git operation through the isolated worker |
| `docs/security.md matches the gates` | this page | the table above |
| `CI installs from the lock` | the CI assumption | `uv sync --locked` in every workflow, `uv.lock` |
| `critical paths are synchronised` | `CODEOWNERS`, signature workflow and contributor policy | canonical `scripts/critical_paths.py` |
| `an audit does not write history` | A15 | connection opened `mode=ro` when `--record` is absent; behavioural, asserted by running the path against a fixture DB and diffing it |
| `the history walk is bounded` | A14 | `sandbox/git_project.walk_bounded` is the only walker; `differ.MAX_HISTORY_COMMITS`, `fetcher.MAX_HISTORY_DIFFS` |
| `run diff assembly is bounded` | A14, B2 | `fetcher.MAX_RUN_DIFF_BYTES` charged across results |
| `a truncated history walk is a declared gap` | B2 | `coverage.HISTORY_TRUNCATED` set on every early stop |
| `every history diff is scored independently` | B1 | no aggregate score reachable from the `--last` path |
| `manifest parses are bounded and refusing` | A4b/A5 | hostile TOML/JSON/line fixtures return a refusal, never a hang |
| `manifest table is configuration` | A6 | the manifest filename table is written to `patterns.toml` |
| `U003 joins the host view` | B11 | a manifest-introduced git host appears in `hosts_gained` |
| `manifest ledger stays weight 0` | B10 | U001/U002/U005/U006 are INFO; only U003/U004 score |
| `archive listing adds no extraction` | A8 | the manifest layer reads committed files only |
| `yaml is only ever safe_load` | A5 | package-controlled YAML is parsed with `yaml.safe_load` only |
| `libgit2 is not the vulnerable version` | A14 | the pygit2 pin bundles libgit2 >= 1.9.5 (delta result-size allocation fix, CVE-2026-53585), read from the runtime version |

How each gate is scoped, and the recurring mistake that lets one pass while its invariant is broken, is set out in [reviewing a security control](../contributing/security-review.md). Read it before adding an invariant or a gate.

The last row is the one that keeps the rest honest: a gate with no entry here is an unstated guarantee, and an entry with no gate is an unsupported promise. Both fail the build.

Detection calibration is enforced separately by `scripts/calibration_gates.py`; see [fire rates](../explanation/fire-rates.md). The taxonomy and the adversarial thread of this model are developed at three depths: [evidence tiers](../reference/evidence-tiers.md) describes the signals; [what TrustSight cannot see](../explanation/what-trustsight-cannot-see.md) describes the limits; this page describes the whole.

The security and regex audits read repository text as UTF-8. Security-gate
path allowlists use forward slashes on every platform. These checks do not
establish that Linux sandbox controls are available on Windows.
