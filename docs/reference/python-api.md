<!-- description: The supported programmatic interface: `trustsight.api` runs the same flows as the CLI in the same order and returns dataclasses instead of printing. -->

# Python API Reference

`trustsight.api` is the supported programmatic interface. It runs the same flows the CLI runs, in the same order, with the same defaults, and returns dataclasses instead of printing.

```python
from trustsight import TrustSight

ts = TrustSight()
report = ts.inspect("some-package")

if report.flagged:
    print(report.verdict)
    for finding in report.findings:
        print(finding.rule_id, finding.severity, finding.description)
```

## What is public and what is not

Public: everything exported from `trustsight.api`, re-exported at the package root (`from trustsight import TrustSight`).

Internal: everything else under `trustsight.`, including `schema.PackageFact`, `db`, `analysis`, `full_aur`, `rules` and `scoring`. Those change shape between releases without notice. If you find yourself importing one of them, the API is missing something; open an issue rather than pinning to an internal.

Every result object has `to_dict()`, which returns the same JSON body the corresponding `--json` flag emits, so a consumer written against the [report schema](report-schema.md) works unchanged. That is an enforced invariant, not a convention: `the API and CLI emit the same JSON body` compares the two bodies key by key on every push.

The defaults match the CLI's too. `score`, `risk` and `risk_label` are **withheld** unless you ask, exactly as the CLI withholds them without `--score` or `--risk`; `to_dict(include_score=True)` is this API's spelling of that flag, and `to_dict(verbose=True)` of `--verbose`, which adds `score_breakdown`. Everything else - `findings`, `changes`, `coverage_gaps`, `suppressed_rules`, `verdict` - is in the default body, because withholding the number must not withhold the evidence.

Reading an attribute is a different act from serialising. `report.score` is always populated: naming the field *is* the request. What `to_dict()` will not do is volunteer the number to a caller who only asked to serialise the result.

`Report.raw` is the serialised `PackageFact` as stored in the database. It uses the storage naming (`package_name`, `final_score`) and always carries the score, so reach for it when you want the internal record rather than the report.

---

## Two properties you must not lose

The CLI has two behaviours that exist to stop a report from reading better than the analysis behind it. The API keeps both, and a caller can defeat either by accident.

### The band is the analysis band

`Report.risk` is the band the analysis actually supports. It is **not** `risk_level(report.score)`. A run that could not read the whole change, or one against a database with no history to compare against, reports `Inconclusive` no matter what the score is.

```python
## Correct
if report.risk in ("High", "Critical"):
    ...

## Wrong: re-deriving the band discards the coverage qualification
if report.score > 50:
    ...
```

`report.risk_label` is the same band with the qualification spelled out in prose, which is what you want in anything a person reads.

### A failed analysis is a result, not a gap

`ReviewResult.reports` holds the packages that were analysed. `ReviewResult.failures` holds the ones that could not be. Iterating `reports` alone silently treats an unvetted package as an absent one, which is exactly the shape an attacker wants: anything able to provoke a crash keeps itself out of your report.

```python
result = ts.review()
if not result.complete:
    for failure in result.failures:
        print(f"NOT VETTED: {failure.package} ({failure.error_type})")
```

---

## Dependencies on a `Report`

`Report.dependencies` is a tuple of analysed AUR dependencies, each carrying
`name`, `depth`, `score`, `risk`, `risk_label`, `finding_count`,
`coverage_gaps`, `via`, `parent`, `failed` and `error`, plus a `flagged`
property and `to_dict()`.

Each dependency is a **full analysis in its own right** - its own score, its
own band, its own row in the database. None of it is folded into the parent's
`score`, and that is deliberate rather than cautious: `depth` is not part of
the config fingerprint, so a parent score that moved with `depth` would break
[B1](../security.md#b1-a-score-is-a-sum-of-matched-evidence-nothing-more) for
anyone comparing two runs.

```python
report = ts.inspect("some-package", depth=2)

for dep in report.flagged_dependencies:
    print(f"L{dep.depth} {dep.name}: {dep.score}/100 ({dep.risk})")

if report.depth_truncated:
    print("the walk stopped early; part of the closure was not analysed")
```

`Report.required_by` is the reverse of `Report.dependencies`: the packages in
the reviewed set that declare this one. It is populated by
`TrustSight.review(deps=True)` - and by `trustsight review --deps` on the CLI -
and is empty otherwise.

```python
result = ts.review(deps=True, depth=2)
for report in result.reports:
    print(report.package, "is required by", ", ".join(report.required_by))
```

`Report.depth_truncated` says the walk stopped before the closure was
exhausted, which also puts `deps_not_scanned` in `coverage_gaps` and so
forbids an unflagged result.

## `TrustSight`

```python
TrustSight(*, auto_import_seed: bool | None = None)
```

Construction does no I/O. The config directory and database are prepared on the first call that needs them. The API may import a bundled seed when a build supplies one, but it does not fetch the release-channel seed automatically; that network fetch is limited to eligible CLI `review` and `inspect` commands.

`auto_import_seed` defaults to `None`, which follows `seed.auto_import` in `config.toml`. Pass `False` to run against a cold database deliberately. A cold database makes every novelty signal meaningless, and TrustSight reports the band as `Inconclusive` rather than pretending otherwise; maturity is database-wide, not per package. See [cold start and maturity](../explanation/cold-start-and-maturity.md).

### API input limits

The API validates caller-controlled collection and loop bounds before it initializes analysis state. `review(limit=...)` and `packages(limit=...)` accept at most 10,000 items; `history(limit=...)` accepts at most 10,000 entries; explicit `review(packages=...)` lists contain at most 10,000 non-empty names; and `review(repos=...)` accepts at most 256 non-empty names. Limits must be integers, not booleans, and cannot be negative. `watch(cycles=...)` and `watch(interval=...)` reject negative or non-integer values. Invalid values raise `ValueError` before database or network work begins.

`inspect()` package names and `pivot()` indicators are limited to 256 UTF-8 bytes. `analyze_text()` limits `new_pkgbuild`, `old_pkgbuild`, and `srcinfo` to 5 MiB each; maintainer names are limited to 256 UTF-8 bytes. Oversized or non-string values are rejected before initialization.

These are process-safety bounds, not pagination guarantees. Use smaller limits for interactive callers, and consume `watch()` incrementally rather than materialising an unbounded cycle stream.

Usable as a context manager, which releases the thread's database connections on exit:

```python
with TrustSight() as ts:
    ...
```

### Properties

| Property | Type | Description |
|---|---|---|
| `config_dir` | `Path` | Where `config.toml`, `rules.toml` and the overrides live. |
| `database_path` | `Path` | The SQLite database. |
| `config_fingerprint` | `str` | Identifies the rules, weights and overrides in force. Two reports are only comparable when their fingerprints match. |

### `config()`

The effective configuration: defaults merged with the user's file.

### `status() -> Status`

Database and corpus health. What `trustsight status` reports, plus the config directory, database path and fingerprint.

---

## Analysis

### `inspect(package, *, check_aur=True, depth=None) -> Report`

Analyse one package. Equivalent to `trustsight inspect`.

Fetches the package's AUR git repository, diffs it against the last state this database saw, runs every rule, and records the run as an observation. That last part is what makes the *next* call's novelty signals mean anything.

Raises `PackageNotFound` when the name is in neither the AUR nor the local database. Pass `check_aur=False` to skip the RPC round trip when you already know the package exists.

`depth` controls how far into the package's AUR dependency closure the analysis goes: `0` off, `1` (the default) direct dependencies, `n` levels, `-1` every level. `None` uses `[depth] levels` from the config. See [`[depth]`](configuration.md#depth) for the bounds.

### `analyze_text(package, new_pkgbuild, old_pkgbuild=None, *, maintainer="", srcinfo=None, last_modified=None, first_submitted=None, previous_modified=None) -> Report`

Analyse PKGBUILD text directly, with no git and no network. For vetting a PKGBUILD you already hold: a pull request, a generated file, a CI checkout.

Nothing is fetched and nothing is recorded as an observation, so the novelty signals see only what the database already knew. The timestamps are Unix seconds and optional; without them the age-based rules have no clock and stay silent. `Report.adapter` reads `corpus` on this path, which is your signal that it is a narrower look than `inspect` gets.

```python
report = ts.analyze_text(
    "my-package",
    new_pkgbuild=pathlib.Path("PKGBUILD").read_text(),
    old_pkgbuild=previous_text,
)
```

### `review(*, packages=None, limit=0, repos=None, foreign=False, all_repos=False, all_packages=False, on_progress=None, on_warning=None, depth=None, deps=False) -> ReviewResult`

Review installed AUR packages. Equivalent to `trustsight review`.

```python
review(
    *,
    packages: Sequence[str] | None = None,
    limit: int = 0,
    repos: Sequence[str] | None = None,
    foreign: bool = False,
    all_repos: bool = False,
    all_packages: bool = False,
    on_progress: Callable[[Progress], None] | None = None,
    on_warning: Callable[[str], None] | None = None,
    depth: int | None = None,
    deps: bool = False,
) -> ReviewResult
```

With no arguments this discovers installed foreign packages, works out which have a newer version in the AUR, and analyses those. Pass `packages` to review an explicit list and skip discovery entirely.

| Parameter | Effect |
|---|---|
| `packages` | Review exactly these names. Skips discovery. |
| `limit` | Analyse at most this many packages. `0` means no limit. |
| `repos` | Local repositories to scan, by name. |
| `foreign` | Include packages `pacman -Qm` reports. |
| `all_repos` | Auto-detect local repos from `pacman.conf`. |
| `all_packages` | Review every discovered package, not only the ones with a newer AUR version. |
| `on_progress` | Called with a `Progress` for each tick. |
| `on_warning` | Called with a string for each non-fatal discovery problem. |
| `depth` | AUR dependency levels to analyse. See below. |
| `deps` | Review the AUR *dependencies* of the discovered packages instead of the packages themselves, as `trustsight review --deps` does. Each report then carries `required_by`. `depth` becomes the number of dependency *levels to review*: `deps=True, depth=2` reviews direct dependencies and theirs. The discovered packages are not reviewed - that is what you get without it. |

The first call on a machine with no local AUR metadata snapshot downloads one and returns `metadata_bootstrapped=True` with no reports. There was no prior snapshot to diff against, so there is no delta to report yet. Call again.

```python
result = ts.review(limit=25, on_progress=lambda p: print(p.phase))
if result.metadata_bootstrapped:
    result = ts.review(limit=25)
for report in result:
    print(report.package, report.risk_label)
```

---

## Corpus

### `refresh_corpus(*, bootstrap=False, resume=False, export_path=None, sign_key=None) -> CycleReport`

Run one full-AUR corpus cycle. Equivalent to `trustsight full-aur`.

Refreshes the AUR metadata snapshot, analyses what changed since the stored copy, runs the corpus-wide sweep and records the adoption feed. With no prior snapshot, `bootstrap=False` refuses the whole-AUR scrape; pass `bootstrap=True` to permit the initial bootstrap, which takes hours. `resume=True` continues an interrupted build.

### `watch(*, interval=None, cycles=0, sleep=time.sleep) -> Iterator[CycleReport]`

`trustsight full-aur --watch` as a generator. Each cycle is exactly what `refresh_corpus` does once; the loop adds repetition plus memory. A cluster appears in `new_alerts` the first time it is seen and is then counted, not re-announced, so a quiet cycle yields a report with nothing new in it rather than the same forty-package adoption again.

The generator sleeps between cycles, so it blocks the calling thread. Stop it by breaking out of the loop or closing it; state is durable at every yield, since each cycle saves the snapshot and the resume file before it returns.

`interval` is in seconds and defaults to `limits.watch_interval` (3600). Values below `limits.watch_min_interval` (60) are clamped up: a shorter interval only re-downloads a snapshot the AUR has not regenerated yet. `cycles=0` means "until the caller stops iterating".

```python
for cycle in ts.watch(interval=1800):
    for package, rule_id in cycle.new_alerts:
        notify(f"{rule_id} {package}")
```

### `import_baseline(path, *, allow_unsigned=False)`

Import a signed baseline corpus artifact. Unsigned artifacts are rejected unless `allow_unsigned` is set, which is for local builds only: an unsigned baseline is data of unknown provenance being written into the database that every subsequent novelty judgement reads.

### `pivot(indicator, *, type=None) -> PivotResult`

Find every corpus package referencing `indicator`, the inverse of a per-package finding. Equivalent to `trustsight corpus pivot`.

The match is exact and reads only stored corpus material, never the network. `type` forces the indicator type (`package`, `domain` or `hash`) when the shape is ambiguous.

An empty `matches` means the corpus holds no reference, not that the indicator is harmless. Check `PivotResult.searched` first: when it is `False` there was no corpus to search at all.

---

## Stored state

### `history(package, *, limit=20, with_rules=False) -> list[HistoryEntry]`

Past analyses of `package`, newest first. Returns an empty list when the package has never been analysed, which is a fact about this database rather than an error. `with_rules=True` also loads the rules that fired on each run.

### `packages(*, limit=0) -> list[TrackedPackage]`

Every package in the database with its latest score. What `trustsight list` shows.

### `forget(*packages) -> dict[str, dict]`

Delete tracked packages and all their history. Returns `{package: {table: rows_deleted}}`; a package that was not tracked maps to an empty dict.

Not reversible. The observations it removes are what the novelty signals count.

### `prune(*, dry_run=False) -> dict[str, dict]`

Forget every tracked package that no longer exists in the AUR. Raises `TrustSightError` when the AUR RPC returns nothing, rather than reading a network blip as "the whole AUR is gone".

---

## Result types

### `Report`

The analysis of one package.

| Field | Type | Description |
|---|---|---|
| `package` | `str` | Package name. |
| `old_version`, `new_version` | `str` | From `inspect`, the pair the diff was taken over. From `review`, the installed version and the version the AUR advertises. |
| `old_commit`, `new_commit` | `str` | AUR git commits bounding the diff. |
| `score` | `int` | 0-100. Never derive the band from it. |
| `risk` | `str` | The band the analysis supports: `Low`, `Medium`, `High`, `Critical` or `Inconclusive`. A closed set - a FATAL finding reports as `Critical` and names itself in `risk_label` rather than adding a member. Not a pure function of `score`: a CRITICAL finding floors the band at `High`, and a cold database or a coverage gap can lower it to `Inconclusive`. |
| `risk_label` | `str` | `risk`, qualified in prose when coverage was incomplete. |
| `verdict` | `str` | Plain-English summary. Always ends with a direction to review. |
| `findings` | `tuple[Finding, ...]` | Rules that fired with positive weight, plus every FATAL and CRITICAL. |
| `suppressed` | `tuple[SuppressedRule, ...]` | Rules that matched but were silenced by an override. They scored nothing and are reported anyway, because a suppression you cannot see is one you cannot audit. |
| `changes` | `tuple[str, ...]` | What the diff did, whether or not a rule matched. Context, not findings: no severity, no points. |
| `coverage_gaps` | `tuple[str, ...]` | What this run could not read. Non-empty forbids a clean verdict. |
| `file_changes` | `tuple[FileChange, ...]` | Path plus `added` / `removed` / `modified`. |
| `added_urls`, `removed_urls` | `tuple[str, ...]` | Source URLs. |
| `source_buckets` | `dict` | URL to its classification, for example `trusted_forge` or `homograph_attack`. |
| `checksum_behavior` | `str` | How the checksum arrays changed. |
| `resolved_commands` | `tuple[str, ...]` | Commands after variable resolution and decoding. |
| `maintainer`, `previous_maintainer`, `maintainer_changed` | `str`, `str`, `bool` | Maintainer transition. |
| `dependency_changes` | `dict` | Newly declared dependency names by field. |
| `first_seen` | `bool` | No prior history, so novelty signals carry no weight yet. |
| `is_trivial` | `bool` | Only `pkgver` and checksums moved. |
| `diff_truncated` | `bool` | The diff exceeded the configured cap and only a deterministic UTF-8-safe prefix was read; the report is incomplete and cannot be read as clean. |
| `tree_analyzed` | `bool` | The repository file manifest was inspected. |
| `version_comparison` | `str` | How the installed version relates to the AUR `pkgver`, or `""` if nothing compared them. |
| `adapter` | `str` | `git` or `corpus`. |
| `config_fingerprint` | `str` | Which instrument produced this. |

Derived properties: `flagged` (score above the 20-point threshold), `fully_vetted` (no coverage gaps), `comparable_versions` (`False` for a VCS package, whose AUR `pkgver` is a build-time placeholder), `coverage_note` (the caveat prefixed to the verdict).

### `Finding`

`rule_id`, `severity`, `weight`, `description`, `file`, `line`, `template`, `evidence`.

### `SuppressedRule`

`rule_id`, `severity`, `override_reason`, `override_package`. A rule that matched and was silenced by an override. It contributed nothing to the score.

### `FileChange`

`path` and `status`, one of `added`, `removed` or `modified`.

### `ReviewResult`

`reports`, `failures`, `total_installed`, `metadata_bootstrapped`. Iterating the result iterates `reports`. Derived: `complete` (no failures), `flagged` (the reports above the threshold). `to_dict()` returns a flat list, not an object: successful report rows first, followed by failed rows with `failed: true`. Failure details remain available on `failures`; the list row's verdict states that the package was not vetted.

### `FailedPackage`

`package`, `old_version`, `new_version`, `error`, `error_type`. This package was **not** vetted.

### `CycleReport`

`added`, `changed`, `removed`, `processed`, `bootstrap`, `elapsed`, `flagged` (`(package, score)` pairs scoring 40 or above, worst first), `cluster_findings`, `new_alerts` (`(package, rule_id)` pairs for clusters seen for the first time).

### `ClusterFinding`

`rule_id`, `name`, `severity`, `match`, `members`. A corpus-wide pattern spanning several packages; `members` names them.

### `PivotResult`

`indicator`, `type`, `listed`, `confidence`, `matches`, `sources`. Derived: `searched`, which is `False` when there was no corpus to search.

### `PivotMatch`

`package`, `surface`, `detail`. Where one corpus package references the indicator.

### `HistoryEntry`

`timestamp`, `old_version`, `new_version`, `score`, `risk`, `triggered_rules`. One past analysis of a package.

### `TrackedPackage`

`name`, `version`, `last_checked`, `score`, `risk`, `maintainer`. One row of `trustsight list`; `score` is `None` when the package has never been analysed.

### `Status`

`packages_tracked`, `total_analyses`, `effective_observations`, `seed_observations`, `dependency_corpus_loaded`, `config_dir`, `database_path`, `config_fingerprint`.

### `Progress`

`current`, `total`, `phase`. `current` is `-1` when the phase changed but there is nothing countable yet; `indeterminate` says so directly.

### Exceptions

| Exception | Raised when |
|---|---|
| `TrustSightError` | Base class for everything this module raises deliberately. |
| `PackageNotFound` | The package is in neither the AUR nor the local database. Carries `.package`. |

### Constants

| Name | Description |
|---|---|
| `FLAG_THRESHOLD` | `20`. Above this, `Report.flagged` is `True`. |
| `RISK_LEVELS` | `("Low", "Medium", "High", "Critical")`, worst last. `Inconclusive` is not on the scale: it is what a band becomes when the analysis cannot support one. |
| `COVERAGE_GAP_REASONS` | Gap identifier to the plain-English reason a run could not read something. |

---

## Using it in CI

The API returns data; deciding what fails a build is yours. A gate that reads only the score will pass a package whose analysis never completed, so gate on the band and on completeness together:

```python
from trustsight import TrustSight

ts = TrustSight()
result = ts.review()

blocked = [r for r in result if r.risk in ("High", "Critical")]
unvetted = list(result.failures) + [r for r in result if not r.fully_vetted]

for r in blocked:
    print(f"BLOCK {r.package}: {r.verdict}")
for item in unvetted:
    print(f"UNVETTED {getattr(item, 'package', item)}")

raise SystemExit(1 if blocked or unvetted else 0)
```

See [using TrustSight in CI](../guides/using-in-ci.md) for the same argument made about the CLI, and [what TrustSight cannot see](../explanation/what-trustsight-cannot-see.md) for the limits that apply to both.
