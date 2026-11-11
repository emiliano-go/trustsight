<!-- description: Every implicit state machine in TrustSight: where the state lives, which values it takes, what moves it, and what can go wrong when the transition is not modelled. -->

# Implicit State Machines

TrustSight has no `StateMachine` class. Correctness still depends on state that
is spread across module globals, SQLite rows, metadata keys, cache files, thread
locals, process lifecycle and observation counters. This page catalogues those
*implicit* machines: the files that own them, the values they can take, the
events that move them, and the failure modes the design is defending against.

The catalogue was produced by reading every file under `src/trustsight` in
sorted order and by running the deterministic scanner committed at
[`scripts/implicit_state_scan.py`](https://github.com/emiliano-go/trustsight/blob/master/scripts/implicit_state_scan.py).
The scanner prints one ledger row per file, so "no machine here" is a recorded
result rather than a guess. Re-run it with:

```bash
python scripts/implicit_state_scan.py
```

An **implicit state machine** here is behaviour that depends on a value which
survives longer than one expression and is not represented by a single
explicit type with a closed transition table. Typical examples: a SQLite row
whose `status` column changes over time, a module-level worker with a
`start`/`alive`/`stop` lifecycle, a cache whose meaning depends on age, or a
counter that changes what the next run does.

---

## 1. Persistence and the observation clock

### P01. Schema and migration ladder

- **Files:** `db/_schema.py` (`init_db`, `_ADDED_COLUMNS`, `_migrate`,
  `_SCHEMA_VERSION`, `_migrate_*`), `db/_connection.py`.
- **State:** the SQLite file itself. `_SCHEMA_VERSION` is `1`; additive columns
  are applied from `_ADDED_COLUMNS`, then data migrations run in a fixed order
  (observed domains, keys, dependency seed counts, first-observation repair,
  rule-id renames, plaintext-maintainer hashing).
- **Transitions:** every `init_db()` moves an older database toward the current
  shape; each migration is idempotent and may no-op. `ALTER TABLE ADD COLUMN`
  failures are tolerated when the column already exists.
- **Persistence:** the database file, shared by every command.
- **Hazards:** a migration that is not idempotent, or a read path that assumes a
  column a not-yet-migrated database lacks. Tables read `row["col"]` defensively
  in several places (for example `_row_to_dict` in `db/_campaigns.py`).
- **Pinned by:** `tests/test_sqlite_hardening.py`, the migration regressions in
  `tests/regressions/`, and the `defensive sqlite` gates.

### P02. Observation clock and metadata keys

- **Files:** `db/_metadata.py` (`OBSERVATION_SEQ_KEY`, `observation_seq`,
  `bump_observation_seq`), `db/_schema.py` (`metadata` table).
- **State:** `observation_seq` is a monotonic count of recorded observations,
  not wall time. Campaigns, overrides and contacts measure age in these units.
- **Transitions:** every recorded analysis bumps the sequence once; read-only
  analyses do not. The seed count and seed version are separate metadata keys.
- **Hazards:** mixing observation units with seconds (a TTL written in seconds
  would never expire, or expire instantly); a read-only run that bumps the
  clock and changes every subsequent TTL decision.
- **Pinned by:** campaign and override tests using `now_obs`, plus the
  cold-replay determinism gate.

### P03. Seed import: absent → verified → downgraded?

- **Files:** `db/_seed.py` (`import_seed`, `_import_v2_seed`),
  `seed_build.py`, `config/_release.py`.
- **State:** absent, imported (v1 SQLite or v2 directory), and metadata
  `seed_version`/`seed_sha256`/`seed_origin`/`seed_observation_count`.
- **Transitions:** first run may auto-import a signed release seed; a bundled
  seed may import silently; an older incoming version is refused unless
  `allow_downgrade`. The digest of what was imported is recorded (A12).
- **Persistence:** database tables plus seed metadata; the seed asset is not
  retained.
- **Hazards:** accepting an unverified seed, or overwriting newer identity data
  with an older seed. Both are explicit refusals rather than silent merges.

### P04. Alert outbox: pending → retry → delivered/parked

- **Files:** `db/_outbox.py` (`enqueue_alert_payload`,
  `pending_alert_payloads`, `mark_alert_sink`, `mark_alert_attempt`,
  `alert_outbox_stats`), `notify.py`.
- **States per row:** pending (not parked, at least one sink undelivered),
  retrying (`next_attempt_at` in the future), delivered (both sink flags set),
  parked (`parked_at` set after 10 attempts or 24 hours).
- **Transitions:** enqueue sets `feed_only` rows with `ntfy_delivered = 1`;
  a successful sink sets its flag and clears `next_attempt_at` once both are
  done; a failure increments `attempts` and schedules
  `min(30 * 2^(attempts-1), 21600)` seconds, or parks the row.
- **Persistence:** `alert_outbox` table; the payload bytes are stored verbatim
  so a retry is the same signed document with the same idempotency identity.
- **Hazards:** replaying a delivered document, delivering the same signed body
  under a new timestamp, or losing the only notification. Parked rows are
  surfaced in `full-aur health` rather than discarded.
- **Pinned by:** `tests/test_notify.py`, outbox tests, the feed-only test in
  `tests/test_scan_export.py`.

### P05. Watcher liveness: not-a-watcher → healthy/unhealthy

- **Files:** `full_aur/watch_state.py` (`record_start`, `record_success`,
  `record_failure`, `health`).
- **States:** not a watcher (no start/success keys), watching-healthy,
  watching-unhealthy with one or more reasons: no successful cycle, success
  older than `max(2*interval + 300, 900)` seconds, three or more consecutive
  failures, or parked outbox rows.
- **Transitions:** each loop iteration records start; a completed cycle resets
  the failure counter to 0; an exception increments it and, at the threshold,
  sends one failure heartbeat.
- **Persistence:** metadata keys (`watch_last_*`, `watch_consecutive_failures`).
- **Hazards:** a quiet log being read as health; an unhealthy watcher that never
  speaks. The health command reconstructs the verdict from recorded keys, not
  from the log.

### P06. One watcher per data directory

- **Files:** `full_aur/watch_lock.py` (`watch_lock`, `WatchAlreadyRunning`).
- **States:** lock free, lock held by a live process, stale lock file with no
  owner.
- **Transitions:** `flock(LOCK_EX | LOCK_NB)` on `<data>/watch.lock`; the lock
  is released by `finally`, and a killed process releases it with the file
  descriptor. The PID written into the file is diagnostic, not the lock.
- **Hazards:** two watchers racing on snapshot, resume file and campaign state.
  The second start fails loudly instead.

### P07. Watch cycle and backfill cursor

- **Files:** `full_aur/_pipeline_watch.py` (`run_watch`),
  `full_aur/pipeline.py`, `full_aur/_baseline_build.py`,
  `full_aur/_pipeline_helpers.py` (`_since_cursor`, `_set_since_cursor`).
- **States per cycle:** refresh metadata → analyse changed packages → campaign
  sweep → record feeds → notify (alert/heartbeat/scan) → optional channel
  auto-pull. Backfill adds a cursor and resume state: not replaying, replaying
  a UTC day window, interrupted with a resume record, or refused because no
  snapshot exists and no cursor is set.
- **Transitions:** `since` sets a cursor; `resume_state` is loaded
  unconditionally and cleared when a fresh replay starts; a refused cycle
  either reports "no corpus snapshot" (and stops) or retries "did no work";
  `backfilling` shortens the inter-cycle sleep to 2 seconds.
- **Persistence:** metadata `since_cursor`, a resume file, and the corpus
  snapshot.
- **Hazards:** a cursor that advances past unprocessed days, or a resume state
  from a different flow being mistaken for this replay. The code distinguishes
  the two before advancing.

### P08. Campaign refractory and TTL

- **Files:** `db/_campaigns.py` (`activate_campaign`, `active_campaigns`,
  `expired_unannounced`, `mark_expiry_announced`, `reactivation_pressure`),
  `full_aur/_pipeline_helpers.py` (`_activate_campaigns`).
- **States per campaign:** inactive, active (`activated_at_obs + ttl_obs >
  now_obs`), lapsed and unannounced, lapsed and announced.
- **Transitions:** a corroborated cluster activates or re-arms a campaign
  (`activation_count += 1`, window refreshed, `expiry_announced = 0`); a lapsed
  campaign is reported once and marked; the active-cap evicts only a lapsed
  campaign, never a live one; re-arming faster than
  `campaign_min_reactivation_observations` emits an M006 note without blocking.
- **Persistence:** `campaign_alerts` rows.
- **Hazards:** treating a cold read as "no campaign" (`campaign_state_available`
  distinguishes them), or silencing a live campaign to make room for a new one.
- **Pinned by:** `tests/test_campaign*`, the calibration gates, and the
  determinism gate.

### P09. All-scan stream: per-cycle records → chunks → feed-only outbox

- **Files:** `notify.py` (`scan_payloads`, `_scan_records`/`_scan_summary` in
  `full_aur/_baseline_build.py`), `db/_outbox.py` (`feed_only`).
- **States per cycle:** attempted, succeeded, `fetch_failed`, `not_vetted`,
  `vanished`, `reserved`, `with_diff`, `alerts`; per chunk: index and count.
- **Transitions:** each attempted root package becomes one compact record; a
  document is split at 500 records or the payload budget; chunks share a cycle
  id and day; the outbox row is enqueued with `feed_only = 1`, so ntfy is never
  a target.
- **Hazards:** publishing a scan document with a diff or finding prose, or
  letting a bootstrap produce one unbounded document. Both are bounded at
  record and byte level.

### P10. Channel pull state

- **Files:** `channel_state.py` (`record_pull`, `pulled`, `pulled_tag`),
  `channels.py` (`auto_pull`, manifest version/expiry checks).
- **States per kind (`baseline`, `ioc`, `watchlist`):** never pulled, pulled at
  tag T, pulled at an older/newer tag; a signed manifest can be absent, current,
  older than imported, expired, or malformed.
- **Transitions:** a verified import records the tag and wall time; auto-pull
  compares the manifest version against the recorded tag before fetching.
- **Persistence:** a bounded JSON state file under the config cache.
- **Hazards:** pulling the same channel every cycle, or importing an expired or
  older signed baseline over a newer one.

### P11. AUR metadata cache TTL

- **Files:** `db/_history.py` (`read_aur_cache`, `write_aur_cache`).
- **States:** cache miss, fresh hit (within TTL, default 60 minutes), stale hit.
- **Persistence:** a cache table; the TTL is wall-clock, unlike the observation
  clock.
- **Hazards:** a cache hit whose age is measured on the wrong clock. The code
  stores the timestamp with the row and compares it explicitly.

### P12. Contract artifact

- **Files:** `contract.py` (`version`, `--emit`, `--check`),
  `contract/contract.json`.
- **States:** current (regenerates byte-for-byte) or stale.
- **Transitions:** a code change that alters the emitted contract requires the
  committed artifact to be regenerated in the same change; `--check` fails
  otherwise.
- **Hazards:** a consumer reading an old shape while the tests pass against the
  new one.

### P13. Baseline build and export

- **Files:** `full_aur/_baseline_build.py`, `full_aur/export.py`,
  `full_aur/metadata.py`.
- **States:** bootstrap (no snapshot), incremental cycle, backfill replay,
  resumed cycle, capped cycle. Export rows carry `first_seen`,
  `first_seen_package_id`, `first_seen_globally_timestamp`, `last_seen`.
- **Transitions:** metadata refresh persists a snapshot; the cursor/resume
  machine (P07) decides which packages are in play; export groups history by
  UTC day into synthetic cycles.
- **Hazards:** a capped cycle that forgets its cursor, or an export that
  fabricates first-seen values. Missing values stay empty.

### P14. Update-notice cache

- **Files:** `cli/updates.py` (`_read_cache`/`_write_cache`, TTL 6 hours,
  `TRUSTSIGHT_NO_UPDATE_CHECK`, pending-baseline cache).
- **States:** no cache, fresh cache, stale cache; notice suppressed or shown.
- **Persistence:** one small JSON cache file.
- **Hazards:** a version check on every command, or a cached "newer" tag that
  outlives the release. The TTL and the explicit disable environment variables
  are the controls.

### P15. Parsed-document cache

- **Files:** `doc_cache.py` (`MAX_DOC_CACHE_BYTES`, content-hash keys, versioned
  JSON entries).
- **States:** cache miss, valid entry, oversize/legacy entry (ignored).
- **Persistence:** files under `$XDG_CACHE_HOME/trustsight/documents`.
- **Hazards:** a cache key that ignores a parser version change, or unbounded
  entry size. Entries are content-addressed and byte-capped.

---

## 2. Analysis pipeline

### A01. Stage-failure tracking and coverage gaps

- **Files:** `coverage.py` (`_stages`, `begin_stage_tracking`,
  `note_stage_failure`, `stage_failures`), `analysis/pipeline/*`,
  `boundaries.py` (`GAP_*` vocabulary).
- **State:** a thread-local list of stages that failed since the current
  analysis began. Separate from the deterministic coverage-gap set that the
  report carries.
- **Transitions:** an analysis calls `begin_stage_tracking` (resetting the
  list), a stage handler records its failure before returning a neutral value,
  and the report adds `stage_degraded` to the coverage gaps. Outside an
  analysis, notes are dropped rather than leaking to the next package.
- **Hazards:** a swallowed exception reading as "nothing found" (the exact
  failure B2 forbids), or cross-package attribution in a worker pool. Thread
  locality and the reset are the guards.

### A02. Layer status derivation

- **Files:** `layers.py` (`_layer_status`, `layer_profile`), `reporting.py`.
- **States per layer:** fired, clear, not-applicable, blinded by a coverage gap,
  or incomplete because the layer's analysis did not run.
- **Transitions:** derived after the evidence record is assembled; a layer's
  status is a statement about *this run*, not a global property of the rule.
- **Hazards:** rendering an unread layer as clear. A coverage gap blinds the
  layer instead.

### A03. Meta-rule gating

- **Files:** `analysis/meta.py`, `scoring.py`.
- **State:** meta findings are computed from other findings after the first
  pass; campaign context (`campaign_id`, `campaign_state`, `campaign_hold`)
  gates some escalations.
- **Transitions:** a meta rule may elevate or annotate only when its precursor
  fired; campaign hold suppresses re-announcement, not scoring.
- **Hazards:** a meta rule that fires on its own input (feedback), or a hold
  that mutes evidence instead of the alert.

### A04. Change classification

- **Files:** `changes.py`, `differ/*` (`_diff.py`, `_checksums.py`,
  `_sources.py`, `_verification.py`, `_companions.py`), `diffdoc.py`.
- **States per file/array:** added, removed, modified, unchanged; checksum
  behaviour (`added_or_changed`, `entry_removed`, `array_removed`,
  `changed_from_sha256_to_skip`); verification evidence (GPG verify removed,
  checksum array removed).
- **Transitions:** computed once from the parsed diff; downstream rules read the
  classification rather than re-parsing.
- **Hazards:** one pass concluding "removed" while another concludes "added"
  for the same semantic change. The single classification is the invariant.

### A05. Manifest baseline and delta

- **Files:** `analysis/manifest_state.py` (`_STATE_VERSION`, `build_manifest_state`,
  `manifest_state_delta`), `analysis/manifest_syntax.py`,
  `analysis/manifests/*`.
- **States:** no baseline, complete baseline, incomplete baseline (never used as
  an empty old tree), delta with per-file added/removed/modified.
- **Transitions:** a cycle serialises complete manifest texts plus the tree
  manifest under a state version; the next cycle compares complete states and
  falls back to a baseline when either side is incomplete.
- **Hazards:** comparing a complete new tree against a partial old one, which
  would report every file as added; the `None` baseline path prevents it.

### A06. Tokenizer, heredoc and expansion state

- **Files:** `tokenizer.py`, `_tokenizer_engine/*` (`_quotes.py`,
  `_variables.py`, `_expansion.py`, `_apply.py`), `line_lex.py`,
  `_heredoc.py`, `analysis/_build_constants.py`, `expansion.py`.
- **States:** per line: quote state, heredoc opener/body state, comment state,
  expansion depth; across lines: open quotes, pending heredoc delimiters,
  whether a heredoc body is data or an executed program; across a diff: old side
  vs new side.
- **Transitions:** `resolve_added_lines`/`resolve_removed_lines` replay the
  state machine over one side; a diff boundary resets the heredoc queue; an
  unresolved variable stays unresolved rather than guessing.
- **Hazards:** a removed heredoc consuming an added opener (tape16-bin), or a
  quoted `<<EOF` in prose opening a fake heredoc. Both are pinned by the
  `line_lex` and FP-triage regressions.

### A07. Review policy profiles

- **Files:** `review_policy.py` (`ReviewPolicy`, profile thresholds),
  `review.py` (`verdict_for`, `is_trivial_update`, `analyze_outdated_batch`),
  `reporting.py`.
- **States:** profile default/strict (and any configured profile); per result:
  flagged or below threshold, trivial or reviewable, verdict text.
- **Transitions:** the profile maps a score and findings to a threshold and a
  flag; the report records both the profile and the threshold used.
- **Hazards:** a profile change silently changing the alert volume without the
  report saying which profile ran.

### A08. Deep analysis and the L9 lane

- **Files:** `analysis/deep.py` (`deep_decision`), `api/client.py`
  (`verify_build`), `cli/inspect/commands.py`, `cli/preinstall.py`,
  `cli/admin.py` (`full-aur verify`), `analysis/artifact.py`.
- **States:** deep not triggered; triggered but verify disabled; triggered with
  no manifest (`l9_unavailable`); triggered with a manifest (`l9_analyzed`);
  analyzed with static/artifact agreement or `l9_divergence`.
- **Transitions:** `deep_decision` computes `triggered` and `l9_requested`;
  `verify_build` checks `[verify] enabled` and the manifest; artifact rules
  never change the static score.
- **Hazards:** advertising an automatic build that does not exist, or letting a
  divergence rewrite the static verdict. Both are pinned by `test_deep` and
  `test_artifact`.

### A09. Novelty and maturity

- **Files:** `novelty.py`, `db/_history.py` (first-seen ledgers),
  `db/_seed.py`, `schema.py` (`NoveltyContext`).
- **States:** cold (no seed/history), warming (some observations), warm;
  globally novel vs package-novel; maturity-scaled weight.
- **Transitions:** maturity is derived from the observation count; a URL or
  maintainer seen before is not novel; the weight is scaled so a cold database
  trusts novelty less.
- **Hazards:** treating first-run absence of history as evidence, or letting a
  seed import silently make everything "known".

### A10. Overrides and URL acknowledgements

- **Files:** `override.py` (`RuleOverride`, `ttl_observations`,
  `created_at_obs`, `override_expired`).
- **States:** override active, expired by observation count, or rejected for a
  fatal rule; acknowledgement active/expired.
- **Persistence:** `overrides.json`, written atomically.
- **Hazards:** a suppressions file that becomes permanent desensitization; the
  observation-based TTL and the fatal-rule refusal are the guards.

### A11. Contacts, profiles and verdicts

- **Files:** `contacts.py`, `db/_contacts.py`, `db/_profiles.py`
  (`package_profiles`, `alert_state`, `record_cycle_events`), `verdict.py`,
  `db/_verdicts.py` (`VERDICTS`, `tender_point`).
- **States:** first contact recorded or absent; profile observation count and
  last-seen; alert row seen/count/last-alert (refractory); verdict
  `confirmed`/`cleared`/`uncertain`; tender point available/unavailable.
- **Transitions:** a recorded analysis updates contact and profile rows; an
  alert updates the alert state; a human verdict is append-only and carries the
  observation sequence it was made at.
- **Hazards:** a verdict being read as fresh after the package changed, or a
  first-contact ledger that writes on a read-only analysis.

### A12. Depth traversal

- **Files:** `depth.py` (`MAX_DEPTH_LEVELS`, `MAX_DEPTH_NODES`,
  `walk_dependencies`, `dependency_closure`, metadata providers), `deps.py`.
- **States:** depth requested/resolved (including `-1` bounded to 8 levels),
  queue/visited sets, node budget exhausted, depth truncated.
- **Transitions:** BFS over dependency arrays; each level is only analysed if
  `_wanted(level, depth)`; the node cap ends the walk with `depth_truncated`.
- **Hazards:** a cycle re-analysed forever, or an unbounded closure. Visited
  sets and the node cap bound both.

### A13. Rule registry identity

- **Files:** `registry.py`, `rule_id_history.py`, `config/*` (shipped rules,
  ruleset version), `anergy.py`.
- **States per rule:** shipped, missing, outdated, drifted, renamed, retired,
  promoted/anergic/conditional.
- **Transitions:** ids are permanent; renames keep an alias; retired ids resolve
  to their survivor; the shipped ruleset version moves with a release and a
  sync fills missing rules without overwriting user patterns.
- **Hazards:** a reused id, or a registry entry that names a rule the code no
  longer emits. Both fail the metadata and gate tests.

---

## 3. Federation, indicators and release channels

### F01. Anergy ledger

- **Files:** `anergy.py` (`ANERGIC`, `CONDITIONAL`, `PROMOTED`,
  `is_anergic`, `review_ids`), `anergy.json`, `scripts/anergic_weekly.py`,
  `scripts/gates/_process.py`.
- **States per rule:** anergic (always weight 0), conditional (weight 0 only
  when a signed corroboration applies), promoted (decided weight), or absent.
- **Transitions:** adding an entry requires a changelog anchor and a release
  section; promotion records `promoted_in`, `decided_in` and a measured outcome;
  the weekly review lists anergic *and* conditional entries.
- **Persistence:** a shipped JSON ledger; it is part of `config_fingerprint`.
- **Hazards:** silently muting a rule (the gates refuse it), or a conditional
  entry being treated as globally anergic.

### F02. IOC baseline

- **Files:** `ioc_baseline.py` (`BaselineManifest`, `IocEntry.expired`,
  `import_baseline`, `match_upstream_hash`), `iocs.py`, `release.py`.
- **States:** no store, verified baseline imported, refused signature, expired
  manifest, older `release_version` than the imported one; per entry: active or
  expired.
- **Transitions:** a signed baseline is verified before import; an older or
  expired baseline is refused; matching filters expired entries so an expired
  indicator never corroborates.
- **Hazards:** importing an unverified or rolled-back baseline, or matching an
  expired entry. Both are explicit refusals.

### F03. Watchlist lifecycle

- **Files:** `watchlist.py`, `channels.py`, `channel_state.py`.
- **States:** never imported, imported at tag T, updated, expired entry.
- **Transitions:** the signed watchlist release is fetched and verified, then
  imported; pull state records the tag.
- **Hazards:** an unpinned watchlist update changing the review surface without
  a recorded version.

### F04. Temporal T-rule state

- **Files:** `full_aur/temporal_engine.py` (`HistorySnapshot`,
  `TemporalInstance`, `_HISTORY_CACHE`, `read_cycle_history`),
  `full_aur/_temporal_*.py`.
- **States:** per package: ownership transition, adoption, dormancy, dependency
  redirection, reappearance, trust erosion; each rule instance is INFO/weight 0
  while anergic.
- **Transitions:** a snapshot of the prior cycle's metadata and maintainer
  transitions is compared with the current cycle; T008-T012 join a stored
  transition to a later payload. Missing history produces no finding.
- **Persistence:** the cycle history tables; a process-local cache with an
  explicit refresh.
- **Hazards:** reading a stale history cache across cycles, or inferring a
  transition from metadata that was never recorded.

### F05. Correlation and campaign state

- **Files:** `analysis/correlation.py`, `analysis/longitudinal.py`,
  `analysis/meta.py`, `analysis/pipeline/_analyze_helpers.py`.
- **States:** campaign state active, held (`campaign_hold`) or unavailable on a
  cold replay; refractory windows; adoption/rotation accumulators.
- **Transitions:** only corroborating G findings prime campaign state; a hold
  suppresses re-announcement; `campaign_state_available` distinguishes cold from
  quiet.
- **Hazards:** a weight-0 context finding consuming a campaign slot (explicitly
  excluded), or a cold replay reported as no campaign.

### F06. Release channel selection

- **Files:** `release.py` (`active_baseline_channel`, `is_newer`,
  `fetch_verified_asset`, `fetch_verified_url`), `config/_release.py`.
- **States:** stable vs prerelease channel; no versioned release, latest tag,
  newer/current/older; asset verified or refused; offline.
- **Transitions:** discovery reads release tags, picks the channel, verifies the
  detached signature against the pinned key, and only then imports.
- **Hazards:** accepting a draft/prerelease on the stable channel, or an asset
  that fails signature verification. Both are refusals, not fallbacks.

---

## 4. Sandbox and process lifecycle

### S01. Tokenizer worker pool

- **Files:** `sandbox/client.py` (`_Worker`, `MAX_REQUESTS_PER_WORKER`,
  `CPU_RETIRE_SECONDS`, `WORKER_POOL_SIZE`, `TokenizerUnavailable`).
- **States per worker:** stopped, starting, alive, retired (request or CPU
  budget), dead/timed out. Per request: answered, refused, retried on a fresh
  worker.
- **Transitions:** a worker is retired at 512 requests or 3.5 s CPU; a timeout
  or malformed frame kills it and raises `TokenizerUnavailable`; a forked child
  resets inherited worker bookkeeping.
- **Hazards:** a wedged worker serving the next package, or residual state
  accumulating. Retirement and per-request deadlines bound both.

### S02. Content/manifest worker

- **Files:** `sandbox/manifest_client.py` (`_Worker`, `MAX_REQUESTS_PER_WORKER`,
  cache byte budget), `sandbox/manifest_worker.py`, `sandbox/tokenizer_ops.py`.
- **States:** alive/stopped; cache hit/miss; parser refused or returned a
  projection; snapshot parse complete/refused.
- **Transitions:** a request failure stops the worker and the next call starts a
  new one; results are cached by content hash under a byte budget.
- **Hazards:** parsing hostile bytes in the parent (never), or unbounded cache
  growth (byte-capped).

### S03. Render worker

- **Files:** `sandbox/render_client.py`, `sandbox/render_worker.py`.
- **States:** worker alive/retired/restarted; progress task started, updated,
  stopped.
- **Transitions:** 256 requests per worker; a request failure raises
  `RenderUnavailable`; progress calls are keyed by task id.
- **Hazards:** a rich object constructed in the parent (gate-enforced), or a
  progress bar left running after an exception.

### S04. Store worker

- **Files:** `sandbox/store_client.py`, `sandbox/store_worker.py`.
- **States:** worker alive/restarted; read-only vs writable role; operation
  allowed or refused; schema initialised or not.
- **Transitions:** reads run on a read-only connection; writes are an explicit
  closed operation set; the worker applies its sandbox floor before serving and
  refuses if it cannot.
- **Hazards:** a private operation reaching the worker, or a fork inheriting a
  connection.

### S05. Git worker session and proxy

- **Files:** `sandbox/git_client.py` (`GitSession`, `run_op`),
  `sandbox/git_worker.py`, `sandbox/_aur_proxy.py`, `sandbox/git_project.py`,
  `sandbox/git_bounds.py`.
- **States:** no session, read session, fetch session; proxy phases (request
  parse, refs advertisement, upload-pack synthesis, forwarding); fetch result
  complete/degraded/refused.
- **Transitions:** a session starts under the kernel floor; the read role has no
  socket syscalls; the fetch role speaks only to the parent proxy, which owns
  TLS and stops reading after forwarding; a lost kernel protection refuses the
  worker.
- **Hazards:** a compromised libgit2 reaching the operator's filesystem or
  network, or the worker choosing request bytes. A16 is the invariant.

### S06. Sandbox floor

- **Files:** `sandbox/_spawn.py` (`spawn_isolated`, `core_sandbox_failures`),
  `sandbox/_limits.py`, `sandbox/_linux_sandbox.py`.
- **States:** floor applied (serve) or not (refuse to start); role (`read`,
  `fetch`, `store`, `render`); limits applied.
- **Transitions:** each child applies namespaces, Landlock, seccomp and rlimits
  before serving; a missing protection is a startup refusal, not a degraded
  serve.
- **Hazards:** silently serving with weaker confinement. The fail-closed refusal
  is the whole state machine.

### S07. Fetch freshness state

- **Files:** `sandbox/fetch_state.py` (`FetchState`, `load`, `store`),
  `sandbox/git_client.py`, `full_aur/fetch.py`.
- **States:** absent, unusable (wrong version, unverified, malformed OID,
  symlink/non-regular), verified. Per fetch: fresh, upstream-changed,
  forced-refresh refused, offline with no verified state.
- **Transitions:** a verified fetch stores HEAD, advertised HEAD, fetched time,
  upstream mtime, verified=true; the next fetch compares the advertised HEAD and
  freshness before deciding whether to clone or refuse.
- **Persistence:** parent-owned `.fetch-state/<pkg>.json`, mode 0600, atomic.
- **Hazards:** a compromised worker writing the freshness marker (it lives
  outside the worker's view), or a substituted commit (advertised vs actual
  HEAD).

---

## 5. Interfaces and integrations

### I01. Gate decision

- **Files:** `gate.py` (`run_gate`, `run_inspect`, `_read_answer`,
  `_lint_body`, `entrypoint`).
- **States per package:** approved, refused, inspection failed, no terminal.
- **Transitions:** inspect → render → prompt; `--yes` approves, `--no` refuses,
  a missing TTY returns `EXIT_NONINTERACTIVE`, `TRUSTSIGHT_GATE_DISABLE=1`
  approves with a visible log; a local directory with an AUR miss falls back to
  `trustsight lint`.
- **Persistence:** none; the decision is per invocation.
- **Hazards:** a refusal rendered as approval, or package-controlled text
  reaching the terminal (sanitised at the boundary).
- **Exit codes:** 0 approved, 10 refused, 20 inspection error, 30 no answer.

### I02. Hook setup

- **Files:** `cli/hook.py`.
- **States:** absent, ours (marked), foreign, conflicting PreBuildCommand;
  actions create/update/no-op/conflict/remove.
- **Transitions:** `--print`/`--dry-run` stop before writing; a conflict or a
  foreign yay file requires `--force`, which writes a timestamped backup first;
  `--remove` deletes only the marked block.
- **Hazards:** editing a user's executable yay Lua without consent, or following
  a symlink. Both are refused.

### I03. Preinstall scanner

- **Files:** `cli/preinstall.py`.
- **States:** scanning, completed (exit 0, whatever was found), could not run
  (exit 2); optional deep block with L9 unavailable/analyzed.
- **Transitions:** AUR lookup → whole-recipe analysis → optional deep decision →
  JSON/human report.
- **Hazards:** encoding a verdict in the exit status (B6). It never does; exit 2
  means it could not run.

### I04. Admin and health views

- **Files:** `cli/admin.py` (`anergic`, `full-aur health`, `export-scans`).
- **States:** rendered from the ledgers above: anergic/conditional table, watch
  health, outbox stats, scan export. Read-only except the explicit export.
- **Hazards:** a health view that reports "quiet" when the watcher is dead; the
  recorded keys are the source, not the log.

### I05. Notification payload fitting

- **Files:** `notify.py` (`_fit_payload`, `_PAYLOAD_BUDGET_BYTES`).
- **States:** whole payload, trimmed in a fixed order (diffs, reasons, findings
  beyond a cap, findings entirely, member detail, lowest-scoring entries).
- **Hazards:** a pathological cycle producing an unbounded body, or the headline
  and counts being dropped by the trimmer. The order keeps them.

### I06. Config fingerprint and rule sync

- **Files:** `config/__init__.py` (`config_fingerprint`),
  `config/_rule_sync.py`, `cli/config.py`.
- **States:** instrument identity (config + rules + anergy ledger) and sync
  states missing/outdated/drifted/synced.
- **Transitions:** a fingerprint change means a different instrument by design;
  a sync adds missing rules and updates superseded patterns while keeping user
  edits.
- **Hazards:** comparing runs made by different instruments without noticing, or
  overwriting a user's rule edit during sync.

---

## 6. Cross-cutting properties

### X01. Fail-closed vocabulary

The recurring pattern is a three-way outcome: **succeeded**, **refused /
incomplete**, **not applicable**. Refusals are named (`TokenizerUnavailable`,
`StoreUnavailable`, `RenderUnavailable`, `GitSandboxUnavailable`,
`snapshot_refused`, `stage_degraded`) and become coverage gaps or explicit
error states. A refusal never reads as "clean".

### X02. Two clocks

Wall time drives fetch freshness, outbox age, update notices and the watch
heartbeat. The observation sequence drives campaign TTL, override expiry,
refractory windows and verdict age. Mixing them is the most likely
state-machine bug in the codebase; every TTL site names its clock explicitly.

### X03. Caches and budgets

Every cache has a bound and a staleness rule: the tokenizer/manifest/render
worker caches are byte- or request-capped, the document cache is 16 MiB, the
AUR cache has a TTL, the history cache has an explicit refresh, and payload
builders fit a byte budget. An unbounded cache is treated as a defect, not a
configuration choice.

---

### X03a. Module caches and memoization

The small caches are state machines too: a hit and a miss must answer the same,
and a miss must never be mistaken for "no data".

| Cache | Location | Key and bound |
|-------|----------|---------------|
| Tokenizer memo | `_tokenizer_engine/_common.py` | thread-local `_memo`, per-call |
| Variable table | `_tokenizer_engine/_variables.py` | `lru_cache(maxsize=8)` |
| Heredoc indices | `analysis/delivery/__init__.py`, `line_lex.py` | `lru_cache` per line tuple |
| Build resolution | `analysis/buildfetch.py` | `lru_cache(maxsize=4)` |
| Refusal patterns | `analysis/refusals.py` | `lru_cache(maxsize=256)` |
| Path trust | `analysis/_path_trust.py` | `lru_cache(maxsize=256)` |
| TOML/shipped rules | `config/__init__.py` | process-lifetime, explicit refresh |
| Registry metadata | `registry.py` | process-lifetime |
| Parsed documents | `doc_cache.py` | content hash, 16 MiB |
| AUR RPC results | `db/_history.py`, `discovery.py` | DB rows, TTL 60 minutes |
| History snapshot | `full_aur/temporal_engine.py` | `_HISTORY_CACHE`, explicit `refresh` |

The rule for all of them: the cache key includes every input that can change the
answer (content hash, parser/state version, configuration), and a stale or
oversize entry is ignored rather than used.

## 7. Where to look next

- The state vocabulary is most concentrated in `db/_schema.py`,
  `db/_outbox.py`, `db/_campaigns.py`, `coverage.py`, `layers.py`,
  `notify.py`, `gate.py`, `anergy.py`, `ioc_baseline.py`, `release.py` and the
  sandbox clients.
- The most stateful analysis module is the tokenizer family
  (`_tokenizer_engine/*`, `line_lex.py`, `_heredoc.py`); it is also the one with
  the densest regression suite.
- The scanner in `scripts/implicit_state_scan.py` is deterministic and
  read-only: they are intended to be re-run when a module grows a new `status`
  field, a new `_CACHE`, or a new `start`/`stop` pair.
