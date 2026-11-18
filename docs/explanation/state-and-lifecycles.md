<!-- description: Where state lives in TrustSight, which parts are explicit types, which are implicit in ordinary code, and the transitions and invariants that keep a partial read from becoming a false verdict. -->

# State and Lifecycles

TrustSight reads hostile text and reports evidence about it. Between the two, a great deal of state accumulates: a quote opened on one line and closed three hundred lines later, a diff hunk whose closer was cut off, an alert that failed to send, a campaign that expires by observation count, a corpus cursor that must survive a restart. None of that state is the product, but every one of those decisions changes what the product says.

This page names where that state lives, which parts of it are explicit types, which remain implicit in ordinary code, and the invariants a change must keep. It is a map for a contributor, not a second specification: the [security model](../security-design/security-model.md) states the guarantees, and the [enforcement map](../security-design/enforcement-map.md) names the gate behind each one.

The inventory at the end is generated from `scripts/state_machines.toml`. Every symbol, test and database column it names is checked against the code, so a rename or a removed column fails the build until this page follows.

## Why state is a security property here

Three properties make state a correctness problem rather than an implementation detail.

**Determinism.** The same diff, effective configuration and observation history must produce the same evidence. A module-global cursor or a thread-local flag that leaks between packages breaks that promise quietly: the report still looks plausible, it is just about a different run.

**Fail-closed.** A reader that loses track of where it is must record the uncertainty, not guess. A truncated diff sets a coverage gap; an unresolved source URL becomes `unresolved_source`; a dead sandbox worker becomes a named refusal. The state machine's failure mode is part of the security model.

**No partial reads presented as whole ones.** A hunk whose declared count does not match its body, an array whose closer sits outside the fragment, an IOC manifest imported without its signature: each is a state that must be distinguishable from the complete version. Collapsing the two is how a partial analysis becomes a clean verdict.

## The explicit layer

The persisted lifecycles that had caused real bugs now have frozen value types and pure transition functions in `trustsight.db._lifecycles` and `trustsight.channel_state`. The caller builds the state from a database row, applies one transition, and writes it back. An illegal transition raises instead of producing a row no reader expects, and the rule is testable without SQLite.

### Alert outbox

An alert document is recorded before any sink is tried, so a failed delivery does not disappear with the log line. The row is **pending** while it is due and at least one sink has not accepted it, **waiting** while a retry is scheduled, **partially delivered** when exactly one sink accepted it, **delivered** when both did, and **parked** after the attempt or age cap.

Parked is terminal. It is reported by the health command and the outbox statistics rather than discarded, because losing an alert silently is worse than reporting that delivery failed. A `feed_only` document starts with the ntfy sink already marked, so it never goes to the ntfy channel, and the stored payload is the exact signed document a retry will send. SQLite enforces the same shape with CHECK constraints on fresh databases and additive triggers on migrated ones.

The page does not restate the retry arithmetic as a new guarantee: the outbox tests own that behaviour. What a reader of the code needs is the state vocabulary and the terminal state, both of which are in the table below.

### Campaign lifetime

A campaign is absent, **active** while `activated_at_obs + ttl_obs` is in the future, or **expired** once it is not. Expiry is arithmetic on the observation sequence, not wall time and not a sweep, so a replay is deterministic and an expired campaign is never returned by `active_campaigns`. `expiry_announced` is a separate two-state flag: expiry and the report of expiry are different events.

Re-activation refreshes the window, increments the activation count and clears the announcement flag, but it never shortens a live TTL; the `CampaignState.reactivated` transition raises rather than silently clamping. Re-arming faster than the configured minimum is reflected, never blocked: the cycle reports an M006-style tool-health note.

### Acknowledged state: orphan and channel pulls

The AUR orphan column is a tri-state: `-1` unknown, `0` maintained, `1` orphaned. Unknown is load-bearing. A cold database that has never asked has not observed "maintained", and H086's "adopted from orphan" claim needs a prior observed `1`. Collapsing unknown into either neighbour manufactures an adoption or hides one.

Channel pull memory is one record per channel and feed: **unpulled**, or **pulled at tag X**. The comparison includes the channel, because reading only the tag made the same tag on a different channel look already pulled. IOC records are keyed by feed so one feed's pull cannot mask another feed's update. A corrupt or empty record is a miss, not a successful pull.

### Fetch trust

`trustsight.sandbox.fetch_state` stores the verified HEAD record outside the repository, because the fetch worker can write inside its own checkout. The parent follows no marker the worker can reach. The file is regular, not a symlink, non-blocking and bounded; a state that fails validation reads as absent, never as partially trusted. `store()` refuses an unverified or malformed state. This is the only persisted proof that a commit was actually fetched and verified.

## Parser and document state

The parser internals remain implicit by design. Turning every carried quote frame into an enum would add indirection to the hottest path in the analysis without changing what can be tested; the contract tests are the safety net, not a rewrite.

`line_lex` carries a stack of quote frames (single, double, ANSI-C, backtick, command substitution) across lines, plus a FIFO of heredoc delimiters. Bash reads heredoc bodies in opener order, so two openers on one line are a queue, not a stack. A line past the tokenizer ceiling is scanned only to the bound and its quote state is reset; `LexedLine.truncated` records the refusal so a crafted line cannot hide the rest of a recipe behind a quote that opens past the ceiling. The fast path must agree with the full scan on the state it leaves, and the contract tests pin that agreement.

The unified-diff parser is one walk from raw lines to files, hunks and classified lines. Its boundary decisions are legacy-compatible on purpose: a file header does not close an open hunk, a pure rename materialises a file from metadata alone, and a hunk shorter than its header claims becomes a `partial_hunk` gap rather than a quietly short array. Downstream stages query that one document instead of re-walking the text, which is the [typed core](architecture-and-pipeline.md) claim.

Recipe function segmentation is the same shape at a smaller scale: brace depth opens and closes function bodies, a one-line body closes on its own line, and a redefined function keeps the last body, because that is what bash will run.

## Orchestration state

The corpus cycle chooses its mode at entry: **backfill** when a `since` cursor exists, **bootstrap** when there is no snapshot and it was asked for, **delta** when a previous snapshot exists, **no-op** when there is nothing to process, and **refused** when metadata is empty or a from-scratch bootstrap was not requested. A refused cycle does not clobber the snapshot. The resume set and cursor are persisted; a different `--since` origin resets the replay, while the same origin re-passed on every restart does not. A fetch failure is marked processed so a resume does not retry a mirror-missing package forever.

The watch loop records start, success and failure independently, because a watcher whose every cycle fails is quiet in exactly the same way as a watcher with nothing to report. Health is derived: no database, not a watcher, stale beyond `max(2 * interval + 300, 900)` seconds, too many consecutive failures, or a parked outbox entry all read differently. The loop sleeps interruptibly, backs off on failure, shortens the interval while backfilling, and finishes the current package on a stop request. One owner holds an advisory lock; a second watcher against the same data directory refuses rather than racing.

The analysis comparison base is a six-way decision (fresh, cached, explicit old commit, recorded baseline, parent baseline, whole recipe) and it changes the entire diff. Choosing the parent instead of the recorded baseline is correct only on a first review, and that choice is recorded as the `parent_baseline` coverage gap. Cached analysis is keyed on the commit, version pair, depth and ruleset, so a changed input is a miss.

Stage failures are thread-local: a shared set would attribute one package's failed stage to another package analysed concurrently. The list is reset per package and folded into coverage, where a degraded stage forbids a clean verdict.

Dependency walking is a bounded level-by-level frontier. A ceiling that cuts the walk below the requested depth sets `truncated`; a finite depth that ended by its own limit is a complete answer. The distinction matters because one is silence and the other is a reported gap.

Sandbox workers have a lifecycle: absent, starting, ready, busy, retired after their request cap, or stopped after a timeout or invalid reply. A dead worker is a named refusal, never a silent pass. The git worker additionally carries a one-way degradation list: protections it could not apply are reported on every response, so the parent can surface weaker isolation for the rest of the process lifetime. Git sessions are created, live, then closed exactly once; close is idempotent, and process exit drains every live session.

## Inventory

The table is generated. `Where` is the first implementation anchor, and `Pinned by` is the first contract or round-trip test; the registry lists the rest. A machine marked **explicit** has a state type and transition functions; an **implicit** one encodes the same rules in ordinary variables and branches.

<!-- generated: state-machines -->
*20 documented machines; 81 further modules classified as single-pass scanners, memos or one-way latches.*

| Machine | Kind | Status | States | Where | Pinned by |
|---|---|---|---|---|---|
| Shell quote and heredoc state | lexical | implicit | code, single, double, ANSI-C, backtick, command substitution; heredoc delimiter queue | `trustsight.line_lex:QuoteState` | `test_quote_state_carries_across_lines` |
| Recipe function segmentation | document | implicit | outside a function, opener seen, body open at depth > 0, closed | `trustsight.recipedoc:_function_segments` | `test_one_line_body_stays_closed` |
| Unified-diff parser | document | implicit | no current file, in file, in hunk; pending old path, pending hunk boundary, pending file metadata | `trustsight.diffdoc:parse_diff_lines` | `test_diffdoc_classifies_every_input_line` |
| Alert dedupe and refractory window | persisted | implicit | absent, seen, repeated; refractory cell absent or seen | `trustsight.db._profiles:record_alerts` | `test_repeat_alerts_are_counted_not_forgotten` |
| Alert outbox | persisted | explicit | pending, waiting, partially delivered, delivered, parked | `trustsight.db._lifecycles:AlertOutboxState` | `test_outbox_parked_is_terminal` |
| AUR orphan tri-state | persisted | explicit | unknown, maintained, orphaned | `trustsight.db._lifecycles:OrphanState` | `test_orphan_observation_mapping` |
| Campaign lifetime | persisted | explicit | absent, active, expired; expiry unannounced or announced | `trustsight.db._lifecycles:CampaignState` | `test_campaign_expiry_is_structural` |
| Channel pull memory | persisted | explicit | unpulled, pulled at tag X | `trustsight.channel_state:ChannelPull` | `test_channel_pull_matches_channel_and_tag` |
| Fetch trust state | persisted | explicit | absent, unusable (unverified or malformed), verified | `trustsight.sandbox.fetch_state:FetchState` | `test_state_round_trips_and_is_parent_only` |
| IOC active and expired lifecycle | persisted | implicit | never expires, active, expired | `trustsight.ioc_baseline:_is_expired` | `test_a_renewed_indicator_becomes_active_again` |
| Property stability and transitions | persisted | implicit | absent, observed, unchanged, changed; below or above the stability floor | `trustsight.full_aur.properties:update_properties` | `test_changed_value_writes_one_transition_row` |
| Schema migration version | persisted | implicit | shipped version or below, stamped at the current version | `trustsight.db._schema:_migrate` | `test_a_fresh_database_is_stamped_with_the_schema_version` |
| Analysis comparison base | orchestration | implicit | fresh, cached, explicit old commit, recorded baseline, parent baseline, full recipe | `trustsight.analysis.pipeline._analyze:analyze_package` | `TestComparisonBase::test_a_first_review_names_the_parent_baseline` |
| Corpus cycle mode and resume | orchestration | implicit | backfill, bootstrap, delta, no-op/removals-only, refused; resume set empty or populated | `trustsight.full_aur._baseline_build:_run_baseline_build` | `test_since_replays_one_aur_day_per_cycle` |
| Dependency BFS and graph closure | orchestration | implicit | frontier non-empty, seen set, level, truncated or complete | `trustsight.depth:walk_dependencies` | `test_a_dependency_cycle_terminates` |
| Git session lifecycle | orchestration | implicit | created, live, closed | `trustsight.sandbox.git_client:GitSession` | `test_a_closed_session_refuses` |
| Sandbox worker lifecycle | orchestration | implicit | absent, starting, ready, busy, retired, stopped/failed | `trustsight.sandbox.manifest_client:_Worker` | `test_worker_applies_the_linux_sandbox` |
| Stage-failure tracking | orchestration | implicit | tracking off, tracking on, one or more stages failed | `trustsight.coverage:begin_stage_tracking` | `test_dependency_stage_failure_does_not_leak_into_the_parent` |
| Watch loop and liveness | orchestration | implicit | starting, running, sleeping, failing, backfilling, stopping; healthy, unhealthy, not a watcher | `trustsight.full_aur._pipeline_watch:run_watch` | `test_watch_health_distinguishes_alive_from_failing` |
| Sandbox degradation latch | latch | implicit | no degradation recorded, one or more protections recorded | `trustsight.sandbox.git_worker:_DEGRADED` | `test_the_worker_refuses_to_start_with_a_vulnerable_libgit2` |
<!-- /generated: state-machines -->

## Changing state safely

- **Name the states and the terminal states first.** If a state cannot be named, the transition rules cannot be reviewed.
- **Put the transition in one function.** A state change spread across three call sites is how a parked row gets unparked or a live TTL gets shortened.
- **Test the transition, not only the output.** The round-trip tests are the model: build the state, apply the event, assert the new state, reopen the database where the state is persisted.
- **Make the unknown state explicit.** A missing row, an unparseable file and a dead worker are states with consequences. Do not default them to the neighbour that reads better.
- **Record truncation at the point it happens.** A bound that drops input without a coverage gap turns an incomplete analysis into an apparently clean one.
- **Never reset a persisted cursor as a side effect.** Resume state is cleared deliberately, by the path that knows the replay is over.
- **Do not widen a guarantee in prose.** If the page needs a new invariant, the invariant needs a gate; the enforcement map is the other half of the claim.

## How this page stays true

The gate `state machines are documented and exist` runs with the security gates:

```bash
python scripts/security_gates.py
```

It fails when a documented symbol or test disappears, when a table or column named in the registry no longer exists, when the generated inventory is stale, or when the scanner finds a stateful module that is neither documented nor classified as an exemption. To fix an inventory failure, edit `scripts/state_machines.toml` and run:

```bash
python scripts/build_state_doc.py
```

The scanner is a heuristic, not a proof of coverage. It looks for carried lexical state, module-level mutable state, rebinding globals and state-named locals that gate control flow. A new module of that shape fails until someone classifies it; a module that changes shape without matching the heuristic can still escape. The tests, not the scanner, are what pin behaviour.

## See also

- [The Typed Core](architecture-and-pipeline.md): the one-parse, many-projections design behind the document state.
- [Sandboxing the Tokenizer](static-analysis-and-resolution.md): why the parser state runs in a worker.
- [Security Model](../security-design/security-model.md): the guarantees these states must preserve.
- [Enforcement Map](../security-design/enforcement-map.md): every guarantee's gate.
