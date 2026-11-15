<!-- description: How findings become alerts: the alert kinds and budget, campaign and neighborhood modes, the immune-inspired design, the H-series intake freeze, and the evaluation methodology. -->

# Detection and Evidence


Detection is more than a rule firing. This page explains the alert kinds
and budget, how a corroborated campaign changes the surrounding packages, the
immune-inspired design behind correlation, why the H-series is under an intake
freeze, and how the result is measured against a locked corpus.

## Kinds of Alerts

"Alert" is an overloaded word in TrustSight. This page spells out the
different things that name can mean, so a report is never read as the wrong
one.

### Findings (the payload)

The ordinary result of a rule matching. A finding has a rule id, a severity,
and - where it can - a file and line. Findings score according to their
severity weight. Everything else on this page either *describes* findings or
describes the run, rather than adding new suspicions.

### Boundaries (what the run could not read)

Some W-series rules and coverage gaps are **weight-0 boundaries**: statements
that something ran, or was skipped, that the analysis could not fully read.
They are always shown, they never score, and a gap among them forbids a clean
verdict. See [What TrustSight Cannot See](limitations-and-uncertainty.md).

**W010 (Alert Volume Capped)** is a boundary of a different flavour - it
records that the terminal was capped, not that anything was unread, so it
never forbids a clean verdict. See [Alert Budget](detection-and-evidence.md).

### Corpus cluster findings (a campaign shape)

When TrustSight runs over the whole AUR (`full-aur`), several rules look
*across* packages at once: **H045/H052/H055/H073** and the **G-series**. One
firing covers the whole cluster and names its members - a campaign is one
alert, not N. Most of these score; the burst rules (`H052`/`H055`) only score
when a member actually impersonates a popular package.

**G005 (Impersonation Campaign)** is the sharp end of this family: many
name-clones of popular packages under one account. Every G rule is live on a
real cycle, including **G002** (shared added literal) and **G004** (shared
upstream dependency). See the
[correlation reference](../rules/correlation.md).

### Campaign alerts (primed state)

When a campaign is corroborated, TrustSight enters **campaign alert mode** for
a bounded number of observations. While primed, a package in the campaign's
scope is flagged (**G006**, weight 0). This is state, not a new finding. See
[Campaign Alert Mode](detection-and-evidence.md).

### The watch webhook (something to read now)

`full-aur --watch` POSTs one JSON document per cycle that had something new.
It is a *notification*, not a finding: it carries counts, the flagged
packages, IOC matches, campaign clusters, and any impersonation campaign. Its
priority is deliberately mild - the urgent tier pages at night, which is
worse than a quiet panel in the morning.

### Heartbeat

A once-a-day "still watching" message, priority low. Its whole job is to tell
apart "nothing found" from "the watcher is dead".

### Expiry notices (state that lapsed)

Two things can lapse and are reported once rather than silently dropped: an
**expired indicator** and an **expired override** (a suppression past its
observation TTL). In both cases silence is never allowed to mean both "never
existed" and "ended". Overrides are covered in
[Override Tolerance](scoring-and-verdicts.md).

### Tool-health (M-series)

A few M-series entries describe the **instrument**, not the package - for
example a rule that is expected to co-fire and did not. They are weight-0,
never scored, and go to the harness/calibration output rather than a
package's finding list.

### Related

- [Alert Budget](detection-and-evidence.md)
- [Campaign Alert Mode](detection-and-evidence.md)
- [Override Tolerance](scoring-and-verdicts.md)

## Alert Budget

A tool that reports everything a noisy package does can be turned against the
person reading it. Fill the screen with findings and the real one scrolls
past.

The alert budget is the guard against that. It caps how much the **terminal**
shows at once, and it always says when it did.

### Where it comes from

The analogy is a **superantigen**. A normal immune response is targeted. A
superantigen instead activates a huge fraction of T cells at once, and the
resulting flood of signals does more damage than the pathogen - the response
becomes the threat, and the host stops reacting to anything real.

The same thing happens to a reviewer. A campaign that makes every package
moderately noisy is not attacking any single package; it is **raising the
noise floor** until reviews get skimmed. That is the attack the budget
exists to blunt.

### What the cap does

- **`[alerts] max_rendered_findings`** (default 50). The terminal shows the
  first 50 findings in full, then a single `...and N more findings (see
  --json)` line.
- The JSON report is **never filtered**. Every finding is there. The cap only
  bounds what a person reads on screen.
- A weight-0 boundary, **W010 (Alert Volume Capped)**, records that the cap
  was reached, with the count per severity band.

### It is a saturation, not a gap

This is the important distinction. A coverage gap (the [W-series
rules](../rules/unverifiable.md)) means *something was not read* -
the analysis could not conclude, and that is a boundary that forbids a clean
verdict.

W010 is the opposite. Nothing was left unread; the report simply had more to
say than fits comfortably on screen. So W010 never forbids a clean verdict
and never changes the score. It is a statement about the **run**, not about
the package.

### The same idea, one level up

A single `full-aur --watch` cycle can flag hundreds of packages at once. The
per-cycle cap (`[alerts] max_cycle_alerts`) keeps one noisy cycle from
becoming one enormous notification: past the cap the webhook names the top-K
by score and reports the counts, while the stored record keeps every package.

Volume is never evidence about any single package, so none of this ever moves
a score.

### Related

- [Campaign Alert Mode](detection-and-evidence.md) - the other guard, against a
  state that never expires.
- [Kinds of Alerts](detection-and-evidence.md) - where W010 sits among everything
  else.

## Campaign Alert Mode

Most findings are about one package. A **campaign** is the opposite: several
packages moving together in a way that only makes sense when you look at them
all at once.

Campaign alert mode is what TrustSight does when it sees one. For a short,
bounded stretch it treats the packages a campaign touched as *primed* - more
worth a second look - and then it lets that state **expire on its own**.

### Where it comes from

The idea is borrowed from the immune system, specifically **trained
immunity**. A strong infection leaves the innate immune layer temporarily on
higher alert, so the next brush with the same threat is met faster. That is
useful.

The failure mode is just as important. If the state never switches off, the
alert *becomes* the disease - chronic inflammation, where the body attacks
itself because it forgot how to stand down. So the design is less about
switching alert mode *on* and more about making sure it switches itself
*off*.

### What counts as a campaign

TrustSight turns on campaign mode only when independent evidence already
agrees that something is a campaign. Today that is the correlation family:

- **G005 - Impersonation Campaign.** One account publishing many name-clones
  of popular packages (`yyay` next to `yay`). This is the strongest trigger.
- **G001/G002/G003/G004/G008/G011/G015.** Many unrelated packages sharing a
  gained host, an added literal, an upstream dependency, or an adopter, a
  first-seen account sweeping dormant packages, a first-seen account creating
  many brand-new packages, or a dormant multi-account adoption cohort that
  reactivates together after a delay.

Only those corroborating rules prime campaign state. The report-only members
of the family never do: **G006/G007** are context, **G009** is the operator's
watchlist note, and **G010** is a first-seen-host census. A weight-0
observation must not take one of the bounded campaign slots a real cluster may
need.

Each G rule reads a bounded transition window. G001/G002/G003/G004 feeds are
cleared at cycle start, so a host, literal or adoption recorded in an earlier
cycle cannot re-fire the join or keep a lapsed campaign primed. G011 reads the
recorded `cycle_events` window instead, because a creation burst can span
several cycles. A G002 campaign
is keyed by a digest of the shared literal (never its content); a G004 campaign
by the dependency *and* its host.

A single publisher's campaign tag on an indicator is *corroboration*, not a
campaign on its own. One source saying "campaign" is exactly the lane a
poisoner would use; agreement is what raises the alarm.

### What "primed" means

While a campaign is active, a package that ever touches the campaign's scope
- for G005, a name-clone of an impersonated target; for the host rules, a
host in the shared set - is flagged as standing in an alerted neighborhood
(rule **G006**, weight 0). This is a *report*, not a score. "Touches a hot
host" is a context, not a behaviour, so it never moves a number and never
blocks a clean verdict on its own.

### Why it expires, and how that is enforced

The lifetime is measured in **observations**, not seconds or days. One
observation is one recorded analysis. Two consequences follow:

- The tool never consults a clock it does not control. A campaign cannot be
  kept alive by a future-dated commit or a skewed machine clock.
- Expiry is **structural**, not a cleanup job. A campaign whose
  `activated_at_obs + ttl_obs` is behind the current observation count is
  simply never returned by the query that reads campaigns. There is no
  sweeper to forget to run.

When a campaign does lapse, TrustSight says so once - the way an expired
indicator is reported rather than quietly dropped. Silence is never allowed
to mean both "there was no campaign" and "the campaign ended".

### The caps that keep it from becoming chronic

- **`[alerts] max_active_campaigns`** limits how many campaigns can be primed
  at once. A new one evicts the oldest *only if its own lifetime has already
  lapsed*. A live campaign's window is never shortened.
- **`[alerts] campaign_ttl_observations`** keeps the default lifetime short -
  tens of observations, not thousands.
- A campaign class that re-arms far too often is surfaced as a tool-health
  note (`M006`, weight 0), not silently re-armed. The window is still
  refreshed; only the churn is reported.

None of this state is stored in a report or a config fingerprint. Like
recorded history, it is **instrument state**: it changes what TrustSight
knows, not what it is. Two machines with the same configuration and the same
observations stay in step.

### One stimulus, one alert

A campaign alert is emitted once per `(rule, campaign-cell)` per window. The
window is the campaign's observation TTL, and the refractory row is part of
the cycle's audit record, so a replay emits the same set. This is
debounce as semantics, not suppression: a signal that re-fired every cycle
would carry no more information than one that fired once.

The same guarantee covers rendering. When N packages share one campaign
finding, the alert names all of them once, with members sorted and
de-duplicated; per-package duplicates are not emitted.

### Related

- [Alert Budget](detection-and-evidence.md) - the other guard against a run becoming
  noise the reviewer learns to ignore.
- [Kinds of Alerts](detection-and-evidence.md) - where a campaign alert sits among
  everything else TrustSight reports.

## Neighborhood Elevation

When a campaign is active, the packages *around* it are worth a glance even
if they are not part of it. **Neighborhood elevation** is how TrustSight
raises them - carefully.

### Where it comes from

**Cytokine signaling.** An alerted immune cell releases signals that raise
the readiness of the surrounding tissue, so a threat is met faster. It is
local, temporary, and useful.

The failure mode is a **cytokine storm**: unbounded elevation damages the
very tissue it was meant to protect. So the whole design here is the cap.

### What happens

While a campaign is active (see [Campaign Alert Mode](detection-and-evidence.md)),
a package in the window that *gains* a host or domain in the campaign's
scope - without itself being corroborated - gets one finding, **G006
(Neighborhood Under Campaign Alert)**, weight 0.

It is **reported, not scored**. "This package touches a neighbourhood that is
under alert" names a context, not a behaviour. Scoring it would hand an
attacker a lever: touch a host that is *already* hot and your package looks
worse for reasons you did not cause.

Only *gained* hosts count. A package that already had the host is not newly
elevated, so nothing changes for it.

### Why weight 0 in v1

Scoring this needs a number nobody has yet: how often *benign* packages touch
a hot neighbourhood during a real campaign window (CDNs, `github.io`, shared
build hosts). Until that is measured, a score here is a guess that would
inflate exactly the packages an attacker wants inflated. The weight-0 report
is the instrumentation that will eventually answer the question.

### Related

- [Campaign Alert Mode](detection-and-evidence.md)
- [Kinds of Alerts](detection-and-evidence.md)

## Immune-Inspired Design

The immune system is not a metaphor pasted onto TrustSight; it is a set of
solutions to the same problem the tool has. An audit engine must decide what
to look at, remember what it has seen, raise its posture without accusing any
one package, and say when it is blind. These are the borrowings, and the one
inspiration that is rejected.

### Missing-self (NK cells)

The immune system does not wait for a foreign antigen. It kills cells that
stopped proving they are themselves. TrustSight's corpus says what packages
*already have*; the missing-self axis says what they *stopped having*.

- **T004 Vouch Surface Removed** - a partial `validpgpkeys` removal with no
  replacement.
- **T005 Scheme Downgrade** - the same source host falls from TLS while the
  URL path also changes, the shape H019's exact-match rule misses.
- **C033 Context Bleed** - a diff guts a large fraction of the recipe's
  comment prose.
- **C034 Metadata Inconsistency** - committed `.SRCINFO` and PKGBUILD
  disagree on the version fields.

T004 and T005 are the T-axis twin of G008: G008 watches *who arrived*;
T004/T005 watch *what disappeared when they did*.

### Danger over stranger (Matzinger)

The system responds to damage signals, not foreignness. The Contact Ledger
is already built on this: a first contact is recorded, not attacked. C033 and
C034 extend the same posture to the host's own tissue: the recipe's prose and
its generated metadata are damage signals about reviewability, not evidence
that a payload exists.

### Opsonization (complement)

Tag first, clear later. Weight-0 tag events - first contacts, campaign
context, entropy bumps, annotations, techniques - are not indecision. They
are the coating that makes later detection cheap. The report's `tag_panel`
is the one grouped surface for that coating, and `TAG_CONVERGENCE` is the
bounded escalation: N distinct kinds on one diff earns one INFO ledger entry,
never a score.

### Sickness behavior

Systemic infection changes the whole organism's posture. When G006/G007
declare a campaign perimeter, a standing boundary note on an in-perimeter
package (W009, another W finding, or a coverage gap) becomes visible as
`W013` until the campaign TTL expires. Fever is not a verdict about any one
cell, and W013 is not an accusation: it is context, weight 0, and
escalation-only. `campaign_hold` is the same posture in machine-readable
form; enforcement is outside the tool.

### Refractory period

A neuron that could re-fire every millisecond would convey nothing. One spike
per stimulus is what makes a signal informative. The emission layer enforces
one alert per `(rule, campaign-cell)` per window, and the refractory state is
part of the cycle's audit record. Debounce is not suppression; it is
semantics. Lateral inhibition is the rendering half: when N packages share
one campaign finding, the single alert names all members, sorted.

### Nociception

Pain is prioritization without a damage claim. A package with repeated
unresolved review verdicts earns a tender point in the report header: "N
unresolved in M months; a human should look once." It never says the package
is broken, and it never scores.

### Interoception

An organism that cannot feel its own state confuses blindness with safety.
The report's `self_state` block names cold/warm mode, observation counts,
ruleset versions, channel tags and observation-clock ages, federation and
contact availability, campaign state, and a sorted `blind` list. A blind run
must never masquerade as a clean one.

### Rejected: gain control

Gain control - continuously adapting a threshold to the recent signal - is
rejected as a runtime mechanism. It would make the same diff score
differently depending on where the epoch happened to sit, breaking B1
(fingerprint reproducibility) and cold-replay determinism. Thresholds are
re-derived at release time from the pinned corpus, committed to config, and
covered by the fingerprint. Gain control survives only as a release-process
note and as this documented rejected inspiration.

### Two-signal activation

A detection shape is not evidence that the shape is calibrated. A new rule
ships anergic: visible, weight 0, listed in the anergy ledger with the signal
it is waiting for. Promotion is explicit, measured, and changelogged. The
state is queryable with `trustsight admin anergic`.

## Reducing the H-Series

The H series is TrustSight's catch-all. A rule lands in H by **exclusion**:
if a detection is not a regex (`R`), a structural check (`C`), a dependency
rule (`D`), a sabotage rule (`S`), a crossfire rule (`X`), a signature match
(`T`), a correlation (`G`) or an entropy measure (`E`), it is a heuristic, and
heuristics are H. That default is why the series grew to 103 ids - and why some
of them overlap, some are corpus-dependent, and some have never fired on the
locked corpus.

This page explains the plan to shrink it, the two mechanisms that enforce the
plan, and why the retirement map is still empty.

### The problem: an unbounded drawer

Two H rules can describe the same behaviour from slightly different angles.
`H026` (maintainer change to a never-seen identity) is a strict subset of
`H044` (ownership transition): every `H026` firing is also an `H044` firing.
Left alone, that is two ids, two doc entries, two config overrides and two
weights for one phenomenon - and a reviewer who sees both cannot tell whether
they are looking at one signal or two.

The reduction plan is to **merge rules that co-fire** and shrink the live,
emitting surface to a target band of **55-65 ids**.

### How a merge is decided

`scripts/h_reduction_audit.py` measures, for each candidate pair, the co-fire
ratio

```
|A & B| / min(|A|, |B|)
```

over the benign corpus, the labelled malicious fixtures and the replayable
history cycles. The published decision rule: a pair co-firing at or above the
epsilon (default **0.95** of the rarer rule's firings) *may* merge, with the
higher-severity id surviving. The script **measures only**; it never retires an
id. The output is evidence a human adjudicates in the changelog.

### Why nothing was retired

The audit measured nine candidate pairs. The strongest co-firers are either

- **strict subsets** - `H026` is contained in `H044`, so there is nothing to
  merge that `H044` does not already say; or
- **different mismatches** - `H053` (name/host consensus) and `H059`
  (name/repo path) share a name but describe different disagreements, and a
  merge would erase which one fired.

The rest are distinct. So `RETIRED_RULE_IDS` stays empty: the mechanism ships
ready, but the map is a **data change no evidence currently supports**.

The zero-fire ledger is not a retirement licence either. It includes rules with
no fixture that still carry real detection value - the temporal and correlation
families, `H083`-`H085`, `H089`/`H090`/`H093`/`H094`. Retiring from a count
alone would delete detections the security model does not license removing.

### The two mechanisms

#### Intake freeze (hard)

`FROZEN_H_IDS` is the explicit set `H001`-`H103`, taken at the start of the
reduction. `tests/test_h_reduction.py` and the `H-series intake is frozen`
security gate fail a PR that adds a new H id. A new detection must be filed as
an instance of an existing H family, or into the series that fits its mechanism
(`T` for temporal rules, `T001`-`T003` and `T006`-`T007`; `C`, `D`, `X`, `E`,
`I` or `M` otherwise). The freeze set only ever shrinks: a retired id moves to
`RETIRED_RULE_IDS` and stays out of the freeze, so its former id is never
re-issued.

#### Residue report (advisory until the ceiling)

The `H-series reduction residue` gate reports the live (emitting) count against
the target band but **fails only above the frozen ceiling** - the frozen set
minus the retained documentation anchors (`H005`-`H014`, `H028`, which emit
nothing and exist so reference links resolve):

```
ceiling = len(FROZEN_H_IDS) - len(ANCHOR_RULE_IDS) = 103 - 11 = 92
```

A count that is merely **above the target band does not fail**. No
evidence-supported merger remains, so failing on the number would force a
change the evidence does not license. Only exceeding the ceiling - a new id
slipping past the freeze - is a hard failure.

### If a merge is later supported

1. Add the pair to `RETIRED_RULE_IDS` (`retired_id -> survivor_id`).
2. Remove the retired id from `FROZEN_H_IDS` (it never returns).
3. The survivor keeps emitting. A `config.toml` override keyed to the retired
   id still suppresses the survivor: `survivor_id` resolves a retired id to its
   survivor and then through `RENAMED_RULE_IDS`, and
   `override.filter_triggered_rules` applies it.
4. The retired id's reference entry becomes a one-paragraph stub, and
   `sync-rules` never resurrects it.

See also [Rule Series](../rules/series.md#h-series)
and the [Rule Series](../rules/series.md).

## Benchmarks and Methodology

### Scope of this evaluation

These results are regression measurements, not an independent efficacy study.
The malicious side consists of **self-authored, labelled fixtures**: historical
cases represented as fixtures plus holdout, evasion, synthetic, and campaign
fixtures maintained in this repository. Labels express what each fixture is
intended to exercise; they do not establish prevalence, real-world recall, or
adversarially independent performance. The benign side is a locked,
point-in-time AUR-derived corpus. Its measurements describe that snapshot and
the shipped configuration, not all AUR updates or future traffic.

An external blinded evaluation is the route for evidence beyond this internal
regression suite; see [Blinded Evaluation](../contributing/blinded-evaluation.md).

### How separation is measured: per-class, not pooled

The lesson that made the evaluation converge.

Early benchmarks pooled all malicious-class packages together and compared the pooled mean and median against the benign mean and median. This produced a misleading picture: the gap appeared to be approximately 5 points, which was not useful for decision-making.

#### Why pooling hid the separation

The malicious test corpus includes packages at multiple severity levels: CRITICAL (clear malicious patterns like curl pipe bash), HIGH (checksum manipulation), MEDIUM (unusual sources), and LOW (minor anomalies). Pooling them together averaged the high scores from CRITICAL packages with the lower scores from MEDIUM and LOW packages. The average was dominated by the low-severity tail, making it look like the tool did not separate malicious from benign.

The benign corpus includes package updates that are not perfectly clean: routine dependency changes, source URL format changes, and maintainer updates. The tail of the benign distribution (packages that score 5 to 20) pulled the benign average up. The pooled comparison compared the middle of both distributions, which overlapped significantly.

The fix was to split by class. When CRITICAL-only packages were isolated from the rest, the separation became meaningful:

- **CRITICAL** p5 = 40
- **Benign** p95 = 30
- Gap = +10 points

Pooling was hiding the separation. Advisory-level and low-severity malware dragged the malicious-class average down, while the benign tail dragged the benign average up. Per-class measurement revealed that the tool cleanly separates the threats that matter.

### Why benign-p95-versus-malicious-p5 is the number that matters

Absolute p95 on either class is not useful in isolation. A tool that scores everything 50 would have a benign p95 of 50 and a malicious p95 of 50, showing zero separation.

The gap between the bottom 5th percentile of malicious scores and the top 95th percentile of benign scores is the operational separation. It answers the question: how much room is there to set a threshold that catches real threats without false-positive burden?

If the CRITICAL p5 is 40 and the benign p95 is 30, a threshold set inside the gap catches every CRITICAL-class sample in the benchmark set while labeling only 5% of benign packages as FLAGGED. The 10-point gap provides margin for error: moving the threshold within it trades false-positive rate against headroom while still catching all CRITICAL samples.

The gap is measured as p5 of the worst class (CRITICAL) versus p95 of the benign class because these are the tails that matter for threshold setting. The center of the distribution is irrelevant for operational decision-making.

### Per-class CI gates

The benchmark enforces three gates:

| Gate | Requirement | What it prevents |
|------|-------------|------------------|
| Malicious fixture coverage | Every labelled malicious fixture still detects what it is labelled for (skips known_gap) | A change that weakens detection of a labelled fixture is rejected. The committed corpus is 213 self-authored fixtures across historical, holdout, evasion, synthetic, campaign and warm groups; `scripts/verify_fixtures.py` enforces record-to-diff completeness. This is not independently sampled recall. |
| Separation | benign p95 stays below malicious p5 (strict; currently 30 < 40, a 10-point margin) | A change that narrows the gap (by reducing malicious scores or inflating benign scores) is rejected. |
| Benign fire rates | No scoring rule fires on >= 30% of benign diffs | Prevents weight inflation: a rule that becomes a census on benign packages is rejected. |
| Score-not-size + weight-zero annotations | \|Pearson(score, diff_lines)\| < 0.30; weight-0 rules move the score by exactly 0 | Prevents measuring activity instead of risk. |

A known-gaps gate additionally requires each `known_gap` fixture to *still*
fail its label, so closing a gap forces an explicit relabel.

#### Why several gates and not one

A single gate (for example, "CRITICAL recall >= 100%") would allow weight inflation: making all rules fire harder would increase malicious scores but would also increase benign scores. The separation gate (benign p95 < malicious p5) prevents this by requiring the gap to stay positive. The fire-rate cap prevents any single rule from becoming a false-positive census on the benign corpus.

The gates together enforce three distinct properties: detection (no missed labelled attacks), separation (meaningful threshold gap), and baseline (low false-positive rate). Each gate independently blocks regressions in its dimension.

#### Current numbers

Measured against the locked benign corpus as `tests/fixtures/corpus.lock` records it - **8,393** diffs - with the same code path the calibration gates use. Re-derive with `scripts/rebaseline.py` when scoring changes; `test_the_documented_corpus_size_matches_the_lock` keeps the figure and the lock from drifting apart.

| Metric | Value | Benchmark target |
|--------|-------|------------------|
| Benign zero-rate | 74.0% | no minimum; fire-rate cap controls FPs |
| Ruleset trigger rate | 30.1% | benign diffs that fire at least one non-INFO entry (rule or annotation) |
| Benign flag rate | 6.7% | about **1 in 15** benign corpus diffs exceed the default profile's 20-point threshold |
| Labelled-fixture detection | 100% | 100% of labelled fixtures; not independent recall |
| CRITICAL p5 | 40 | > benign p95 |
| Benign p95 | 30 | < CRITICAL p5 (margin: 10) |
| Tests | Run `uv run --extra dev pytest` for the current checkout | n/a |

The numbers are not aspirational; they are the measured state of the current rule set and scoring model on this corpus and fixture set. CI rejects gate regressions, not changes to an external performance claim.

In one line: 74.0% benign zero-rate, benign p95 = 30 against malicious p5 = 40 on the 8,393-diff locked corpus.

### Reproducible methodology

- **Corpus pinned** via `corpus.lock`: the AUR snapshot is versioned and reproducible. The same lock names the same packages and diffs on any machine, but a rebuild is not byte-stable across git versions (`git diff -W` output moves), so reproducible numbers come from the packed corpus release asset, not a local rebuild.
- **Baseline committed** as `baseline.json`: benchmark results are checked into the repository. Every commit can be compared against the baseline to detect regressions.
- **Regeneration** is monthly: `corpus-drift.yml` downloads the packed corpus release asset (the same bytes `calibration.yml` uses, not a rebuild whose `git diff -W` output is not byte-stable across git versions), re-derives the baseline and compares it against the committed `baseline.json`, filing an issue on any change. Reproducibility comes from that committed baseline plus git history.

The pinned corpus prevents a common failure mode in security tooling: benchmarks that improve over time because the corpus drifted toward easier samples. Pinning freezes the corpus, so any improvement or regression is from the tool, not the data.

### Per-stratum evaluation

The locked corpus is divided into sixteen strata: the original eight (`source_patched`, `bin_repack`, `vcs_git`, `lang_ecosystem`, `data_fonts`, `dkms_kernel`, `autotools`, `large_electron`) plus eight expansion cohorts (`persist_surface`, `signed_sources`, `multi_client_fetch`, `maintainer_churn`, `dependency_heavy`, `vcs_other`, `appimage_repack`, `lang_deep`). The next lock adds a seventeenth, `runtime_carriers`, for committed units, timers, sockets and runtime scripts. Every catalog id is accounted for in `tests/fixtures/coverage-ledger.json` as measured, zero-fire with a reason, cold-only, or adversarial-only; the ledger is the expansion's control panel and is checked by the `coverage ledger is complete` gate. Breaking the corpus down by package shape keeps a rule that is loud on one shape from hiding inside an aggregate rate: `scripts/rebaseline.py` records fire rates per stratum under `strata.<name>.rules` in `baseline.json`, and [Fire Rates](historical-and-behavioral-analysis.md) reports them per rule.

A stratum is selected by packaging shape, never by a rule target. The provenance screen rejects any candidate or diff already on a compromised-package, IOC or watchlist list, and records the `N of M` exclusion count. A `vcs_other` cohort is deliberately labelled low-power because Mercurial/Subversion/Bazaar/Fossil packaging is rare; padding it would measure duplicates, not the ecosystem.

The corpus-level gate is the `>= 30%` benign fire-rate cap (`scripts/calibration_gates.py`): no scoring rule may fire on 30% or more of the benign diffs, so a rule cannot become a census on ordinary packaging.

Per-rule fire rates (false-positive rate of each rule on the benign corpus) are tracked separately in [Fire Rates](historical-and-behavioral-analysis.md). The 74.0% zero-rate means 74.0% of benign diffs score 0, while **6.7% exceed the 20-point threshold**: roughly one reviewer workload item per fifteen benign corpus diffs. A score of 0 and a clean fire record are not the same thing: the largest contributors to the remaining fires are H015 (Build Function Modified, INFO/weight 0, fires on 19.7% of diffs but never moves a score) and R010/R011 (curl/wget in PKGBUILD, LOW, fire on <2%).

### The methodology habit

1. Pool results, get suspicious. If pooled numbers look good, they are hiding a problem.
2. Split by class, find the truth. The real separation is in the tails, not the center.
3. Measure the gap, not the absolute. The gap between classes is the operational metric; absolute scores are meaningless in isolation.
4. Enforce per-stratum, not aggregate. Aggregate recall hides blind spots.

This methodology generalizes beyond TrustSight. Any security tool that claims a recall number should be asked: recall on what class, against what corpus, pinned at what version, and measured against which tail of the benign distribution?

## Benchmark performance

Measured against the TrustSight test corpus.

!!! warning "Two rows measure a narrower configuration"

    The recall rows above were measured with `observation_count` unpopulated, so Tier C novelty contributed zero to every score (see [Cold Start and Maturity](scoring-and-verdicts.md#cold-start-and-maturity)), and against a smaller ruleset than the one documented here. Read them as a floor, not as current recall. The three distribution rows below are re-measured by the calibration gates against the current 8,393-diff corpus on every push.

| Rule | Recall | Notes |
|------|--------|-------|
| CRITICAL class (all) | 100 % | Every CRITICAL-class sample detected. |
| R012 (prompt injection) | 17 % | Tripwire; catches obvious patterns only. Low recall is intentional. |
| R013 (unicode bidi) | 88 % | Misses some bidi variants. |
| Benign zero-rate | 74.0 % | Percentage of benign diffs scoring 0. |
| Benign p95 | 30 | 95th percentile score on benign corpus. |
| CRITICAL p5 | 40 | 5th percentile score on CRITICAL-class corpus. |
