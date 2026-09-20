<!-- description: What a TrustSight result claims, and what it does not: score determinism, coverage gaps, FATAL handling, suppression, honesty of the prose, and surface parity, B1-B11. -->

# Part B: What the result claims

A TrustSight result is an assertion about **evidence found in a diff**, not a statement about whether a package is safe. The distinction is the whole model, and every clause below is a limit on the claim.

### B1. A score is a sum of matched evidence, nothing more

Determinism is algorithmic, not configurational. The same input, under the same configuration and the same shipped ruleset, always produces the same score and the same breakdown. Changing rules, thresholds or overrides changes the instrument, deliberately, visibly, and at the operator's hand. That is a different instrument, not a nondeterministic one.

**Stored history is part of the instrument, not part of the input.** The novelty and maturity signals read observations this database has accumulated: whether a URL has been seen before, how many analyses a package has, how established a maintainer is. Two machines with the same diff and the same fingerprint can therefore report different scores if their databases hold different history, and the same machine can score a package differently after importing a seed or a baseline. That is the design, not a defect. It is also why a cold database reports **Inconclusive** rather than Low, which is [cold start](../explanation/cold-start-and-maturity.md) in the explanation section, and why A12 and A13 constrain what may write that history.

So the determinism claim is: same diff, same fingerprint, same observation history, same score. The gate holds all three fixed and compares two runs. A differing score with all three fixed is a vulnerability; a differing score across databases is the novelty model working.

Every machine-readable report carries a **config fingerprint**, a hash over the effective ruleset, the scoring weights, the thresholds and the active overrides:

```
"config_fingerprint": "sha256:4f2a..."
```

Every JSON path: `review --json`, `inspect --json`, the API's `to_dict()` and the stored `fact_json` each carry it, which the `every JSON report carries the fingerprint` gate checks by running them rather than by reading them. The first three are one function since [B11](#b11-every-surface-reports-the-same-thing), so the gate exercises that function and the storage serialiser beside it. The terminal renders do not print it, because it is a value for comparing two runs mechanically and not something a person reads off a panel; `--json` is where a consumer that needs it looks.

Two operators comparing results can see immediately whether they are running the same instrument. It also gives Part D's nondeterminism clause a precise meaning: same input and same fingerprint with a different score is a vulnerability; a different fingerprint is a different configuration.

The score is not a probability, not a confidence, and not a prediction. A score of 0 means "no published rule matched the evidence examined", which is exactly as strong as the rule set is, and no stronger. The score is computed on every run so that `--score`, `--json`, coverage logic and CI gating all see the same value: determinism does not depend on how it is displayed.

### B2. An unflagged verdict is never issued for an analysis that was incomplete

Fourteen things make a run partial, and all fourteen are recorded as **coverage gaps** on the result:

| Gap | Meaning |
|-----|---------|
| `diff_truncated` | The diff exceeded `[diff] max_diff_bytes`, so only its prefix was examined. |
| `scan_truncated` | The diff held more lines than `rules.MAX_SCANNED_LINES`, so only its first lines were matched. Separate from `diff_truncated` because the caps are separate: matching costs per line, so a diff of many short lines passes the byte cap and is still cut here (A5, A14). |
| `line_truncated` | A logical line exceeded `rules.MAX_RULE_LINE_BYTES`, so its tail was not matched against any rule (A5). |
| `tree_not_analyzed` | The repository file manifest was unavailable, so only the PKGBUILD was examined. |
| `companion_truncated` | A committed file the recipe names - and copies into `$srcdir`, executes, sources or patches by path - was larger than `differ.MAX_COMPANION_BYTES`, or there were more of them than `MAX_COMPANION_FILES`, so its content was not matched against any rule (A5, A14). |
| `unresolved_source` | A `source=` entry is computed at build time (including a `$(...)` on a continuation line of a multi-line `source=()` array), so the URL the build will actually fetch is not in the analysed text. |
| `unresolved_parse_time` | A top-level command substitution runs while makepkg *sources* the PKGBUILD for metadata, so part of the recipe executes and produces a value before any rule reads it. |
| `snapshot_refused` | The snapshot archive exceeded `full_aur.fetch.MAX_TAR_MEMBER_BYTES` and was refused, so the committed file tree was not examined and the PKGBUILD came from the text endpoint instead (A4, A14). |
| `unpinned_build_deps` | A build function resolves dependencies from a package registry (`npm install`, `pip install`, `cargo fetch`, …), so the code the build will fetch and execute is not in the analysed text and no checksum in the recipe covers it. |
| `deps_not_scanned` | The AUR dependency walk stopped before the closure was exhausted - a ceiling cut it short, or a dependency could not be analysed - so some packages this build will pull in were never read. |
| `stage_degraded` | An analysis stage raised on this input and returned a neutral value, so the checks it performs did not run over all of the change. Recorded by `coverage.note_stage_failure` from the handler itself. |
| `history_truncated` | The history walk (`--last N`) stopped before yielding the requested N results: a ceiling was reached, the run diff budget was exhausted, or the repository had fewer content-bearing commits than requested. Attached to the newest result, with the run-level count also reported (A14). |
| `ruleset_drifted` | The installed `rules.toml` differs from the shipped rule set in a field that changes what a rule detects, so this analysis did not run the checks this version documents. |
| `noextract_suppressed` | `noextract=()` suppresses extraction of specific source archives, so their contents were not available for rule matching. |

`companion_truncated` is separate from `diff_truncated` for the reason `scan_truncated` is: they point at different dials. A companion is read on its own budget, and a reader told only "the diff was truncated" would raise `max_diff_bytes` and find it changed nothing. The bound itself is not the interesting part - every bound drops content. What made this one a vulnerability rather than a limit was that it dropped content *and said nothing*, so a payload past 64 KiB in a committed `Makefile` scored identically to a package with no companions at all.

`stage_degraded` covers the other kind of shortfall. The fourteen gaps above are all *anticipated* - a configured bound was reached, a value was not statically resolvable - and each one is raised by the code that knows it hit the limit. `stage_degraded` is raised where a stage that was meant to run could not: an unbalanced quote that makes `shlex` refuse a `source=` array, a git walk that raises part-way, a blob past the streaming ceiling. Every one of those handlers returned a neutral value, which reads identically to a stage that ran and found nothing, so the shortfall was invisible in the verdict. It fires on 0 of the 3,739 diffs in the locked benign corpus, which is the property that makes it worth reading: it means something went wrong, not that the input was unusual.

`deps_not_scanned` is the dependency walk's half of the same honesty. An AUR package's `depends` and `makedepends` can name other AUR packages, and `makepkg` builds those on the reviewer's machine in the same run, so a review that reads only the package you typed has read one recipe out of several that will execute. `--depth` decides how far the walk goes, and each dependency is analysed *as a package* - its own score, its own band, its own row in the database - never folded into the parent's number, because `depth` is deliberately absent from the config fingerprint and a score that moved with a flag would break [B1](#b1-a-score-is-a-sum-of-matched-evidence-nothing-more) for anyone comparing two runs.

The gap is recorded when the walk stopped **early**, and only then. `--depth 1` completing is a complete answer to the question the operator asked, even though a level 2 exists; treating a bounded walk as incomplete coverage would make every default run report a gap and teach the reader to ignore it. What does earn the gap is a walk cut short by `depth.MAX_DEPTH_LEVELS` or `depth.MAX_DEPTH_NODES`, or a dependency whose own analysis failed. Those ceilings exist because the dependency graph is written by the party under review: a recipe declaring five hundred AUR `makedepends`, each declaring five hundred more, would otherwise decide how many repositories this machine clones, which is the A14 breach and the Part D vulnerability. `--depth -1` therefore means "as deep as it goes, and it tells you when it stopped", not "unbounded".

`unpinned_build_deps` is the gap the June 2026 AUR campaign would have tripped on every one of the ~1,500 packages it hijacked, and it is worth being precise about why it is a gap and not a rule. `makepkg` verifies `source=()` against `sha256sums`; it verifies nothing about a dependency a build step resolves at build time. When `prepare()` runs `npm install foo`, the bytes that arrive are whatever the registry serves at that moment, and the code that will execute on the reviewer's machine is simply not in the text being analysed. That is a missing sensor.

It cannot be a scored rule, because `npm install` inside a build function is what thousands of legitimate AUR packages do - which is precisely why the attack was invisible, and why H035 is scoped to install hooks with a calibration gate keeping it there. A rule would either blow the 30% benign fire-rate ceiling or have to be weighted into meaninglessness. A gap makes no accusation at all: it says the analysis could not see what the build will run, which is equally true of the attack and of every honest Node package. Scoring it would be a claim the evidence does not support; hiding it is the quiet skip B2 exists to prevent. Measured against the locked benign corpus the gap fires on 0.3% of diffs, because it keys on a *change* that introduces a registry resolution rather than on the recipe's steady state.

`snapshot_refused` travels *with* `tree_not_analyzed` rather than instead of it, and the pairing is deliberate. A refused archive and a package that simply has no snapshot both fall back to the same cgit text fetch and both leave the tree unexamined, so on the fallback alone they are indistinguishable. `tree_not_analyzed` says the tree was not read; `snapshot_refused` says a bound in this program is why. A14 requires a bound that drops content to be visible as a bound, and "the manifest was unavailable" would read as an absent tarball - which is the quiet-skip substitution B2 exists to prevent, one layer down.

The `unresolved_*` pair are the same underlying fact seen from two angles: TrustSight does not source the PKGBUILD (A1: the input is not code), so it never sees what a `$(...)` evaluates to. `unresolved_source` names the case where that value flows into a `source=` entry, so the URL the build will fetch is unknowable; `unresolved_parse_time` names a top-level `$(...)` anywhere else, which makepkg still runs the moment it sources the file for metadata, before any build step. A `$(...)` inside `pkgver()` or `build()` is **not** a gap: it runs at build time, in a function whose body TrustSight reads as text and matches rules against, so nothing about it is unseen; only substitutions that execute at *source* time produce a value the static read cannot recover.

A gap adds no points: it is not evidence about the package, and scoring it would corrupt the calibration. What it does is constrain how the result may be presented, in two ways that work together.

**First, a gap forbids an unflagged verdict.** A run with any gap and no HIGH or worse finding is reported as **Inconclusive**, never as Low or Medium. A run whose score falls in the Low or Medium range is demoted to Inconclusive by the gap; a band that scores High is kept but is shown as an incomplete analysis wherever it appears (`High (incomplete analysis)`), never as a bare High. This closes the padding bypass. Without it, padding a diff past the size cap and appending the payload turns a High into a Low, and the evasion reads as "looks fine". The taxonomy explains why: a gap is a missing sensor, and a missing sensor is a signal that must reach the panel.

**Second, a gap always travels with the band.** A HIGH, CRITICAL or FATAL finding does keep its band, because hiding a confirmed finding behind "inconclusive" would lose the thing that matters most. The seam is defined, because an attacker's move is obvious once the rules are published: pad the diff past the cap, put the real payload after the cut, and include one cheap deliberate HIGH in the visible prefix. The verdict then reads "High", which is a confident-looking answer, and the reviewer's attention lands on the decoy instead of the fact that most of the change was never read.

So no human-facing render ever shows a bare band for an incomplete run; the band is qualified wherever it appears:

```
Score: 75/100 (High (incomplete analysis))
```

and the gap itself is listed, naming which part was not examined. `Inconclusive` is not qualified, because it already says the same thing.

Default does not mean optional. Hiding the band by default must not become a way to skip the qualification when `--score` is passed: the moment a band is shown, it is shown qualified.

Machine output keeps the two facts separate rather than in a sentence: `risk` is the bare band, `coverage_gaps` is the list, and `risk_label` is the qualified string for consumers that want to display it. **A consumer gating on `risk` alone, without reading `coverage_gaps`, reintroduces the seam.** That is stated in [using TrustSight in CI](../guides/using-in-ci.md), which treats a non-empty `coverage_gaps` as blocking.

**Where the threshold comes from.** UNFLAGGED is at or below 20 points (`scoring.FLAG_THRESHOLD`). The number is stated here because a reader cannot otherwise tell whether it is measured or chosen, and the honest answer is: it was measured, then the measurement moved underneath it.

Twenty was originally the 95th percentile of the benign corpus. It is not any more. Against the locked 3,739-diff corpus as currently calibrated:

| Measure | Value |
|---------|-------|
| benign median | 0 |
| benign 95th percentile | 35 |
| benign diffs scoring 0 | 68.4% |
| benign diffs above 20 | 13.1% |
| percentile that 20 now sits at | 86.9th |
| malicious 5th percentile | 60 |
| malicious minimum | 40 |

So about one benign diff in eight lands above the threshold: in practice a reviewer running `trustsight review` should expect to look manually at roughly one in eight benign updates it flags, and the tool is built to make that look cheap (evidence first, the score on request) rather than to drive the number to zero. That rate is a direct and intended consequence of [B10](#b10-positive-evidence-is-reported-never-credited): declared checksums, PGP keys and trusted-forge hosting subtract nothing, so no package can declare its way under 20.

The property the calibration gates actually enforce is the one that matters for separation: **benign p95 (35) stays below malicious p5 (60)**, a margin of 25. Twenty remains the published threshold because moving it is a calibration decision with its own evidence, not a bookkeeping fix to keep a sentence true.

**The 13.1% benign flag rate is a security property, not just a workload characteristic.** About one in eight benign updates flagging means a reviewer who hits several in a row is reading mostly noise, and a reviewer who skims because seven of eight flags were benign is precisely the fatigue failure [B9](#b9-no-output-grants-permission-to-skip-review) spends a section preventing structurally. The separation metric (p95 35 < p5 60) is the gate that matters for detection quality; it does not bound what the reader will still be reading at month three. This rate is accepted because the alternative - subtractive weights that let a package declare its way under the threshold - would corrupt the calibration (see [B10](#b10-positive-evidence-is-reported-never-credited)), and because the tool's design (evidence first, score on request) makes each individual flag cheap to triage. But the rate itself is a cost the model imposes on the reviewer, and a reviewer who stops reading carefully is a failure mode the model does not currently bound.

Be precise about what is automated here. `scripts/calibration_gates.py` re-computes **benign p95 and malicious p5 on every push** and fails the build if they cross. The other figures in the table above are a point-in-time measurement, not a per-push one; they are published in [fire rates](../explanation/fire-rates.md) and have to be re-derived with `scripts/rebaseline.py` when scoring changes. A number in this table is only as current as the last person who ran that script.

### B3. Inconclusive is not presented as UNFLAGGED

`Inconclusive` is produced in two situations:

1. The score landed in the Medium band (21 to 50), `maturity()` is below 0.5, and no HIGH, CRITICAL or FATAL entry is in the breakdown. Maturity ramps linearly to 1.0 at `scoring._MATURITY_THRESHOLD` observations, which is **50**, so "below 0.5" means **fewer than 25 recorded analyses** for that package. See [cold start and maturity](../explanation/cold-start-and-maturity.md).
2. The analysis had a coverage gap, per B2. This applies at any maturity.

In both cases the tool is saying it could not form a picture, not that the picture is good.

### B4. FATAL cannot be switched off

A FATAL finding caps the score at 100 and is never suppressible, whichever of the two surfaces tries:

- **At the finding surface.** A FATAL finding is never suppressed by an override, whatever `overrides.toml` says. `add_override` refuses to create such an override, and the filter ignores one added by hand.
- **At the rules surface.** A FATAL rule this build ships cannot be removed or downgraded by editing `rules.toml`. If the on-disk file drops it or lowers its severity, the shipped definition is used for the run and a warning is logged. Nothing is written back - your file stays your file, you just do not get an analysis that pretends the rule was never there.

The protected set is derived from the shipped rules, not hardcoded in this page. Today it is **R012** (prompt injection) and **R013** (unicode deception). H056 (exact match against a shipped `iocs.toml` indicator) also reaches FATAL at its **confirmed** confidence tier: each `iocs.toml` entry carries a confidence tier, and the `confirmed` tier maps to FATAL while weaker tiers map to lower severities, so an unsourced entry cannot quietly acquire a confirmed entry's weight. H056 is emitted from code rather than from `rules.toml`. This is the legacy exact-match rule and is distinct from the unscored IOC federation layer in [A13b](program-under-attack.md#part-a-trustsight-as-a-program-under-attack).

The reason these two in particular are locked: the payload targets the *reviewer*, not the machine. A run that skips them has no tuning justification; its output cannot be trusted at all.

### B5. Suppression is always visible

A suppressed finding is returned and reported, never discarded. A silent suppression is indistinguishable from a missed detection, and those two must never look the same to a reviewer: one means a rule was switched off on purpose, the other means the tool failed.

**No flag hides it.** `suppressed_rules` is emitted unconditionally on every JSON path. Behind `--verbose` it would be absent from the default machine-readable output with nothing to say so, which gives the consumer least able to notice the plainest possible reason to think nothing had been switched off. The `suppression is never hidden by a flag` gate fails the build if the key is moved back under a verbosity branch.

### B6. What a result does not claim

- **It does not claim the package is safe.** It claims no published rule matched the evidence it examined. An UNFLAGGED result is a *detection outcome*, not a certificate - absence of alerts is not a statement about airworthiness.
- **It does not claim the ruleset is complete.** Fire rates and known gaps are published in [fire rates](../explanation/fire-rates.md) and enforced by `scripts/calibration_gates.py`. Detection has documented ceilings.
- **It does not claim runtime behaviour was observed.** Nothing is executed.
- **It does not claim the build will fetch what the recipe says.** Where that cannot be determined statically, B2 applies.
- **The exit code is not a verdict.** `trustsight review` exits 0 when the analysis completed and 2 when it could not. A package that flags is reported in the output, not in the exit status. Gate CI on the JSON, as [using TrustSight in CI](../guides/using-in-ci.md) shows.

### B7. A result reports what changed, not only what fired

A report made only of findings cannot distinguish "nothing fired and nothing changed" from "nothing fired and a great deal changed". Absence of alerts then reads as absence of change, which is the collapse the taxonomy already forbids one layer down.

Every result carries a **change summary** beside its findings: the declared facts about what the diff did, whether or not a rule matched. Version moves, checksum behaviour, files added, removed or renamed, dependency changes, maintainer changes, source host changes, and the no-change case (`no changes in the AUR since last review (commit 8646e821)`). `.SRCINFO` and `.gitignore` are suppressed: they regenerate on nearly every bump, and listing them trains the reader to skim the section.

Change entries are **not findings**. They carry no severity, no points, and never appear in `triggered_rules`; conflating the two would corrupt both the calibration and the reader's sense of what a finding is. In JSON they are a separate `changes` array, sibling to `findings` and `coverage_gaps`, so a consumer reading only `findings` is unaffected.

### B8. A finding is checkable

Every finding that matches file content carries `file` and `line`. A finding the reader can open and confirm in five seconds is a different object from an assertion they must trust, and that is the difference between an instrument reading and an opinion.

Rules that legitimately cannot report a location (maintainer, temporal, graph, corpus) declare an **evidence class** instead, in `findings.NON_CONTENT_RULES`. Silently omitting the field is not permitted: a missing location must not be indistinguishable from a rule that forgot to set one.

### B9. No output grants permission to skip review

No rendered output states or implies that reading the diff is unnecessary, **including when nothing fired**. The trivial case states a fact, it does not issue a clearance:

```
some-pkg 1.2.3-1 -> 1.2.4-2
  Only pkgver and sha256sums changed.
  Review the diff before building.
```

Forbidden: "clean", "safe", "no issues", "looks fine", "nothing to review", or any phrasing whose plain reading is *you may proceed*.

Enforced **structurally rather than lexically**. Every terminal render of a result ends with a direction to review, and the gate asserts the presence of that direction rather than the absence of a phrasing. A wording the denylist never anticipated cannot bypass a check that requires something to be there. The denylist is retained as a secondary check for the obvious cases.

The denylist covers **template text only**. Substituted field values are package-controlled, and a package legitimately named `safe-rs` or `clean-arch` must not fail the build or trip a check. This is [A7](program-under-attack.md#the-invariants)'s separation applied to B9: templates are code-owned and checked, fields are package-owned and never checked.

This is a verdict-integrity bound, not a style preference. The rest of Part B bounds what a *score* may claim; this bounds what the *prose* may claim, and the prose is what most readers act on. An UNFLAGGED band with a reassuring sentence beside it defeats B6 regardless of what B6 says.

### B10. Positive evidence is reported, never credited

Verification and hardening signals (declared checksums, `validpgpkeys`, GPG signature sources, pinned commits, trusted-forge sources) are emitted as **INFO findings with weight 0** in the `P` namespace. They appear in the report in their own group, and in the machine-readable `score_breakdown`; the JSON `findings` array carries weighted findings only, so a weight-0 declared practice is not in it. They do not enter the score in either direction.

**Why weight 0 rather than a credit.** Everything TrustSight sees is attacker-declared. Adding `validpgpkeys=(...)`, pinning a `#commit=`, or routing through github.com costs an attacker nothing, and TrustSight never fetches, so it never confirms that a declared key signs anything or that a pinned commit contains what it claims. A signal an attacker can trivially assert must not be able to lower a score: the only reliable effect of such a mechanism is buying points back for whoever bothers to read the rules.

Reporting it is still worth doing. The reader can verify these claims in ways TrustSight cannot, and "this package declares GPG verification" is genuinely useful context for a human decision. That is the division of labour the whole model rests on.

They are called **declared-practice findings**, not benign rules. They do not establish that anything is benign; they report that the recipe declares a practice.

**Why there are no subtractive weights.** Nothing subtracts: not `checksum_present`, `validpgpkeys_declared`, `gpg_verify_present`, `checksum_pinned`, `tag_pinned`, nor trusted-forge hosting. The calibration problem a subtraction appears to solve, a package doing GPG verification scoring worse than one doing nothing because SKIP on a `.asc` file added points, is fixed at source instead: H001 does not fire on a SKIP that is mandatory for a VCS source, structurally uncheckable for a signature file, or covered by declared PGP keys. The right fix was to stop the false positive, not to pay it back.

**Presentation.** They render in their own group, visually distinct from risk findings and never as a running total:

```
Declared verification
  PKGBUILD:24   validpgpkeys declared
  PKGBUILD:22   a signature source accompanies a source, with PGP keys declared
  PKGBUILD:11   source pinned to a full commit hash

  TrustSight does not verify these claims. It reports that the recipe makes them.
```

That last line serves as the finding's actual content, not a disclaimer. Without it the group reads as a safety certificate, which is the failure this page exists to prevent.

Not all of them are emitted every time. Seventeen INFO lines on every package buries the risk findings, which is the opposite of what the group is for, so the default set is the ones a reader would find surprising by their absence and the rest render under `--verbose`.

Declared practices that depend on corpus or longitudinal state follow the same cold-start discipline as their risk-side counterparts: silent when there is no history, never reporting "unchanged since first observation" when the answer is "nothing observed yet". Those are also the ones an attacker cannot fake cheaply: `validpgpkeys` can be added in a single commit, two years of stable maintainership in your local database cannot.

### B11. Every surface reports the same thing

TrustSight has three machine-readable surfaces - `review --json`, `inspect --json`, and the Python API's `to_dict()` - and one terminal render. A guarantee that holds on one of them and not the others is not a guarantee; it is a property of whichever path the check happened to exercise. So the surfaces differ in **form** and never in **information**, in three parts.

**The body is one body.** All three JSON paths render through `reporting.report_body`, and every key in `reporting.REPORT_KEYS` is present on every one of them, with the same value for the same result. The divergence this forecloses is concrete, not hypothetical: three paths building three dicts invite two naming conventions between them (`package` against `package_name`, `score` against `final_score`) and an API body carrying no `findings` at all while its docstring claims to be what the CLI writes. A consumer could then be written against one path and silently miss evidence on another, which is [B2](#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete)'s failure one layer up: not content skipped without a gap, but a whole field absent without anything saying so.

**The score is available on request, never volunteered.** The `Not headline-shaped` guarantee is about what the tool leads with, and it is worthless to a machine consumer if the JSON leads with the number anyway. `score`, `risk` and `risk_label` (`reporting.SCORE_KEYS`) are absent from every default body and present in all of them when asked for: `--score` or `--risk` on the CLI, `include_score=True` on the API, which is the same act spelled for a different caller. Per-finding `weight` travels with the breakdown under `--verbose` / `verbose=True`, because a weight is score arithmetic. Withholding the number withholds nothing else: `findings`, `changes`, `coverage_gaps`, `suppressed_rules` and `verdict` are in the default body on every surface, so the evidence is what a caller gets for free and the verdict is what they have to ask for.

Reading an attribute is not the same act. `report.score` is always populated, because naming the field *is* the request; what `to_dict()` will not do is hand the number to a caller who only asked to serialise the result.

**One analysis underneath.** The API is an adapter, not an implementation. It reaches a package through the entry points the CLI uses - `review.analyze_outdated_batch`, `review.discover_packages`, `analysis.analyze_package`, `full_aur.analyze.analyze_package_text` - and derives meaning through `reporting.evaluate_fact`. It computes no score of its own: importing `calculate_score`, `apply_rules` or `risk_level`, or reaching the rule engine, the differ or the tokenizer directly, fails the build. A second pipeline would be free to drift while every behavioural parity check kept passing on whichever surface it happened to exercise.

**And the terminal is a surface.** Comparing JSON with JSON says nothing about what a reviewer actually reads, and a reviewer reads whichever of the four renders their terminal gave them. So a field the body carries may not be dropped by a render: the coverage gap ([B2](#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete)), the suppressed rule ([B5](#b5-suppression-is-always-visible)) and the change summary ([B7](#b7-a-result-reports-what-changed-not-only-what-fired)) are each asserted on all four. Each of those three already had a gate, and each gate was aimed at the layer where the value is *set* rather than at the renders that have to show it - so all three were, in fact, false somewhere: `inspect` reported nothing about a partial read unless a band was requested, `review` carried suppressions only in its JSON body, and `inspect` without Rich had no change summary at all.

The gates are behavioural where the property is about values and structural where it is about reachability, and the body gates run through the surfaces a caller actually reaches rather than through the shared helper: comparing `report_body` with itself would prove only that it equals itself. The render gate loops over all four renderers for the same reason `terminal output is inert` does.
