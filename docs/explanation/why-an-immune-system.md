<!-- description: Why TrustSight is an immune-inspired system, how the AUR works as the organism, and how TrustSight and people complete the immune loop. -->

# Why an immune system?

This page is more personal than the rest of the docs. I've studied immunology for years as a side interest, and I never expected it to explain anything about distributed systems, let alone security. TrustSight wasn't designed around the immune system. I noticed the pattern when the G-series came together. I think it grew that way because the AUR and the body run into similar shapes of trouble.

## A comprehensive map of the immunological ideas in TrustSight

TrustSight is an immune-inspired security intelligence system for the Arch User Repository. It accumulates prior ecosystem knowledge, recognizes suspicious changes, remembers behavior, correlates activity across packages, primes bounded responses to known campaigns, shares threat intelligence, and watches its own analysis for blind spots.

It supplies the sensing, memory, and correlation. People supply judgment, triage, and action; maintainers and Arch volunteers act on reports. The immune system is the loop between them, not the software alone.

The design borrows immunological concepts by name: trained immunity, cytokine signaling, cytokine storms, superantigens, autoimmune disease, missing-self recognition, NK cells, opsonization, refractory periods, lateral inhibition, nociception, interoception, anergy, and two-signal activation. Other mappings, such as the novelty seed as a vaccine or the detector stack as innate immunity, are interpretations. They are not literal biology.

Each section pairs an immunological idea with the mechanism it informed. Where the docs name the link, I say so; where it is my interpretation, I say that.

## The loop: who is the immune system?

The AUR is the organism. A package update is a cell change. A malicious campaign is a systemic infection. TrustSight is a sensory and memory organ; people are the response.

The unit of protection is the AUR ecosystem, not one machine. A bad update still lands on a user's machine, but the pattern that identifies it may only be visible across thousands of packages, maintainers, and update waves.

| Stage | TrustSight | People and community |
|---|---|---|
| Sense | Rules, diff analysis, the watcher, signed indicators | Read the report and inspect the evidence |
| Remember | Local observation database, the signed seed, the public feed | Incident notes and maintainer history |
| Correlate | G-series cross-package correlation | Recognize the campaign context and affected packages |
| Signal | Findings, campaign alerts, coverage gaps, `self_state` | Prioritize what needs attention |
| Act | Recommendations only; no enforcement | Triage, report, escalate, remove locally; maintainers remove from the repository |
| Learn | New observations and shared feed data | Report outcomes, tune rules, contribute detections |

An alert is the signal that recruits the response. In a system where the effector is a person, signal quality is protection.

The decision stays with the user, because only a person can judge context and act.

---

## 1. The vaccine: the novelty seed

A new TrustSight install has a cold local observation database. Without prior observations, every source URL and maintainer looks new. Novelty would mean almost nothing, because ordinary sources would look novel just because this machine had not seen them.

The novelty seed fixes that. It gives a new install a point-in-time body of AUR history before the first local review, and it ships as a signed release asset.

At the September 24, 2026 snapshot, the published seed contains:

- 185,902 normalized source URLs, with first-seen observations;
- 36,912 hashed maintainer identities, with package counts and first-seen observations;
- 215,504 dependency, package, and provides aliases.

Maintainer identities are salted hashes. The seed does not redistribute plaintext identity data.

### Why "vaccine" fits

The seed is not a whitelist of safe packages. It does not certify that a URL, maintainer, or dependency is harmless. It supplies prior observations so the detector can tell "new to this installation" apart from "new or unusual in the AUR."

The analogy is immune priming, not a vaccine with a weakened pathogen and not a safety certificate.

The seed is tightly constrained:

- It is distributed outside the AUR package being inspected, so it does not create a circular trust anchor.
- Its detached Ed25519 signature is verified against a pinned public key.
- It is additive; it cannot overwrite observations learned from real local analyses.
- It can set only the metadata keys it owns. It cannot change rules, patterns, weights, or severities.
- Real local observations take over as they accumulate.

A forged seed must not be able to fabricate positive findings or rewrite local history. The residual risk is narrower: a malicious but validly signed seed could make an attacker's URL or maintainer look familiar and weaken novelty signals. The additive boundary limits the damage, but the signing key and provenance still matter.

The seed gives a cold install historical familiarity. It primes recognition; it does not prove health.

Sources:
- [Historical and Behavioral Analysis](https://docs.trustsight.org/explanation/historical-and-behavioral-analysis/)
- [Threat Intelligence - Seed Provenance](https://docs.trustsight.org/explanation/threat-intelligence/)
- [Baseline Keys](https://docs.trustsight.org/reference/baseline-keys/)
- [Security Boundaries - A12/A13](https://docs.trustsight.org/security-design/security-boundaries/)

---

## 2. Adaptive immunity: temporal and historical memory

TrustSight does not only match static signatures. It remembers what it has seen and compares current activity with past behavior.

Its history can capture:

- whether a URL has appeared before globally or within a package;
- whether a maintainer is new to a package or to the observed ecosystem;
- whether a signing key has been seen before;
- whether a maintainer's domain or behavior has changed;
- whether a package was dormant and is active again;
- whether ownership, provenance, integrity, or dependency behavior changed before a suspicious payload appeared.

The T-series uses the same observation store as the alerting layer. That store lets temporal rules detect changes in identity and behavior, not just earlier activity.

Novelty has maturity gates. A cold database does not pretend to know what it has not observed. Novelty weight climbs with effective observations and reaches full weight at 50 observations. A verified seed can provide bootstrap observations, after which local analyses take over.

The seed primes the system. Local observations build its own memory, and temporal rules use that memory to spot departures from normal behavior.

Sources:
- [Temporal Rules](https://docs.trustsight.org/rules/temporal/)
- [Historical and Behavioral Analysis](https://docs.trustsight.org/explanation/historical-and-behavioral-analysis/)
- [Scoring and Verdicts](https://docs.trustsight.org/explanation/scoring-and-verdicts/)

---

## 3. Innate immunity: immediate threat recognition

The immediate rules work like innate recognition. That is an architectural analogy, not a claim that TrustSight has immune cells. The machinery is deterministic:

| TrustSight mechanism | What it recognizes |
|---|---|
| R-series | Known dangerous command and payload patterns |
| C-series | Structural invariants and integrity changes |
| H-series | Behavioral and contextual suspicion |
| D-series | Dependency-graph and naming anomalies |
| S-series | Destructive or sabotaging behavior |
| X-series | Evasion and attempts to defeat analysis |
| E-series | Statistical abnormalities in added content |
| T-series | Temporal and historical anomalies |
| G-series | Correlated behavior across packages |
| I-series | Exact matches against signed indicators |
| U-series | Declared upstream manifests and release surfaces |
| A-series | Optional artifact and built-package inspection |

The diversity matters. This is not a pile of regular expressions. The rules look at commands, structural relationships, history, package metadata, upstream declarations, known indicators, and correlations between packages. A threat has to evade several kinds of detector, not one signature.

Sources:
- [Rule Series](https://docs.trustsight.org/rules/series/)
- [Evidence Categories](https://docs.trustsight.org/reference/evidence-categories/)
- [Assurance Layers](https://docs.trustsight.org/security-design/assurance-layers/)

---

## 4. Missing-self recognition: NK-cell analogy

The missing-self idea maps to rules that notice what a package stopped having, not just what it added.

Examples:
- T004 (Vouch Surface Removed): partial removal of `validpgpkeys` without replacement.
- T005 (Scheme Downgrade): the same source host falls from TLS while the URL path also changes.
- C033 (Context Bleed): a diff removes a large fraction of the recipe's comment or prose context.
- C034 (Metadata Inconsistency): committed `.SRCINFO` and PKGBUILD disagree on version fields.

G008 watches who arrived; T004 and T005 watch what disappeared when they did.

Missing-self detection complements foreign-pattern recognition. A threat can show up as the loss of a trust or identity feature that used to be there.

Source:
- [Detection and Evidence - Missing-self (NK cells)](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Temporal Rules](https://docs.trustsight.org/rules/temporal/)

---

## 5. Danger over stranger: Matzinger's Danger Theory

This is Polly Matzinger's danger model. A new domain, maintainer, or dependency is not automatically malicious. Unknown does not mean dangerous.

The Contact Ledger records first contacts as context. It does not attack them with a score. The system waits for damage, suspicious behavior, or corroborating changes before escalating.

C033 and C034 apply the same idea to internal review surfaces. Missing recipe context or inconsistent generated metadata can signal damage to the review surface without proving that a malicious payload exists.

TrustSight responds to evidence, not to unfamiliarity.

Source:
- [Detection and Evidence - Danger over stranger](https://docs.trustsight.org/explanation/detection-and-evidence/)

---

## 6. Clonal recognition: the G-series campaign immune system

The G-series came out of the campaign-alert design, and it behaves most like an ecosystem-level immune response.

One package with a suspicious property can be ambiguous. Many unrelated packages gaining the same host, literal, dependency, or coordinated maintainer behavior in a short window can reveal a campaign.

G-series mechanisms include:

| Rule | Campaign signal |
|---|---|
| G001 | Shared gained host |
| G002 | Shared added literal |
| G003 | Coordinated adoption |
| G004 | Shared upstream dependency |
| G005 | Impersonation campaign |
| G006 | Neighborhood under campaign alert (context) |
| G007 | Campaign corroboration / trained-immunity context |
| G008 | First-seen account adoption burst |
| G009 | Watchlisted subject |
| G010 | Shared first-seen host |
| G011 | Maintainer package-creation burst |
| G012 | Shared payload signal |
| G013 | Shared fetch target |
| G014 | Shared adoption window |
| G015 | Sleeper adoption campaign |

A campaign becomes visible when otherwise plausible observations join one shared pattern. TrustSight can then produce one campaign-level alert naming the members instead of N disconnected package alerts.

### The October 2026 yay name-clone campaign

On October 14, 2026, the watcher raised two clusters:

- 15 newly published names impersonating `yay`;
- 14 names impersonating `brave-beta-bin`, plus a hijacked legitimate `firefox-git-bin`.

The malicious delivery used committed `.install` files while the upstream recipe stayed byte-intact. The live watcher identified the coordinated activity through G003, H045, and H052. The install-scriptlet payload rules had not caught the carrier during that live cycle; later rule work, including X034, took lessons from the incident.

Correlation caught the campaign before the payload detector recognized the carrier.

BleepingComputer reported the incident on October 15, 2026: [Fake Arch Linux packages push malware with root privileges](https://www.bleepingcomputer.com/news/security/fake-arch-linux-packages-push-malware-with-root-privileges/).

Sources:
- [Correlation Rules](https://docs.trustsight.org/rules/correlation/)
- [October 14, 2026 AUR Name-Clone Waves](https://docs.trustsight.org/reports/2026-10-14-aur-name-clone-waves/)
- [Detection and Evidence](https://docs.trustsight.org/explanation/detection-and-evidence/)

---

## 7. Cytokine signaling: neighborhood elevation

When a campaign is active, packages around it may deserve attention even if they are not corroborated members.

If a package newly gains a host or domain within the campaign's scope, G006 can record that it touches an alerted neighborhood.

G006 has weight zero. It is context, not a malicious score. Touching an already-hot host should not inflate a package's risk or accuse its maintainer.

This is the cytokine-like move: a recognized threat raises readiness in nearby tissue without treating the whole neighborhood as infected.

Source:
- [Detection and Evidence - Neighborhood Elevation](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Correlation Rules - G006](https://docs.trustsight.org/rules/correlation/)

### Bystander activation: G016 account blast radius

One level up, a weaker field effect appears. When one package on an account fires a specific payload rule or a FATAL finding, other packages that the same account processed in that cycle are bystanders. The biology is bystander activation: antigen-nonspecific cells can be activated by cytokines during an ongoing response without direct recognition of the antigen.

G016 reports that shared-account context. It does not say the account is compromised, and it does not score the siblings. Unregulated bystander activation can itself cause immune pathology, which is why G016 has weight zero and stays anergic instead of feeding the package score.

Source: [Mechanisms governing bystander activation of T cells](https://pmc.ncbi.nlm.nih.gov/articles/PMC11635090/)

### Apoptosis and anoikis: the sandbox worker

The worker lifecycle is the engineering analogue of apoptosis. A death is
staged, not incidental: a detector stops intake, one effector writes a
bounded corpse record, then the process group and pipes are released. The
corpse is discoverable by contract, not by a crash trace.

Anoikis is the closest sub-analogue for the anchorage check. The worker
checks its own anchors on every loop: effective uid, cwd, `no_new_privs`,
network namespace, and a root that was read-only at spawn. Losing one is a
death signal, because results produced after detachment are unaudited. The
pool also has a restart-intensity contract: three failed replacements in a
minute stop it, rather than restarting a deterministic failure forever.

This is a design note, not a rule. No package is scored because a worker
died, and the corpse is one silent record rather than an alert cascade.

Source: [Where, O Death, Is Thy Sting?](https://pmc.ncbi.nlm.nih.gov/articles/PMC2894370/), [Anoikis](https://pmc.ncbi.nlm.nih.gov/articles/PMC11401975/)

---

## 8. Trained immunity: G007 and bounded campaign priming

After a campaign is corroborated, TrustSight can keep its scope for a bounded number of observations. A package later found in that scope can get a G007 corroboration record carrying the campaign ID.

This is the trained-immunity part. It is context, not a new risk score.

The state is bounded:

- the campaign has an observation-clock TTL;
- a campaign expires once its observation lifetime ends;
- active campaign count is capped;
- repeated reactivation is reported through M006;
- expiration is visible, not silently forgotten.

Past campaign recognition primes the system for a while and speeds up contextual recognition of related activity. It does not create permanent suspicion.

Source:
- [Correlation Rules - G007](https://docs.trustsight.org/rules/correlation/)
- [Detection and Evidence - Campaign Alert Mode](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [State and Lifecycles](https://docs.trustsight.org/explanation/state-and-lifecycles/)

---

## 9. Opsonization: tag first, clear later

Tagging works like opsonization: mark the observation, interpret it later.

TrustSight groups contextual observations such as:

- first contacts;
- campaign context;
- entropy bumps;
- annotations;
- recognized techniques.

None of these is automatically evidence of malice. They go into the report's `tag_panel`. When several distinct kinds of tag converge on one diff, `TAG_CONVERGENCE` can produce one bounded informational ledger entry, never a score.

This is opsonization in the design's terms: "Tag first, clear later."

Tagging keeps observations available without turning noise into an accusation.

Source:
- [Detection and Evidence - Opsonization](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Report Schema](https://docs.trustsight.org/reference/report-schema/)

---

## 10. Sickness behavior: the system changes its posture

When a campaign perimeter is active, a package inside it may already have an analysis boundary: an upstream manifest not examined, an unverifiable surface, or a coverage gap.

W013 can make that boundary visible in the campaign context until the campaign TTL expires. It does not create evidence or accuse the package. It makes the defensive posture explicit.

The report can also carry `campaign_hold` and `campaign_state` for downstream enforcement systems.

This is sickness behavior: the organism changes posture during a systemic infection, but fever is not a verdict about one cell.

Source:
- [Detection and Evidence - Sickness Behavior](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Unverifiable Rules - W013](https://docs.trustsight.org/rules/unverifiable/)
- [Report Schema](https://docs.trustsight.org/reference/report-schema/)

---

## 11. Refractory periods: one stimulus, one alert

TrustSight emits one alert per `(rule, campaign-cell)` per campaign window. The refractory state is part of the cycle audit record, so replay stays deterministic.

One alert per stimulus is enough; a repeat would add no information.

### Lateral inhibition

When N packages share one campaign finding, the alert names the members once, sorted and deduplicated, instead of rendering N copies.

That is lateral inhibition. Repeated signals stay informative instead of turning into noise.

Source:
- [Detection and Evidence - Refractory Period](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [State and Lifecycles](https://docs.trustsight.org/explanation/state-and-lifecycles/)

---

## 12. Superantigens and cytokine storms: controlling alert overload

Noisy alert floods are the superantigen problem. A tool can be turned against a reviewer by filling the screen until the important findings disappear. The response becomes part of the threat.

TrustSight addresses that with:

- a cap on terminal-rendered findings;
- W010, a visible weight-zero boundary reporting that the cap was reached;
- a per-cycle cap for watcher notifications;
- retention of the full findings in the JSON record even when terminal output is capped.

It also treats unbounded campaign-neighborhood elevation as a cytokine-storm failure. Neighborhood alerts stay weight zero, contextual, and bounded by campaign lifetime.

Defensive signaling has to stay targeted, bounded, and readable. Alert volume must never become evidence against one package.

Source:
- [Detection and Evidence - Alert Budget](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Unverifiable Rules - W010](https://docs.trustsight.org/rules/unverifiable/)

---

## 13. Chronic inflammation: M006 and campaign re-arming

A campaign can be refreshed when evidence supports it. Repeated reactivation at an excessive rate is itself a tool-health observation.

M006 does not simply block reactivation. It reports the churn, so operators can see that the system keeps entering the same alert state.

An unbounded campaign posture is chronic inflammation: the defense becomes part of the disease if it never returns to baseline.

Campaigns expire. Repeated activation stays observable instead of silently becoming permanent suspicion.

Source:
- [Meta and Confluence - M006](https://docs.trustsight.org/rules/meta/)
- [Detection and Evidence - Campaign Alert Mode](https://docs.trustsight.org/explanation/detection-and-evidence/)

---

## 14. Autoimmune disease: self-tolerance and the M-series

The M-series is the autoimmune check. The detection system itself can become unreliable, contradictory, noisy, or overreactive.

M-series rules look at relationships between findings and the health of the detection process. They do not just add another package-level pattern match.

Examples include:

- contradictions between a declared security practice and structural evidence;
- combinations of multiple evidence layers;
- corroboration across independent rule families;
- expected co-firings that do not occur;
- repeated campaign activation.

### Confluence

Confluence is the same idea: one immune cell binding an antigen is not enough to launch a full response. In TrustSight, several independent signals can support escalation better than one isolated observation.

The detector has to tell a threat to the ecosystem apart from malfunction or overreaction in its own recognition.

Source:
- [Meta and Confluence Rules](https://docs.trustsight.org/rules/meta/)
- [Detection and Evidence - Immune-Inspired Design](https://docs.trustsight.org/explanation/detection-and-evidence/)

---

## 15. Anergy and two-signal activation: new detectors must earn authority

A new detection shape is not a calibrated detector.

TrustSight lets an experimental or insufficiently calibrated rule stay visible while adding zero scoring weight. The anergy ledger records what evidence the rule is waiting for. Promotion is explicit, measured, and recorded in the changelog.

This is two-signal activation: a suspicious-looking pattern is not, by itself, enough for a detector to carry scoring authority.

The project records a standing anergy state and has process gates that refuse silent promotion. Immature recognition can observe and learn without launching a full response.

Source:
- [Detection and Evidence - Two-Signal Activation](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Standards](https://docs.trustsight.org/standards/)
- [Changelog](https://docs.trustsight.org/changelog/)

---

## 16. Nociception: unresolved pain becomes a prioritization signal

A package with repeated unresolved review verdicts can get a tender-point notice in the report header, for example: "N unresolved in M months; a human should look once."

That does not say the package is broken, and it does not score. It tells a reviewer that an unresolved issue has piled up and deserves attention.

The principle is pain as prioritization without a damage claim.

Source:
- [Detection and Evidence - Nociception](https://docs.trustsight.org/explanation/detection-and-evidence/)

---

## 17. Interoception: the system knows its own condition

TrustSight reports its own analysis state instead of leaving users to infer it from silence.

`self_state` can communicate:

- cold or warm mode;
- observation counts;
- ruleset versions;
- channel tags and observation-clock ages;
- federation availability;
- Contact Ledger availability;
- campaign state;
- a sorted list of blind spots.

That keeps a cold database, stale channel, unavailable subsystem, or unexercised analysis lane from looking like a healthy, fully informed system.

An instrument that cannot feel its own state confuses blindness with safety. The report has to say not just what it sees, but whether its sensors and memory are available.

Sources:
- [Detection and Evidence - Interoception](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Report Schema](https://docs.trustsight.org/reference/report-schema/)
- [Evidence and Confidence](https://docs.trustsight.org/security-design/evidence-and-confidence/)

---

## 18. Gain control: an immune-inspired mechanism TrustSight rejected

TrustSight considered adapting thresholds to recent signal levels. It rejected that because the same diff could then score differently depending on where the observation epoch sat.

That would break deterministic reproducibility and cold-replay consistency.

Instead, thresholds are re-derived at release time from a pinned corpus, committed to configuration, and covered by the configuration fingerprint.

TrustSight does not adopt every biological mechanism. It borrows the useful ideas and rejects adaptations that would undermine its security invariants.

Source:
- [Detection and Evidence - Rejected: Gain Control](https://docs.trustsight.org/explanation/detection-and-evidence/)

---

## 19. IOC Federation: shared knowledge of known pathogens

The novelty seed, local history, corpus baseline, and IOC federation are different kinds of knowledge.

IOC federation supplies concrete known-bad indicators such as:

- domains;
- hashes;
- package names;
- file paths;
- PKGBUILD patterns;
- upstream repository observations.

Independent curators can publish signed indicator sets. TrustSight verifies the signatures, keeps provenance and attribution, applies confidence tiers, and preserves expiry.

IOC matches are reported outside the ordinary heuristic score, at their own alert priority. An expired indicator stays visibly expired instead of disappearing.

The system can recognize a known threat from shared, attributed intelligence instead of rediscovering it from local behavior.

Source:
- [IOC Federation](https://docs.trustsight.org/reference/ioc/)
- [Indicator Rules](https://docs.trustsight.org/rules/indicator/)
- [Threat Intelligence](https://docs.trustsight.org/explanation/threat-intelligence/)

---

## 20. The Watcher: continuous systemic surveillance

The watcher moves TrustSight beyond one package at a time. It watches AUR changes, analyzes changed packages, keeps historical state, joins cross-package observations, and reports new clusters.

It supports:

- initial bootstrap;
- bounded, resumable cycles;
- incremental delta scans;
- historical replay using `--since`;
- campaign alerts;
- heartbeats;
- health and liveness reporting;
- delivery retries and an alert outbox.

A daily heartbeat separates "nothing new was found" from "the watcher is dead." A failed delivery is kept and retried instead of silently lost.

The watcher is continuous surveillance of the ecosystem, not a wait for one user to ask about one package.

Sources:
- [Watching the AUR Continuously](https://docs.trustsight.org/workflows/watching-the-aur-continuously/)
- [State and Lifecycles](https://docs.trustsight.org/explanation/state-and-lifecycles/)

---

## 21. The shared immune network: [The Watcher](https://watcher.trustsight.org/)

The shared feed at [watcher.trustsight.org](https://watcher.trustsight.org/) receives signed watcher-cycle reports and stores searchable alerts.

The feed repository documents:

- Ed25519 verification of the raw incoming alert document;
- public-key publication for later verification;
- persistent alert storage;
- package, rule, maintainer, IOC, and campaign indexes;
- signed daily Merkle checkpoints;
- API routes for alerts, campaigns, package histories, rule triggers, IOCs, source files, diffs, and verification material.

Observations from a deployed watcher become reusable threat intelligence for people and systems beyond the original machine.

It is a shared threat-surveillance network rather than a literal distributed immune system, but the architectural analogy holds.

Sources:
- [Watcher](https://watcher.trustsight.org/)
- [trustsight-feed repository](https://github.com/emiliano-go/trustsight-feed)
- [Continuous Watching Documentation](https://docs.trustsight.org/workflows/watching-the-aur-continuously/)

---

## 22. Self-protection: the immune apparatus must not be infected

TrustSight reads hostile package-controlled text and metadata, so the analysis engine is an attack surface.

Its safeguards:

- never executing a PKGBUILD;
- never fetching an arbitrary URL declared by a package in the default analysis path;
- bounded diff, line, archive, history, and parser work;
- tokenizer and manifest parsing in isolated read-role workers;
- resource limits and kernel-enforced sandboxing where supported;
- refusal when required sandbox guarantees cannot be established;
- visible coverage gaps when part of the evidence cannot be read;
- no clean verdict for an incomplete analysis.

The optional upstream-scan lane is a deliberate exception with strict controls: declared upstreams are allowlisted and pinned; redirects are constrained; checksums are verified; archive reads are bounded; parsing runs in a read-role sandbox. The optional L9 artifact lane reads a supplied built-package manifest without blending it into the static score.

The design adds upstream and artifact inspection through explicit lanes instead of executing arbitrary package code to get more visibility.

Sources:
- [Static Analysis and Resolution](https://docs.trustsight.org/explanation/static-analysis-and-resolution/)
- [Security Model](https://docs.trustsight.org/security-design/security-model/)
- [Security Boundaries](https://docs.trustsight.org/security-design/security-boundaries/)
- [Upstream Manifests](https://docs.trustsight.org/rules/upstream-manifests/)
- [Artifact Rules](https://docs.trustsight.org/rules/artifact/)

---

## 23. Homeostasis: false-positive control and calibration

A defense system that attacks everything unfamiliar, or floods the screen, is not healthy.

TrustSight uses several checks. Novelty gains weight only after enough observations. First contacts and campaign-neighborhood touches stay weight zero. Uncalibrated rules stay in anergy. Suppressions are reported with reasons and expiry. Positive-looking practices do not subtract evidence. A false-positive fix must keep a true-positive twin. Changes are tested against a locked benign corpus and labeled malicious fixtures. Incomplete analysis is named as a boundary.

At the last published count, the benchmark has 8,393 benign diffs and 213 self-authored labeled malicious fixtures. These are internal regression numbers, not independent estimates of real-world efficacy.

Homeostasis is the balance between responsiveness, tolerance, and restraint. The system defends the ecosystem without treating every unfamiliarity as disease.

Sources:
- [Benchmarks and Methodology](https://docs.trustsight.org/reports/benchmarks-and-methodology/)
- [Fire Rates](https://docs.trustsight.org/reports/fire-rates/)
- [Tuning False Positives](https://docs.trustsight.org/workflows/tuning-false-positives/)
- [What a Result Claims](https://docs.trustsight.org/security-design/what-a-result-claims/)

---

## 24. The biological foundations and their architectural translations

| Biological principle or concept | TrustSight architectural translation | Relationship to biology |
|---|---|---|
| Vaccine / inoculation | Novelty seed | Interpretive analogy; primes historical familiarity, not a safety whitelist |
| Adaptive immunity | Historical and temporal analysis | Explicitly described as immune memory |
| Innate immunity | Immediate structural and behavioral detection | Architectural analogy |
| Missing-self recognition | T004, T005, C033, C034 | Explicitly documented |
| NK cells | Recognition of missing expected properties | Explicitly documented analogy |
| Danger Theory | Danger over stranger; Contact Ledger | Explicitly documented |
| Clonal recognition | G-series campaign correlation | Explicitly documented |
| Cytokine signaling | G006 neighborhood elevation | Explicitly documented |
| Bystander activation | G016 account blast radius | Interpretive analogy; context only, never a compromise claim |
| Apoptosis / anoikis | Sandbox worker teardown and restart budget | Engineering analogue; staged death, corpse record and anchorage loss, not a rule claim |
| Trained immunity | G007 and campaign priming | Explicitly documented |
| Opsonization / complement | Weight-zero tags and `tag_panel` | Explicitly documented |
| Sickness behavior | W013 and campaign-wide posture | Explicitly documented |
| Refractory period | Per-campaign alert debounce | Explicitly documented |
| Lateral inhibition | Shared campaign finding deduplication | Explicitly documented |
| Superantigen | Alert-volume overload | Explicitly documented |
| Cytokine storm | Unbounded neighborhood elevation | Explicitly documented failure mode |
| Chronic inflammation | Repeated campaign reactivation / M006 | Explicitly documented analogy |
| Autoimmune disease | Meta-series self-tolerance | Explicitly documented |
| Confluence | Multiple independent signals agreeing | Explicitly documented |
| Anergy | Weight-zero uncalibrated rules | Explicitly documented |
| Two-signal activation | Evidence plus calibration before promotion | Explicitly documented |
| Nociception | Tender-point notice for unresolved reviews | Explicitly documented |
| Interoception | `self_state` and blind-spot reporting | Explicitly documented |
| Gain control | Runtime adaptive thresholds | Explicitly rejected to preserve determinism |
| Shared immunity | IOC federation and public watcher | Strong systems analogy |
| Self-protection | Sandboxing and bounded analysis | Strong systems analogy |
| Homeostasis | Calibration and false-positive control | Synthesis of several mechanisms |

---

## 25. What the analogy does not claim

The boundaries are part of the design:

- TrustSight produces evidence and intelligence. It does not automatically remove malicious packages or guarantee that every AUR user is protected.
- The seed is not a whitelist and does not certify a URL, maintainer, or package as safe.
- G007's trained-immunity analogy is bounded campaign context, not permanent learning of a new detection rule.
- The public watcher distributes observations, but protection still depends on deployment and consumption by local workflows or people.
- Recipe-level static analysis cannot prove the safety of arbitrary upstream source code or runtime behavior. The optional upstream and artifact lanes add controlled inspection; they do not claim omniscience.
- An `UNFLAGGED` result means no published rule matched the evidence examined. It is not a certificate of safety.

A healthy immune system knows what it can see, what it cannot see, and when to abstain.

Source: [Security Model](https://docs.trustsight.org/security-design/security-model/), [What a Result Claims](https://docs.trustsight.org/security-design/what-a-result-claims/), and [Limitations and Uncertainty](https://docs.trustsight.org/explanation/limitations-and-uncertainty/).

---

## Primary sources

1. [Detection and Evidence - Immune-Inspired Design](https://docs.trustsight.org/explanation/detection-and-evidence/)
2. [Correlation Rules](https://docs.trustsight.org/rules/correlation/)
3. [Meta and Confluence Rules](https://docs.trustsight.org/rules/meta/)
4. [Temporal Rules](https://docs.trustsight.org/rules/temporal/)
5. [Historical and Behavioral Analysis](https://docs.trustsight.org/explanation/historical-and-behavioral-analysis/)
6. [Threat Intelligence and Seed Provenance](https://docs.trustsight.org/explanation/threat-intelligence/)
7. [State and Lifecycles](https://docs.trustsight.org/explanation/state-and-lifecycles/)
8. [IOC Federation](https://docs.trustsight.org/reference/ioc/)
9. [Evidence Categories and Assurance Layers](https://docs.trustsight.org/reference/evidence-categories/)
10. [Security Model](https://docs.trustsight.org/security-design/security-model/)
11. [Security Boundaries](https://docs.trustsight.org/security-design/security-boundaries/)
12. [Watching the AUR Continuously](https://docs.trustsight.org/workflows/watching-the-aur-continuously/)
13. [October 14, 2026 AUR Name-Clone Waves](https://docs.trustsight.org/reports/2026-10-14-aur-name-clone-waves/)
14. [Benchmarks and Methodology](https://docs.trustsight.org/reports/benchmarks-and-methodology/)
15. [Standards](https://docs.trustsight.org/standards/)
16. [Complete Changelog](https://docs.trustsight.org/changelog/)
