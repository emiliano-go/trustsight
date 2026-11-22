<!-- description: Why TrustSight is an immune-inspired system, how the AUR works as the organism, and how TrustSight and people complete the immune loop. -->

# Why an immune system?

This is a more *personal* page than the other docs: immunology is what drives the tool itself. I've studied it for years as a side interest, and I never expected those concepts to apply to distributed systems, much less to securing them. TrustSight wasn't planned around the immune system; I only recognized the pattern when the G-series took shape. I suspect it grew that way because the AUR and our bodies face similarly shaped problems.

## A comprehensive map of the immunological ideas in TrustSight

TrustSight is an immune-inspired security intelligence system for the Arch User Repository. It builds prior ecosystem knowledge, recognizes suspicious changes, remembers behavior, correlates activity across packages, primes bounded responses to known campaigns, shares threat intelligence, and monitors the reliability and limits of its own analysis.

**The system is a loop.** The AUR is the organism. TrustSight supplies sensing, memory, and correlation. A person supplies judgment, triage, and action; maintainers and Arch volunteers act on reports. The immune system is the loop between those parts, not the software alone.

TrustSight's documentation explicitly uses immunological concepts including **trained immunity, cytokine signalling, cytokine storms, superantigens, autoimmune disease, missing-self recognition, NK cells, opsonization, refractory periods, lateral inhibition, nociception, interoception, anergy, and two-signal activation**. Other mappings, such as the novelty seed as a vaccine or the overall detector stack as innate immunity, are useful architectural interpretations, but should be labelled as analogies rather than literal biology.

---

### How to read the sections that follow

Each section connects an immunological idea to a TrustSight mechanism. Read the connection as a design lineage: the biological principle supplied a way to think about a security problem, and the implementation expresses that thinking in software. Where the documentation explicitly names the connection, the section says so. Where the connection is an architectural interpretation, it is identified as such. The biological language is therefore neither decorative branding nor a claim of literal equivalence.

This page keeps the project's detailed terminology, rule references, examples, limitations, and source links. Its purpose is to make the origin and direction of the design influence easier to recognize while preserving the technical map.

---

## The loop: who is the immune system?

The AUR is the organism. A package update is a cell change. A malicious campaign is a systemic infection. TrustSight is a sensory and memory organ; people are the response.

The unit of protection is the AUR ecosystem, not one machine. A bad update still lands on a user's machine, but the pattern that identifies it may only be visible across thousands of packages, maintainers, and update waves.

| Stage | TrustSight | People and community |
|---|---|---|
| Sense | Rules, diff analysis, the watcher, signed indicators | Read the report and inspect the evidence |
| Remember | Local observation database, the signed seed, the public feed | Incident notes and maintainer history |
| Correlate | G-series cross-package correlation | Recognize the campaign context and affected packages |
| Signal | Findings, campaign alerts, coverage gaps, `self_state` | Prioritise what needs attention |
| Act | Recommendations only; no enforcement | Triage, report, escalate, remove locally; maintainers remove from the repository |
| Learn | New observations and shared feed data | Report outcomes, tune rules, contribute detections |

An alert is not a passive notification. It is the signal that recruits the response. In a system where the effector is a person, signal quality *is* protection.

The decision stays with the user, because only a person can judge context and act.

---

## 1. The vaccine: the novelty seed

**Immunization / priming prior immune memory: signed, AUR-derived novelty seed.**

A fresh TrustSight installation has a cold local observation database. Without prior observations, every source URL and maintainer looks newly encountered. Novelty would therefore be nearly meaningless: even ordinary, common sources would appear novel simply because this particular machine had not seen them.

The novelty seed solves that cold-start problem. It gives a new installation a point-in-time body of historical observations before it performs its first local review. The seed is built from AUR history and published as a signed release asset.

The published seed described in the documentation contains, at the September 24, 2026 snapshot:

- **185,902 normalized source URLs**, with first-seen observations;
- **36,912 hashed maintainer identities**, with package counts and first-seen observations;
- **215,504 dependency/package/provides aliases**.

The seed uses salted hashes for maintainer identities rather than redistributing plaintext identity data.

### Why “vaccine” is a good description

The seed does not contain a whitelist of safe packages. It does not certify that a known URL, maintainer, or dependency is harmless. It supplies prior ecosystem observations so that the detector can distinguish “new to this installation” from “new or unusual in the AUR.”

The analogy is therefore **immune priming**, not a literal vaccine containing a weakened pathogen and not a safety certificate.

The seed is also tightly constrained:

- It is distributed outside the AUR package being inspected, avoiding a circular trust anchor.
- Its detached Ed25519 signature is verified against a pinned public key.
- It is additive: it cannot overwrite observations learned from real local analyses.
- It can set only the metadata keys it owns; it cannot alter rules, patterns, weights, or severities.
- Real local observations take over as they accumulate.

A hostile or forged seed must not be able to fabricate positive findings or rewrite local history. The documented residual risk is narrower: a malicious but validly signed seed could make an attacker's URL or maintainer appear familiar and thereby weaken novelty signals. The additive boundary limits the damage, but the signing key and provenance still matter.

The seed inoculates a cold installation with historical ecosystem familiarity. It primes recognition; it does not prove health.

Sources:
- [Historical and Behavioral Analysis](https://docs.trustsight.org/explanation/historical-and-behavioral-analysis/)
- [Threat Intelligence - Seed Provenance](https://docs.trustsight.org/explanation/threat-intelligence/)
- [Baseline Keys](https://docs.trustsight.org/reference/baseline-keys/)
- [Security Boundaries - A12/A13](https://docs.trustsight.org/security-design/security-boundaries/)

---

## 2. Adaptive immunity: temporal and historical memory

**Adaptive immune memory: the observation database, novelty context, temporal rules, and corpus history.**

TrustSight does not only match static signatures. It remembers what it has previously observed and compares current activity with historical behavior.

Its history can capture:

- whether a URL has appeared before globally or within a particular package;
- whether a maintainer is new to a package or to the observed ecosystem;
- whether a signing key has been seen before;
- whether a maintainer's domain or behavior has changed;
- whether a package has been dormant and is now active again;
- whether ownership, provenance, integrity, or dependency behavior changed before a suspicious payload appeared.

The T-series is explicitly described in immune-memory terms: the same observation store that lets the alerting layer recognize earlier activity also allows temporal rules to detect changes in identity and behavior.

The system uses maturity gates. A cold database does not pretend to know what it has not observed. Novelty weight ramps with effective observations and reaches full weight at 50 observations. A verified seed can provide bootstrap observations, after which real local analyses take over.

The seed primes the system; local observations develop its own memory; temporal rules use that memory to recognize departures from normal behavior.

Sources:
- [Temporal Rules](https://docs.trustsight.org/rules/temporal/)
- [Historical and Behavioral Analysis](https://docs.trustsight.org/explanation/historical-and-behavioral-analysis/)
- [Scoring and Verdicts](https://docs.trustsight.org/explanation/scoring-and-verdicts/)

---

## 3. Innate immunity: immediate threat recognition

**Innate immune recognition: complementary deterministic rule families.**

This is an architectural analogy, not a claim that TrustSight contains literal innate immune cells. Its immediate recognition machinery includes multiple types of deterministic analysis:

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

The important feature is diversity. TrustSight is not simply a large collection of regular expressions. Different mechanisms examine different evidence: commands, structural relationships, history, package metadata, upstream declarations, known indicators, and correlations between packages.

Multiple recognition mechanisms provide complementary sensors, rather than requiring one universal signature detector. A threat has to evade several kinds of sensor, not one signature.

Sources:
- [Rule Series](https://docs.trustsight.org/rules/series/)
- [Evidence Categories](https://docs.trustsight.org/reference/evidence-categories/)
- [Assurance Layers](https://docs.trustsight.org/security-design/assurance-layers/)

---

## 4. Missing-self recognition: NK-cell analogy

**Natural killer (NK) cells recognizing loss of normal self-signals: rules that detect the removal or degradation of expected package properties.**

TrustSight explicitly describes a missing-self axis. The detector does not only ask what suspicious thing was added; it also asks what a package stopped having.

Examples are:

- **T004 - Vouch Surface Removed:** partial removal of `validpgpkeys` without replacement.
- **T005 - Scheme Downgrade:** same source host falls from TLS while the URL path also changes.
- **C033 - Context Bleed:** a diff removes a large fraction of the recipe's comment/prose context.
- **C034 - Metadata Inconsistency:** committed `.SRCINFO` and PKGBUILD disagree on version fields.

The docs make the contrast explicit: G008 watches who arrived; T004/T005 watch what disappeared when they did.

Missing-self detection complements foreign-pattern recognition. A threat can be indicated by the loss of a previously expected trust or identity feature.

Source:
- [Detection and Evidence - Missing-self (NK cells)](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Temporal Rules](https://docs.trustsight.org/rules/temporal/)

---

## 5. Danger over stranger: Matzinger's Danger Theory

**Danger signals matter more than foreignness alone: first-contact observations, contextual tags, and weight-zero evidence.**

TrustSight explicitly references the “danger over stranger” idea associated with Polly Matzinger's Danger Theory.

A new domain is not automatically malicious. A new maintainer is not automatically malicious. A new dependency is not automatically malicious. Unknown is not synonymous with dangerous.

The Contact Ledger records first contacts as contextual observations rather than automatically attacking them with a score. The system seeks stronger evidence of damage, suspicious behavior, or corroborating changes before escalating.

C033 and C034 extend the same philosophy to internal reviewability signals: missing recipe context or inconsistent generated metadata can be a damage signal about the integrity of the review surface without proving that a malicious payload exists.

TrustSight should respond to suspicious evidence, not merely to unfamiliarity.

Source:
- [Detection and Evidence - Danger over stranger](https://docs.trustsight.org/explanation/detection-and-evidence/)

---

## 6. Clonal recognition: the G-series campaign immune system

**Shared antigen recognition and clonal response: cross-package correlation.**

The G-series is the clearest example of ecosystem-level immunity. The documentation says directly that the G-series is TrustSight's immune system, imported from the campaign-alert design.

A single package displaying a suspicious property may be ambiguous. Many unrelated packages gaining the same host, literal, dependency, or coordinated maintainer behavior in a short window can reveal a campaign.

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

A campaign becomes visible when otherwise plausible observations join into one shared pattern. The system can produce one campaign-level alert naming the members instead of N disconnected package alerts.

### Real-world illustration: the October 2026 yay name-clone campaign

The TrustSight incident report says that on October 14, 2026, the watcher raised two clusters:

- 15 newly published names impersonating `yay`;
- 14 names impersonating `brave-beta-bin`, plus a hijacked legitimate `firefox-git-bin`.

The malicious delivery used committed `.install` files while the upstream recipe itself remained byte-intact. The live watcher identified the coordinated activity through G003, H045, and H052. The install-scriptlet payload rules had not caught the carrier during that live cycle; later rule work, including X034, incorporated lessons from the incident.

This is an important demonstration of correlation: the system could recognize coordinated malicious activity from the ecosystem pattern even before its payload-specific detector recognized that exact carrier.

The incident was covered by BleepingComputer on October 15, 2026: [Fake Arch Linux packages push malware with root privileges](https://www.bleepingcomputer.com/news/security/fake-arch-linux-packages-push-malware-with-root-privileges/).

Sources:
- [Correlation Rules](https://docs.trustsight.org/rules/correlation/)
- [October 14, 2026 AUR Name-Clone Waves](https://docs.trustsight.org/reports/2026-10-14-aur-name-clone-waves/)
- [Detection and Evidence](https://docs.trustsight.org/explanation/detection-and-evidence/)

---

## 7. Cytokine signalling: neighborhood elevation

**Alerted cells signal surrounding tissue: G006 - Neighborhood Under Campaign Alert.**

When a campaign is active, packages around it may deserve additional attention even if they have not themselves been corroborated as part of the campaign.

If a package newly gains a host or domain within the campaign's scope, G006 can record that it touches an alerted neighborhood.

Crucially, G006 is weight zero. It is reported as context, not scored as malicious behavior. Merely touching an already-hot host should not inflate the package's risk score or accuse its maintainer.

The documentation explicitly compares this local, temporary readiness signal to cytokine signaling.

A recognized threat can raise awareness in its neighborhood without automatically treating the entire neighborhood as infected.

Source:
- [Detection and Evidence - Neighborhood Elevation](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Correlation Rules - G006](https://docs.trustsight.org/rules/correlation/)

### Bystander activation: G016 account blast radius

A second, weaker field effect appears one level up: when one package on an
account fires a specific payload rule or a FATAL finding, other packages that
the same account had processed in that cycle are **bystanders**. The biology
is bystander activation: antigen-nonspecific cells can be activated by
cytokines during an ongoing response, without direct recognition of the
antigen.

G016 reports that shared-account context. It does not say the account is
compromised and it does not score the siblings. Unregulated bystander
activation can itself cause immune pathology, which is why G016 is weight zero
and anergic rather than a promotion path into the package score.

Source: [Mechanisms governing bystander activation of T cells](https://pmc.ncbi.nlm.nih.gov/articles/PMC11635090/)

---

## 8. Trained immunity: G007 and bounded campaign priming

**Temporary heightened readiness after an earlier infection: G007 and campaign alert mode.**

After a campaign is corroborated, TrustSight can retain its scope for a bounded number of observations. A package later encountered in that scope can receive a G007 corroboration record carrying the campaign ID.

The documentation explicitly calls this “trained immunity.” It is context, not a new risk score.

This state is deliberately bounded:

- the campaign has an observation-clock TTL;
- a campaign expires structurally once its observation lifetime ends;
- active campaign count is capped;
- repeated reactivation is reported through M006;
- expiration is visible rather than silently forgotten.

Past campaign recognition primes the system for a limited period, enabling faster contextual recognition of related activity without creating permanent suspicion.

Source:
- [Correlation Rules - G007](https://docs.trustsight.org/rules/correlation/)
- [Detection and Evidence - Campaign Alert Mode](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [State and Lifecycles](https://docs.trustsight.org/explanation/state-and-lifecycles/)

---

## 9. Opsonization: tag first, clear later

**Complement-mediated tagging that makes later recognition easier: weight-zero events, `tag_panel`, and `TAG_CONVERGENCE`.**

TrustSight groups contextual observations such as:

- first contacts;
- campaign context;
- entropy bumps;
- annotations;
- recognized techniques.

These are not automatically treated as evidence of malice. They are recorded in the report's `tag_panel`. When multiple distinct kinds of tag converge on one diff, `TAG_CONVERGENCE` can produce one bounded informational ledger entry, never a score.

The documentation explicitly describes this as opsonization: “Tag first, clear later.”

Contextual signals mark observations for later interpretation, rather than prematurely turning every mark into an accusation, as noise makes reviewing harder.

Source:
- [Detection and Evidence - Opsonization](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Report Schema](https://docs.trustsight.org/reference/report-schema/)

---

## 10. Sickness behavior: the system changes its posture

**Systemic infection changes the organism's overall behavior: W013, `campaign_hold`, and campaign perimeter context.**

When a campaign perimeter is active, a package inside that perimeter may already have an analysis boundary: an upstream manifest not examined, an unverifiable surface, or a coverage gap.

W013 can make that standing boundary visible in the campaign context until the campaign TTL expires. It does not create new evidence or accuse the package. It makes the system's defensive posture explicit.

The report can also carry `campaign_hold` and `campaign_state` for downstream enforcement systems.

The documentation explicitly describes this as sickness behavior: systemic infection changes the posture of the organism, but fever is not a verdict about an individual cell.

When the ecosystem is under a recognized campaign alert, relevant blind spots and boundaries become more visible across the affected neighborhood.

Source:
- [Detection and Evidence - Sickness Behavior](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Unverifiable Rules - W013](https://docs.trustsight.org/rules/unverifiable/)
- [Report Schema](https://docs.trustsight.org/reference/report-schema/)

---

## 11. Refractory periods: one stimulus, one alert

**A refractory period prevents meaningless repeated firing: persisted campaign alert deduplication.**

TrustSight emits one alert per `(rule, campaign-cell)` per campaign window. The refractory state is part of the cycle audit record, making replay deterministic.

This is not silent suppression. A repeated firing would carry no new information, so the emission layer treats one stimulus as one alert during the same window.

### Lateral inhibition

The rendering side has a related mechanism: when N packages share one campaign finding, the alert names the members once, sorted and deduplicated, rather than rendering N copies.

The documentation explicitly calls this lateral inhibition.

Repeated signals are controlled so that the response remains informative and does not turn into noise.

Source:
- [Detection and Evidence - Refractory Period](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [State and Lifecycles](https://docs.trustsight.org/explanation/state-and-lifecycles/)

---

## 12. Superantigens and cytokine storms: controlling alert overload

**Excessive immune activation can harm the host: alert budgets, W010, campaign caps, and cycle caps.**

TrustSight explicitly compares noisy alert floods to a superantigen. A tool can be turned against a reviewer by filling the screen until important findings are overlooked. The response becomes part of the threat.

TrustSight addresses this with:

- a cap on terminal-rendered findings;
- W010, a visible weight-zero boundary reporting that the cap was reached;
- a per-cycle cap for watcher notifications;
- retention of the complete findings in the JSON record even when terminal output is capped.

It also describes unbounded campaign-neighborhood elevation as a cytokine-storm failure mode. That is why neighborhood alerts are weight zero, contextual, and bounded by campaign lifetime.

Defensive signaling must remain targeted, bounded, and readable. Alert volume itself must never become evidence against one package.

Source:
- [Detection and Evidence - Alert Budget](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Unverifiable Rules - W010](https://docs.trustsight.org/rules/unverifiable/)

---

## 13. Chronic inflammation: M006 and campaign re-arming

**A defensive state that never stands down becomes harmful: M006 - Campaign Re-armed Too Often.**

A campaign can be refreshed when evidence supports it, but repeated reactivation at an excessive rate is itself surfaced as a tool-health observation.

M006 does not simply block reactivation. It reports the churn, helping operators notice when the system is repeatedly entering the same alert state.

The docs compare an unbounded campaign posture to chronic inflammation: the defense can become part of the disease if it never returns to baseline.

Campaigns must expire, and repeated activation must be observable rather than silently becoming permanent suspicion.

Source:
- [Meta and Confluence - M006](https://docs.trustsight.org/rules/meta/)
- [Detection and Evidence - Campaign Alert Mode](https://docs.trustsight.org/explanation/detection-and-evidence/)

---

## 14. Autoimmune disease: self-tolerance and the M-series

**An immune system that attacks its own body: meta and confluence rules M001-M006.**

TrustSight explicitly describes an autoimmune failure mode: the detection system itself can become unreliable, contradictory, noisy, or overreactive.

The M-series analyzes relationships between findings and the health of the detection process rather than merely adding another package-level pattern match.

Examples include:

- contradictions between a declared security practice and structural evidence;
- combinations of multiple evidence layers;
- corroboration across independent rule families;
- expected co-firings that do not occur;
- repeated campaign activation.

### Confluence

The docs describe confluence as a further immune idea: a single immune cell binding an antigen is not enough to launch a full response. In TrustSight, multiple independent signals can provide a stronger basis for escalation than one isolated observation.

The detection system must distinguish a threat to the ecosystem from malfunction or overreaction in its own recognition mechanisms.

Source:
- [Meta and Confluence Rules](https://docs.trustsight.org/rules/meta/)
- [Detection and Evidence - Immune-Inspired Design](https://docs.trustsight.org/explanation/detection-and-evidence/)

---

## 15. Anergy and two-signal activation: new detectors must earn authority

**Anergy / tolerance after incomplete activation: the anergy ledger, weight-zero rules, and explicit promotion.**

A new detection shape is not automatically a calibrated detector.

TrustSight allows an experimental or insufficiently calibrated rule to remain visible while contributing zero scoring weight. It is listed in the anergy ledger with the evidence it is waiting for. Promotion is explicit, measured, and recorded in the changelog.

The documentation calls this **two-signal activation**: the existence of a suspicious-looking pattern is not, by itself, evidence that the detector is ready to carry scoring authority.

The project also records a standing anergy state and has process gates that refuse silent promotion.

Immature recognition mechanisms can observe and learn without immediately launching a full response against the ecosystem.

Source:
- [Detection and Evidence - Two-Signal Activation](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Standards](https://docs.trustsight.org/standards/)
- [Changelog](https://docs.trustsight.org/changelog/)

---

## 16. Nociception: unresolved pain becomes a prioritization signal

**Detecting and communicating pain without necessarily diagnosing tissue damage: the tender-point notice for unresolved review decisions.**

A package with repeated unresolved review verdicts can receive a tender-point notice in the report header: for example, “N unresolved in M months; a human should look once.”

This does not say that the package is broken, and it does not score. It tells a human reviewer that an unresolved issue has accumulated and deserves attention.

The documentation explicitly summarizes the principle as: **pain is prioritization without a damage claim**.

Source:
- [Detection and Evidence - Nociception](https://docs.trustsight.org/explanation/detection-and-evidence/)

---

## 17. Interoception: the system knows its own condition

**Sensing one's own internal state: the `self_state` report block.**

TrustSight exposes its own analysis state rather than expecting users to infer it from silence.

`self_state` can communicate:

- cold/warm mode;
- observation counts;
- ruleset versions;
- channel tags and observation-clock ages;
- federation availability;
- Contact Ledger availability;
- campaign state;
- a sorted list of blind spots.

This prevents a cold database, stale intelligence channel, unavailable subsystem, or unexercised analysis lane from masquerading as a healthy, fully informed system.

The documentation says that an organism unable to feel its own state confuses blindness with safety.

The instrument must report not just what it sees, but also whether its own sensors and memory are available.

Sources:
- [Detection and Evidence - Interoception](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Report Schema](https://docs.trustsight.org/reference/report-schema/)
- [Evidence and Confidence](https://docs.trustsight.org/security-design/evidence-and-confidence/)

---

## 18. Gain control: an immune-inspired mechanism TrustSight deliberately rejected

**Continuously adapting response thresholds to recent signal levels: explicitly rejected as a runtime mechanism.**

TrustSight considered dynamically adapting thresholds to recent signal levels. It rejected that approach because the same package diff could then receive different scores depending on where the observation epoch happened to sit.

That would undermine deterministic reproducibility and cold-replay consistency.

Instead, thresholds are re-derived at release time using a pinned corpus, committed to configuration, and covered by the configuration fingerprint.

This is an important part of the design story: TrustSight does not adopt every biological mechanism. It borrows the useful ideas while rejecting adaptations that would undermine its security invariants.

Source:
- [Detection and Evidence - Rejected: Gain Control](https://docs.trustsight.org/explanation/detection-and-evidence/)

---

## 19. IOC Federation: shared knowledge of known pathogens

**Shared recognition of previously identified threats: signed, curator-attributed IOC baselines.**

The novelty seed, local history, corpus baseline, and IOC federation are distinct kinds of knowledge.

IOC federation supplies concrete known-bad indicators such as:

- domains;
- hashes;
- package names;
- file paths;
- PKGBUILD patterns;
- upstream repository observations.

Independent curators can publish signed indicator sets. TrustSight verifies their signatures, retains provenance and attribution, applies confidence tiers, and preserves expiry information.

IOC matches are reported outside the ordinary heuristic score, at their own alert priority. An expired indicator remains visibly expired rather than silently disappearing.

The system can recognize a previously characterized threat using shared, attributed intelligence rather than having to rediscover it from local behavior.

Source:
- [IOC Federation](https://docs.trustsight.org/reference/ioc/)
- [Indicator Rules](https://docs.trustsight.org/rules/indicator/)
- [Threat Intelligence](https://docs.trustsight.org/explanation/threat-intelligence/)

---

## 20. The Watcher: continuous systemic surveillance

**Ongoing surveillance throughout the organism: `trustsight full-aur --watch`.**

The watcher moves TrustSight beyond local, one-package-at-a-time analysis. It continuously observes AUR changes, analyzes changed packages, maintains historical state, joins cross-package observations, and reports new clusters.

It supports:

- initial bootstrap;
- bounded, resumable cycles;
- incremental delta scans;
- historical replay using `--since`;
- campaign alerts;
- heartbeats;
- health and liveness reporting;
- delivery retries and an alert outbox.

A daily heartbeat distinguishes “nothing new was found” from “the watcher is dead.” A failed delivery is retained and retried rather than silently lost.

The watcher is systemic surveillance, continuously observing the ecosystem rather than waiting for one user to ask about one package.

Sources:
- [Watching the AUR Continuously](https://docs.trustsight.org/workflows/watching-the-aur-continuously/)
- [State and Lifecycles](https://docs.trustsight.org/explanation/state-and-lifecycles/)

---

## 21. The shared immune network: [The Watcher](https://watcher.trustsight.org/)

**Distributed threat awareness and communication: the public TrustSight watcher feed.**

The shared feed at [watcher.trustsight.org](https://watcher.trustsight.org/) receives signed watcher-cycle reports and stores searchable alerts.

The feed repository documents:

- Ed25519 verification of the raw incoming alert document;
- public-key publication for later verification;
- persistent alert storage;
- package, rule, maintainer, IOC, and campaign indexes;
- signed daily Merkle checkpoints;
- API routes for alerts, campaigns, package histories, rule triggers, IOCs, source files, diffs, and verification material.

This allows observations from a deployed watcher to become reusable threat intelligence for people and systems beyond the original machine.

It is more precise to call this a shared threat-surveillance and intelligence network than a literal distributed immune system, but the architectural analogy is strong.

Sources:
- [Watcher](https://watcher.trustsight.org/)
- [trustsight-feed repository](https://github.com/emiliano-go/trustsight-feed)
- [Continuous Watching Documentation](https://docs.trustsight.org/workflows/watching-the-aur-continuously/)

---

## 22. Self-protection: the immune apparatus must not be infected

**Protecting the defense machinery itself: static analysis, bounded reads, sandboxed parsers, and fail-closed behavior.**

TrustSight consumes hostile package-controlled text and metadata. The analysis engine itself is therefore an attack surface.

Its safeguards include:

- never executing a PKGBUILD;
- never fetching an arbitrary URL declared by a package in the default analysis path;
- bounded diff, line, archive, history, and parser work;
- tokenizer and manifest parsing in isolated read-role workers;
- resource limits and kernel-enforced sandboxing where supported;
- refusal when required sandbox guarantees cannot be established;
- visible coverage gaps when part of the evidence cannot be read;
- no clean verdict for an incomplete analysis.

The optional upstream-scan lane is a deliberate exception with strict controls: declared upstreams are allowlisted and pinned; redirects are constrained; checksums are verified; archive reads are bounded; parsing occurs in a read-role sandbox. The optional L9 artifact lane inspects a supplied built-package manifest without being blended into the static score.

This is not a failure to inspect upstream. It is a design that adds upstream and artifact inspection through explicit, bounded lanes rather than executing arbitrary package code to obtain more visibility.

The system must protect its own analysis machinery and preserve its trust boundary while examining adversarial inputs.

Sources:
- [Static Analysis and Resolution](https://docs.trustsight.org/explanation/static-analysis-and-resolution/)
- [Security Model](https://docs.trustsight.org/security-design/security-model/)
- [Security Boundaries](https://docs.trustsight.org/security-design/security-boundaries/)
- [Upstream Manifests](https://docs.trustsight.org/rules/upstream-manifests/)
- [Artifact Rules](https://docs.trustsight.org/rules/artifact/)

---

## 23. Homeostasis: false-positive control and calibration

**Maintaining a responsive but non-destructive equilibrium: maturity gates, calibration corpora, visible suppression, anergy, and evidence boundaries.**

A defense system that attacks everything unfamiliar or generates endless alerts is not healthy.

TrustSight has several explicit mechanisms to avoid that failure:

1. **Maturity gating:** novelty only gains weight as sufficient observations accumulate.
2. **Weight-zero context:** first contacts and campaign-neighborhood touches can be recorded without being scored as malicious.
3. **Anergy:** uncalibrated rules remain visible but do not gain scoring authority.
4. **Visible suppression:** overrides are reported with their reasons and expiration; they are not silent deletion of evidence.
5. **No subtractive weights:** positive-looking practices do not erase suspicious evidence.
6. **True-positive twins:** a false-positive fix must preserve the corresponding malicious case.
7. **Locked benchmarking:** changes are tested against a stable benign corpus and labelled malicious fixtures.
8. **Explicit uncertainty:** incomplete analysis and unavailable sensors are named as boundaries rather than presented as a clean result.

The published benchmark documentation reports 8,393 benign diffs and 213 self-authored labelled malicious fixtures. These are internal regression measurements, not independent real-world efficacy estimates.

Homeostasis is the balance between responsiveness, tolerance, and restraint. The system must defend the ecosystem without treating every unfamiliarity as disease.

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
| Cytokine signalling | G006 neighborhood elevation | Explicitly documented |
| Bystander activation | G016 account blast radius | Interpretive analogy; context only, never a compromise claim |
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

The branding is strongest when the technical boundaries are explicit.

- TrustSight produces evidence and intelligence; it does not automatically remove malicious packages or guarantee that every AUR user is protected.
- The seed is not a whitelist and does not certify a known URL, maintainer, or package as safe.
- G007's trained-immunity analogy is bounded campaign context, not permanent learning of a new detection rule.
- The public watcher distributes observations, but protection still depends on deployment and consumption by local workflows or people.
- Recipe-level static analysis cannot prove the safety of arbitrary upstream source code or runtime behavior. The optional upstream and artifact lanes add controlled inspection; they do not claim omniscience.
- An `UNFLAGGED` result means no published rule matched the evidence examined. It is not a certificate of safety.

These caveats are not flaws in the metaphor. They are part of the same philosophy: a healthy immune system must know what it can see, what it cannot see, and when it should abstain.

Source: [Security Model](https://docs.trustsight.org/security-design/security-model/), [What a Result Claims](https://docs.trustsight.org/security-design/what-a-result-claims/), and [Limitations and Uncertainty](https://docs.trustsight.org/explanation/limitations-and-uncertainty/).

---


## Documentation index

The following pages are the most important primary sources for the immune-system mapping:

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

---
