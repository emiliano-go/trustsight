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

A vaccine works by giving the immune system a safe preview of an antigen. The antigen is the thing the immune system learns to recognize. An adjuvant is the extra signal that tells the innate system the antigen matters. The first exposure primes the response, and a later exposure produces a faster, stronger one. That is the useful part of the analogy. The seed gives a new install a preview of the AUR's common shapes, so the first local review is not starting from zero.

At the September 24, 2026 snapshot, the published seed contains:

- 185,902 normalized source URLs, with first-seen observations;
- 36,912 hashed maintainer identities, with package counts and first-seen observations;
- 215,504 dependency, package, and provides aliases.

Maintainer identities are salted hashes. The seed does not redistribute plaintext identity data.

The seed is not a whitelist of safe packages. It does not certify that a URL, maintainer, or dependency is harmless. It supplies prior observations so the detector can tell "new to this installation" apart from "new or unusual in the AUR."

Calling it a vaccine is a shorthand, and a loose one. There is no weakened pathogen and no adjuvant. There is a signed body of historical observations. The accurate word is priming, or an antigen library. The seed teaches the novelty layer what ordinary looks like before the first local review.

The seed is tightly constrained:

- It is distributed outside the AUR package being inspected, so it does not create a circular trust anchor.
- Its detached Ed25519 signature is verified against a pinned public key.
- It is additive; it cannot overwrite observations learned from real local analyses.
- It can set only the metadata keys it owns. It cannot change rules, patterns, weights, or severities.
- Real local observations take over as they accumulate.

A forged seed must not be able to fabricate positive findings or rewrite local history. The residual risk is narrower: a malicious but validly signed seed could make an attacker's URL or maintainer look familiar and weaken novelty signals. The additive boundary limits the damage, but the signing key and provenance still matter.

The seed also has a time problem of its own. A vaccine trains the immune system against a pathogen that may still exist. The seed describes the AUR at one moment, and the AUR moves. A maintainer who was ordinary in September may be hostile in December. A source that was rare may become common. The seed is a starting point, not a permanent definition of normal.

That is why local observations take over. The seed gives the cold install a first layer, and the local database replaces it as the install sees more. The novelty weight ramps with effective observations and reaches full weight at 50. A verified seed can supply bootstrap observations, but it cannot keep the system at the bootstrap stage.

The seed gives a cold install historical familiarity. It primes recognition; it does not prove health.

Sources:
- [Historical and Behavioral Analysis](https://docs.trustsight.org/explanation/historical-and-behavioral-analysis/)
- [Threat Intelligence - Seed Provenance](https://docs.trustsight.org/explanation/threat-intelligence/)
- [Baseline Keys](https://docs.trustsight.org/reference/baseline-keys/)
- [Security Boundaries - A12/A13](https://docs.trustsight.org/security-design/security-boundaries/)

Further reading: [Vaccine](https://en.wikipedia.org/wiki/Vaccine), [Immunization](https://en.wikipedia.org/wiki/Immunization), [Adjuvant](https://en.wikipedia.org/wiki/Adjuvant), and [Immunological memory](https://en.wikipedia.org/wiki/Immunological_memory).

---

## 2. Adaptive immunity: temporal and historical memory

Adaptive immunity is the slow, specific branch. B cells and T cells are selected by what they bind. The ones that fit are expanded, and some become memory cells. A later encounter with the same antigen produces a faster response because the clone is already there. The system does not remember every possible pathogen. It remembers the ones it met.

TrustSight remembers the AUR it has seen. The observation database stores the source URLs, maintainer identities, signing keys, dependency relationships, and package histories that the temporal rules compare against. A maintainer who has owned a package for years is different from a maintainer who appeared last week, and the difference is only visible if the history exists.

Its history can capture:

- whether a URL has appeared before globally or within a package;
- whether a maintainer is new to a package or to the observed ecosystem;
- whether a signing key has been seen before;
- whether a maintainer's domain or behavior has changed;
- whether a package was dormant and is active again;
- whether ownership, provenance, integrity, or dependency behavior changed before a suspicious payload appeared.

The T-series uses the same observation store as the alerting layer. A signing-key change, a maintainer change, a dormant package waking up, or a source host that has never appeared before can all be checked against the store. The rule does not need to know the payload. It needs to know what normal looked like for this package.

Novelty has maturity gates. A cold database does not pretend to know what it has not observed. Novelty weight climbs with effective observations and reaches full weight at 50 observations. A verified seed can provide bootstrap observations, after which local analyses take over. The ramp is the software version of affinity maturation: the response gets stronger as the evidence accumulates, and it does not start at full strength on a hunch.

There is a useful distinction between the seed and the local database. The seed is a snapshot of the ecosystem. The local database is what this installation has actually seen. A seed can make a new install useful on day one, but it cannot tell the install what changed yesterday. That is the difference between inherited memory and lived memory.

The adaptive analogy has a limit. B and T cells are selected against antigens, and the selection is physical. TrustSight selects rules and observations, not cells. A local database can be thin, stale, or poisoned by a bad observation. The seed can be validly signed and still describe a hostile history. The system does not have a thymus that deletes self-reactive clones. It has calibration, explicit promotion, and the ability to revise a rule.

The seed primes the system. Local observations build its own memory, and temporal rules use that memory to spot departures from normal behavior.

Sources:
- [Temporal Rules](https://docs.trustsight.org/rules/temporal/)
- [Historical and Behavioral Analysis](https://docs.trustsight.org/explanation/historical-and-behavioral-analysis/)
- [Scoring and Verdicts](https://docs.trustsight.org/explanation/scoring-and-verdicts/)

Further reading: [Adaptive immune system](https://en.wikipedia.org/wiki/Adaptive_immune_system), [Clonal selection](https://en.wikipedia.org/wiki/Clonal_selection), [Affinity maturation](https://en.wikipedia.org/wiki/Affinity_maturation), [Memory B cell](https://en.wikipedia.org/wiki/Memory_B_cell), and [Plasma cell](https://en.wikipedia.org/wiki/Plasma_cell).

---

## 3. Innate immunity: immediate threat recognition

Innate immunity is fast and broad. It does not learn a specific pathogen the way adaptive immunity does. It recognizes molecular shapes that usually mean danger: pathogen-associated molecular patterns on microbes, damage-associated molecular patterns from stressed or dying cells, and the absence of normal self-signals. The receptors are germline-encoded, and they cover classes of threat rather than one strain.

The immediate rules work the same way. They do not need a named malware family. They need a command shape, a structural break, a behavioral pattern, or an unresolved construct. The machinery is deterministic:

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

The receptor families in immunology are a useful comparison. Toll-like receptors recognize conserved microbial structures. NOD-like receptors sense intracellular damage and microbial products, and some assemble the inflammasome. RIG-I-like receptors recognize viral RNA. The cGAS-STING pathway senses misplaced DNA. Each family covers a different compartment and a different kind of evidence. A pathogen that hides from one can still trigger another.

TrustSight's families are not receptors. They are rule sets, and they run on text. But the design logic is similar. R, H, C, and X cover different evidence surfaces. C watches structure. H watches behavior. R watches known dangerous commands. X watches the attempt to keep a command from resolving. A package that avoids one still has to pass the others.

The diversity matters. This is not a pile of regular expressions. The rules look at commands, structural relationships, history, package metadata, upstream declarations, known indicators, and correlations between packages. A threat has to evade several kinds of detector, not one signature.

The analogy has two limits. First, innate immunity is a biological system with cells, receptors, and signaling. TrustSight has none of those. Second, not every rule family is innate. The T-series is memory, the G-series is correlation, and the I-series is exact known-threat matching. Calling the whole rule set innate would flatten the distinctions the rest of this page is trying to make.

The C-series is a good example of the difference between a receptor and a rule. A tight junction does not recognize a pathogen. It maintains a barrier, and the loss of the barrier is the signal. C033 and C034 do something similar for the review surface. They do not need a payload. They need the structure to be wrong.

Sources:
- [Rule Series](https://docs.trustsight.org/rules/series/)
- [Evidence Categories](https://docs.trustsight.org/reference/evidence-categories/)
- [Assurance Layers](https://docs.trustsight.org/security-design/assurance-layers/)

Further reading: [Innate immune system](https://en.wikipedia.org/wiki/Innate_immune_system), [Pattern recognition receptor](https://en.wikipedia.org/wiki/Pattern_recognition_receptor), [Pathogen-associated molecular pattern](https://en.wikipedia.org/wiki/Pathogen-associated_molecular_pattern), [Damage-associated molecular pattern](https://en.wikipedia.org/wiki/Damage-associated_molecular_pattern), [Macrophage](https://en.wikipedia.org/wiki/Macrophage), and [Dendritic cell](https://en.wikipedia.org/wiki/Dendritic_cell).

---

## 4. Missing-self recognition: NK-cell analogy

Natural killer cells do not only look for a foreign antigen. They look for the absence of MHC class I, the molecule that tells the immune system a cell is self. Many viruses downregulate MHC class I to hide from cytotoxic T cells. NK cells catch that move because the loss of the self-marker is itself a signal. The missing-self hypothesis is the idea that the absence can be more informative than the presence.

T004 is the cleanest software example. A package that used to carry `validpgpkeys` loses it without a replacement. The source may still be the same, and the build may still work. The trust surface that told the user which key was expected is gone. T005 is the same shape with a different surface: the same source host falls from TLS while the URL path changes. The connection is still there, but the expected security property is not.

C033 and C034 extend the idea to reviewability. C033 removes a large fraction of the recipe's comment or prose context. The commands may be valid, but the reviewer has lost the explanation around them. C034 makes the committed `.SRCINFO` and the PKGBUILD disagree on version fields. The package is presenting two different selves.

G008 watches who arrived. T004 and T005 watch what disappeared when they did. The contrast is the point. A new maintainer or a new domain is a presence signal. A removed key surface or a downgraded scheme is an absence signal. The first asks who is new. The second asks what the package stopped proving.

Missing-self detection complements foreign-pattern recognition. A threat can show up as the loss of a trust or identity feature that used to be there. It can also show up as a new feature that does not belong. The two axes cover different failure modes.

NK cells are educated by their inhibitory receptors. A cell that fails to engage the inhibitory receptor is a candidate for killing, but the response depends on the balance of activating and inhibitory signals. The missing-self signal is not a simple absence detector. It is an absence interpreted against a repertoire.

The NK analogy has limits. NK cells are educated against self-MHC, and the missing-self signal is interpreted through activating and inhibitory receptors. TrustSight has no such education. A removed `validpgpkeys` line can be a legitimate cleanup, a key rotation, or a packaging simplification. The rule reports the loss; the reviewer decides what it means.

Source:
- [Detection and Evidence - Missing-self (NK cells)](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Temporal Rules](https://docs.trustsight.org/rules/temporal/)

Further reading: [Natural killer cell](https://en.wikipedia.org/wiki/Natural_killer_cell), [Missing self](https://en.wikipedia.org/wiki/Missing_self), [MHC class I](https://en.wikipedia.org/wiki/MHC_class_I), and [Killer-cell immunoglobulin-like receptor](https://en.wikipedia.org/wiki/Killer-cell_immunoglobulin-like_receptor).

---

## 5. Danger over stranger: Matzinger's Danger Theory

Polly Matzinger's danger model changed the question immunology was asking. The older view was that the immune system distinguishes self from non-self. The danger model says the immune system responds to danger signals, which can come from pathogens or from damaged tissue. A foreign molecule without a danger signal may be ignored. A damaged self-tissue can trigger a response without a pathogen.

The model is contested, and it is not the whole story. But it is useful for TrustSight because it explains why unfamiliarity alone is a weak signal. A new domain is not automatically malicious. A new maintainer is not automatically malicious. A new dependency is not automatically malicious. Unknown does not mean dangerous.

DAMPs are the damage side of the model. They include molecules released by dying cells, such as ATP, HMGB1, and mitochondrial DNA. Alarmins are a related class of signals that recruit and activate immune cells. The innate system can respond to a damaged tissue without knowing which pathogen, or whether there is one.

The Contact Ledger records first contacts as context. It does not attack them with a score. The system waits for damage, suspicious behavior, or corroborating changes before escalating. That is the software version of a danger signal: something has to be wrong, not just new.

C033 and C034 apply the same idea to internal review surfaces. Missing recipe context or inconsistent generated metadata can signal damage to the review surface without proving that a malicious payload exists. The damage is to the reviewability of the package, not to the user's machine. The distinction matters because the response is different. A malicious payload needs containment. A damaged review surface needs a human to look.

The innate immune system has a similar split between pathogen-associated and damage-associated patterns. PAMPs say "a microbe is here." DAMPs say "tissue is damaged." The response can overlap, but the signals are not the same. TrustSight's first-contact ledger and its structural findings are the same split. A new URL is a PAMP-like presence signal. A removed key surface is a DAMP-like damage signal.

The danger model also explains why the seed cannot be a whitelist. A familiar URL is not proof of safety. It is a prior observation. If the URL later hosts a malicious payload, the familiarity is exactly what the attacker wants. The model says to look for the damage signal, not to trust the familiar shape.

TrustSight responds to evidence, not to unfamiliarity.

Source:
- [Detection and Evidence - Danger over stranger](https://docs.trustsight.org/explanation/detection-and-evidence/)

Further reading: [Danger model](https://en.wikipedia.org/wiki/Danger_model), [Damage-associated molecular pattern](https://en.wikipedia.org/wiki/Damage-associated_molecular_pattern), [Alarmin](https://en.wikipedia.org/wiki/Alarmin), and [Pattern recognition receptor](https://en.wikipedia.org/wiki/Pattern_recognition_receptor).

---

## 6. Clonal recognition: the G-series campaign immune system

Clonal selection is the mechanism behind adaptive specificity. A B or T cell that binds an antigen is selected, expanded, and retained. The expansion is clonal because the descendants share the same receptor. A germinal center is where B cells mutate, compete for antigen, and mature their affinity. The result is a response that gets more specific over time.

The G-series is the closest thing TrustSight has to clonal expansion. A single package with a suspicious property can be ambiguous. Many unrelated packages gaining the same host, literal, dependency, or coordinated maintainer behavior in a short window can reveal a campaign. One observation is a clone. The correlated set is the expansion.

The G-series came out of the campaign-alert design, and it behaves most like an ecosystem-level immune response. It does not need one package to be conclusive. It needs several packages to share a shape.

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

A campaign becomes visible when otherwise plausible observations join one shared pattern. TrustSight can then produce one campaign-level alert naming the members instead of N disconnected package alerts. That is the software version of a polyclonal response: many weak recognitions converge on one target.

### The October 2026 yay name-clone campaign

On October 14, 2026, the watcher raised two clusters:

- 15 newly published names impersonating `yay`;
- 14 names impersonating `brave-beta-bin`, plus a hijacked legitimate `firefox-git-bin`.

The malicious delivery used committed `.install` files while the upstream recipe stayed byte-intact. The live watcher identified the coordinated activity through G003, H045, and H052. The install-scriptlet payload rules had not caught the carrier during that live cycle; later rule work, including X034, took lessons from the incident.

Correlation caught the campaign before the payload detector recognized the carrier. That is the value of the clonal layer. The individual package may look ordinary. The shared shape is what gives it away.

BleepingComputer reported the incident on October 15, 2026: [Fake Arch Linux packages push malware with root privileges](https://www.bleepingcomputer.com/news/security/fake-arch-linux-packages-push-malware-with-root-privileges/).

The analogy has a limit. Clonal selection is specific, and the G-series is correlational. A cluster can join packages that share a hosting provider, a popular dependency, or a packaging convention without sharing an attacker. That is why G006 is weight zero and why campaign state is bounded. The cluster is evidence, not a verdict.

Sources:
- [Correlation Rules](https://docs.trustsight.org/rules/correlation/)
- [October 14, 2026 AUR Name-Clone Waves](https://docs.trustsight.org/reports/2026-10-14-aur-name-clone-waves/)
- [Detection and Evidence](https://docs.trustsight.org/explanation/detection-and-evidence/)

Further reading: [Clonal selection](https://en.wikipedia.org/wiki/Clonal_selection), [Germinal center](https://en.wikipedia.org/wiki/Germinal_center), [Affinity maturation](https://en.wikipedia.org/wiki/Affinity_maturation), and [Immunological memory](https://en.wikipedia.org/wiki/Immunological_memory).

---

## 7. Cytokine signaling: neighborhood elevation

Cytokines are small signaling proteins. Some act on the cell that released them, some on nearby cells, and some travel through the blood to distant sites. Chemokines are a subset that direct cell movement, often along a concentration gradient. The property that matters here is that a signal can change the behavior of tissue around a threat without making every cell in that tissue part of the threat.

When a campaign is active, packages around it may deserve attention even if they are not corroborated members. If a package newly gains a host or domain within the campaign's scope, G006 can record that it touches an alerted neighborhood.

G006 has weight zero. It is context, not a malicious score. Touching an already-hot host should not inflate a package's risk or accuse its maintainer. This is the cytokine-like move: a recognized threat raises readiness in nearby tissue without treating the whole neighborhood as infected.

The chemokine part of the analogy is about direction. A chemokine gradient tells a cell where to go. The campaign scope tells the reviewer where to look. G006 does not move a detector; it moves attention. The reviewer sees that a package is near a known cluster and can decide whether to inspect it.

The cytokine part is about dosage. A small local signal can be useful. A systemic flood is a cytokine storm. G006 is deliberately local and temporary. It is bounded by the campaign's observation lifetime, and it is not allowed to become a permanent property of the package.

### Bystander activation: G016 account blast radius

One level up, a weaker field effect appears. When one package on an account fires a specific payload rule or a FATAL finding, other packages that the same account processed in that cycle are bystanders. The biology is bystander activation: antigen-nonspecific cells can be activated by cytokines during an ongoing response without direct recognition of the antigen.

G016 reports that shared-account context. It does not say the account is compromised, and it does not score the siblings. Unregulated bystander activation can itself cause immune pathology, which is why G016 has weight zero and stays anergic instead of feeding the package score.

Source: [Mechanisms governing bystander activation of T cells](https://pmc.ncbi.nlm.nih.gov/articles/PMC11635090/)

The limit is that a cytokine is a molecule with a receptor and a concentration. G006 is a rule with a scope and a TTL. The analogy explains why a local signal should not become a global verdict. It does not explain the exact boundary. That boundary is an engineering choice, and the campaign scope is where it lives.

Sources:
- [Detection and Evidence - Neighborhood Elevation](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Correlation Rules - G006](https://docs.trustsight.org/rules/correlation/)

Further reading: [Cytokine](https://en.wikipedia.org/wiki/Cytokine), [Chemokine](https://en.wikipedia.org/wiki/Chemokine), [Cytokine storm](https://en.wikipedia.org/wiki/Cytokine_storm), and [Bystander activation review](https://pmc.ncbi.nlm.nih.gov/articles/PMC11635090/).

---

## 8. Trained immunity: G007 and bounded campaign priming

Trained immunity is innate immune memory. It is not the same as adaptive memory. Monocytes, macrophages, and NK cells can be reprogrammed after an encounter, through metabolic and epigenetic changes, so a later challenge produces a stronger innate response. The memory is broad and nonspecific. It is also shorter-lived than adaptive memory, and it can be maladaptive.

After a campaign is corroborated, TrustSight can keep its scope for a bounded number of observations. A package later found in that scope can get a G007 corroboration record carrying the campaign ID. This is the trained-immunity part. It is context, not a new risk score.

The state is bounded:

- the campaign has an observation-clock TTL;
- a campaign expires once its observation lifetime ends;
- active campaign count is capped;
- repeated reactivation is reported through M006;
- expiration is visible, not silently forgotten.

Past campaign recognition primes the system for a while and speeds up contextual recognition of related activity. It does not create permanent suspicion.

The difference between trained immunity and adaptive immunity matters here. Adaptive memory is specific. Trained immunity is broad. G007 is broad in the same way: it does not remember a single package. It remembers a campaign scope, and it uses that scope to give context to later observations. The scope is narrower than the whole ecosystem, but wider than one package.

The bound is the safety mechanism. A trained innate response that never resolves becomes chronic inflammation. A campaign scope that never expires becomes permanent suspicion. M006 reports the churn when a campaign keeps re-arming, and the TTL makes the state visible.

Trained immunity is carried by metabolic and epigenetic changes in innate cells. It is not a rearrangement of antigen receptors, and it is not the same as immunological memory in B and T cells. The response is broad, and it can be weaker or stronger depending on the stimulus. The analogy should not be used to claim that G007 has learned a specific attacker.

The analogy is not a claim that TrustSight has trained monocytes. It is a claim that a bounded, nonspecific prior exposure can change how a later observation is read. The software version is a campaign record, a scope, and an expiry.

Sources:
- [Correlation Rules - G007](https://docs.trustsight.org/rules/correlation/)
- [Detection and Evidence - Campaign Alert Mode](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [State and Lifecycles](https://docs.trustsight.org/explanation/state-and-lifecycles/)

Further reading: [Trained immunity](https://en.wikipedia.org/wiki/Trained_immunity), [Immunological memory](https://en.wikipedia.org/wiki/Immunological_memory), and [Innate immune system](https://en.wikipedia.org/wiki/Innate_immune_system).

---

## 9. Opsonization: tag first, clear later

Opsonization is the process of marking a target so a phagocyte can recognize it. Antibodies do it by binding the target and presenting their Fc region to Fc receptors on a macrophage or neutrophil. Complement fragments do it by coating the target with C3b, which binds complement receptors. The mark does not kill anything by itself. It makes the target easier to find and easier to eat.

TrustSight tags observations in a similar spirit. A first contact, a campaign context, an entropy bump, an annotation, or a recognized technique can be recorded without being scored as malicious. The tag is a mark for later interpretation.

The marks go into the report's `tag_panel`. When several distinct kinds of tag converge on one diff, `TAG_CONVERGENCE` can produce one bounded informational ledger entry, never a score. That is the opsonization analogy: the tag makes the observation easier to interpret, but it does not pass judgment.

The biology has a step that TrustSight does not have. Opsonization ends in phagocytosis. A phagocyte recognizes the Fc or complement receptor, engulfs the target, and destroys it. TrustSight has no phagocyte. The human reviewer is the closest equivalent, and the report is the tag that helps the reviewer decide what to look at.

That missing step is the limit. A tag is not an accusation. A tag panel full of context is not a verdict. If the page used opsonization to imply that a tagged package will be removed, it would be describing a different system.

The analogy is still useful because it explains why tags are weight zero. The innate immune system does not need a full adaptive response to opsonize a target. It needs a mark that connects the target to an effector. TrustSight needs a mark that connects an observation to a reviewer. The mark is information, not punishment.

Antibodies are not the only opsonin. C3b and its breakdown products coat a target and bind complement receptors on phagocytes. Some pathogens evade opsonization by producing proteins that block complement or bind host regulators. The immune system has to recognize the coated surface, not just the pathogen. TrustSight's tags are closer to the coat than to the pathogen. A tag can be present while the package is benign, and a package can be malicious without a tag.

The `tag_panel` is also a place where context can accumulate without changing the score. A first contact, a campaign neighborhood, an entropy bump, and a recognized technique can all be true at once. The panel preserves the combination. `TAG_CONVERGENCE` reports the combination once. It does not add a point for each tag, because that would turn context into a score.

Sources:
- [Detection and Evidence - Opsonization](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Report Schema](https://docs.trustsight.org/reference/report-schema/)

Further reading: [Opsonization](https://en.wikipedia.org/wiki/Opsonization), [Complement system](https://en.wikipedia.org/wiki/Complement_system), [Phagocytosis](https://en.wikipedia.org/wiki/Phagocytosis), and [Antibody](https://en.wikipedia.org/wiki/Antibody).

---

## 10. Sickness behavior: the system changes its posture

Sickness behavior is the set of changes an organism makes during an infection: fever, fatigue, loss of appetite, reduced movement, and increased pain sensitivity. It is not the pathogen doing those things. It is the immune system signaling the brain, often through cytokines and the vagus nerve, that the body should change its priorities.

When a campaign perimeter is active, a package inside it may already have an analysis boundary: an upstream manifest not examined, an unverifiable surface, or a coverage gap. W013 can make that boundary visible in the campaign context until the campaign TTL expires. It does not create evidence or accuse the package. It makes the defensive posture explicit.

The report can also carry `campaign_hold` and `campaign_state` for downstream enforcement systems. That is the posture part. The system is not saying the package is malicious. It is saying the environment is under a campaign alert, and the report should be read in that context.

The analogy is useful because sickness behavior is adaptive and costly at the same time. Fever helps fight infection, but it also consumes energy and makes the organism vulnerable. A campaign posture helps the reviewer, but it can also inflate attention and create alert fatigue. The TTL and the visible boundary are the controls.

The biology has a limit. Sickness behavior is a whole-organism response mediated by the brain and the immune system. TrustSight has no brain and no metabolism. W013 is a report field. It changes how the report is read, not how the machine behaves.

That is enough for the analogy. TrustSight does not get a fever, but a systemic threat can justify a temporary change in posture, and the change should be visible rather than hidden in a score.

Cytokines such as interleukin-1, interleukin-6, and tumor necrosis factor are part of the signaling path that produces fever and sickness behavior. The vagus nerve carries some of that signal to the brain. The acute-phase response changes what the liver produces, which changes the blood chemistry. The response is coordinated across organs, not confined to the site of infection.

TrustSight's version is coordinated across report fields. W013 makes the campaign boundary visible. `campaign_hold` and `campaign_state` give downstream systems the posture. The package's own findings do not change. The context around them does.

Sources:
- [Detection and Evidence - Sickness Behavior](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Unverifiable Rules - W013](https://docs.trustsight.org/rules/unverifiable/)
- [Report Schema](https://docs.trustsight.org/reference/report-schema/)

Further reading: [Sickness behavior](https://en.wikipedia.org/wiki/Sickness_behavior), [Fever](https://en.wikipedia.org/wiki/Fever), [Acute-phase protein](https://en.wikipedia.org/wiki/Acute-phase_protein), and [Cytokine](https://en.wikipedia.org/wiki/Cytokine).

---

## 11. Refractory periods: one stimulus, one alert

A refractory period is a short window after a response during which the same stimulus cannot produce another full response. Neurons have one. Muscle fibers have one. Immune signaling has desensitization and tachyphylaxis, where repeated exposure to a signal produces a smaller response. The common idea is that a system needs a recovery window or it drowns in its own output.

TrustSight emits one alert per `(rule, campaign-cell)` per campaign window. The refractory state is part of the cycle audit record, so replay stays deterministic. One alert per stimulus is enough; a repeat would add no information.

This is not silent suppression. The state is recorded. The alert is deduplicated because the same stimulus in the same window would produce the same message. The JSON record still carries the full findings. The terminal or notification layer is what gets the one alert.

The rendering side has a related mechanism: when N packages share one campaign finding, the alert names the members once, sorted and deduplicated, instead of rendering N copies. That is lateral inhibition. The signal stays informative instead of turning into noise.

The biology here is regulatory physiology more than immunology. A refractory period is not a cell type, and tachyphylaxis is a pharmacological phenomenon as much as an immune one. The analogy is useful because it explains why repetition is not the same as strength. It should not be presented as a core immune mechanism.

The limit is the same. A refractory period protects a system from overstimulation. It can also hide a real second event if the window is too wide. TrustSight keeps the state in the cycle audit record and keeps the full findings in JSON, so the deduplication is visible and reviewable.

Desensitization and tachyphylaxis are the pharmacological versions of the same idea. A receptor that is exposed to a signal repeatedly can stop responding, or the downstream pathway can adapt. The response gets smaller even though the stimulus is the same. A refractory window does the same thing for alerts: the second identical stimulus does not produce a second full response.

The difference is that a refractory period is time-based and a desensitized receptor is state-based. TrustSight uses a campaign window and a key. The key is the rule and campaign cell; the window is the campaign's observation lifetime. That is enough to prevent a repeat without suppressing a different rule or a different campaign.

Sources:
- [Detection and Evidence - Refractory Period](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [State and Lifecycles](https://docs.trustsight.org/explanation/state-and-lifecycles/)

Further reading: [Refractory period](https://en.wikipedia.org/wiki/Refractory_period), [Desensitization](https://en.wikipedia.org/wiki/Desensitization_(medicine)), [Tachyphylaxis](https://en.wikipedia.org/wiki/Tachyphylaxis), and [Negative feedback](https://en.wikipedia.org/wiki/Negative_feedback).

---

## 12. Superantigens and cytokine storms: controlling alert overload

A superantigen is a molecule that bypasses the normal antigen-specific path. It crosslinks MHC class II on an antigen-presenting cell with the T-cell receptor on many T cells at once, without needing the usual peptide-MHC fit. The result is polyclonal T-cell activation, a massive release of cytokines, and a response that is disproportionate to the threat. The immune system attacks the host's own signaling.

TrustSight compares noisy alert floods to a superantigen. A tool can be turned against a reviewer by filling the screen until the findings that matter disappear. The response becomes part of the threat.

TrustSight addresses that with:

- a cap on terminal-rendered findings;
- W010, a visible weight-zero boundary reporting that the cap was reached;
- a per-cycle cap for watcher notifications;
- retention of the full findings in the JSON record even when terminal output is capped.

It also treats unbounded campaign-neighborhood elevation as a cytokine-storm failure. Neighborhood alerts stay weight zero, contextual, and bounded by campaign lifetime.

Defensive signaling has to stay targeted, bounded, and readable. Alert volume must never become evidence against one package.

The superantigen analogy is strong because the failure is not a failure of recognition. The immune system recognizes something, but the recognition is so broad that the response loses specificity. An alert flood does the same thing. It does not prove there are more threats. It proves the response is no longer sorted.

The limit is clinical. A cytokine storm is a medical emergency. An alert budget is a UI and notification control. The analogy explains the shape of the failure, not the severity of the human condition.

The superantigen example is useful because the molecule does not need to be processed like a normal antigen. It binds outside the peptide groove and forces a connection between MHC class II and the T-cell receptor. The result is a large fraction of the T-cell repertoire firing at once. That is the software failure where every finding is rendered at once and the reviewer cannot tell which one matters.

The alert budget is the countermeasure. It caps the rendered output, reports the cap through W010, and keeps the full set in JSON. The reviewer gets a readable summary and the machine keeps the complete evidence. The response is smaller at the interface, not smaller in the record.

Sources:
- [Detection and Evidence - Alert Budget](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Unverifiable Rules - W010](https://docs.trustsight.org/rules/unverifiable/)

Further reading: [Superantigen](https://en.wikipedia.org/wiki/Superantigen), [Cytokine storm](https://en.wikipedia.org/wiki/Cytokine_storm), and [Cytokine release syndrome](https://en.wikipedia.org/wiki/Cytokine_release_syndrome).

---

## 13. Chronic inflammation: M006 and campaign re-arming

Acute inflammation is a short response to injury or infection. Chronic inflammation is what happens when the stimulus does not clear or the response does not shut down. The tissue keeps remodeling, immune cells keep arriving, and the repair process can produce fibrosis or exhaustion. The response becomes part of the disease.

A campaign can be refreshed when evidence supports it. Repeated reactivation at an excessive rate is itself a tool-health observation. M006 does not simply block reactivation. It reports the churn, so operators can see that the system keeps entering the same alert state.

An unbounded campaign posture is chronic inflammation: the defense becomes part of the disease if it never returns to baseline. Campaigns expire. Repeated activation stays observable instead of silently becoming permanent suspicion.

The analogy explains why M006 is a tool-health rule, not a package verdict. The finding is about the detector's behavior. A campaign that keeps re-arming may be a real campaign that keeps producing evidence, or it may be a rule that is too eager. The report says which, and the operator decides.

The limit is that TrustSight has no tissue. It has state, timers, and rules. The chronic inflammation analogy is about the shape of a response that will not resolve. It is not a claim that a package is causing fibrosis.

The distinction between acute and chronic is useful for M006. An acute campaign is a short response to a real cluster. A chronic campaign is one that keeps re-arming, keeps refreshing its window, and never returns to baseline. M006 reports that churn. It does not decide whether the underlying campaign is real. It says the response is not settling.

The rule is deliberately a report, not a block. Blocking a refresh would make the system less able to respond to a real campaign that keeps producing evidence. Reporting the churn gives the operator the information without making the decision for them.

The control is expiry. A campaign that cannot expire becomes a permanent property of the package or the neighborhood. The TTL and the active campaign cap make the state temporary. M006 makes the churn visible when the temporary state keeps coming back.

Sources:
- [Meta and Confluence - M006](https://docs.trustsight.org/rules/meta/)
- [Detection and Evidence - Campaign Alert Mode](https://docs.trustsight.org/explanation/detection-and-evidence/)

Further reading: [Chronic inflammation](https://en.wikipedia.org/wiki/Chronic_inflammation), [Inflammation](https://en.wikipedia.org/wiki/Inflammation), and [T-cell exhaustion](https://en.wikipedia.org/wiki/T_cell_exhaustion).

---

## 14. Autoimmune disease: self-tolerance and the M-series

Autoimmunity is what happens when the immune system recognizes self as foreign. Central tolerance deletes many self-reactive B and T cells in the bone marrow and thymus. Peripheral tolerance catches others in the tissue through anergy, regulatory T cells, and checkpoint signals. When those mechanisms fail, the response can attack the host.

The M-series is the autoimmune check. The detection system itself can become unreliable, contradictory, noisy, or overreactive. M-series rules look at relationships between findings and the health of the detection process. They do not just add another package-level pattern match.

Examples include:

- contradictions between a declared security practice and structural evidence;
- combinations of multiple evidence layers;
- corroboration across independent rule families;
- expected co-firings that do not occur;
- repeated campaign activation.

Confluence is the same idea: one immune cell binding an antigen is not enough to launch a full response. In TrustSight, several independent signals can support escalation better than one isolated observation.

The detector has to tell a threat to the ecosystem apart from malfunction or overreaction in its own recognition.

The analogy needs a strict boundary. Autoimmunity is not any false positive. A false positive is a rule that fired on a benign package. Autoimmunity is the detector attacking its own expectations, or a rule that treats the system's normal behavior as hostile. M001 to M006 are the closest thing to that failure mode. They are not a diagnosis of the package.

The value of the analogy is that it makes self-checks part of immunity. A system that only looks outward misses the case where the detector is the problem.

Central tolerance is the first filter. Developing B and T cells that react strongly to self are deleted or edited. Peripheral tolerance is the second filter. Mature cells that escape the first filter are controlled by anergy, regulatory T cells, and checkpoint signals. The M-series is closer to the second filter. It watches the detector in operation, not during development.

The examples are worth separating. A contradiction between a declared practice and structural evidence is a consistency failure. A combination of multiple evidence layers is a confluence signal. A missing expected co-firing is a failure of the detector to behave the way its own model predicts. Repeated campaign activation is a churn failure. All four are tool-health observations, not package verdicts.

Sources:
- [Meta and Confluence Rules](https://docs.trustsight.org/rules/meta/)
- [Detection and Evidence - Immune-Inspired Design](https://docs.trustsight.org/explanation/detection-and-evidence/)

Further reading: [Autoimmunity](https://en.wikipedia.org/wiki/Autoimmunity), [Central tolerance](https://en.wikipedia.org/wiki/Central_tolerance), [Peripheral tolerance](https://en.wikipedia.org/wiki/Peripheral_tolerance), and [Regulatory T cell](https://en.wikipedia.org/wiki/Regulatory_T_cell).

---

## 15. Anergy and two-signal activation: new detectors must earn authority

T-cell activation usually needs two signals. Signal one is the antigen presented by MHC. Signal two is costimulation, often through CD28 binding CD80 or CD86 on an antigen-presenting cell. A T cell that receives signal one without signal two can become anergic: alive, but unresponsive. The second signal is how the immune system avoids reacting to every self-antigen it encounters.

TrustSight lets an experimental or insufficiently calibrated rule stay visible while adding zero scoring weight. The anergy ledger records what evidence the rule is waiting for. Promotion is explicit, measured, and recorded in the changelog. That is the software version of signal one and signal two. A suspicious pattern is signal one. Calibration and evidence are signal two.

This is two-signal activation: a suspicious-looking pattern is not, by itself, enough for a detector to carry scoring authority. The project records a standing anergy state and has process gates that refuse silent promotion. Immature recognition can observe and learn without launching a full response.

The analogy explains why anergy is not deletion. The rule is still there. It still reports. It simply does not score. That is useful because a rule can be informative before it is trustworthy. Removing it would lose the observation. Promoting it too early would add noise.

The limit is that a rule is not a cell. A T cell that receives signal one without signal two becomes unresponsive through a biochemical program. A rule in the anergy ledger is held at weight zero by configuration and process. The analogy is about the two-key structure, not the biochemistry.

Costimulation is the second key. CD28 on the T cell binds CD80 or CD86 on the antigen-presenting cell. Without it, the T cell can become anergic even after antigen recognition. CTLA-4 is the brake that competes with CD28 and limits the response. The immune system has both an accelerator and a brake, and the balance decides whether the response proceeds.

TrustSight's accelerator is promotion. The brake is the anergy ledger and the process gates. A rule can be visible, can produce observations, and can wait for the evidence that promotes it. The wait is not a failure. It is the second signal.

The anergy ledger also makes the wait auditable. Each rule has a reason, a missing evidence class, and a promotion path. A reviewer can see why the rule is not scoring and what would change that. The ledger is the difference between a rule that is quietly ignored and a rule that is explicitly held back.

Sources:
- [Detection and Evidence - Two-Signal Activation](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Standards](https://docs.trustsight.org/standards/)
- [Changelog](https://docs.trustsight.org/changelog/)

Further reading: [Anergy](https://en.wikipedia.org/wiki/Anergy), [Co-stimulation](https://en.wikipedia.org/wiki/Co-stimulation), [T cell](https://en.wikipedia.org/wiki/T_cell), and [Immune tolerance](https://en.wikipedia.org/wiki/Immune_tolerance).

---

## 16. Nociception: unresolved pain becomes a prioritization signal

Nociception is the nervous system's detection of harmful or potentially harmful stimuli. Nociceptors are not the same as pain. Pain is the conscious experience, and it can exist without tissue damage. Nociception is the signal that something needs attention.

A package with repeated unresolved review verdicts can get a tender-point notice in the report header, for example: "N unresolved in M months; a human should look once." That does not say the package is broken, and it does not score. It tells a reviewer that an unresolved issue has piled up and deserves attention.

The principle is pain as prioritization without a damage claim. The notice is a signal that the review process has not resolved something, not a finding that the package is malicious.

The neuroimmune angle is real. Nociceptors can be sensitized by inflammatory mediators, and the immune system can change pain sensitivity. Sickness behavior and pain overlap. But the analogy here is narrow: a persistent unresolved signal becomes more salient over time.

The limit is that TrustSight has no nervous system. A tender-point notice is a report field, not a sensation. The value is that it makes an unresolved state visible without pretending it is a detection.

Nociceptors can be sensitized by prostaglandins, bradykinin, and nerve growth factor. The threshold for firing drops, so a stimulus that was not painful becomes painful. That is not the same as tissue damage increasing. The signal is amplified by the state of the system.

The tender-point notice is similar. A package with repeated unresolved reviews has not necessarily become more dangerous. The review process has accumulated unresolved state, and the notice raises the priority. The reviewer should look once. The notice does not claim that the package is broken.

Sensitization is the reason the notice is time-based. A single unresolved review is not a tender point. Repeated unresolved reviews over months are. The threshold is the accumulated state, not one event. The notice is a prompt to break the loop, not a claim about the package's intent.

Sources:
- [Detection and Evidence - Nociception](https://docs.trustsight.org/explanation/detection-and-evidence/)

Further reading: [Nociception](https://en.wikipedia.org/wiki/Nociception), [Alarmin](https://en.wikipedia.org/wiki/Alarmin), and [Sickness behavior](https://en.wikipedia.org/wiki/Sickness_behavior).

---

## 17. Interoception: the system knows its own condition

Interoception is the nervous system's sense of the body's internal state: heartbeat, breathing, hunger, temperature, and the vague sense that something is off. It is not introspection. It is a continuous readout of the conditions that keep the organism alive. The vagus nerve carries a large part of that traffic, and the immune system can change the signal through cytokines and inflammation.

TrustSight reports its own analysis state instead of leaving users to infer it from silence. `self_state` can communicate:

- cold or warm mode;
- observation counts;
- ruleset versions;
- channel tags and observation-clock ages;
- federation availability;
- Contact Ledger availability;
- campaign state;
- a sorted list of blind spots.

That keeps a cold database, stale channel, unavailable subsystem, or unexercised analysis lane from looking like a healthy, fully informed system.

The interoception analogy is about the difference between "no finding" and "no signal." A report with no findings can mean the package is clean, or it can mean the ruleset is stale, the seed is missing, the channel is down, or the analyzer could not read the evidence. `self_state` makes that difference visible.

Allostasis is the related idea that an organism does not hold a fixed internal set point. It changes its own parameters to meet a demand. TrustSight does something similar when it reports cold or warm mode, campaign state, and channel ages. The state is not a constant. It is a posture.

The vagus nerve is one of the main routes for immune-to-brain signaling. Cytokines can act on the vagus, and the brain can send signals back through the autonomic nervous system. The result is a loop, not a one-way report. Interoception is the brain's model of the body's state, and the model can be wrong.

`self_state` is TrustSight's model of its own analysis state. It can be wrong in the same way. A channel can look available while returning stale data. A database can look warm while missing a table. The report has to be checked against the actual evidence, not trusted because it is a report.

The limit is that a report field is not a feeling. An instrument that reports its own condition can still be wrong about the condition. `self_state` is a claim about the analysis environment, and it has to be checked like any other claim.

Sources:
- [Detection and Evidence - Interoception](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Report Schema](https://docs.trustsight.org/reference/report-schema/)
- [Evidence and Confidence](https://docs.trustsight.org/security-design/evidence-and-confidence/)

Further reading: [Interoception](https://en.wikipedia.org/wiki/Interoception), [Allostasis](https://en.wikipedia.org/wiki/Allostasis), [Homeostasis](https://en.wikipedia.org/wiki/Homeostasis), and [Immune system](https://en.wikipedia.org/wiki/Immune_system).

---

## 18. Gain control: an immune-inspired mechanism TrustSight rejected

Gain control is a feedback idea. A system measures the output, compares it with a target, and adjusts the amplification. Biological reflexes use it. Homeostasis uses it. Control theory uses it everywhere. The goal is to keep a signal in a useful range as the input changes.

TrustSight considered adapting thresholds to recent signal levels. It rejected that because the same diff could then score differently depending on where the observation epoch sat. That would break deterministic reproducibility and cold-replay consistency.

Instead, thresholds are re-derived at release time from a pinned corpus, committed to configuration, and covered by the configuration fingerprint.

TrustSight does not adopt every biological mechanism. It borrows the useful ideas and rejects adaptations that would undermine its security invariants.

The gain control analogy is useful because it explains why the rejection is not a failure of imagination. A biological system can adapt continuously because it has no requirement to replay the same input and get the same output. An audit system does. A score that depends on the recent alert volume is not reproducible, and a non-reproducible score is hard to defend in a report.

Gain is the amount of amplification a signal receives. A reflex can increase gain when the input is weak and decrease it when the input is strong. Homeostasis uses negative feedback to keep a variable near a set point. The system is always adjusting, and the adjustment is part of the response.

The problem with runtime gain control is memory. A system that adjusts to recent signal levels has to remember those levels, and the same input produces a different output depending on what came before. That is acceptable in a reflex and unacceptable in an audit that has to replay.

TrustSight's thresholds are fixed at release time instead. The adjustment happens in the corpus, the calibration, and the configuration, not in the running score. That is a deliberate trade: less biological, more reproducible.

The limit is that this is control theory, not immunology. The section is here because the project considered an immune-like adaptive mechanism and rejected it. That rejection is part of the design lineage.

Source:
- [Detection and Evidence - Rejected: Gain Control](https://docs.trustsight.org/explanation/detection-and-evidence/)

Further reading: [Homeostasis](https://en.wikipedia.org/wiki/Homeostasis), [Negative feedback](https://en.wikipedia.org/wiki/Negative_feedback), and [Allostasis](https://en.wikipedia.org/wiki/Allostasis).

---

## 19. IOC Federation: shared knowledge of known pathogens

Passive immunity is what an organism receives ready-made. Maternal antibodies cross the placenta, and antibody preparations can be given after exposure. The recipient does not make the antibody. The protection is immediate and temporary.

IOC federation is the software version. Independent curators publish signed indicator sets. TrustSight verifies the signatures, keeps provenance and attribution, applies confidence tiers, and preserves expiry. The indicator is ready-made specificity, and the local system does not have to rediscover it.

IOC federation supplies concrete known-bad indicators such as:

- domains;
- hashes;
- package names;
- file paths;
- PKGBUILD patterns;
- upstream repository observations.

The difference from the seed matters. The seed is historical familiarity, not known-bad. The IOC is a claim that a specific indicator is malicious or suspicious. The seed says "this source existed before." The IOC says "this source is associated with a threat."

IOC matches are reported outside the ordinary heuristic score, at their own alert priority. An expired indicator remains visibly expired instead of disappearing. That is the passive-immunity fade. The protection is temporary, and the report says so.

The limit is the same as passive immunity. The recipient depends on the donor. A stale indicator, a low-confidence curator, or a compromised signing key can all produce a bad match. The provenance and confidence fields are not decoration. They are how the recipient decides whether to trust the donation.

Indicators also have a specificity problem. A domain indicator can match a shared host that many benign packages use. A hash indicator can match a file that appears in several packages. A PKGBUILD pattern can match a common idiom. The confidence tier and the context fields are what keep an exact match from becoming an automatic verdict.

The confidence tier is not a score. It is a label that tells the reader how much weight the curator put on the indicator. A high-confidence hash is a different claim from a low-confidence pattern. The reader can see the difference without opening the curator's notes.

The report keeps the IOC match outside the ordinary heuristic score for that reason. An exact indicator is a different kind of claim from a heuristic finding. It says "this value is on a list," not "this package behaves like a threat." The two claims can both be true, but they need different handling.

Sources:
- [IOC Federation](https://docs.trustsight.org/reference/ioc/)
- [Indicator Rules](https://docs.trustsight.org/rules/indicator/)
- [Threat Intelligence](https://docs.trustsight.org/explanation/threat-intelligence/)

Further reading: [Passive immunity](https://en.wikipedia.org/wiki/Passive_immunity), [Neutralization](https://en.wikipedia.org/wiki/Neutralization_(immunology)), [Antibody](https://en.wikipedia.org/wiki/Antibody), and [Immunological memory](https://en.wikipedia.org/wiki/Immunological_memory).

---

## 20. The Watcher: continuous systemic surveillance

Immunosurveillance is the continuous search for abnormal cells. Sentinel cells in the tissue sample their surroundings and carry information to lymphoid organs. The lymphatic system moves immune cells and antigen through the body. The response is distributed, not controlled from one place.

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

The sentinel-cell analogy is better than a central-brain analogy. A sentinel cell does not know the whole organism. It samples a local area and reports. The watcher samples the AUR change stream and reports clusters. The public feed is the shared lymphoid tissue where those reports become searchable.

The limit is that the watcher does not eliminate. Immunosurveillance can lead to killing by cytotoxic cells. The watcher leads to a report. The human or the maintainer decides what happens next. That is the boundary the page keeps returning to.

The watcher's cycle is the unit of work. A cycle observes changes, analyzes what changed, updates state, joins observations, and reports clusters. A bounded cycle can be resumed if it stops. A heartbeat says whether the cycle is alive. An outbox keeps a failed delivery from disappearing. Those are operational details, but they are what make continuous surveillance different from a one-shot scan.

The sentinel analogy also explains why the watcher is not omniscient. A sentinel cell samples a local area. The watcher samples the change stream it can see. A package that never changes, a channel that is down, or a delivery that fails is outside the sample. `self_state` and the heartbeat are how the watcher says so.

The outbox is the part that makes delivery reliable. An alert that cannot be delivered is kept and retried instead of dropped. The watcher can be behind, and the record can still be complete. That is closer to a lymph node holding antigen than to a fire-and-forget notification.

Sources:
- [Watching the AUR Continuously](https://docs.trustsight.org/workflows/watching-the-aur-continuously/)
- [State and Lifecycles](https://docs.trustsight.org/explanation/state-and-lifecycles/)

Further reading: [Immune surveillance](https://en.wikipedia.org/wiki/Immune_surveillance), [Sentinel cell](https://en.wikipedia.org/wiki/Sentinel_cell), [Lymphatic system](https://en.wikipedia.org/wiki/Lymphatic_system), and [Immunoediting](https://en.wikipedia.org/wiki/Immunoediting).

---

## 21. The shared immune network: [The Watcher](https://watcher.trustsight.org/)

Secondary lymphoid organs are where local encounters become shared memory. A lymph node collects antigen and immune cells from a region, supports the activation of B and T cells, and sends the response back out. A germinal center inside the node is where B cells mutate and compete for affinity. The organ is not a central brain. It is a meeting point.

The shared feed at [watcher.trustsight.org](https://watcher.trustsight.org/) receives signed watcher-cycle reports and stores searchable alerts. The feed repository documents:

- Ed25519 verification of the raw incoming alert document;
- public-key publication for later verification;
- persistent alert storage;
- package, rule, maintainer, IOC, and campaign indexes;
- signed daily Merkle checkpoints;
- API routes for alerts, campaigns, package histories, rule triggers, IOCs, source files, diffs, and verification material.

Observations from a deployed watcher become reusable threat intelligence for people and systems beyond the original machine.

The lymphoid organ analogy is better than a herd-immunity analogy. A lymph node does not make the whole body immune. It is a place where local information is concentrated and shared. The feed does the same for watcher observations. It is a shared memory organ, not a guarantee of protection.

The germinal center is the part of the lymph node where B cells mutate and compete. It is a specialization inside the organ, not the whole organ. The feed has its own specializations: the indexes, the checkpoints, the API routes, and the verification material. Each one makes a different kind of recall possible.

The signed daily Merkle checkpoints are the feed's equivalent of a verifiable record. They let a later reader check that the alert history was not rewritten. The immune system does not have a Merkle tree, but it does have memory that is shaped by repeated exposure. The analogy is about shared memory, not cryptography.

The API routes are the feed's recall surface. A reader can ask for an alert, a campaign, a package history, a rule trigger, an IOC, a source file, a diff, or a verification record. The germinal center does not expose an API, but it does make different kinds of recall possible from the same shared tissue.

It is a shared threat-surveillance network rather than a literal distributed immune system, but the architectural analogy holds.

Sources:
- [Watcher](https://watcher.trustsight.org/)
- [trustsight-feed repository](https://github.com/emiliano-go/trustsight-feed)
- [Continuous Watching Documentation](https://docs.trustsight.org/workflows/watching-the-aur-continuously/)

Further reading: [Lymphatic system](https://en.wikipedia.org/wiki/Lymphatic_system), [Germinal center](https://en.wikipedia.org/wiki/Germinal_center), and [Immunological memory](https://en.wikipedia.org/wiki/Immunological_memory).

---

## 22. Self-protection: the immune apparatus must not be infected

The immune system has to protect itself while it fights. Immune privilege limits inflammation in sensitive tissues. Barriers keep pathogens out. Apoptosis removes damaged cells without spilling their contents. Autophagy clears intracellular debris. Phagocytes engulf and digest what is left.

TrustSight reads hostile package-controlled text and metadata, so the analysis engine is an attack surface. Its safeguards:

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

The immune-privilege analogy is useful because it explains why the analyzer cannot inspect everything. The eye does not allow unrestricted inflammation, and TrustSight does not allow unrestricted execution. The boundary is not a failure. It is a condition of safe operation.

The limit is that sandboxing is not a cell. A jailed parser does not heal. It fails closed. That is the point.

Apoptosis and autophagy are the cleanup side. Apoptosis removes a damaged cell without spilling its contents. Autophagy digests intracellular material and can capture pathogens. Phagocytosis clears the debris. The three together keep the immune response from becoming a source of damage.

TrustSight's cleanup is less biological. A bounded parser, a read-only worker, a coverage gap, and a refusal are the equivalents. They do not heal the package. They keep the analyzer from being damaged by it. The design is closer to fail-closed containment than to cellular repair.

The fail-closed choice is the key. When the sandbox guarantee cannot be established, TrustSight refuses rather than analyzing without it. When part of the evidence cannot be read, the report says so rather than returning a clean result. The immune system does the same when it walls off a site it cannot clear.

Sources:
- [Static Analysis and Resolution](https://docs.trustsight.org/explanation/static-analysis-and-resolution/)
- [Security Model](https://docs.trustsight.org/security-design/security-model/)
- [Security Boundaries](https://docs.trustsight.org/security-design/security-boundaries/)
- [Upstream Manifests](https://docs.trustsight.org/rules/upstream-manifests/)
- [Artifact Rules](https://docs.trustsight.org/rules/artifact/)

Further reading: [Immune privilege](https://en.wikipedia.org/wiki/Immune_privilege), [Autophagy](https://en.wikipedia.org/wiki/Autophagy), [Apoptosis](https://en.wikipedia.org/wiki/Apoptosis), [Phagocytosis](https://en.wikipedia.org/wiki/Phagocytosis), and [Tight junction](https://en.wikipedia.org/wiki/Tight_junction).

---

## 23. Homeostasis: false-positive control and calibration

Homeostasis is the maintenance of a stable internal state through feedback. The immune system uses it constantly. Inflammation has to resolve. Regulatory T cells suppress overreaction. Checkpoints put brakes on activation. When the feedback fails, the response damages the host.

A defense system that attacks everything unfamiliar, or floods the screen, is not healthy. TrustSight uses several checks. Novelty gains weight only after enough observations. First contacts and campaign-neighborhood touches stay weight zero. Uncalibrated rules stay in anergy. Suppressions are reported with reasons and expiry. Positive-looking practices do not subtract evidence. A false-positive fix must keep a true-positive twin. Changes are tested against a locked benign corpus and labeled malicious fixtures. Incomplete analysis is named as a boundary.

At the last published count, the benchmark has 8,393 benign diffs and 213 self-authored labeled malicious fixtures. These are internal regression numbers, not independent estimates of real-world efficacy.

Homeostasis is the balance between responsiveness, tolerance, and restraint. The system defends the ecosystem without treating every unfamiliarity as disease.

The feedback analogy is useful because it explains why calibration is continuous. A threshold that works on one corpus can fail on another. The corpus and the fire rates are the feedback signal. The release process is the adjustment.

The limit is that TrustSight has no metabolism. It does not return to a physiological set point. It returns to a tested configuration. The analogy explains the goal, not the mechanism.

The calibration corpus is the feedback signal. A change that raises the benign p95 or lowers the true-positive rate is a deviation from the target. The release process adjusts the threshold or the rule. That is a slow loop compared with a biological reflex, but it is a loop.

The true-positive twin is the part that keeps the loop honest. A false-positive fix that removes the malicious case is not a fix. It is a trade that hides one failure behind another. The twin keeps both cases in the test set.

The benchmark is the long feedback loop. A rule change is measured against a locked benign corpus and a set of labeled malicious fixtures. The numbers are not an independent estimate of real-world efficacy, and the page should not present them as one. They are a regression signal, which is what a homeostatic loop needs.

Sources:
- [Benchmarks and Methodology](https://docs.trustsight.org/reports/benchmarks-and-methodology/)
- [Fire Rates](https://docs.trustsight.org/reports/fire-rates/)
- [Tuning False Positives](https://docs.trustsight.org/workflows/tuning-false-positives/)
- [What a Result Claims](https://docs.trustsight.org/security-design/what-a-result-claims/)

Further reading: [Homeostasis](https://en.wikipedia.org/wiki/Homeostasis), [Negative feedback](https://en.wikipedia.org/wiki/Negative_feedback), [Inflammation](https://en.wikipedia.org/wiki/Inflammation), [Regulatory T cell](https://en.wikipedia.org/wiki/Regulatory_T_cell), and [Immune checkpoint](https://en.wikipedia.org/wiki/Immune_checkpoint).

---

## 24. The biological foundations and their architectural translations

The table is the compressed version of the page. It is useful for finding a concept quickly, and it is not a substitute for the sections that explain the limits.

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

Three rows deserve a note. Vaccine is the loosest label in the table; priming is the better word. Shared immunity is a systems analogy, not a claim that the feed makes the AUR immune. Self-protection is a design boundary, not a literal immune privilege.

The table also shows the difference between a documented borrowing and a structural one. Missing-self, danger, trained immunity, opsonization, anergy, and homeostasis are named in the docs. Crossfire, complement, and passive immunity are structural mappings added later. The table keeps both visible instead of flattening them into one kind of claim.

A useful way to read the table is to ask what would falsify the row. For missing-self, the falsifier is a package that loses a trust surface for a benign reason and produces no other signal. For trained immunity, it is a G007 record that persists past its TTL or changes the score. For opsonization, it is a tag that becomes a verdict without a rule. The falsifier keeps the analogy honest.

The table is also a reminder that the strongest rows are not the most biological. The strongest rows are the ones where the mechanism and the biology share a structure: a loss signal, a bounded memory, a mark that is not a verdict. The weakest rows are the ones where the biology is doing rhetorical work.

Sources:
- [Detection and Evidence - Immune-Inspired Design](https://docs.trustsight.org/explanation/detection-and-evidence/)
- [Rule Series](https://docs.trustsight.org/rules/series/)

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

The page also does not claim that the AUR is a literal organism, that users are cells, or that the watcher is a central brain. The metaphor is about sensing, memory, correlation, and restraint. It is not a theory of the AUR's politics, economics, or governance.

The strongest boundary is enforcement. TrustSight does not block, quarantine, or remove. A maintainer can remove a package from the AUR. A user can remove it from a machine. The software produces the signal, and people act. The immune system analogy is useful only while that division stays visible.

The second boundary is certainty. The page can explain why a rule exists and what it detects. It cannot turn a heuristic into a proof. A finding is evidence, and evidence has a scope. The scope is the report.

The third boundary is the metaphor itself. The AUR is not a body, and TrustSight is not an immune system. It is a tool that borrows useful ideas from one. The borrowing is worth keeping because it changes how the tool is built. It is not worth defending as literal biology.

The fourth boundary is the reader's response. A finding is not an instruction to remove a package. It is a reason to look. The page can explain why the tool exists and what it detects. It cannot make the decision for the person reading the report.

Source: [Security Model](https://docs.trustsight.org/security-design/security-model/), [What a Result Claims](https://docs.trustsight.org/security-design/what-a-result-claims/), and [Limitations and Uncertainty](https://docs.trustsight.org/explanation/limitations-and-uncertainty/).

Further reading: [Immune tolerance](https://en.wikipedia.org/wiki/Immune_tolerance), [Immune privilege](https://en.wikipedia.org/wiki/Immune_privilege), and [Janeway's Immunobiology](https://www.ncbi.nlm.nih.gov/books/NBK10767/).

---

## 26. Which immune system?

"Immune system" is not one thing. It is several systems with different speeds, memory, and failure modes. TrustSight borrows from more than one branch, and mixing them without saying which is which is how the metaphor turns into decoration.

| Branch | What it does | Closest TrustSight layer | Strength |
|---|---|---|---|
| Innate immunity | Fast, broad recognition of danger patterns | R, H, C, and X rules | Structural |
| Adaptive immunity | Slow, specific response with memory | Local observations, seed, T-series | Documented |
| Humoral immunity | Antibodies, neutralization, passive transfer | I-series and IOC federation | Structural |
| Complement | Cascading plasma proteins that amplify and mark targets | Composition rules and opsonization tags | Structural |
| Regulatory immunity | Restraint, tolerance, and shutdown | M-series, alert budgets, anergy | Documented |
| Barrier immunity | Epithelium, mucus, tight junctions | Structural invariants and context rules | Structural |

Innate immunity is the fast layer. It recognizes classes of danger through pattern recognition receptors, not one named pathogen at a time. The receptor does not need to know the species. It needs to know that a molecular shape is wrong for a healthy host. R, H, C, and X rules work the same way. They recognize a command shape, a structural break, or an unresolved construct, not a particular malware family.

Adaptive immunity is slower and specific. B and T cells are selected, expanded, and retained after an encounter. The local observation database and the T-series do that for packages: they remember a maintainer, a source, a key, a dependency, and a behavior, then compare today with the remembered version. The seed is the shortcut for a cold install, not a substitute for the local memory.

Humoral immunity is the antibody branch. Antibodies bind a target, neutralize it, or mark it for destruction. IOC federation is the closest software analogue because it carries ready-made specificity from someone else. It is not learned locally, and it expires. That is passive immunity, not active immunity.

Complement is a cascade. One activation step recruits the next, and the result is amplification, opsonization, and a membrane attack complex. Composition rules like H043 do something similar at the finding level: one stage makes the next stage meaningful, and the cluster matters more than any single step. The analogy is structural. TrustSight does not lyse anything.

Regulatory immunity is the part that stops the response. Regulatory T cells suppress overreaction, checkpoints put brakes on activation, and anergy keeps a receptor alive but unresponsive. The M-series, alert budgets, weight-zero context, and the anergy ledger are the same idea in software. Without this branch, an immune system damages the host.

Barrier immunity is the first line: skin, mucosa, tight junctions, and the chemical environment. C033 and C034 are the closest software analogue. A recipe that loses its comment context or ships metadata that disagrees with the PKGBUILD has a breach in the review surface, even if no malicious payload is visible.

The branches overlap. A real immune response uses all of them, and TrustSight does too. The point of the table is not to assign one cell type to one rule family. It is to keep the reader from treating "immune system" as a single metaphor.

The branch that maps least cleanly is cell-mediated immunity. Cytotoxic T cells kill infected cells after recognizing a specific antigen on MHC class I. TrustSight has no equivalent killing step. The closest software moment is a human deciding to remove a package after reading a report, and that is a person acting, not a rule. I would rather leave that gap visible than dress a report as a cytotoxic response.

The innate and adaptive branches are also not stages in a pipeline. They run at the same time. A local rule can fire on a diff while the historical layer is still updating its observations, and the G-series can correlate a campaign before any single rule has enough evidence. The immune system works through parallel sensing and later integration, and so does this one.

### The rule families at a glance

| Family | What it recognizes | Immune analogue | Strength |
|---|---|---|---|
| R | Known dangerous command and payload patterns | PAMP-like innate recognition | Structural |
| H | Behavioral and contextual suspicion | Danger signals and alarmins | Documented |
| C | Structural invariants and integrity changes | Barrier and tissue integrity | Structural |
| D | Dependency-graph and naming anomalies | Molecular mimicry and decoy surfaces | Structural |
| S | Destructive or sabotaging behavior | Pathogen effector arsenal | Interpretive |
| X | How a diff is written rather than what it does | Layered innate sensing of evasion | Structural |
| T | Temporal and historical anomalies | Immune memory and latency | Documented |
| G | Correlated behavior across packages | Clonal selection and ring response | Documented |
| I | Exact matches against signed indicators | Passive immunity and neutralization | Structural |
| U | Declared upstream manifests and release surfaces | Antigen presentation and self-report | Interpretive |
| M | Relationships between findings and detector health | Self-tolerance and regulation | Documented |
| W | What the analysis could not read | Immune privilege and declared blind spots | Structural |

E, A, and P are deliberately absent from the map. E flags statistical anomalies in added content, which is closer to a laboratory signal than to an immune function. A inspects a built artifact, which is closer to a biopsy than to immunity. P is a claims ledger for declared practices, and it does not describe an immune mechanism. Forcing those three into the metaphor would make the table look complete and the argument weaker.

The table also shows where the design is uneven. The innate and memory families have the strongest mappings. The naming and dependency families are structural but less exact. The artifact and statistical families sit outside the immune story. That is fine. A metaphor does not have to cover every module.

Further reading: [Immune system](https://en.wikipedia.org/wiki/Immune_system), [Innate immune system](https://en.wikipedia.org/wiki/Innate_immune_system), [Adaptive immune system](https://en.wikipedia.org/wiki/Adaptive_immune_system), [Complement system](https://en.wikipedia.org/wiki/Complement_system), and [Regulatory T cell](https://en.wikipedia.org/wiki/Regulatory_T_cell).

## 27. Crossfire: sensing the attempt to hide

Crossfire is the rule family that fires on how a diff is written instead of what it does. A payload rule sees a fetch, a write, a privilege change, or an execution. Crossfire sees that the normal path from text to a resolved command is broken. The tokenizer cannot reduce a word to a literal, a command is carried inside a configuration value, a pipeline ends somewhere the analyzer does not recognize.

The engineering name comes from military crossfire: two guns with overlapping fields of fire. A defender who slips past the first walks into the second. The payload rules are the first gun. Crossfire is the second. An attacker who defeats the tokenizer silences the payload rules and trips the crossfire rules instead.

The immune analogue is not an antibody. The closest idea is layered innate sensing. Pattern recognition receptors recognize conserved molecular patterns that signal danger, not a named pathogen. Different receptor families cover different compartments and different threats, so a pathogen that evades one sensor can still trigger another. Crossfire and the payload rules are parallel sensor layers. One watches what resolved. The other watches the failure to resolve.

The second analogue is missing-self recognition. Natural killer cells do not only ask whether a cell carries a foreign antigen. They ask whether the cell has lost the MHC class I signal that says "self." The absence is the signal. Crossfire often works the same way: a construct that should resolve does not, and the failed presentation becomes the finding.

The third analogue is immune evasion. Pathogens hide antigens, block presentation, interfere with complement, or disable the sensors that would notice them. Crossfire is the software response to that behavior. It does not need the payload's identity. It needs evidence that the normal presentation path is broken.

### The crossfire clusters

The 34 X rules fall into a small number of mechanisms. Mapping all 34 one-to-one to immune cells would be a gimmick. The clusters are what matter.

| Cluster | Rules | What crossfire sees | Immune analogue | Strength |
|---|---|---|---|---|
| Camouflage and encoding | X001, X002, X003, X008, X014, X017, X018, X024, X030, X032 | Names, arguments, whitespace, and encoded blobs that hide the real command | Antigenic camouflage and molecular mimicry | Structural |
| Mimicked surface | X005, X006, X025, X033 | Home paths, sources, functions, or files that imitate a legitimate surface | Decoy epitopes and molecular mimicry | Structural |
| Delayed activation | X015, X021, X023, X028, X029 | Work scheduled later, executed later, or completed across commits | Viral latency and reactivation | Structural |
| Host machinery redirected | X011, X012, X020, X022 | Build tools, configs, or package machinery turned against the host | Viral hijack of host machinery | Structural |
| Sensor refusal | X004, X026, X027 | Output suppressed, constructs unresolved, or analysis refusing | Alarmins, DAMPs, and missing-self | Structural |
| Novel route | X009, X010, X016, X034 | New client, new consumer, or archival laundering | Emerging route or novel vector | Interpretive |
| Multiple techniques | X007 | Several evasion techniques at once | Redundant virulence factors | Structural |
| Trust root replaced | X013 | Fetch or trust anchor redirected | Receptor switch or antigenic shift | Interpretive |
| Exfiltration | X019 | Host material sent or packaged | Not evasion; left out of this map | Not applicable |
| Non-code text | X031 | Build reads text that is not code | Cross-context activation | Interpretive |

Camouflage is the largest cluster. X001 decodes and executes an encoded blob. X003 hides a command in a truncated long option, a shell option cluster, or an encoded IP. X008 uses whitespace a shell does not split on. X014 names code through an environment variable. X017 carries a command inside a tool flag or builtin. X018 assembles an interpreter name one piece at a time. X024 assigns a sensitive value indirectly. X030 uses ANSI-C quoting. X032 splices a command name together. The biology here is antigenic camouflage: the pathogen changes its surface so the old antibody does not bind, or hides an epitope behind a glycan. The command is still there. The presentation is what changed.

Mimicked surface is smaller and more specific. X005 reaches a home directory by a spelling H032 does not match. X006 points a source at a URL shortener or a raw IP. X025 shadows a function across lines. X033 executes a file with no provenance. The biology is molecular mimicry and decoy epitopes: the attacker presents something that looks like a legitimate self-structure, or leaves the recognition site intact while changing what sits behind it. This is also where naming and dependency impersonation belong, even though those live in the H and D families.

Delayed activation is the latency cluster. X015 schedules work after the build. X021 executes a file chosen at runtime. X023 runs command output as a script. X028 completes a pattern across commits. X029 leaves encoded material at rest. The biology is viral latency: the genome persists without producing a full payload, then reactivates when the conditions change. This is also why a single-commit view can miss a campaign that only makes sense across revisions.

Host machinery redirected is the hijack cluster. X011 makes a package manager run fetched code at build time. X012 redirects the build toolchain into the source tree. X020 writes the build steps the engine later runs. X022 generates a config and hands it to the tool that reads it. The biology is viral hijack of host machinery: the virus does not build its own ribosome, it uses the host's. A package build has a lot of host machinery, and a recipe that redirects it has more leverage than one that adds a new binary.

Sensor refusal is the alarm cluster. X004 suppresses build output. X026 reports unresolved constructs in executable positions. X027 fires on the refusal cluster itself. The biology is alarmin and DAMP release: damaged or stressed tissue releases signals that recruit a response even when the pathogen is not visible. A failed analysis is not a clean result. It is damaged evidence, and it should make noise.

Novel route is the weakest cluster, and I would keep it short. X009 uses an uncatalogued fetch client. X010 reaches the network from an interpreter one-liner. X016 pipes a fetch into an unrecognized consumer. X034 launders a fetch through an archival service. The analogy is an emerging route or a novel vector. It is useful for explaining why a new client matters, but it is closer to ecology than to immunology. Do not build a larger argument on it.

Multiple techniques is X007. One evasion technique can be a mistake or a false positive. Several at once is a strategy. The biology is a pathogen with redundant virulence factors: it does not rely on one mechanism to escape the response.

Trust root replacement is X013. A fetch is redirected or the trust anchor is replaced. The closest immune idea is a receptor switch or antigenic shift: the target the response was trained on is no longer the target in front of it. This is a useful analogy, not a precise one.

X019 is not evasion. It sends or packages host material. It belongs in the payload and exfiltration story, not in the immune-evasion map. X031 reads non-code text during the build. The cross-context activation analogy is interesting but thin, so it stays at the edge.

The design consequence is that payload and crossfire findings can both fire on the same diff and are scored independently. The payload rule catches what resolved. The crossfire rule catches the attempt to keep it from resolving. Evasion and alarm become the same event instead of evasion and silence.

This is also why crossfire shrinks as the tokenizer improves. Every construct the analyzer learns to resolve removes one reason for a crossfire finding. That is the intended direction. The family is a function of refusal, and a refusal that becomes a resolution is progress, not a lost detection.

Further reading: [Pattern recognition receptor](https://en.wikipedia.org/wiki/Pattern_recognition_receptor), [Pathogen-associated molecular pattern](https://en.wikipedia.org/wiki/Pathogen-associated_molecular_pattern), [Damage-associated molecular pattern](https://en.wikipedia.org/wiki/Damage-associated_molecular_pattern), [Natural killer cell](https://en.wikipedia.org/wiki/Natural_killer_cell), [Missing self](https://en.wikipedia.org/wiki/Missing_self), and [Immune evasion](https://en.wikipedia.org/wiki/Immune_evasion).

## 28. Complement and composition

Complement is a cascade of plasma proteins. One event activates the next, the signal amplifies, and the end result can be opsonization, inflammation, or a membrane attack complex. No single protein carries the cascade; the connection does.

H027, H043, and H098 are composition rules. They do not detect one more payload. They detect that several findings are related.

H027 counts distinct capability categories in one diff. A network fetch, a filesystem write, an execution, and an encoding step are each ordinary enough on their own. Together they describe a chain. The immune analogue is a polyclonal response: many clones recognize different epitopes on the same target, and the combined response is stronger than any one clone. The software version is weaker than that, because H027 is weight zero and only annotates. It does not add score.

H043 counts distinct kill-chain stages. Takeover, adoption, install hook, foreign fetch, registry, payload, obfuscation, anti-analysis, write-then-execute, staging, recon, persistence, exfiltration, hidden drop, integrity removal, and sabotage. When at least three stages appear, the cluster is reported. The complement cascade is the closest structural analogue: the later steps only become meaningful because the earlier ones happened. A single C3b molecule is not the point. The amplification and the membrane attack complex are.

H098 counts naming and deception signals. A name that resembles a popular package, a novel dependency, a typosquatted dependency, a `provides` or `replaces` expansion, a source domain that resembles the upstream, a name and host that diverge, a name and repo that diverge, a new maintainer without history. One signal can be coincidence. Two or more describe a method. The immunology here is avidity rather than a single binding constant: several weak interactions together produce a strong attachment. An immune complex is another way to see it, because the complex is what the effector system recognizes, not the individual antigen.

H102 is the maintainer change plus signing-key change. The old keyring said who was allowed to sign. The new maintainer says something else. The closest immune idea is a mismatch between the presented identity and the self-marker the system expects, which is roughly what happens in a transplant mismatch. The analogy is useful for explaining why the conjunction matters. It is not a claim that package maintainers are grafts.

C021 removes a `checkdepends` entry while the build, prepare, or check function changes. The test suite that would have caught the payload is gone. The immune analogue is a checkpoint being removed. That is a structural analogy, not a complement one, and it belongs with the regulation section as much as here.

The composition rules are deliberately restrained. H027 and H043 carry no weight because the members already scored on their own; adding a composition score would double count. H098 carries weight because the individual naming signals are weak and the combination is materially stronger. That design choice matters more than the biology. A complement cascade amplifies. A composition rule has to decide whether amplification is double counting, and TrustSight answers that per rule.

| Rule | What it composes | Immune analogue | Limit |
|---|---|---|---|
| H027 | Distinct capability categories in one diff | Polyclonal response | Weight zero; it annotates, it does not add score |
| H043 | Distinct kill-chain stages in one package | Complement cascade and membrane attack complex | The stages are not a literal protease cascade |
| H098 | Naming and deception signals | Avidity and immune complex | The member signals are weaker than antibodies |
| H102 | Maintainer change plus signing-key change | Mismatch between presented identity and expected self-marker | A package maintainer is not a transplanted organ |
| C021 | Lost `checkdepends` during a build change | Checkpoint removal | The checkpoint is a test suite, not a T-cell brake |

The complement system has three activation routes, a convertase amplification loop, and several regulators that stop it from attacking host cells. I am not going to pretend that H043 has a convertase. The useful part is the shape: an early event creates the conditions for a later event, and the later event is what produces the response. H043's stage count is a coarse version of that. It asks whether the findings have moved from preparation to payload to cleanup, not whether a specific molecular step occurred.

Avidity is the better fit for H098 than a single antibody. A single weak interaction can be ignored. Several weak interactions together hold. H098 uses the same logic with naming signals: a similar name, a novel dependency, a mismatched host, and a new maintainer are each weak, and the cluster is what makes them worth a second look. The rule still has to avoid the cross-reactivity problem. A cluster of weak signals can also describe a legitimate fork with a new maintainer and a renamed upstream.

Further reading: [Complement system](https://en.wikipedia.org/wiki/Complement_system), [Opsonization](https://en.wikipedia.org/wiki/Opsonization), [Avidity](https://en.wikipedia.org/wiki/Avidity), [Immune complex](https://en.wikipedia.org/wiki/Immune_complex), [Polyclonal antibody](https://en.wikipedia.org/wiki/Polyclonal_antibody), and [MHC class I](https://en.wikipedia.org/wiki/MHC_class_I).

## 29. Barriers and structural integrity

The C-series is the closest thing TrustSight has to an epithelial barrier. The barrier does not kill pathogens. It keeps the tissue organized, limits what gets through, and makes a breach visible.

C033 is context bleed. A diff removes a large fraction of the recipe's comment and prose context. The commands may still be valid. The review surface is gone. C034 is metadata inconsistency. The committed `.SRCINFO` and the PKGBUILD disagree on version fields. The package is presenting two different selves.

In immunology, the epithelial barrier and tight junctions separate the inside from the outside. When the barrier is damaged, damage-associated molecular patterns are released, and the innate system responds to the breach even before it identifies a pathogen. The C-series does something similar. It reports that the normal structure of the review surface has been damaged. The finding is about the loss of integrity, not about a payload.

This is why context bleed is not cosmetic. A recipe with its comments stripped is harder for a human to review. A recipe with inconsistent metadata is harder for a machine to trust. The attack does not need a malicious command if it can make the review surface unreliable.

The analogy has a limit. Not every C rule is a barrier rule. Some C rules check dependency relationships, some check generated metadata, some check structural invariants. The family is broader than the barrier metaphor. Treat C033 and C034 as the clearest barrier cases and describe the rest as structural integrity checks.

The barrier analogy also explains why the review surface matters. A tight junction does not kill a bacterium. It keeps the tissue from leaking, and the leak is what exposes the underlying cells. C033 does not prove a payload. It removes the context that a reviewer needs to understand the change. C034 does not prove a payload. It makes the package's own metadata disagree with itself. Both are leaks in the review surface, and both deserve attention before a payload appears.

There is a repair side too. Epithelial cells can reseal a barrier, and the innate system can resolve inflammation after the breach is closed. TrustSight does not repair a recipe. It can show the reviewer where the surface is damaged, and it can avoid treating the damage as a permanent verdict. A context-bleed finding is evidence about the diff, not a life sentence for the package.

Further reading: [Epithelium](https://en.wikipedia.org/wiki/Epithelium), [Tight junction](https://en.wikipedia.org/wiki/Tight_junction), [Damage-associated molecular pattern](https://en.wikipedia.org/wiki/Damage-associated_molecular_pattern), and [Innate immune system](https://en.wikipedia.org/wiki/Innate_immune_system).

## 30. Passive and active immunity

Active immunity is what the body builds after an encounter. It takes time, it is specific, and it leaves memory. Passive immunity is what the body receives ready-made, through maternal antibodies or an antibody preparation. It works immediately, it is not learned, and it fades.

TrustSight has both. Local observations and the novelty seed are active immunity. The system learns the AUR it sees, remembers maintainers and sources, and updates its expectations. The seed is a shortcut for a cold install, but it still becomes local history. IOC federation is passive immunity. A curator has already identified a domain, hash, package name, file path, PKGBUILD pattern, or upstream repository. TrustSight receives that specificity, verifies the signature, keeps the attribution, and applies the indicator.

The distinction matters because the failure modes are different. Active immunity can be wrong because the local history is thin or poisoned. Passive immunity can be wrong because the indicator is stale, low confidence, or from a curator with a different threat model. The docs already handle this with provenance, confidence tiers, and expiry. The immune analogy explains why both layers exist: a system that only learns locally is slow to recognize a known threat, and a system that only receives indicators never develops its own memory.

The seed is closer to a prime than a vaccine. It gives the immune system a first look at common shapes, and the real response develops after exposure. Calling it a vaccine in public copy suggests a guarantee of protection that the seed does not provide. Priming is the accurate word.

IOC expiry is the passive-immunity fade. An expired indicator remains visible as expired instead of silently disappearing. That is better than pretending the antibody is still there.

| Layer | Immune analogue | Time scale | Failure mode |
|---|---|---|---|
| Local observations | Active immunity | Learned over many analyses | Thin history, poisoned history |
| Novelty seed | Prime or early exposure | Point-in-time snapshot | A valid but poisoned seed weakens novelty |
| IOC federation | Passive immunity | Until the indicator expires | Stale, low-confidence, or mismatched indicators |
| Public feed | Shared memory | Continuous, with signed checkpoints | A watcher that is down or compromised |

The seed and the local database are not the same kind of memory. The seed says what the AUR looked like at a point in time. The local database says what this installation has seen since then. A seed can make a new install useful on day one, but it cannot tell the install what changed yesterday. That is why the local observations take over as they accumulate.

The prime-boost analogy is useful but easy to overdo. A prime exposes the immune system to an antigen, and a boost raises the response later. The seed exposes a cold install to historical shapes, and local analyses raise the response. TrustSight has no adjuvant and no guarantee that the second exposure will be stronger. The analogy explains the sequence, not the strength.

Further reading: [Passive immunity](https://en.wikipedia.org/wiki/Passive_immunity), [Adaptive immune system](https://en.wikipedia.org/wiki/Adaptive_immune_system), [Immunological memory](https://en.wikipedia.org/wiki/Immunological_memory), and [Neutralization](https://en.wikipedia.org/wiki/Neutralization_(immunology)).

## 31. Monoclonal and polyclonal recognition

A monoclonal antibody recognizes one epitope. A polyclonal response recognizes many epitopes on the same target, because many B-cell clones respond. Monoclonal is precise and reproducible. Polyclonal is broader and more tolerant of a target that changes shape.

The I-series is monoclonal. An exact indicator matches a domain, hash, package name, file path, PKGBUILD pattern, or upstream repository. The match is specific, and the evidence is easy to explain. The weakness is the same as a monoclonal antibody: change the epitope and the match is gone.

The R, H, C, D, and G families are closer to a polyclonal response. They recognize different kinds of evidence: command shape, behavior, structure, dependency relationships, naming, and cross-package correlation. A campaign that changes one host or one literal can still trip a different family. The tradeoff is cross-reactivity. A polyclonal response can bind something that merely looks similar. A heuristic rule can fire on a benign package that shares the shape.

This is the precision and recall tradeoff in immunological clothing. Exact indicators are high precision and narrow. Heuristic families are broader and need calibration. Neither is inherently better. The design uses both because an attacker can evade one and not the other.

Cross-reactivity also explains a class of false positives. A rule trained on a malicious shape may recognize a benign package that uses the same shape for a legitimate reason. The fix is not to remove the rule family. It is to add the benign twin to the corpus, keep the true-positive twin, and calibrate the weight. That is the same lesson as serum cross-reactivity: the assay needs a blocking step or a more specific target.

Affinity is the strength of one binding site. Avidity is the combined strength of many binding sites. A monoclonal antibody can have high affinity and low avidity because it only binds one epitope. A polyclonal response can have modest affinity per clone and high avidity because many clones bind at once. The I-series is high affinity and narrow. The heuristic families are closer to avidity, with many weak recognizers adding up.

This is also why an exact indicator is valuable even when the heuristic families are broader. A known-bad hash is a high-affinity match. It does not need a cluster, and it does not need a campaign. The tradeoff is that it only catches the exact bytes. The heuristic families catch the behavior around the bytes. A mature system needs both.

Further reading: [Monoclonal antibody](https://en.wikipedia.org/wiki/Monoclonal_antibody), [Polyclonal antibody](https://en.wikipedia.org/wiki/Polyclonal_antibody), and [Cross-reactivity](https://en.wikipedia.org/wiki/Cross-reactivity).

## 32. Original antigenic sin and cross-reactivity

Immunological memory is usually an advantage. It can also mislead. Original antigenic sin is the observation that a first exposure can bias later responses toward the first antigen, even when the new antigen is different. The immune system remembers the shape it learned and tries to fit the new threat into the old template.

TrustSight's campaign priming has the same risk. G007 keeps a campaign's scope for a bounded number of observations. A package later encountered in that scope can get a corroboration record carrying the campaign ID. That is useful when the campaign continues. It is dangerous when the new activity is a different campaign that happens to touch the same host, maintainer, or dependency.

The seed has a similar risk at a larger scale. A validly signed seed can make an attacker's URL or maintainer look familiar if the seed was built from a poisoned history. The additive boundary limits the damage, and the signature protects provenance, but the seed cannot make a bad history good.

The docs already bound both mechanisms. G007 expires, the active campaign count is capped, repeated reactivation is reported through M006, and expiration is visible. The seed is additive and cannot rewrite local observations. Those are the engineering equivalents of affinity maturation and negative selection: the system is not allowed to commit permanently to the first shape it saw.

Original antigenic sin is a phenomenon, not a universal law. Some responses do broaden. The lesson for TrustSight is narrower: prior familiarity is evidence, not proof, and a bounded memory is safer than a permanent one.

Antigenic drift is the other side. A campaign can change a host, a package name, a literal, or a dependency while keeping the same operational shape. The G-series can catch the shared pattern even when the specific indicator changes. That is the value of a polyclonal, correlation-based layer over a purely exact-match one.

Original antigenic sin is usually described with influenza and dengue. The first exposure biases the antibody response toward the first strain, so the response to a later strain is weaker or misdirected. The analogy for TrustSight is not that G007 is an antibody. It is that a prior campaign can shape what the analyst expects to see. A package that touches the old campaign's host may look like a continuation when it is a new campaign using the same infrastructure.

Antigenic shift is the larger change, usually a reassortment that produces a very different surface. A campaign that switches from one delivery mechanism to another, or from one package family to another, is closer to a shift than a drift. The G-series can still catch the shared behavior, but the exact indicators will not. That is why the correlation layer and the indicator layer have to be separate.

The bounded campaign state is the control. G007 is not a permanent memory of the campaign. It expires, the active count is capped, and M006 reports churn. The system is allowed to learn from the prior campaign without letting the prior campaign define every future one.

Further reading: [Original antigenic sin](https://en.wikipedia.org/wiki/Original_antigenic_sin), [Antigenic drift](https://en.wikipedia.org/wiki/Antigenic_drift), [Immunological memory](https://en.wikipedia.org/wiki/Immunological_memory), and [Trained immunity](https://en.wikipedia.org/wiki/Trained_immunity).

## 33. Ring vaccination and the neighborhood response

Ring vaccination protects a population by immunizing the contacts of a known case, not the whole population. The ring is bounded by the contact network and the time window. It is a response to a known case, not a permanent state.

G006 is the software version. When a campaign is active, a package that newly gains a host or domain inside the campaign's scope can be tagged as touching an alerted neighborhood. The tag is weight zero. It is context, not an accusation. The neighborhood is bounded by the campaign's lifetime, not by a permanent list.

The analogy is useful because it explains why G006 is not a quarantine. A ring vaccination does not imprison the contacts. It raises their readiness. G006 does not block a package. It tells the reviewer that this package is near a known campaign. The response is still human.

The ring also explains why G006 has to expire. A ring that never dissolves becomes a permanent suspicion of a whole neighborhood. The campaign TTL, the observation clock, and M006 are the mechanisms that keep the ring temporary.

The analogy breaks if it is stretched. Ring vaccination is a public-health strategy, not an immune mechanism. The biological part is the local tissue response to a known infection, not the vaccination policy. Say that plainly.

The ring also has a boundary problem. A ring that is too wide becomes a permanent alert on the whole ecosystem. A ring that is too narrow misses the next contact. G006 uses the campaign's scope and the observation clock to draw the boundary, and it stays weight zero so the ring does not become an accusation. That is the software version of a public-health ring: identify the contacts, raise their readiness, and stop when the window closes.

The difference from quarantine matters. Quarantine restricts movement. G006 adds context. A package inside the ring is not blocked, removed, or scored as malicious. A reviewer sees that it touches an alerted neighborhood and decides what to do. The immune system recruits cells to a site; it does not arrest every cell in the tissue.

Further reading: [Ring vaccination](https://en.wikipedia.org/wiki/Ring_vaccination), [Chemokine](https://en.wikipedia.org/wiki/Chemokine), and [Cytokine](https://en.wikipedia.org/wiki/Cytokine).

## 34. Immune privilege and blind spots

Some tissues are immune-privileged. The eye, the brain, and the testes limit immune access to avoid damage from inflammation. Privilege is not the same as safety. It is a controlled reduction in surveillance, and it can become a place where a pathogen persists.

W-series findings are the closest software analogue. A W rule reports what the analysis could not check: an unreadable surface, a missing manifest, a boundary in the evidence. The report does not pretend the package is clean. It names the blind spot.

The analogy needs care. Immune privilege is an active, regulated state. A W finding is often a limitation, not a designed privilege. The useful part is the honesty: a system that cannot see something should say so instead of treating silence as health. `self_state` does the same at the report level, with cold or warm mode, observation counts, channel ages, federation availability, and a sorted list of blind spots.

The failure mode is treating privilege as protection. A blind spot is not a safe package. An `UNFLAGGED` result is not a certificate. W findings exist to keep that distinction visible.

The W-series is broader than a single blind spot. W010 reports that the alert budget was reached. W013 makes a campaign boundary visible. Other W rules name an unreadable manifest, an unavailable channel, or a surface the analyzer cannot inspect. The common thread is that the report says what it could not do. That is the opposite of a system that treats silence as a clean bill of health.

Immune privilege is not absolute, and neither is a W finding. The eye can still mount an inflammatory response under some conditions. A W finding can still be followed by a payload finding in another layer. The value is the honesty, not a claim that the blind spot is safe.

Further reading: [Immune privilege](https://en.wikipedia.org/wiki/Immune_privilege), [Immune tolerance](https://en.wikipedia.org/wiki/Immune_tolerance), and [Innate immune system](https://en.wikipedia.org/wiki/Innate_immune_system).

## 35. Immunosurveillance and immunoediting

Immunosurveillance is the continuous search for abnormal cells. Immunoediting describes three outcomes: elimination, equilibrium, and escape. The immune system removes some threats, holds others in a dormant state, and sometimes selects for variants that survive the response.

The watcher is TrustSight's surveillance layer. It watches AUR changes, analyzes changed packages, keeps historical state, joins cross-package observations, and reports new clusters. It does not eliminate anything. It observes and signals, and a person decides what to do. The public feed turns those observations into shared memory.

The three Es are a useful way to describe what happens next. Elimination is the human response: a maintainer removes a package, a user removes it locally, a report is acted on. Equilibrium is the bounded campaign state: the threat is known, the scope is retained for a while, and the system watches for reactivation. Escape is the campaign that changes its host, name, or dependency and survives the current rules.

TrustSight can support elimination, but it is not the eliminator. That distinction matters. A watcher that claims to eliminate becomes an enforcement system with a different threat model and a different failure mode. A watcher that observes and signals stays inside the current trust boundary.

Immunoediting also explains why a campaign can look weaker after a response. The visible payload may disappear while the operational pattern persists. The G-series and the watcher are built for the pattern, not just the payload.

The watcher's architecture matters here. It keeps historical state, joins observations across packages, and reports new clusters. That is closer to a surveillance system than to a single immune cell. The public feed adds shared memory and signed checkpoints, so a deployment can verify what another deployment observed. The immune analogue is a distributed surveillance network, not a central brain.

The three Es also give a clean way to talk about failure. Elimination is the human action. Equilibrium is the bounded campaign state. Escape is the campaign that changes shape and survives the current rules. A watcher that claims all three is overclaiming. A watcher that reports which one it is seeing is useful.

Further reading: [Immunosurveillance](https://en.wikipedia.org/wiki/Immunosurveillance), [Immunoediting](https://en.wikipedia.org/wiki/Immunoediting), and [Immune evasion](https://en.wikipedia.org/wiki/Immune_evasion).

## 36. Exhaustion, regulation, and resolution

An immune response has to end. T-cell exhaustion is what happens when a response runs too long: the cells lose effector function and retain inhibitory receptors. Regulatory T cells suppress overreaction. Immune checkpoints put brakes on activation. Efferocytosis clears apoptotic cells without starting a new inflammatory response.

TrustSight has the same problem. A campaign that never expires, a rule that keeps firing, or an alert budget that keeps overflowing will exhaust the reviewer. M006 reports repeated campaign reactivation. Alert budgets cap terminal output and report the cap through W010. Suppressions expire and carry reasons. Anergy keeps uncalibrated rules visible without scoring them.

The regulatory T-cell analogy is structural, not literal. Tregs are antigen-specific cells that suppress other immune cells. TrustSight's brakes are budgets, weights, expiry, and explicit promotion. The shared property is that restraint is an active function with its own mechanisms, not the absence of detection.

Efferocytosis is the cleanup analogy. When cells die by apoptosis, phagocytes clear them without spilling inflammatory contents. A campaign that ends should be cleared without leaving permanent suspicion. Expiry, visible suppression, and campaign cleanup do that. A stale campaign that never clears is closer to a necrotic mess than to resolution.

The failure mode is overcorrection. A system that suppresses too much looks calm and misses threats. A system that resolves too aggressively creates noise. The balance is the same one the immune system manages: enough response to clear the threat, enough restraint to protect the host.

Checkpoints are the other half of regulation. An immune checkpoint is a receptor that dampens activation, and checkpoint inhibitors release that brake. TrustSight's brakes are alert budgets, weight-zero context, anergy, and explicit promotion. Releasing a brake without evidence is how an immune response becomes autoimmunity. Releasing a rule from anergy without calibration is how a detector becomes noise.

Efferocytosis is not just cleanup. It actively resolves inflammation and prevents the contents of dead cells from triggering a new response. TrustSight's equivalent is the visible expiry of a campaign and the removal of stale suppression state. A campaign that ends should leave a record, not a permanent suspicion. A suppression that expires should be visible, not silently forgotten.

The design has no literal Tregs and no literal checkpoints. What it has is a set of mechanisms that make restraint explicit. That is the part worth keeping in the analogy.

Further reading: [T-cell exhaustion](https://en.wikipedia.org/wiki/T_cell_exhaustion), [Regulatory T cell](https://en.wikipedia.org/wiki/Regulatory_T_cell), [Immune checkpoint](https://en.wikipedia.org/wiki/Immune_checkpoint), and [Efferocytosis](https://en.wikipedia.org/wiki/Efferocytosis).

## 37. Latency, mimicry, and drift

Viral latency is a persistent infection with little or no active replication. The virus remains, sometimes for years, and reactivates when conditions change. Herpes simplex and varicella-zoster are the familiar examples. The immune system can keep a latent infection in check without eliminating it.

The T-series sees the software version. A package that was dormant and becomes active again, a maintainer who returns after a long gap, a source that reappears after a quiet period. None of those is malicious on its own. They are changes in the timing and history of the package, and they become evidence when combined with other findings.

Molecular mimicry is the second idea. A pathogen presents an epitope that resembles a host structure, so the immune response either misses it or attacks the host. Package names, source domains, and dependency names do the same thing in the AUR. H029, D002, and C012 are the software recognition of that mimicry. The name looks like a popular package. The dependency looks like a legitimate one. The domain looks like the upstream.

Antigenic drift is the third. A virus accumulates small changes that escape existing immunity. A campaign changes a host, a package name, a literal, or a dependency while keeping the same operational shape. The G-series watches for the shared pattern, and the T-series watches the history around it.

These three ideas belong together because they describe the same problem from different angles. Latency explains why a quiet package is not automatically safe. Mimicry explains why a familiar name is not automatically trusted. Drift explains why a campaign can survive a rule that caught the previous version.

Latency is the hardest of the three to detect because nothing is happening. A dormant package has no payload in the current diff. The T-series notices that the package is active again after a long gap, that a maintainer returned, or that a source reappeared. The finding is about the change in timing, not about a command.

Mimicry is easier to see but harder to judge. A package name that resembles a popular package can be a fork, a rename, or an impersonation. The H and D rules record the resemblance. The reviewer decides whether it is legitimate. The immune system has the same problem: a self-antigen and a mimic can look alike, and the response has to distinguish them without attacking the host.

Drift is the reason a single campaign can produce several waves. The first wave uses one host, the second uses another, and the payload changes. The G-series looks for the shared operational pattern, and the T-series looks at the history. Neither is enough alone. Together they describe a campaign that is still the same campaign even when its surface has changed.

Further reading: [Virus latency](https://en.wikipedia.org/wiki/Virus_latency), [Molecular mimicry](https://en.wikipedia.org/wiki/Molecular_mimicry), [Antigenic drift](https://en.wikipedia.org/wiki/Antigenic_drift), and [Immune evasion](https://en.wikipedia.org/wiki/Immune_evasion).

## 38. Failure modes and non-claims

The immune system has failure modes that are as instructive as its successes. Cytokine storm is an uncontrolled release of pro-inflammatory cytokines. Autoimmunity is an attack on self. Immunodeficiency is a missing or weakened response. Each has a software analogue, and each analogy has a limit.

Cytokine storm maps to alert overload. TrustSight caps terminal findings, caps watcher notifications per cycle, and reports the cap through W010. The full findings stay in the JSON record. The goal is to keep the response readable, not to hide the evidence.

Autoimmunity maps to the M-series. The detection system can contradict itself, fire on its own expectations, or keep re-arming a campaign. M001 to M006 check the health of the detection process, not just the package. This is the closest thing to self-tolerance in the design.

Immunodeficiency maps to `self_state`. A cold database, a stale channel, an unavailable federation source, or an unexercised analysis lane are missing sensors. The report says so instead of treating silence as health.

The limits matter. TrustSight does not have a literal cytokine storm, autoimmune disease, or immunodeficiency. The analogies explain why the controls exist. They do not diagnose the software.

The strongest mappings are the ones the docs already name: missing-self, danger, trained immunity, cytokine signaling, opsonization, anergy, exhaustion, regulation, and immune privilege. The structural mappings are crossfire as layered innate sensing, complement as composition, barriers as integrity checks, passive immunity as IOC federation, and monoclonal versus polyclonal as exact versus diverse recognition. The interpretive mappings are useful for explanation but should not be used to justify a rule.

What the page does not claim: TrustSight does not block, quarantine, or remove packages. It does not make the AUR immune. The seed is not a whitelist. G007 is not permanent learning. The watcher is not a central brain. `UNFLAGGED` is not a certificate of safety. A healthy immune system knows what it can see, what it cannot see, and when to abstain.

| Mapping | Strength | Why |
|---|---|---|
| Missing-self, danger, trained immunity, cytokines, opsonization, anergy, exhaustion, regulation | Documented | The docs name the concept and tie it to a mechanism |
| Crossfire as layered innate sensing, complement as composition, barriers as integrity, passive immunity as IOC, monoclonal versus polyclonal | Structural | The mechanism and the biology solve the same problem without a literal cell |
| Receptor switch, cross-context activation, graft mismatch | Interpretive | Useful for explanation, not a justification for a rule |

Further reading: [Cytokine storm](https://en.wikipedia.org/wiki/Cytokine_storm), [Autoimmunity](https://en.wikipedia.org/wiki/Autoimmunity), [Immunodeficiency](https://en.wikipedia.org/wiki/Immunodeficiency), and Janeway's Immunobiology (NCBI Bookshelf NBK10767).

## 39. What the metaphor cannot carry

The immune analogy explains sensing, memory, correlation, and restraint. It does not explain the AUR's social and economic shape.

A package can be abandoned because the maintainer burned out, not because the package is malicious. A name can be squatted because the original project changed its name, not because an attacker is impersonating it. A dependency can be added because a library split, not because someone is building a campaign. The immune system has no concept of maintainer burnout, license churn, or a downstream distribution deciding to patch a package differently.

The AUR is also not a body. It is a set of Git repositories, a web interface, a group of maintainers, and a community of users. The "organism" is a way to talk about the whole, not a claim that the whole has a single metabolism or a single intent. When the metaphor starts to imply that the AUR has a will, or that a package is a cell with a fixed role, it has gone too far.

The metaphor can also justify the wrong response. "The immune system must eliminate the threat" sounds natural and leads straight to blocking, quarantine, and automated removal. TrustSight does not do those things. The human loop is not a weakness in the design. It is the design. A tool that confuses sensing with enforcement starts a different kind of immune response, one with its own autoimmune risks.

The last limit is evidence. The immune system does not tell you whether a package is safe. It tells you that something looks like danger, that a response is needed, or that a blind spot exists. TrustSight does the same. The report is an instrument reading, not a verdict. `UNFLAGGED` means no published rule matched the evidence examined. It does not mean the package is healthy.

Those limits are not a reason to drop the metaphor. They are the reason the page keeps returning to the human loop. The software supplies scale, memory, and correlation. People supply judgment, context, and action. The metaphor is useful while it keeps that division visible.

Further reading: [Immune system](https://en.wikipedia.org/wiki/Immune_system), [Immune tolerance](https://en.wikipedia.org/wiki/Immune_tolerance), and [Immune privilege](https://en.wikipedia.org/wiki/Immune_privilege).

## Immunology sources

The core definitions below are from Wikipedia, with Janeway's Immunobiology for mechanism and the existing PMC review for bystander activation. I use Wikipedia for accessible definitions, not as the final authority on a contested claim.

- [Immune system](https://en.wikipedia.org/wiki/Immune_system)
- [Innate immune system](https://en.wikipedia.org/wiki/Innate_immune_system)
- [Adaptive immune system](https://en.wikipedia.org/wiki/Adaptive_immune_system)
- [Pattern recognition receptor](https://en.wikipedia.org/wiki/Pattern_recognition_receptor)
- [Pathogen-associated molecular pattern](https://en.wikipedia.org/wiki/Pathogen-associated_molecular_pattern)
- [Damage-associated molecular pattern](https://en.wikipedia.org/wiki/Damage-associated_molecular_pattern)
- [Complement system](https://en.wikipedia.org/wiki/Complement_system)
- [Opsonization](https://en.wikipedia.org/wiki/Opsonization)
- [Natural killer cell](https://en.wikipedia.org/wiki/Natural_killer_cell)
- [Missing self](https://en.wikipedia.org/wiki/Missing_self)
- [Immune evasion](https://en.wikipedia.org/wiki/Immune_evasion)
- [Immunosurveillance](https://en.wikipedia.org/wiki/Immunosurveillance)
- [Immunoediting](https://en.wikipedia.org/wiki/Immunoediting)
- [Immune privilege](https://en.wikipedia.org/wiki/Immune_privilege)
- [Immune tolerance](https://en.wikipedia.org/wiki/Immune_tolerance)
- [Regulatory T cell](https://en.wikipedia.org/wiki/Regulatory_T_cell)
- [Co-stimulation](https://en.wikipedia.org/wiki/Co-stimulation)
- [Anergy](https://en.wikipedia.org/wiki/Anergy)
- [T-cell exhaustion](https://en.wikipedia.org/wiki/T_cell_exhaustion)
- [Efferocytosis](https://en.wikipedia.org/wiki/Efferocytosis)
- [Immunological memory](https://en.wikipedia.org/wiki/Immunological_memory)
- [Clonal selection](https://en.wikipedia.org/wiki/Clonal_selection)
- [Trained immunity](https://en.wikipedia.org/wiki/Trained_immunity)
- [Original antigenic sin](https://en.wikipedia.org/wiki/Original_antigenic_sin)
- [Antigenic drift](https://en.wikipedia.org/wiki/Antigenic_drift)
- [Molecular mimicry](https://en.wikipedia.org/wiki/Molecular_mimicry)
- [Virus latency](https://en.wikipedia.org/wiki/Virus_latency)
- [Passive immunity](https://en.wikipedia.org/wiki/Passive_immunity)
- [Neutralization](https://en.wikipedia.org/wiki/Neutralization_(immunology))
- [Monoclonal antibody](https://en.wikipedia.org/wiki/Monoclonal_antibody)
- [Polyclonal antibody](https://en.wikipedia.org/wiki/Polyclonal_antibody)
- [Cross-reactivity](https://en.wikipedia.org/wiki/Cross-reactivity)
- [Avidity](https://en.wikipedia.org/wiki/Avidity)
- [Immune complex](https://en.wikipedia.org/wiki/Immune_complex)
- [Ring vaccination](https://en.wikipedia.org/wiki/Ring_vaccination)
- [Immunodeficiency](https://en.wikipedia.org/wiki/Immunodeficiency)
- [Cytokine storm](https://en.wikipedia.org/wiki/Cytokine_storm)
- [Autoimmunity](https://en.wikipedia.org/wiki/Autoimmunity)
- [Vaccine](https://en.wikipedia.org/wiki/Vaccine)
- [Immunization](https://en.wikipedia.org/wiki/Immunization)
- [Adjuvant](https://en.wikipedia.org/wiki/Adjuvant)
- [Antigen](https://en.wikipedia.org/wiki/Antigen)
- [Macrophage](https://en.wikipedia.org/wiki/Macrophage)
- [Dendritic cell](https://en.wikipedia.org/wiki/Dendritic_cell)
- [Mast cell](https://en.wikipedia.org/wiki/Mast_cell)
- [MHC class I](https://en.wikipedia.org/wiki/MHC_class_I)
- [Killer-cell immunoglobulin-like receptor](https://en.wikipedia.org/wiki/Killer-cell_immunoglobulin-like_receptor)
- [Danger model](https://en.wikipedia.org/wiki/Danger_model)
- [Alarmin](https://en.wikipedia.org/wiki/Alarmin)
- [Germinal center](https://en.wikipedia.org/wiki/Germinal_center)
- [Affinity maturation](https://en.wikipedia.org/wiki/Affinity_maturation)
- [Memory B cell](https://en.wikipedia.org/wiki/Memory_B_cell)
- [Plasma cell](https://en.wikipedia.org/wiki/Plasma_cell)
- [Cytokine](https://en.wikipedia.org/wiki/Cytokine)
- [Chemokine](https://en.wikipedia.org/wiki/Chemokine)
- [Cytokine release syndrome](https://en.wikipedia.org/wiki/Cytokine_release_syndrome)
- [Phagocytosis](https://en.wikipedia.org/wiki/Phagocytosis)
- [Antibody](https://en.wikipedia.org/wiki/Antibody)
- [Sickness behavior](https://en.wikipedia.org/wiki/Sickness_behavior)
- [Fever](https://en.wikipedia.org/wiki/Fever)
- [Acute-phase protein](https://en.wikipedia.org/wiki/Acute-phase_protein)
- [Refractory period](https://en.wikipedia.org/wiki/Refractory_period)
- [Desensitization](https://en.wikipedia.org/wiki/Desensitization_(medicine))
- [Tachyphylaxis](https://en.wikipedia.org/wiki/Tachyphylaxis)
- [Superantigen](https://en.wikipedia.org/wiki/Superantigen)
- [Chronic inflammation](https://en.wikipedia.org/wiki/Chronic_inflammation)
- [Inflammation](https://en.wikipedia.org/wiki/Inflammation)
- [Central tolerance](https://en.wikipedia.org/wiki/Central_tolerance)
- [Peripheral tolerance](https://en.wikipedia.org/wiki/Peripheral_tolerance)
- [Nociception](https://en.wikipedia.org/wiki/Nociception)
- [Interoception](https://en.wikipedia.org/wiki/Interoception)
- [Allostasis](https://en.wikipedia.org/wiki/Allostasis)
- [Sentinel cell](https://en.wikipedia.org/wiki/Sentinel_cell)
- [Lymphatic system](https://en.wikipedia.org/wiki/Lymphatic_system)
- [Autophagy](https://en.wikipedia.org/wiki/Autophagy)
- [Apoptosis](https://en.wikipedia.org/wiki/Apoptosis)
- [Homeostasis](https://en.wikipedia.org/wiki/Homeostasis)
- [Immune checkpoint](https://en.wikipedia.org/wiki/Immune_checkpoint)
- [T cell](https://en.wikipedia.org/wiki/T_cell)
- [Janeway's Immunobiology, NCBI Bookshelf](https://www.ncbi.nlm.nih.gov/books/NBK10767/)
- [Bystander activation review, PMC11635090](https://pmc.ncbi.nlm.nih.gov/articles/PMC11635090/)

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
