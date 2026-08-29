<!-- description: Rules that fire when distinct kinds of finding co-occur. The combination is the signal and the points are already scored, so both carry weight 0 by design. -->

# Composition

Distinct kinds of finding co-occurred. The combination is the signal, and
the points are already on the board from the rules that fired, so both
rules here carry weight 0 by design: adding a score for the combination
would double-count what the individual rules already scored.

H027 counts distinct capability `category` values across one diff. H043
counts distinct kill-chain stages. Neither can turn an UNFLAGGED package
into a flagged one on its own, and neither is a detection: they are
annotations on findings that other rules produced.

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [H027](#h027) | Capability Density Anomaly | INFO |
| [H043](#h043) | Attack-Chain Composition | INFO |
<!-- /generated: page-index -->

### H027: Capability Density Anomaly {#h027}

- **Target:** programmatic (existing `triggered_rules`, no new detection)
- **Severity:** INFO (weight 0) - report-only co-occurrence flag
- **Category:** `meta`
- **Condition:** A single diff has rule hits in **3+ distinct capability
  categories** (e.g. `network` + `filesystem` + `execution` + `encoding`).

Most updates change one thing. A diff that *simultaneously* adds a network
fetch, writes a file, and base64-decodes a payload is disproportionate; the
co-occurrence is more suspicious than the sum of its parts.

**Why weight 0:** Adding a score for the combination would **double-count**;
the three categories already scored individually via their own rules. Stacking
extra points on top would inflate the benign p95, exactly the inflation the
accuracy work eliminated. H027 therefore carries weight 0: it is a
**co-occurrence annotation** surfaced to the report.
The pattern is the signal; the points are already there.

**Origin:** Socket.dev's capability profiling - every package is annotated
with a capability profile (network access, filesystem access, shell execution,
encoded payloads) and Socket's diff view flags *permission creep* when a new
version acquires capabilities it did not have before. H027 is the same insight
at the rule-category level: a diff whose rule hits span multiple capability
domains has a density that is itself a pattern.

### H043: Attack-Chain Composition {#h043}

- **Severity:** INFO (weight 0)
- **Category:** `composition`
- **Condition:** The findings on one package span at least `[thresholds] h043.attack_chain_stages` (default 3) distinct kill-chain stages.

Stages: takeover (H026, H044, H074), mass adoption (H045, H073), install hook
(H023, H017), foreign fetch (R001, H035, H066, H034), payload (H068, H069),
obfuscation (H036, H065), anti-analysis (H067), write-then-execute (H072),
staging (H038), recon (H040), persistence (H039, H062, H076), exfil (H041,
H071), hidden drop (H042).

Each stage counts once however many rules in it fired, and H043's own finding
is excluded from its own count. It is a composition annotation, not an additive
score: the point is that several independent stages co-occurred, which is what
separated the 2018 acroread attack and the 2026 Atomic Arch campaign from
single-signal noise.

Fire rate: 0 of 3246. A benign diff with one or two rule hits cannot reach
three distinct stages.
