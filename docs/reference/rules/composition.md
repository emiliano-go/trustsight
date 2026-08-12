# Composition

Distinct kinds of finding co-occurred. The combination is the signal, and
the points are already on the board from the rules that fired, so both
rules here carry weight 0 by design: adding a score for the combination
would double-count what the individual rules already scored.

R072 counts distinct capability `category` values across one diff. R089
counts distinct kill-chain stages. Neither can turn an UNFLAGGED package
into a flagged one on its own, and neither is a detection: they are
annotations on findings that other rules produced.

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

### R072: Capability Density Anomaly {#r072}

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
accuracy work eliminated. R072 therefore carries weight 0: it is a
**co-occurrence annotation** surfaced to the report.
The pattern is the signal; the points are already there.

**Origin:** Socket.dev's capability profiling - every package is annotated
with a capability profile (network access, filesystem access, shell execution,
encoded payloads) and Socket's diff view flags *permission creep* when a new
version acquires capabilities it did not have before. R072 is the same insight
at the rule-category level: a diff whose rule hits span multiple capability
domains has a density that is itself a pattern.

### R089: Attack-Chain Composition {#r089}

- **Severity:** INFO (weight 0)
- **Category:** `composition`
- **Condition:** The findings on one package span at least `[thresholds] r089.attack_chain_stages` (default 3) distinct kill-chain stages.

Stages: takeover (R071, R090, R126), mass adoption (R092, R125), install hook
(R068, R062), foreign fetch (R001, R081, R118, R080), payload (R120, R121),
obfuscation (R082, R117), anti-analysis (R119), write-then-execute (R124),
staging (R084), recon (R086), persistence (R085, R114, R128), exfil (R087,
R123), hidden drop (R088).

Each stage counts once however many rules in it fired, and R089's own finding
is excluded from its own count. It is a composition annotation, not an additive
score: the point is that several independent stages co-occurred, which is what
separated the 2018 acroread attack and the 2026 Atomic Arch campaign from
single-signal noise.

Fire rate: 0 of 3246. A benign diff with one or two rule hits cannot reach
three distinct stages.
