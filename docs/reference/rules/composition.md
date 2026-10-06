<!-- description: Rules that fire when distinct kinds of finding co-occur. H027 and H043 are weight-0 annotations; H098 is the deliberate weight-bearing exception. -->

# Composition

Distinct kinds of finding co-occurred. The combination is the signal.

H027 and H043 carry weight 0 by design: the points are already on the board
from the rules that fired, and adding a score for the combination would
double-count what those rules already scored. H098 is the deliberate
exception. A package that both impersonates a popular name and redirects
its dependencies or source is the attack H029 exists to surface, so the
combination carries its own weight rather than relying on the sum of its
parts. Its members still score individually; the cluster stacks on top by
design, the same safety-first choice the X007 crossfire cluster makes.

H027 counts distinct capability `category` values across one diff. H043
counts distinct kill-chain stages. H098 counts distinct naming/deception
signals. None is a detection on its own: they annotate findings that other
rules produced.

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [C021](#c021) | Dependency Removal During A Build Change | MEDIUM |
| [C024](#c024) | Install Script Not Declared | MEDIUM |
| [H027](#h027) | Capability Density Anomaly | INFO |
| [H043](#h043) | Attack-Chain Composition | INFO |
| [H098](#h098) | Naming/Deception Cluster | HIGH |
| [H102](#h102) | Maintainer Change With Signing Key Change | HIGH |
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
- **Category:** `meta`
- **Condition:** The findings on one package span at least `[thresholds] h043.attack_chain_stages` (default 3) distinct kill-chain stages.

Stages: takeover (H026, H044, H074), mass adoption (H045, H073), install hook
(H023, H017), foreign fetch (R001, H035, H066, H034), payload (H068, H069),
obfuscation (H036, H065), anti-analysis (H067), write-then-execute (H072),
staging (H038), recon (H040), persistence (H039, H062, H076), exfil (H041,
H071), hidden drop (H042), integrity removed (H091) and sabotage (S001-S008).
Later rules also map onto these stages, including R041, R054, R144, the
H080-H083/H089-H091 additions and the X001-X031 crossfire rules; the
authoritative rule-to-stage map is `_STAGE_OF` in `analysis/composition.py`.

Each stage counts once however many rules in it fired, and H043's own finding
is excluded from its own count. It is a composition annotation, not an additive
score: the point is that several independent stages co-occurred, which is what
separated the 2018 acroread attack and the 2026 Atomic Arch campaign from
single-signal noise.

Fire rate: 0 of 3739. A benign diff with one or two rule hits cannot reach
three distinct stages.

### H098: Naming/Deception Cluster {#h098}

- **Target:** programmatic (the package's own findings, no new detection)
- **Severity:** HIGH (weight 25)
- **Category:** `meta`
- **Condition:** The findings on one package carry at least `[thresholds] h098.min_signals` (default 2) distinct naming/deception signals.

Members, each one independent:

| Rule | Signal |
|---|---|
| H029 | package name resembles a far more popular package |
| D001 | novel dependency added |
| D002 | typosquatted dependency |
| D004 | dependency hijack via `provides`/`replaces` |
| H064 | `provides`/`replaces` scope expansion |
| C012 | source domain resembles the declared upstream |
| H053 | name/host divergence |
| H059 | name/repo divergence |
| H026 | untrusted maintainer takeover |

One signal can be a coincidence. A package that is *both* named like a
popular project *and* pulls in a novel or typosquatted dependency, or
fetches from a domain resembling its declared upstream, is a method rather
than a coincidence. H098 is a cluster annotation over findings other rules
produced, and it runs after H029 so it can count the name finding. It is
never fed back into H027 or H043, which keep their own counts.

**Why weight-bearing, unlike H027 and H043:** those annotate a single diff
whose parts already scored separately, where a combination score would
double-count. H098 is the deliberate exception for the naming/deception
surface: the members are individually weak (a name, a dependency, a host)
and the combination is materially stronger than the sum, so the cluster is
scored once on top. The members still score; the stack is the point. Cite
X007 for the same design in the crossfire family.

Fire rate: 0 of 3739. A benign diff with one or two rule hits cannot carry
two naming/deception signals.

### H102: Maintainer Change With Signing Key Change {#h102}

- **Severity:** HIGH (weight 25)
- **Category:** `meta`
- **Condition:** The maintainer changed and `validpgpkeys` moved (H078)
  in the same diff.

The xz shape: a new maintainer plus a keyring change means the person now
able to sign the sources is not the person the keyring was built for.
Each fact scores on its own (H078, the maintainer tier); the conjunction
is the attack, so it stacks the way X007 stacks its members. H078's own
detection stands in for the keyring delta, the same member-rule
composition H098 uses.

### C021: Dependency Removal During A Build Change {#c021}

- **Severity:** MEDIUM (weight 15)
- **Category:** `composition`
- **Condition:** `checkdepends` or `optdepends` loses an entry while
  `build()`, `prepare()` or `check()` changed in the same diff.

Dropping `checkdepends` eliminates the test-suite execution that would
catch a payload; the conjunction with a build change is what makes the
removal suspicious rather than hygienic. Measured on the locked benign
corpus: 27/3,739 (0.72%), the published calibration floor.

### C024: Install Script Not Declared {#c024}

- **Severity:** MEDIUM (weight 15)
- **Category:** `composition`
- **Condition:** A diff adds or modifies a `*.install` file while the
  recipe has no `install=` scalar naming it. pacman never runs the hook,
  so the file is recipe drift or a reverted declaration.

The dangling-declaration half (an `install=` naming an absent file) needs
tree knowledge and is not yet filed. Measured on the locked benign corpus:
12/3,739 (0.32%).
