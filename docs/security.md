<!-- description: TrustSight's threat model and invariants: the thesis, boundaries, assumptions and evidence taxonomy, and the four parts that make it precise and enforceable. -->

# Security Model

TrustSight is an **instrument, not a judge**. It reads AUR PKGBUILD diffs, applies published detection rules (the [rules reference](reference/rules/index.md) documents every shipped rule, pattern, and severity), and reports both findings and recorded gaps. It never decides whether a package is safe or authorizes an update; a person does. A quiet result means no monitored condition matched in the material examined, not that the package is safe.

That distinction, **input not verdict**, rests on four statements the rest of this page makes precise:

- TrustSight reports on evidence, and on the absence of evidence.
- Absence of evidence is never presented as proof of safety.
- The tool's output is input to a human decision, never the decision itself.
- Errors and unknowns travel to the surface; the interface does not hide them.

The page is organised as a thesis (read this first), then the four parts that make it precise and enforceable:

- **The thesis** (below): adversary, boundaries, assumptions, guarantees, non-guarantees, the evidence taxonomy, detection versus authorization, and how uncertainty reaches the person.
- **[Part A](security/program-under-attack.md)**: TrustSight as a program consuming hostile input - the invariants that protect the machine.
- **[Part B](security/what-a-result-claims.md)**: what a result claims about a package, and what it does not.
- **[Part C](security/enforcement-map.md)**: every invariant above, mapped to the check that fails when it stops being true.
- **[Part D](security/vulnerability-reporting.md)**: what counts as a vulnerability in a static analyser, and how to report one.

Nothing here is aspirational. Every invariant in Part A and Part B has an executable gate in `scripts/security_gates.py`, and the calibration properties have theirs in `scripts/calibration_gates.py`. Both run as GitHub Actions workflows (`security.yml` and `calibration.yml`) on every push **and** every pull request, and both exit non-zero when a gate fails, which fails the job. They are blocking CI checks, not pre-commit hooks and not release-only steps, so a change that breaks an invariant cannot land green. The doc-facing gates (cross references resolve, the doc and the gate list describe the same set) run in the same job; they are cheap enough to run every time. A claim without a gate is a claim this project does not make.

---

## The thesis

### The programme

A package update is a moving target: new code, new URLs, new maintainers, new build logic. TrustSight cannot audit what an update *will do*; it can only audit what the update *says*. So every analysis walks the same pipeline:

> **Parse** the PKGBUILD into a structured representation, **Analyse** it against pattern rules and context signals, **Score** the findings through an additive model, with declared practice reported at weight 0, **Classify** the result into a band, and **Report** the findings through a template, in the human-readable panel or the machine-readable JSON.

The bands are `Low`, `Medium`, `High`, `Critical` and `Inconclusive`. The
default `review` profile marks scores above 20 as flagged; `quiet` and `strict`
profiles change that queue without changing arithmetic or bands. This page uses
the default profile for workload figures. JSON carries the band in `risk` and
the separate policy in `review_profile`, `review_threshold`, and `flagged`.

**A band is not a pure function of the score, and two rules say so explicitly.** A cold database and a coverage gap both already override the arithmetic, and severity does too, in two places. First, **a CRITICAL finding floors the band at High**: CRITICAL weighs 40 and the High band opens at 51, so the sum alone can never lift a *single* CRITICAL above Medium, and a lone fork bomb or `rm -rf /` would read as a medium situation on arithmetic that says nothing about severity. The floor moves the band only - no score changes, so the calibrated separation between the benign and malicious score populations is untouched. Second, **a FATAL names itself in `risk_label`**: a FATAL caps the score at 100, so it arrives as `Critical` and so does a score that merely accumulated past 80, and those are different claims. `risk_label` reads `Critical (FATAL: R013)`. It rides the label rather than a new band because `risk` is a closed enum consumers gate on, and nothing is lost without one - the severity is in `score_breakdown` either way. Both are the shape [B4](#b4-fatal-cannot-be-switched-off) already establishes, where severity overrides arithmetic rather than adding to it.

The score and its band are computed on every run and shown on request. The default output is the findings and the change summary: what matched, where, and what changed. `--score` adds the number and the band; `--json` carries them when `--score` or `--risk` is passed, because a consumer needs the machine-readable form. That holds on every machine-readable surface, not just the one the flag was first wired to, and the API spells the same request `to_dict(include_score=True)`: see [B11](#b11-every-surface-reports-the-same-thing).

Computation is local and deterministic: the same diff, against the same stored observation history, always produces the same score and the same evidence record. The stored history is part of the instrument, not part of the input, so two machines with different seeds or different accumulated observations can score the same diff differently; that is the novelty model working, and [B1](#b1-a-score-is-a-sum-of-matched-evidence-nothing-more) makes the boundary precise. What is ruled out is any dependence on a remote service, a model, or a clock TrustSight does not control. Fetching is a separate stage with two declared destinations (`aur.archlinux.org`, and the release channel for verified `baseline-*` assets), described in detail in [the invariants](#the-invariants).

The thesis is not that this pipeline catches everything. It is the opposite: the pipeline has published limits, and **those limits are part of the output**, not a footnote. Everything below follows from that.

### Adversary

The AUR is an unmoderated, user-submitted repository. Anyone can publish, and whoever maintains a package can modify it at will. TrustSight therefore assumes the strongest realistic adversary: **someone who controls every byte of every artifact TrustSight reads about a package, and who knows this source code**. The full adversary description is in [Part A](security/program-under-attack.md); the practical consequence is that every read of package-controlled data is a potential attack on the machine running the tool, and the threat model is about that machine surviving contact with hostile input, detection or no detection.

**State poisoning.** The novelty and maturity signals read accumulated history, so an attacker who can influence that history (a malicious seed, a compromised baseline, or long-term manipulation of the AUR metadata the corpus is built from) can make a future attack look unexceptional: anomalous behaviour reads as established. This is a distinct attack class from the ones the rest of this page bounds. Rule evasion bypasses a pattern, a parser bypass hides a payload from the tokenizer, and coverage-gap exploitation pads past a bound; state poisoning does none of these. It desensitises the calibration itself, so it is a calibration bypass, not a detection bypass, and it is considered and bounded here rather than left implicit. The seed can only make something look more familiar; it can never rewrite state it does not own or raise a score (A12), and it carries no recoverable identity (P1). A baseline is signature-verified and writes only profiles, snapshots and metadata, never a rule, a pattern, a weight or a threshold (A13). The property that closes the class is that poisoning state can only make the present look like the past, never make a rule stop matching: a structural finding fires on the same diff whatever the history says, so the most a poisoned prior can do is quiet the novelty and longitudinal tiers, never silence the rules.

### Boundaries

TrustSight does three things, and only three: it reads, it computes, it reports.

- **Reads** the reviewed repository, the single AUR endpoint, and signed release assets an operator explicitly fetches or an eligible first `review` or `inspect` run auto-imports.
- **Computes** evidence scores, entirely locally, deterministically, and never by executing a PKGBUILD.
- **Reports** findings and their reasons, and what it could not examine.

It does **not** build, run, install, or sandbox. The moment you run `makepkg`, you are outside this model.

Two of the things it never does are worth stating on their own, because each removes an attack surface rather than defending one. It never fetches a URL a package declares, so there is no SSRF primitive to turn a reviewer into a probe. It never connects to a host a package names; the only hosts it can reach are the AUR endpoint at `https://aur.archlinux.org` and the GitHub release channel at `api.github.com` and `github.com`, which is confined to `release.py` and refuses any download whose signature does not verify against the pinned key.

### Assumptions

The model above and the parts that follow are claims *about this program*: that its invariants hold when it runs. They are not claims about the machine it runs on. Like any model, this one rests on a set of assumptions, and stating them is what makes the boundary complete: a reader knows exactly where the analysis stops being the tool's responsibility.

Each of these is taken as given, not defended:

- **The Python runtime is trusted.** The interpreter, its bytecode loader, and the standard library are the substrate the analysis runs on. A compromised interpreter can do anything the process can.
- **The operating system is trusted.** The kernel, the dynamic linker, and the executable the process actually is are outside the model.
- **Local filesystem permissions are trusted.** The files TrustSight reads (its own config, the repository, the snapshots) are at the paths the operator chose and are readable because the operator's permissions say so. A hostile file at a *trusted* path is indistinguishable from a trusted file.
- **The TLS trust store is trusted.** AUR traffic is protected only against a network-level attacker; it assumes the certificate authorities in the local store are honest and the store has not been altered.
- **CI is not compromised.** The gates are meaningful because the machine that runs them is running the code they check, and exercising that code with its shipped configuration. A compromised CI is a compromised review, not a detectable one. What this project does control is the softest edge of that assumption: every workflow installs with `uv sync --locked`, so a job resolves nothing at run time and gets exactly the pinned, hashed versions in `uv.lock`. The flag matters more than it looks: `--frozen` would also install from the lock, but it performs no check that the lock still matches `pyproject.toml`, so a dependency added to the manifest and never locked is silently ignored and the job installs an older closure while appearing to honour the manifest. `--locked` fails instead. Third-party actions are pinned by commit SHA for the same reason. Neither makes CI trustworthy; both remove a live remote dependency from the job that certifies the model, and the `CI installs from the lock` gate keeps it that way.
- **The dependencies are trusted.** `rich`, `pygit2`, `typer`, `tldextract`, the Python interpreter and standard library, the `sqlite3` library and the SQLite it wraps, and the runtime's own libraries (`libc` and friends) are third-party or substrate code this project consumes and does not audit. The concrete list is repeated where Part A documents what its program-level invariants do not cover. If `rich`, `pygit2`, Python, SQLite, or `libc` is compromised, this document no longer applies. `cryptography` belongs on that list too, and is the one whose compromise is most directly a breach of a stated invariant: it verifies the Ed25519 signatures A13 and A13b rest on. Assumed does not have to mean unobserved. A weekly `supply-chain` workflow exports the locked closure, generates a CycloneDX SBOM, and reports known advisories against it. It is a **reporting** job, not a gate: it never fails a build. Making it blocking would put a remote advisory feed in the path of every push, which is exactly the live remote dependency every other workflow's `uv sync --locked` install exists to remove - and an advisory is evidence about a library, not a verdict about this program, so what it means for a static analyser that never runs a PKGBUILD is a judgement for a person. The assumption stands; what changes is that the project can now see when it stops holding.

If any of these is not true, this document no longer applies: the guarantees in Parts A and B are about the program, and the program is only as trustworthy as the layers beneath it. That is not a gap in the model, it is the model stating where its border is.

### Guarantees

What the tool promises, in one paragraph, is that its output is honest about the analysis that produced it. The specifics are in Part A and Part B, and [Part C](security/enforcement-map.md) maps each to the gate that enforces it. The short list is:

- **Reproducible**: the same input, against the same stored history, the same score and evidence record.
- **Transparent**: every point is attributable to a named entry in the score breakdown, and the breakdown is part of the output. Enforced by `positive evidence never changes the score` and `report rendering is data-driven`, which together fix where a number may come from and how it may be described.
- **Fails closed on doubt**: an analysis that did not see the whole change cannot report UNFLAGGED, and its band is marked incomplete wherever a human sees it.
- **Not headline-shaped**: the default output is evidence, not a verdict. The score exists, is deterministic, and is available on request; it is not what the tool leads with, because a number invites a decision the tool is not entitled to make. Enforced by `the default output is not headline-shaped`, which renders a scoring package and fails if the default output volunteers the number.
- **Isolated**: it never fetches a URL the package named, never executes package code, never extracts a package-controlled archive to disk, and never renders untrusted text unescaped.
- **Locked**: FATAL rules cannot be turned off, and suppression is always visible.
- **Configuration is visible, not silently mutable**: the operator may tune the instrument, but not without a trace. The config fingerprint (B1) captures the effective ruleset, thresholds and overrides; FATAL rules cannot be removed without the shipped-rule fallback and a logged warning (B4); and suppressed findings are always reported (B5). A local attacker with filesystem access can edit `rules.toml` or `overrides.toml`, because local permissions are a trusted assumption, but they cannot make the change invisible: the run then carries a different fingerprint, and any suppressed or downgraded rule shows in the output. The model separates operator intent from silent tampering by observability, not by prevention.
- **Calibrated**: the gates enforce *separation*, that the benign 95th percentile stays below the malicious 5th percentile, not that one workload policy is universally correct. Fire rates against a published benign corpus are measured; the default 20-point profile and its 13.1% benign queue rate are disclosed separately (see B2). Other profiles are operator choices, not new calibration claims.

Each of these stops being a promise the moment the machine breaks it. The gates in [Part C](security/enforcement-map.md) are what turn them from sentences into structural commitments.

### Non-guarantees: absence of alerts is not a certificate

An UNFLAGGED result means "no published rule matched the evidence that was actually examined". That is a statement about *detection* alone. It is not the same as "no attack is possible", and it is not, on its own, an instruction to update.

This is the easiest claim to misread. An unknown that is not visible is indistinguishable from a clean result, so incomplete analysis must always be reported. Everything in [B2](#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete) enforces that rule.

TrustSight reports what changed even when no rule matched. Otherwise, "nothing fired" would be indistinguishable from "nothing happened".

Concretely, an UNFLAGGED result does **not** claim:

- that the package is safe (only that no published rule matched what was examined);
- that the ruleset is complete (fire rates and gaps are published; detection has documented ceilings);
- that runtime behaviour was observed (nothing is executed);
- that the build will fetch what the recipe says (where that cannot be determined statically, the result is downgraded).

What it *does* do is tell you exactly which sensors tripped, which sensors are missing, and what was never examined - so the weight of the decision is yours, not the tool's. See [Part B](security/what-a-result-claims.md) for the precise claims.

### The evidence taxonomy

Every result reduces to one of four places in a taxonomy, and the taxonomy has to be stated completely, because the tool's trustworthiness is exactly its refusal to move between them silently:

| What the tool has | Example | How it is presented |
|-------------------|---------|---------------------|
| **Known risk** | a rule matched (e.g. R013 confusable unicode) | FLAGGED, with the matching rule, file and line |
| **Declared verification practice** | checksums declared, PGP keys declared, commit pinned | INFO, reported, never scored (B10) |
| **Evidence that is contextually uncertain** | a `source=` URL computed at build time; a file the manifest did not list | **INCONCLUSIVE** |
| **None known** | history too short to trust novelty at full weight | **INCONCLUSIVE** until warm |

The last two rows are the ones most tools are tempted to collapse into "nothing found", which is exactly the error the thesis forbids. A concrete form: the `unresolved_source` gap - a `source=` entry computed at build time, say `_url="$(curl ...)"` - means the URL the build will actually fetch is not in the analysed text. The tool records the gap, reports INCONCLUSIVE, and tells you the URL was never statically confirmable. The details of the taxonomy live in [evidence tiers](reference/evidence-tiers.md) and [what TrustSight cannot see](explanation/what-trustsight-cannot-see.md).

### Detection and authorization

Detecting is not authorizing. They are different acts, and a tool that lets the first quietly stand in for the second is making the exact substitution this model rejects.

- **Detection** is what TrustSight does: rules fire, scores compute, gaps are recorded. Its output is *input*.
- **Authorization** is what a person does: someone decides whether to update, to click, to merge. The tool does not perform that action, and no synthesized sentence from the tool performs it either.

The boundary does not disappear in CI, it moves. A pipeline still authorizes, it just does so in advance: the pipeline owner writes the decision into a gate (for example, the UNFLAGGED check **and** the coverage check), and that decision is theirs, stated in their own script, where it can be read and argued with. The tool supplies evidence and unknowns; a person decides what they are worth. Human-in-the-loop is not a slogan here, it is the operating principle: **no verdict, however emphatic, is an authorization to act.**

### Uncertainty reaches the surface

The whole model stands on one interface rule: **every unknown the tool recorded must be visible to the person it matters to, and it must never be hidden by default**.

- A coverage gap appears in the JSON and on the terminal, and is never dropped from either.
- A result that could not be examined fully is not shown as a bare "Low": for a human render the band is qualified, e.g. `High (incomplete analysis)`, and for machines `risk` and `coverage_gaps` are separate fields (see [report schema](reference/report-schema.md)).
- An analysis that failed for a tracked package is reported as "this package was NOT vetted", so a skipped package cannot read as an unflagged one.
- A result reports the changes it examined, not only the rules that fired. An update with no findings still tells you what moved, so "nothing fired" cannot read as "nothing happened".
- A failure is reported as a failure and never absorbed into a result. The exit code distinguishes "the analysis ran" from "the analysis could not run", and says nothing about what was found.

Part A states the invariants that protect the machine, Part B the limits on what a result may claim, and Part C maps every one of them to a gate. The taxonomy is the theory; the four part pages below are the enforcement.


---

Back to the panel. The invariants in Part A are what keep the instrument working while the input tries to break it. Part B bounds what a reading is allowed to claim. Part C makes both fail the build the moment they stop being true, which is the only reason the first two paragraphs of this page are worth anything. The decision at the end is yours; the tool's job is to make sure you are making it with the sensors you think you have.

The [evidence tiers](reference/evidence-tiers.md) are the sensor catalogue; [what TrustSight cannot see](explanation/what-trustsight-cannot-see.md) is the list of instruments this aircraft does not carry.

---

## Parts A to D

The model is split across four pages. The thesis above stays here; each part below moved to its own page, and every anchor that used to point into it still resolves.

## Part A: TrustSight as a program under attack {#part-a-trustsight-as-a-program-under-attack}

Moved to [Part A: TrustSight as a program under attack](security/program-under-attack.md).

### The adversary {#the-adversary}

See [Part A: TrustSight as a program under attack](security/program-under-attack.md#the-adversary).

### The trust boundary {#the-trust-boundary}

See [Part A: TrustSight as a program under attack](security/program-under-attack.md#the-trust-boundary).

### The invariants {#the-invariants}

See [Part A: TrustSight as a program under attack](security/program-under-attack.md#the-invariants).

### What this part does not protect {#what-this-part-does-not-protect}

See [Part A: TrustSight as a program under attack](security/program-under-attack.md#what-this-part-does-not-protect).

## Part B: What the result claims {#part-b-what-the-result-claims}

Moved to [Part B: What the result claims](security/what-a-result-claims.md).

### B1. A score is a sum of matched evidence, nothing more {#b1-a-score-is-a-sum-of-matched-evidence-nothing-more}

See [Part B: What the result claims](security/what-a-result-claims.md#b1-a-score-is-a-sum-of-matched-evidence-nothing-more).

### B2. An unflagged verdict is never issued for an analysis that was incomplete {#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete}

See [Part B: What the result claims](security/what-a-result-claims.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete).

### B3. Inconclusive is not presented as UNFLAGGED {#b3-inconclusive-is-not-presented-as-unflagged}

See [Part B: What the result claims](security/what-a-result-claims.md#b3-inconclusive-is-not-presented-as-unflagged).

### B4. FATAL cannot be switched off {#b4-fatal-cannot-be-switched-off}

See [Part B: What the result claims](security/what-a-result-claims.md#b4-fatal-cannot-be-switched-off).

### B5. Suppression is always visible {#b5-suppression-is-always-visible}

See [Part B: What the result claims](security/what-a-result-claims.md#b5-suppression-is-always-visible).

### B6. What a result does not claim {#b6-what-a-result-does-not-claim}

See [Part B: What the result claims](security/what-a-result-claims.md#b6-what-a-result-does-not-claim).

### B7. A result reports what changed, not only what fired {#b7-a-result-reports-what-changed-not-only-what-fired}

See [Part B: What the result claims](security/what-a-result-claims.md#b7-a-result-reports-what-changed-not-only-what-fired).

### B8. A finding is checkable {#b8-a-finding-is-checkable}

See [Part B: What the result claims](security/what-a-result-claims.md#b8-a-finding-is-checkable).

### B9. No output grants permission to skip review {#b9-no-output-grants-permission-to-skip-review}

See [Part B: What the result claims](security/what-a-result-claims.md#b9-no-output-grants-permission-to-skip-review).

### B10. Positive evidence is reported, never credited {#b10-positive-evidence-is-reported-never-credited}

See [Part B: What the result claims](security/what-a-result-claims.md#b10-positive-evidence-is-reported-never-credited).

### B11. Every surface reports the same thing {#b11-every-surface-reports-the-same-thing}

See [Part B: What the result claims](security/what-a-result-claims.md#b11-every-surface-reports-the-same-thing).

## Part C: The enforcement map {#part-c-the-enforcement-map}

Moved to [Part C: The enforcement map](security/enforcement-map.md).

## Part D: Vulnerability reporting {#part-d-vulnerability-reporting}

Moved to [Part D: Vulnerability reporting](security/vulnerability-reporting.md).

### How to report {#how-to-report}

See [Part D: Vulnerability reporting](security/vulnerability-reporting.md#how-to-report).

### Supported versions {#supported-versions}

See [Part D: Vulnerability reporting](security/vulnerability-reporting.md#supported-versions).

### What counts as a vulnerability in this kind of tool {#what-counts-as-a-vulnerability-in-this-kind-of-tool}

See [Part D: Vulnerability reporting](security/vulnerability-reporting.md#what-counts-as-a-vulnerability-in-this-kind-of-tool).

### Timeline {#timeline}

See [Part D: Vulnerability reporting](security/vulnerability-reporting.md#timeline).
