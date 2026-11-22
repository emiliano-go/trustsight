<!-- description: The TrustSight rule system: what a rule claims, how the category and series axes fit together, and where every rule definition, score and identifier is documented. -->

# Rules Overview

TrustSight uses rules to detect structural signals in PKGBUILD diffs. Every
rule belongs to exactly one **category** (the claim it makes) and exactly one
**series** (the mechanism it uses to make it). The two axes are independent:
a temporal finding can come from an `H` heuristic or a `T` history read, and an
integrity claim can be a regex, a heuristic or a structural invariant.

This section is the single entry point for the detection system. It does not
repeat every definition; it routes you to the page that owns it.

## Start with the axis you need

| If you want to know | Read |
|---|---|
| What kinds of findings exist, and what each one claims | [Rule Categories](categories.md) |
| How a rule detects, and what its prefix means | [Rule Series](series.md) |
| How matching, scoring, configuration and identifiers work | [Rule Mechanics](mechanics.md) |
| How to read a finding without over-reading it | [Rule Interpretation](interpretation.md) |
| The definition, severity, target and limitations of a specific rule | [Individual rule definitions](definitions.md) |

## Categories

A category is the **subject** of a rule: the kind of claim it makes. The set is
closed and is defined by `RuleCategory` in `src/trustsight/categories.py`.
Each category owns exactly one page, and that page carries both its threat
context and its rule definitions.

<!-- generated: legend -->
| Category | Slug | Rules | What a rule here claims |
|----------|------|-------|-------------------------|
| [Fetch and Execution](fetch-and-execution.md) | `fetch-and-execution` | 41 | Code reaches the machine and runs: a fetch, an execution, or the path between the two. |
| [Obfuscation](obfuscation.md) | `obfuscation` | 8 | The recipe hides what it does from a reader by encoding, indirection, or runtime assembly. |
| [Deception and Anti-Analysis](deception.md) | `deception` | 6 | The recipe targets whoever reviews it rather than the shell that runs it, or checks whether it is being watched. |
| [Install and Persistence](install-and-persist.md) | `install-and-persist` | 23 | Something survives the build: a root-time hook, a unit, a privileged bit, a file in the user's profile. |
| [Staging and Reconnaissance](staging-and-recon.md) | `staging-and-recon` | 10 | The build steps outside its staging roots, hides a drop, or profiles the host it is running on. |
| [Integrity and Verification](integrity.md) | `integrity` | 48 | A verification the recipe used to carry is weakened, removed, or cannot cover what it claims to. |
| [Naming and Dependencies](naming-and-dependency.md) | `naming-and-dependency` | 14 | A name is claimed or a dependency set changes in a way that redirects what gets installed. |
| [Maintainer and Metadata](maintainer-and-metadata.md) | `maintainer-and-metadata` | 16 | Who owns the package, or a long-stable declared property, changed. |
| [Temporal Context](temporal.md) | `temporal` | 14 | How recently the package or this revision appeared, independent of any diff content. |
| [Composition](composition.md) | `composition` | 6 | Distinct kinds of finding co-occurred; the combination is the signal. H027 and H043 annotate at weight 0; H098 scores the naming/deception cluster. |
| [Count-Based](count-based.md) | `count-based` | 5 | A count of indicators crossed a fixed threshold within one artifact or one cluster. |
| [Corpus Behavioral](corpus-behavioral.md) | `corpus-behavioral` | 6 | The package's position in, or deviation from, the corpus baseline - silent without prior observations. |
| [Crossfire](crossfire.md) | `crossfire` | 34 | The evasion technique itself, not the payload it hides: a rule here fires on how a thing was written rather than on what it does. |
| [Sabotage](sabotage.md) | `sabotage` | 10 | A payload aimed at the operator's machine rather than at getting something out of it: resource exhaustion, deletion, permission sabotage, service disruption, resource theft. |
| [Unverifiable](unverifiable.md) | `unverifiable` | 15 | Not a claim about the recipe but about the analysis: something the package will run that this run could not read. Weight 0 always, and always shown. |
| [Meta and Confluence](meta.md) | `meta` | 6 | A claim about other findings: a declared practice contradicted by structure, or a composition only visible from the whole profile. |
| [Entropy](entropy.md) | `entropy` | 3 | The added content is statistically abnormal - a distribution outlier, not a known pattern. Suspicion, never a verdict. |
| [Correlation](correlation.md) | `correlation` | 15 | The pattern is across packages, not inside one: a host, literal or adopter shared by several packages in a window. |
| [Artifact](artifact.md) | `artifact` | 16 | The built package does not match the recipe: the L9 artifact layer, off by default, never blended into the static score. |
| [Indicators](indicator.md) | `indicator` | 1 | A declared surface matches an entry in signed external data: the IOC list, or a federated publisher's indicator set.  Outside the heuristic score and alerted at maximum priority. |
| [Upstream Manifests](upstream-manifests.md) | `upstream-manifests` | 9 | A committed dependency manifest changed: a dependency moved, a new remote source entered the recipe's reach, or the resolver is being redirected.  Read from the repository, never fetched. |
| [Upstream Release Integrity](upstream-release.md) | `upstream-release` | 6 | What a recipe declares about upstream - its URL, its sources, their access mode - and the CI surface it commits.  Upstream content is never read (A2/A8); the CI exfil and history-sweep shapes arrive over the signed federation channel instead. |
<!-- /generated: legend -->

## Rule series

A series is the **mechanism**: the leading letter of the rule ID. The series
determines what you can tune and what a finding costs to replay. Every series
is described, with its detection characteristics, in [Rule Series](series.md).

The identifier space is intentionally non-contiguous, so a range is not a
count; the [catalog](definitions.md) is authoritative. The counts below are
generated from it.

<!-- generated: series-counts -->
| Series | Mechanism | Rules |
|--------|-----------|-------|
| `C` | Integrity-change | 35 |
| `R` | Regex | 37 |
| `H` | Heuristic | 109 |
| `D` | Dependency | 5 |
| `S` | Sabotage | 10 |
| `X` | Crossfire | 34 |
| `W` | Unverifiable | 15 |
| `P` | Declared-practice | 0 |
| `M` | Meta | 6 |
| `E` | Entropy | 3 |
| `T` | Temporal | 12 |
| `G` | Correlation | 15 |
| `A` | Artifact | 16 |
| `I` | Indicator | 0 |
| `U` | Upstream | 15 |
The catalog lists 312 rule IDs across 15 series; 281 of them contribute to the heuristic score.
<!-- /generated: series-counts -->

`P` and `I` carry no catalog IDs in this build: declared-practice findings
are rendered from `DECLARED_REASONS` (P001-P009, P004 skipped), and the
shipped indicator mechanism is H056, filed under [Indicators](indicator.md).

Two further families are reported but never weighted: declared-practice
findings P001-P009 (P004 is skipped) and unverifiable findings W001-W015. The
optional L9 build lane adds artifact rules A001-A016, reported outside the
heuristic when enabled.

## How rules contribute

Each rule contributes according to its severity weight, match target and
scope, except the P and W series and the weight-0 M annotations, which are
weight 0 and report rather than score. The U-series is mostly the same shape:
U003 (a new remote source), U004 (a redirected resolver), U007 (a federated CI
exfil shape), U008 (a federated history sweep) and U010 (an unauditable source
transport) score; the rest are weight 0. The A and I series are reported
outside the heuristic score.

Crossfire is the anti-evasion family introduced in the current ruleset. Its
34 rules detect tokenizer defeat and command reconstruction; see
[Crossfire](crossfire.md) for the family boundary and rule descriptions.

## Scoring, matching and configuration

Rule findings become a score through severity weights; matching decides what a
rule can see; configuration decides which rules run and how they are weighted.
Those mechanics are shared by every category and are documented once:

- [Rule Scoring](scoring.md): severity weights, the additive score, FATAL
  behaviour and review thresholds.
- [Rule Matching](matching.md): `match_target`, scope, resolved versus
  raw-line matching and its limits.
- [Rule Configuration](configuration.md): `rules.toml`, `config.toml`,
  structural rules, overrides and enablement.
- [Rule Identifiers](identifiers.md): reserved ranges, allocation and retired
  IDs.
- [Rule Interpretation](interpretation.md): what a finding does and does not
  establish, and how false positives are reasoned about.

## Generated inventories

The category table above and the full catalog in
[Individual rule definitions](definitions.md) are generated from
`RuleCategory`, the rule registry and `docs_src/`. Do not edit the generated
blocks by hand; run:

```bash
uv run python scripts/build_rules_index.py
```

The generator is checked by `tests/test_generated_docs.py`, and
`tests/test_docs.py` pins every rule ID to its owning category page.
