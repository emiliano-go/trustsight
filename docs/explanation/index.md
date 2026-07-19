# How TrustSight Works

TrustSight is a deterministic AUR PKGBUILD audit tool. It computes a score from 0–100 over the **end-state** of a diff : the post-patch PKGBUILD, not the delta. Every decision is reproducible: same input always produces the same score and the same evidence record.

These explanation pages describe *why* the tool makes the decisions it does. If you're looking for how to use it, start with the getting-started guide. If you want the reference, see the reference section.

## The pipeline

1. **Parse**: the PKGBUILD is parsed into a structured representation. Unresolvable references produce `INCONCLUSIVE`, not silent guesses.
2. **Analyze**: structural, contextual, historical, and verification signals are extracted. These are the rule firings (R001–R013, C001–C003).
3. **Score**: the signal set is reduced to a 0–100 score. Severity weights, verification subtractions, pinning discounts, and source-bucket modifiers are all applied deterministically in Python.
4. **Classify**: the score maps to a verdict: `CLEAN` (≤20), `FLAGGED` (>20), or `INCONCLUSIVE`.
5. **Translate**: the LLM receives the score, evidence breakdown, and PKGBUILD context and produces an English explanation. It cannot change the score. Verdict assertions gate the output.

## Key numbers

- **267 tests**, **81.5% zero-rate** on benign corpus, **100% CRITICAL recall** (12/12).
- **CRITICAL p5 = 40**, **benign p95 = 20**: the gap that matters.
- **R013 recall 88%**, **R012 recall 17%** (R012 is a tripwire; primary defence is verdict assertions).

## Start here

| Page | What it covers |
|------|----------------|
| [Trust Model](trust-model.md) | Why deterministic core + LLM-as-translator, not LLM-as-judge; verdict integrity |
| [Scoring Philosophy](scoring-philosophy.md) | Evidence tiers, verification subtraction, corpus-derived weights |
| [Cold Start and Maturity](cold-start-and-maturity.md) | Why novelty is meaningless on run one; maturity gating |
| [Corpus and Priors](corpus-and-priors.md) | AUR-wide snapshot, global priors, local novelty weighting |
| [What TrustSight Cannot See](what-trustsight-cannot-see.md) | The reasoned ceiling of the tool |
| [Sandbox Security Model](sandbox-security-model.md) | Planned sandbox design (not yet available) |
| [Benchmarks and Methodology](benchmarks-and-methodology.md) | Per-class separation, CI gates, reproducible eval |
