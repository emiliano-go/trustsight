# Trust Model

**Core thesis: trust evidence, not verdicts.**

TrustSight computes a deterministic score from 0 to 100 for every AUR package update. The score is calculated entirely in Python from structured data: rule firings, URL classification, novelty tracking, and verification metadata. Every decision is reproducible — same input always produces the same score and the same evidence record.

The analysis runs in five stages: **Parse** the PKGBUILD into a structured representation, **Analyze** it against pattern rules and context signals, **Score** the findings through an additive/subtractive model, **Classify** the result as CLEAN, FLAGGED, or INCONCLUSIVE, and **Translate** the findings into a template-based report.

No external API is involved. All computation is local and deterministic.
