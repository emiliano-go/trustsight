# Trust Model

**Core thesis: trust evidence, not verdicts.**

TrustSight computes a deterministic score from 0 to 100 for every AUR package update. The score is calculated entirely in Python from structured data: rule firings, URL classification, novelty tracking, and verification metadata. Every decision is reproducible: same input always produces the same score and the same evidence record.

The analysis runs in five stages: **Parse** the PKGBUILD into a structured representation, **Analyze** it against pattern rules and context signals, **Score** the findings through an additive/subtractive model, **Classify** the result as CLEAN, FLAGGED, or INCONCLUSIVE, and **Translate** the findings into a template-based report.

All *computation* is local and deterministic: nothing about the score depends on a remote service, a model, or a clock TrustSight does not control.

Fetching is a separate stage, and it does reach the network. Four endpoints exist, and every one of them is a literal `https://aur.archlinux.org` constant: the RPC, the metadata dump, the git clone, and cgit. TrustSight never connects to a host named by the package under review, and it never fetches what a `source=` line points at. That boundary, and the rest of what the tool guarantees while reading hostile input, is stated and enforced in [the security model](../security.md).
