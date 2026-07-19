# Changelog

## [Unreleased]

## [0.3.0] - 2026-07-18

- Score column renamed to "Risk Score"
- Rich progress output during review
- AUR RPC batching for performance
- Handle empty AUR repos gracefully
- FATAL severity with hard stop at 100
- Verification evidence detection and scoring
- Source pinning classification
- Code rules C001–C003 for structural anomalies
- URL normalization for novelty dedup
- Maturity-based novelty gating with Inconclusive risk level
- Scope-based rule matching (function_body context)
- R012 (prompt injection) and R013 (unicode bidi) rules
- LLM verdict integrity assertions
- scan_diff offline pipeline for benchmark use
- is_skip_justified analysis for SKIP checksums
- Fix: SKIP checksums no longer count as verification evidence
- Removed R004/R005 from TOML rules (now programmatic, context-aware)
- Default LLM provider changed to openai
- CI workflows for corpus drift monitoring
- 267 tests (was 218)

## [0.2.0] - 2026-07-15

- R004/R005 rule hardening with quote bypass fix
- Tokenizer iteration fix
- Forge classification cap
- IDN detection
- Shell variant coverage
- base64 --decode detection

## [0.1.0] - 2026-07-12

- Initial release
- R001–R011 rules
- AUR diff analysis pipeline
- Deterministic scoring
- SQLite novelty tracking
- LLM verdict integration
- Basic CLI (review, inspect, history, config)
