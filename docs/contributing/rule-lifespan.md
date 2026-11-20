<!-- description: How rule measurement age is checked and how a demotion is proposed, without letting the analyser rewrite its own rules. -->

# Rule lifespan

Every rule carries a measurement date and a review horizon. The rule lab
produces a health document; this gate fails a live rule that is past its
horizon without a disposition.

The gate never edits the anergy ledger. A demotion is a reviewed patch:
`status = "anergic"`, `weight = 0`, and a named reason.

```bash
python scripts/rule_lifespan.py --health tests/fixtures/rule-health.json
```
