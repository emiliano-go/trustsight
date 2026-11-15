<!-- description: The rule identifier space: reserved and retired ranges, non-contiguous allocation, and how new identifiers are assigned. -->

# Rule Identifiers

A rule ID is a durable citation target. Reports, baselines, changelogs and a
user's `config.toml` overrides all name rules by ID, so an ID is never reused
for an unrelated detection. The space is deliberately non-contiguous.

## Allocation rules

- The leading letter is the series (mechanism), assigned when the rule is
  created and immutable afterwards.
- A new rule takes the next free ID in its series. A gap is not an invitation
  to fill it.
- A retired ID stays retired. The linter refuses a `rules.toml` entry that
  claims one; the reservation is derived from
  `trustsight.rule_id_history.RENAMED_RULE_IDS` rather than restated in prose.
- A category (subject) never owns an ID range. Series and category are
  independent axes; see [Rule Series](series.md).

## Reserved and unassigned identifiers

- **H028 (release cadence)** is metadata on the analysis record, not a scored
  finding. See [H028](corpus-behavioral.md#h028).
- **R103 and R109** describe the ruleset's ceiling rather than a detection.
  See [the novelty ceiling](../explanation/limitations-and-uncertainty.md).

The R-series identifier space is not contiguous. Reserved ids appear nowhere
in the shipped config or the code-emitted rule set:

- `R015`, `R026`-`R038`: held apart so the core and expanded ranges stay
  readable, and reassigning them could clash with user `rules.toml` overrides.
- `R103`, `R109`, `R113`: unassigned in the current shipped configuration.
  `R103`/`R109` are claimed above as the novelty ceiling; the rest are simply
  unused and may be returned to service when a detection needs them.
- The ninety-five ids retired by the R/H split are **retired, not
  recycled**. A stored report, a published baseline and a user's
  `[rules.R###]` override can all still name an old id; handing that number
  to an unrelated new rule would make those references quietly wrong rather
  than loudly absent. The linter refuses a `rules.toml` entry that claims
  one, and the reservation is derived from
  `trustsight.rule_id_history.RENAMED_RULE_IDS` rather than restated here,
  so this page cannot drift from what is enforced. The full mapping is in
  [the changelog](../changelog.md#rule-id-mapping).

---

The full old-to-new mapping is recorded in
[the changelog](../changelog.md#rule-id-mapping).

