# Writing a Rule

TrustSight has two rule namespaces to avoid identifier collision:

| Namespace | IDs          | Defined in       | Editable by users | Purpose                     |
|-----------|--------------|------------------|-------------------|-----------------------------|
| R-series  | R001-R003, R007-R008, R010-R013, R039-R059 | `rules.toml` | Yes | Regex-detectable patterns   |
| R-series  | R004-R006, R009, R060+ | `analysis/*.py` | No | Code-emitted detection |
| D-series  | D001-D004   | `analysis/*.py`  | No                | Dependency-graph rules      |
| C-series  | C001-C007   | `analysis/*.py`  | No                | Structural / multi-condition |
| S-series  | S001-S008   | `analysis/sabotage.py` | No          | Sabotage: payloads aimed at the machine |
| X-series  | X001-X007   | `analysis/crossfire.py` | No         | Crossfire: the evasion technique itself |

## R-series rules (TOML)

R-series rules live in `rules.toml` under `~/.config/trustsight/`. Each rule has:

| Field         | Description                                           |
|---------------|-------------------------------------------------------|
| `id`          | Unique rule identifier, e.g. `R001`                   |
| `name`        | Human-readable name                                   |
| `pattern`     | Regex pattern to match                                |
| `severity`    | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`        |
| `category`    | Risk category, e.g. `network`, `integrity`            |
| `match_target`| Where to match: `raw_line` or `resolved`      |

Example:

```toml
[rules.R001]
id = "R001"
name = "curl-pipe-bash"
pattern = "curl .* \\| bash"
severity = "CRITICAL"
category = "network"
match_target = "raw_line"
```

## S-series rules (code)

S-series rules live in `analysis/sabotage.py` and describe a payload aimed at
the operator's machine rather than at getting something out of it: resource
exhaustion, deletion, permission sabotage, service disruption, resource theft.
They are code-emitted and cannot be disabled.

The series exists separately because the family's calibration problem is
unlike the rest of the ruleset's. Its commands are not rare in a PKGBUILD -
`rm -rf` appears in most recipes - so each rule is written against a
*distinction* rather than a command: the build sandbox is not the system, a
mention is not an invocation, and a package's own service is not the system's.
See [the sabotage reference](../reference/rules/sabotage.md).

## C-series rules (code)

C-series rules are defined as Python code in the `analysis/` package. They express multi-condition invariants that cannot be captured by a single regex; for example *"checksum changed AND URLs unchanged AND pkgver unchanged"*.

Users cannot disable C-series rules.

## Categorising and documenting it {#categorising}

Two different things are called a category, and a new rule needs both.

The `category` field above names the **capability** a match touched
(`network`, `persistence`, `obfuscation`). It is fine-grained, it is set
per-rule, and it is what `R072` counts when it looks for a diff whose hits
span three or more capabilities. Reuse an existing value where one fits.

`RuleCategory`, in `src/trustsight/categories.py`, names the **kind of
claim** the rule makes. The set is closed, every rule has exactly one, and
it decides which page under `docs/reference/rules/` carries the rule's
definition. Add the id to `RULE_CATEGORIES` in the same change that adds
the rule:

```python
RULE_CATEGORIES: dict[str, RuleCategory] = {
    ...
    "R141": _C.MAINTAINER_AND_METADATA,
}
```

Then write the `### R141: Name {#r141}` section on that category's page,
and add a stub to `docs/reference/rules/system.md`:

```markdown
### R141 {#r141}

See [R141: Name](../reference/rules/maintainer-and-metadata.md#r141).
```

Then regenerate the index, whose legend and quick-reference table are both
derived rather than hand-maintained:

```bash
python scripts/build_rules_index.py
```

`tests/test_docs.py` fails if any of those is missing, if the section lands
on a page the category does not own, if a quoted pattern has drifted from
the shipped one, or if the id is absent from the quick-reference table.

## When to use each

| Scenario                                       | Use      |
|------------------------------------------------|----------|
| A single regex matches a pattern in diff lines | R-series |
| A single regex matches a resolved string       | R-series |
| Logic spans multiple fields / conditions       | C-series |
| Rule must always run (cannot be disabled)      | C-series |

## Fixtures

Every new scored rule needs two fixture pairs:

### Benign fixture

Place under `tests/fixtures/benign/`:

```
tests/fixtures/benign/<rule-id>-no-false-positive/
├── PKGBUILD.diff
└── expected.json
```

The `.diff` must be a real or plausible benign change. The `expected.json` must contain a score of **0** for this rule.

### Malicious fixture

Place under `tests/fixtures/malicious/synthetic/`:

```
tests/fixtures/malicious/synthetic/<rule-id>-detection/
├── PKGBUILD.diff
└── expected.json
```

The `.diff` must trigger the rule. The `expected.json` must contain a non-zero score for this rule.

### expected.json schema

```json
{
  "expected_score": <0-100>,
  "expected_rule": "<rule-id>",
  "expected_severity": "<severity>"
}
```

## Fire-rate gate

Any new **scored** rule (severity other than `INFO`) must pass the benign-corpus fire-rate check:

1. Run the rule against the full **benign corpus** (`tests/fixtures/benign-corpus/`).
2. Compute the fire rate: `hits / n_diffs`.
3. If **fire rate < 30%** → rule passes, keep its severity.
4. If **fire rate ≥ 30%** → demote to `INFO`/severity 0 (cannot affect scoring).

To check the fire rate, re-baseline and read the per-rule rates it records. Rebuild the corpus first, as it is gitignored (see [Re-baselining](re-baselining.md)):

```bash
python scripts/build_corpus.py --from-manifest \
  --manifest tests/fixtures/corpus.lock \
  --out tests/fixtures/benign-corpus
python scripts/rebaseline.py --baseline /tmp/baseline-check.json
```

Each stratum's `rules` map in the output holds that rule's fire rate:

```bash
python -c "import json; d=json.load(open('/tmp/baseline-check.json')); \
  print({s: v['rules'].get('R0XX') for s, v in d['strata'].items()})"
```

## Tests

Add test cases in `tests/test_rules.py`. Each rule must have at least two tests:

```python
def test_r001_curl_bash_detection():
    """Malicious fixture must fire."""
    ...

def test_r001_curl_bash_benign():
    """Benign fixture must NOT fire."""
    ...
```

Run them with:

```bash
pytest tests/test_rules.py::test_r001_curl_bash_detection -v
pytest tests/test_rules.py::test_r001_curl_bash_benign -v
```

## Common mistakes

### ID collision

C-series IDs start with `C` (`C001`, `C002`, …). R-series IDs start with `R` (`R001`, `R002`, …). Do not assign an `R0xx` ID to a code rule. (The rule formerly known as `R016` was renamed to `C001` for this reason.)

### Delta vs. end-state

Verification evidence is computed over the **resolved PKGBUILD end-state**, not the diff delta. A rule that checks whether `source` contains an `http://` URL should inspect the resolved PKGBUILD *after* the diff is applied, not just the lines that changed.
