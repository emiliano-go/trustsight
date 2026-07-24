# Writing a Rule

TrustSight has two rule namespaces to avoid identifier collision:

| Namespace | IDs          | Defined in       | Editable by users | Purpose                     |
|-----------|--------------|------------------|-------------------|-----------------------------|
| R-series  | R001 - R013  | `rules.toml`     | Yes               | Regex-detectable patterns   |
| C-series  | C001 - C003  | `analysis.py`    | No                | Structural / multi-condition |

## R-series rules (TOML)

R-series rules live in `rules.toml` under `~/.config/trustsight/`. Each rule has:

| Field         | Description                                           |
|---------------|-------------------------------------------------------|
| `id`          | Unique rule identifier, e.g. `R001`                   |
| `name`        | Human-readable name                                   |
| `pattern`     | Regex pattern to match                                |
| `severity`    | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`        |
| `category`    | Risk category, e.g. `network`, `integrity`            |
| `match_target`| Where to match: `diff_line` or `resolved_string`      |

Example:

```toml
[rules.R001]
id = "R001"
name = "curl-pipe-bash"
pattern = "curl .* \\| bash"
severity = "CRITICAL"
category = "network"
match_target = "diff_line"
```

## C-series rules (code)

C-series rules are defined in `analysis.py` as Python classes. They express multi-condition invariants that cannot be captured by a single regex; for example *"checksum changed AND URLs unchanged AND pkgver unchanged"*.

Users cannot disable C-series rules.

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

1. Run the rule against the full **benign corpus** (`tests/fixtures/benign/`).
2. Compute the fire rate: `hits / total_packages`.
3. If **fire rate < 30%** → rule passes, keep its severity.
4. If **fire rate ≥ 30%** → demote to `INFO`/severity 0 (cannot affect scoring).

To check the fire rate manually:

```bash
python scripts/rebaseline.py --check-fire-rate
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
