# Maintenance scripts

Operator-run tools. CI runs only the scripts a workflow names; everything
else here is invoked by hand.

## Calibration

- `calibration_gates.py` — the gate decisions CI runs.
- `aur_calibrate.py` — per-stratum false-positive/ablation runner. It is the
  only script with `--ablate {denoise,tokenizer,delta}` and is not part of
  CI. Use it when a calibration gate moves and you need to isolate which
  stage changed the score.
- `rebaseline.py` — records the measured fire rates the gates compare
  against.

## Dead code

- `dead_code.py` — the guard, also run by `tests/test_dead_code.py`. It fails
  on a module-level or class-method definition with no reference outside its
  own line, and on a distinctive `DEFAULT_CONFIG` key never named in the code.
  Names loaded by string or called by a foreign framework are listed in
  `ALLOWLIST` with their reason instead of being deleted.
