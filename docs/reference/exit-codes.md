# Exit Codes

| Code | Name | Condition |
|------|------|-----------|
| **0** | Success : CLEAN | All reviewed packages scored ≤20. No FLAGGED or INCONCLUSIVE verdicts. |
| **2** | Error | Analysis failed for one or more packages (e.g. network error, repository clone failure, invalid configuration). |

---

## Per-command behaviour

### `trustsight review`

Exit code 2 on fatal error:

- **0**: every analysed package has `final_score ≤ 20`. The summary table is printed and the tool exits cleanly.
- **2**: a fatal error occurred before or during analysis (e.g. `pacman -Qm` failed, AUR RPC unreachable, config file unreadable, disk full).

### `trustsight inspect`

Exit code 2 if the analysis pipeline cannot complete (clone failure, database error). Otherwise exits 0; `inspect` is an information command and does not flag.

### `trustsight history`

Exit code 2 if the database cannot be opened. Exits 0 even if no history is found for the requested package (an empty result is not an error).

### `trustsight config`

- **`show`**: exits 0 on success, 2 on config read error.
- **`set`**: exits 0 on success, 2 on write error.

## Rationale

The exit code design follows the principle that **CLEAN is the default expected state**: 81.5 % of benign diffs score 0. Exit 2 is reserved for operational failures where no useful result could be produced.
