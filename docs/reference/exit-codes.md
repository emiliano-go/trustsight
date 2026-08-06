# Exit Codes

| Code | Name | Condition |
|------|------|-----------|
| **0** | Analysis completed | Every requested package was analysed. Says nothing about what was found. |
| **2** | Error | Analysis could not run or could not complete (network error, clone failure, unreadable config, invalid flag combination). |

**The exit code is not a verdict.** A FLAGGED or INCONCLUSIVE package still exits
0, because the exit code answers "did the tool run", not "is this package safe".
Findings are reported in the output and in `--json`. To gate a pipeline, read the
JSON; see [using TrustSight in CI](../guides/using-in-ci.md).

This is a deliberate choice, and it is stated as an invariant in
[the security model](../security.md#b6-what-a-result-does-not-claim): a verdict
is evidence for a human decision, not an authority that halts a build on its own.

---

## Per-command behaviour

### `trustsight review`

- **0**: every package was analysed and the results were printed. Packages that
  could not be vetted are listed in the output and counted in the summary line.
- **2**: a fatal error occurred before or during analysis (`pacman -Qm` failed,
  the AUR was unreachable, the config file is unreadable, the disk is full).

### `trustsight inspect`

Exit code 2 if the analysis pipeline cannot complete (clone failure, database
error). Otherwise 0; `inspect` is an information command and does not flag.

### `trustsight history`

Exit code 2 if the database cannot be opened. Exits 0 even if no history is found
for the requested package: an empty result is not an error.

### `trustsight full-aur`

Exit code 2 on an incompatible flag combination (`--watch` with `--export` or
`--sign`) or on a fatal pipeline error. Otherwise 0.

### `trustsight config`

- **`show`**: 0 on success, 2 on config read error.
- **`set`**: 0 on success, 2 on write error.

## Rationale

Exit 2 is reserved for operational failures where no useful result could be
produced. Everything else is a result, and a result is data for the reviewer to
act on. Encoding "flagged" in the exit status would make every score threshold a
breaking change for anyone scripting the tool, and would invite the exact
misreading the model rejects: treating a deterministic evidence sum as a
pass/fail authority.
