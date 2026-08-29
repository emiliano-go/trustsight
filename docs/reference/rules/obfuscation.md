<!-- description: Rules for a recipe hiding what it does from whoever reads it: encoding, runtime assembly and name indirection, where the line shown is not the command that runs. -->

# Obfuscation

The recipe hides what it does from whoever reads it. Encoding (R003, R043,
R045), runtime assembly (H014, R039, R040) and name indirection (H080) are
all the same move: the line a reviewer sees is not the command that runs.

H065 is the counterpart rather than a detection. The tokenizer rebuilds
these forms so the other rules match on meaning rather than spelling, and
H065 is what tells the reader the reconstruction happened, so the report
never quotes text the file does not contain.

Density, not shape, is [H036](count-based.md#h036): three or more
indicators on one line, counted rather than pattern-matched. Integrity
checks that read as hiding (a hidden drop, an archive trailer) belong to
[staging and reconnaissance](staging-and-recon.md) and
[integrity](integrity.md), which own the target rather than the technique.

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [H014](#h014) | Eval or Exec Usage | MEDIUM |
| [H065](#h065) | Obfuscated Literal Reconstructed | INFO |
| [H080](#h080) | Indirect Command Expansion | CRITICAL |
| [R003](#r003) | Base64 Decode and Execute | CRITICAL |
| [R039](#r039) | Eval With Dynamic Content | CRITICAL |
| [R040](#r040) | Shell -c With Dynamic Payload | CRITICAL |
| [R043](#r043) | Base64 Blob Decode | CRITICAL |
| [R045](#r045) | Binary Encoding Pipe | MEDIUM |
<!-- /generated: page-index -->

### R003: Base64 Decode and Execute {#r003}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `obfuscation`
- **Pattern:** `base64.*(?:\-d|\-\-decode).*(?<!\\)\|`
- **Description:** Detects `base64 -d |` and `base64 --decode |` piped to execution. Base64-encoded scripts are a common obfuscation technique to hide malicious commands from casual review.
- **Note:** The pipe must be **unescaped**. An escaped bar is an argument to the command and starts no pipeline, so it is not a match. The tokenizer preserves the escape (`tokenizer._ESCAPE_REMOVABLE`) so the distinction survives resolution. A `rules.toml` written by an earlier release may hold a wider pattern that does match it; [`trustsight config sync-rules --update`](../cli.md#sync-rules) replaces patterns this project shipped previously.

### H014: Eval or Exec Usage {#h014}

- **Target:** `raw_line`
- **Severity:** MEDIUM (weight 15)
- **Category:** `obfuscation`
- **Pattern:** `\b(?:eval|exec)\s`
- **Scope:** `["function_body", "install_script"]`
- **Description:** Detects `eval` or `exec` at the start of a command inside `build()`, `package()`, or an install script. `eval` re-parses its argument at runtime, so the executed content cannot be guaranteed statically; `exec` replaces the current process. Scoped out of declarations and comments, which routinely spell the same words in messages.

### R039: Eval With Dynamic Content {#r039}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `execution`
- **Pattern:** `` \beval\s+(?:"|\$\(|\$\{|`|\$[a-zA-Z_]) ``
- **Description:** Detects `eval` applied to a variable, command substitution, or backtick expression. The payload is assembled at runtime, so no static pattern can see what will execute.

### R040: Shell -c With Dynamic Payload {#r040}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `execution`
- **Pattern:** `` \b(?:(?:ba|z|da|k|mk|pdk|ya|po|a)?sh|busybox\s+(?:ash|sh))\s+-c\s+(?:\$\(|`|\$\{|["\x27]?\$[A-Za-z_]|"[^"]*\$) ``
- **Description:** Detects `sh -c` / `bash -c` whose argument contains a variable or substitution rather than a literal command.

### R043: Base64 Blob Decode {#r043}

- **Target:** `resolved`
- **Severity:** CRITICAL (weight 40)
- **Category:** `obfuscation`
- **Pattern:** `base64\s+(?:-d|--decode)\s*(?:<<<|<<\w*|\$\{?[a-zA-Z_])`
- **Description:** Detects `base64 -d` fed from a here-string or a variable, as opposed to decoding a file that is itself part of the source array.

### R045: Binary Encoding Pipe {#r045}

- **Target:** `resolved`
- **Severity:** MEDIUM (weight 15)
- **Category:** `obfuscation`
- **Pattern:** `\b(?:xxd|uudecode)\s+[^|]*(?<!\\)\|`
- **Description:** Detects `xxd` or `uudecode` piped onward. Both reconstruct binary content from a text representation, a way to carry a payload past text review.
- **Note:** The pipe must be **unescaped**. An escaped bar is an argument to the command and starts no pipeline, so it is not a match. The tokenizer preserves the escape (`tokenizer._ESCAPE_REMOVABLE`) so the distinction survives resolution. A `rules.toml` written by an earlier release may hold a wider pattern that does match it; [`trustsight config sync-rules --update`](../cli.md#sync-rules) replaces patterns this project shipped previously.

### H065: Obfuscated Literal Reconstructed {#h065}

- **Severity:** INFO (weight 0)
- **Category:** `obfuscation`
- **Condition:** An added line changes under literal reconstruction (ANSI-C hex `$'\x62\x75\x6e'`, ANSI-C octal, empty-quote concatenation `b''u''n`, `$(printf '\x62...')`) and the reconstruction reveals a word the raw line did not carry, or an ANSI-C quote survives reconstruction.

The tokenizer rebuilds these forms so that H035, R003 and R039 match on what a
line *means* rather than how it is spelled. H065 is what tells the reader that
this happened: without it the report quotes text the file does not contain. It
carries no weight, so it cannot move a score; it changes what the reader is
looking at.

A literal that cannot be rebuilt is reported as the inconclusive case.
Unreconstructable input is never read as UNFLAGGED.

Fire rate: 0 of 3246.

### H080: Indirect Command Expansion {#h080}

- **Severity:** CRITICAL (weight 40)
- **Category:** `obfuscation`
- **Condition:** An added line inside a build function contains the indirect-expansion form `${!name}` where `name` is a plain (non-subscripted) variable name, and the expanded fragment participates in a command that reaches the shell.

`${!C}` expands to the *value of the variable whose name is held in `C`*, so
`C=curl; ${!C} URL | bash` executes `curl` while the recipe carries no literal
`curl` and no literal shell on the line R001/R002/H077/H069 read. The tokenizer
refuses to evaluate indirection statically, so the obfuscated line reaches the
rules verbatim and every literal-match rule steps over it: flagging the
indirection itself closes that whole family at once.

Only the plain `${!name}` form is indirection. `${!arr[@]}` and `${!arr[*]}`
list an array's keys, and `${!prefix*}` lists variable names by prefix - all
common and benign - so the trailing `}` after the bare name is required, which
excludes every subscripted or globbing form. Detected by
`_indirect_expansion_findings()` in `src/trustsight/analysis/build.py`.
