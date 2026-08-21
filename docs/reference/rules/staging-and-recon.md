# Staging and Reconnaissance

A packaging step may write inside `$srcdir` and `$pkgdir` and nowhere else.
These rules are the boundary (R058, R084, R128, R140), the hidden case
(R088, R018) and the question of what the build learned about the host it
ran on (R086).

One shared write-target resolver in `analysis/persistence.py` backs the
write rules: `install`/`cp`/`mv`/`ln` destinations including `-t DIR`, `>`
redirects, and the verb-substitution forms `tee`, `dd of=`, `mkdir -p`,
`touch`, `rsync` and `sed -i`. Every match is command-position anchored, so
a quoted string such as `'cp x ~/.zshrc'` never reads as a write.

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [R018](#r018) | Symlink Redirect | MEDIUM |
| [R021](#r021) | Suspicious file write | HIGH |
| [R058](#r058) | Write Outside Package Root | HIGH |
| [R084](#r084) | World-Writable Staging | HIGH |
| [R086](#r086) | Host Reconnaissance | INFO |
| [R088](#r088) | Hidden Drop | HIGH |
| [R128](#r128) | Build Writes Outside Staging Root | HIGH |
| [R140](#r140) | PATH Injection With Undeclared Directory | HIGH |
<!-- /generated: page-index -->

### R018: Symlink Redirect {#r018}

- **Target:** `raw_line`
- **Severity:** MEDIUM (weight 15)
- **Category:** `filesystem`
- **Pattern:** `ln\s+-sf`
- **Description:** Detects `ln -sf` (force-symlink) invocations. Re-pointing a symlink to a new target can redirect what a later step writes or reads, including replacing a config file or a cacheable binary path with a copy the attacker controls.

### R021: Suspicious file write {#r021}

- **Target:** `runtime` (resolved execution path)
- **Severity:** HIGH (weight 25)
- **Category:** `filesystem`
- **Pattern:** `(?!)` (never matches)
- **Description:** A write to a sensitive filesystem location (services, `cron.d`, `$HOME/.config/autostart`). Same treatment as R020: shipped as a reserved `runtime` placeholder, never emitted by the static diff engine.

### R058: Write Outside Package Root {#r058}

- **Target:** `raw_line`
- **Severity:** HIGH (weight 25)
- **Category:** `system`
- **Pattern:** `^\+?\s*(?:sudo\s+)?(?:install|cp|mv|dd|tee)\s+[^;&|]*(?:(?<=\s)|(?<=\s["\x27]))(?:/etc|/boot|/usr/bin|/usr/lib)/`
- **Description:** Detects writes to `/etc`, `/boot`, `/usr/bin`, or `/usr/lib` by absolute path. The same write prefixed with `$pkgdir` is normal packaging and does not match.

### R084: World-Writable Staging {#r084}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** `/tmp`, `/var/tmp` or `/dev/shm` is used as a working or execution directory. `mktemp -d` is excluded wholesale: a random private directory is not a fixed world-writable path.

Fire rate: 0 of 3246.

### R088: Hidden Drop {#r088}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** A leading-dot (hidden) executable is written outside `$srcdir` and `$pkgdir`.

R088 is deliberately the quietest rule in the group so that one payload does
not fire three times: a hidden write that is later executed belongs to
R121/R124, one in a world-writable directory to R084, one in the user's home to
R077. R088 claims only the hidden drop none of those own.

Fire rate: 0 of 3246.

### R128: Build Writes Outside Staging Root {#r128}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** `prepare`, `build`, `check`, `package` or a top-level line writes to a plain absolute path outside `$srcdir`/`$pkgdir`.

Rather than a list of interesting directories, the rule is the shape: a
packaging step may only write inside the staging roots. An absolute system path
changes the machine doing the build, and pacman tracks none of it. Top level is
the worse case, because it runs when makepkg sources the file. Install hooks
are excluded, since R077/R084/R085/R114 own the target system. Devices
(`> /dev/null`) and extractor artefacts are excluded by requiring a plain
absolute path.

Fire rate: 0 of 3246.

### R140: PATH Injection With Undeclared Directory {#r140}

- **Severity:** HIGH (weight 25)
- **Category:** `build`
- **Condition:** Inside a build/package/check/prepare function, a `PATH=` assignment adds a single-level `$srcdir/<subdir>` directory that is neither a declared `source=()` basename nor a repository manifest member.

`PATH=$srcdir/tools:$PATH make` lets the recipe smuggle a binary into a
standard command's search path. Adding the plain source root is common enough
that it stays silent; deeper paths are more likely to be legitimate project
layouts, so only single-level subdirectories are flagged. Detected by
`_path_injection_findings()` in `src/trustsight/analysis/delivery.py`.

### R086: Host Reconnaissance {#r086}

- **Severity:** INFO (weight 0)
- **Category:** `recon`
- **Condition:** Host-profiling commands from `[patterns] recon_commands` run at a command position inside a build or install function.

A lone `uname -m` is an architecture check and is reported at INFO by design.
`env`, `dmidecode` and `systemd-detect-virt` are deliberately absent: the first
produced a false positive on a `sed` expression, and the other two are R119's.

Fire rate: 0 of 3246.
