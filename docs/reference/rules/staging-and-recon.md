<!-- description: Rules for a packaging step writing outside `$srcdir` and `$pkgdir`, hiding what it wrote, or learning about the host it ran on. -->

# Staging and Reconnaissance

A packaging step may write inside `$srcdir` and `$pkgdir` and nowhere else.
These rules are the boundary (R058, H038, H076, H085), the hidden case
(H042, H007) and the question of what the build learned about the host it
ran on (H040).

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
| [H007](#h007) | Symlink Redirect | MEDIUM |
| [H010](#h010) | Suspicious file write | HIGH |
| [H038](#h038) | World-Writable Staging | HIGH |
| [H040](#h040) | Host Reconnaissance | INFO |
| [H042](#h042) | Hidden Drop | HIGH |
| [H076](#h076) | Build Writes Outside Staging Root | HIGH |
| [H085](#h085) | PATH Injection With Undeclared Directory | HIGH |
| [R058](#r058) | Write Outside Package Root | HIGH |
<!-- /generated: page-index -->

### H007: Symlink Redirect {#h007}

- **Target:** `raw_line`
- **Severity:** MEDIUM (weight 15)
- **Category:** `filesystem`
- **Pattern:** `ln\s+-sf`
- **Description:** Detects `ln -sf` (force-symlink) invocations. Re-pointing a symlink to a new target can redirect what a later step writes or reads, including replacing a config file or a cacheable binary path with a copy the attacker controls.

### H010: Suspicious file write {#h010}

- **Target:** `runtime` (resolved execution path)
- **Severity:** HIGH (weight 25)
- **Category:** `filesystem`
- **Pattern:** `(?!)` (never matches)
- **Description:** A write to a sensitive filesystem location (services, `cron.d`, `$HOME/.config/autostart`). Same treatment as H009: shipped as a reserved `runtime` placeholder, never emitted by the static diff engine.

### R058: Write Outside Package Root {#r058}

- **Target:** `raw_line`
- **Severity:** HIGH (weight 25)
- **Category:** `system`
- **Pattern:** `^\+?\s*(?:sudo\s+)?(?:install|cp|mv|dd|tee)\s+[^;&|]*(?:(?<=\s)|(?<=\s["\x27]))(?:/etc|/boot|/usr/bin|/usr/lib)/`
- **Description:** Detects writes to `/etc`, `/boot`, `/usr/bin`, or `/usr/lib` by absolute path. The same write prefixed with `$pkgdir` is normal packaging and does not match.

### H038: World-Writable Staging {#h038}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** `/tmp`, `/var/tmp` or `/dev/shm` is used as a working or execution directory. `mktemp -d` is excluded wholesale: a random private directory is not a fixed world-writable path.

Fire rate: 0 of 3246.

### H042: Hidden Drop {#h042}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** A leading-dot (hidden) executable is written outside `$srcdir` and `$pkgdir`.

H042 is deliberately the quietest rule in the group so that one payload does
not fire three times: a hidden write that is later executed belongs to
H069/H072, one in a world-writable directory to H038, one in the user's home to
H032. H042 claims only the hidden drop none of those own.

Fire rate: 0 of 3246.

### H076: Build Writes Outside Staging Root {#h076}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** `prepare`, `build`, `check`, `package` or a top-level line writes to a plain absolute path outside `$srcdir`/`$pkgdir`.

Rather than a list of interesting directories, the rule is the shape: a
packaging step may only write inside the staging roots. An absolute system path
changes the machine doing the build, and pacman tracks none of it. Top level is
the worse case, because it runs when makepkg sources the file. Install hooks
are excluded, since H032/H038/H039/H062 own the target system. Devices
(`> /dev/null`) and extractor artefacts are excluded by requiring a plain
absolute path.

Fire rate: 0 of 3246.

### H085: PATH Injection With Undeclared Directory {#h085}

- **Severity:** HIGH (weight 25)
- **Category:** `build`
- **Condition:** Inside a build/package/check/prepare function, a `PATH=` assignment adds a single-level `$srcdir/<subdir>` directory that is neither a declared `source=()` basename nor a repository manifest member.

`PATH=$srcdir/tools:$PATH make` lets the recipe smuggle a binary into a
standard command's search path. Adding the plain source root is common enough
that it stays silent; deeper paths are more likely to be legitimate project
layouts, so only single-level subdirectories are flagged. Detected by
`_path_injection_findings()` in `src/trustsight/analysis/delivery.py`.

### H040: Host Reconnaissance {#h040}

- **Severity:** INFO (weight 0)
- **Category:** `recon`
- **Condition:** Host-profiling commands from `[patterns] recon_commands` run at a command position inside a build or install function.

A lone `uname -m` is an architecture check and is reported at INFO by design.
`env`, `dmidecode` and `systemd-detect-virt` are deliberately absent: the first
produced a false positive on a `sed` expression, and the other two are H067's.

Fire rate: 0 of 3246.
