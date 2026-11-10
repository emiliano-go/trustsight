<!-- description: Wire TrustSight into yay and paru as a per-package approval gate before AUR sources are downloaded or built. Hard gate: a refusal aborts the transaction. -->

# Gating yay and paru

`trustsight inspect` is a report; `trustsight-gate` is the policy wrapper that
turns it into an approval step inside yay and paru.

For a manual check of a package you have not installed yet, use
`trustsight preinstall <package>…`. It is the same analysis without
`--allow-uninstalled` and without the approval prompt: a read-only remote
scanner that exits 0 when the scan completed and 2 when it could not (it never
installs and never encodes a verdict in its status). `trustsight-gate` remains
the interactive pre-build approval step.

The hooks require a TrustSight build that provides the `trustsight-gate`
console script. Verify it with `command -v trustsight-gate`; an older package
that only ships `trustsight` will abort the hook with "command not found".

Both package managers expose a per-package-base hook that runs **after the AUR
PKGBUILD is checked out and before sources are downloaded or built**:

| Manager | Hook | Config |
|---------|------|--------|
| yay >= 13.0.0 | `AURPreInstall` | `~/.config/yay/init.lua` |
| paru | `PreBuildCommand` | `[bin]` in `~/.config/paru/paru.conf` |

The gate inspects the target packages, prints a short report, and asks for a
**yes/no per package**, including AUR packages pulled as dependencies.

## Hard gate, by design

A “no” aborts the whole install or update. This is deliberate:

- Neither yay's `AURPreInstall` nor paru's `PreBuildCommand` can remove a
  single package from the transaction at that point. yay's Lua event table is
  read-only and paru's hook only signals success or failure.
- The per-package drop menus in both managers (`UpgradeSelect` exclusions,
  paru's upgrade menu) are **update-only** and do not see the PKGBUILD.
- An AUR package may be a pulled dependency of an approved package, so
  dropping it silently would produce a partial transaction.

If you need a softer workflow for updates, inspect first with
`trustsight review`, then use yay's exclude menu or `--ignore` explicitly.

## yay

Copy [`packaging/hooks/yay-init.lua`](https://github.com/emiliano-go/trustsight/blob/master/packaging/hooks/yay-init.lua)
to `~/.config/yay/init.lua` (or `require` it from an existing file).
The hook calls `trustsight-gate` with the package base, the build directory and
every target package of that base.

The optional `AURPostDownload` block in the same file re-runs the gate after
`makepkg --verifysource`; uncomment it when the downloaded source surface is
the concern.

## paru

Merge [`packaging/hooks/paru.conf`](https://github.com/emiliano-go/trustsight/blob/master/packaging/hooks/paru.conf)
into `~/.config/paru/paru.conf`:

```ini
[bin]
PreBuildCommand = trustsight-gate --base "$PKGBASE" --dir "$PWD"
```

paru sets the working directory to the checked-out PKGBUILD, so the gate reads
the split package names from `.SRCINFO`.

## What you see

```text
:: TrustSight gate: demo-bin
   version: 1.1-1 (from 1.0-1)
   verdict: review   risk: Medium   score: 35
   - H017 (HIGH): install hook changed [demo-bin.install:3]
Continue with demo-bin? [y/N]
```

The report goes to stderr and the prompt is read from the controlling
terminal, so it still works when the manager's output is piped.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | every package approved |
| `10` | a package was refused |
| `20` | inspection failed, timed out, or returned unusable output |
| `30` | no answer was possible (no TTY and no explicit `--yes`) |

Codes `10`, `20` and `30` are all non-zero, so both managers abort.

## Unattended runs

Nothing is approved by accident. For a timer or `--noconfirm` workflow you must
choose one explicitly:

- `trustsight-gate --yes` approves every package without prompting.
- `TRUSTSIGHT_GATE_DISABLE=1` skips the gate entirely and logs that it did.

`--no` refuses every package, which is useful for testing the abort path.

## Options

| Flag | Effect |
|------|--------|
| `--depth N` | AUR dependency levels to inspect (default `1`) |
| `--timeout N` | seconds allowed per inspection (default `180`) |
| `--full-recipe` / `--no-full-recipe` | force whole-recipe or diff analysis (default: whole recipe when the package is not installed) |
| `--base NAME` | package base label in the report |
| `--dir PATH` | read split package names from `PATH/.SRCINFO` |
| `--yes` / `--no` | non-interactive approve / refuse |

Environment: `TRUSTSIGHT_BIN` overrides the `trustsight` executable,
`TRUSTSIGHT_GATE_BIN` overrides `trustsight-gate` for the yay hook,
`TRUSTSIGHT_GATE_DEPTH` sets the default depth for the yay hook, and
`TRUSTSIGHT_GATE_DISABLE=1` is the explicit bypass.

## Limits

- yay's hook is AUR-only. paru also runs `PreBuildCommand` for PKGBUILD
  repositories and local `-B` builds; when the package is not in the AUR the
  gate falls back to `trustsight lint` on the checked-out PKGBUILD, so a local
  build is still stopped on recipe findings but is not diff-analysed.
- The gate inspects the recipe and its AUR dependency graph. It does not see
  downloaded source tarballs unless you enable the yay `AURPostDownload` check.
  A local paru build uses `trustsight lint`, which reports recipe hygiene
  findings but has no diff and no score.
- The hook is a user-controlled guard against AUR content, not an enforcement
  boundary against a local root user who can edit the hook or set the bypass.
- Approvals are not cached: a package is asked about on every transaction.
