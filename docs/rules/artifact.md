<!-- description: A-series rules inspect the built package manifest in the optional L9 build lane - off by default, never blended into the static score. -->

# Artifact

## Overview


A rules inspect the **built package manifest**, not the diff. They are the
optional **L9 build lane**: off by default, parsed and inspected inside the
project's read-role sandbox, and never blended into the static score.

The static core never executes package code. An L9 finding is evidence from
*outside* the static analysis, reported alongside it; when the lane did not
run, the report says `l9_unavailable`; when inputs hit a cap, it says
`l9_partial` and includes the limits that fired.

This is a reference page. For how weight and scope work, see
[Rule Mechanics](mechanics.md).

## Reading an A finding

- It is L9 evidence, never folded into the L1-L8 score.
- When the lane is disabled or the read-role sandbox is unavailable, the run
  carries an `l9_unavailable` boundary (weight 0), which never reads as
  "malicious" or "clean".
- Disagreement between a complete L9 inspection and L1-L8 renders both
  profiles in full and carries an explicit `l9_divergence` notice; an
  incomplete inspection cannot establish the absence of a disagreement.
- `l9_partial` means the manifest exceeded an entry, link, path, content or
  finding cap. The returned `limits` object names the bound; a partial
  inspection never reads as clean.

## L9 input boundary

The manifest is attacker-controlled evidence, so both the parent and the
read-role worker are bounded.

**Parent process**

- `--manifest` is read under `MAX_MANIFEST_BYTES` (8 MiB) and passed as raw
  UTF-8. The parent never calls `json.loads` on it.
- The Python `manifest=` form is normalised first: only the fields the
  inspector uses are retained, unknown fields are dropped, record shapes are
  checked, and strings are capped before they are encoded.
- A single aggregate text budget (`MAX_MANIFEST_BYTES`) covers the normalised
  entries, so a wide list of long paths or links cannot force a larger
  serialisation.
- Raw C0 control bytes are refused before serialisation; normal JSON
  escapes remain valid.
- A request larger than `protocol.MAX_FRAME_BYTES` is refused before the
  worker is spawned.
- The parent never calls `inspect_manifest` on the production L9 path and has
  no in-process fallback when the worker fails.
- Terminal rendering cleans finding text and limit reasons; the JSON result
  keeps the exact strings the worker returned.

**Read-role worker**

- `sandbox/manifest_worker.py` parses the JSON and calls
  `inspect_manifest_bounded`; the worker runs with user/network/mount
  namespaces, Landlock ABI 6, a seccomp allowlist with no socket or `execve`,
  no capabilities, `RLIMIT_AS` 512 MiB, `RLIMIT_CPU` 300 s and
  `RLIMIT_NOFILE` 64.
- The parent deadline is 10 s; a timeout, channel failure or invalid frame
  kills the worker's process group. A worker that cannot apply the sandbox
  exits before serving.
- The worker re-checks the manifest size and requires a JSON array of objects
  with a non-empty string `path`.
- The inspector stops at the first cap and returns `limits.truncated` plus
  the reasons. It never walks a wider input to build a larger result.
- The worker's response is capped by the framed protocol; the parent
  re-validates the projection (4,096 findings, 8 KiB per finding field and
  16 limit reasons of 128 bytes).

| Bound | Value |
|---|---|
| Manifest text | 8 MiB |
| Records | 10,000 |
| Links per record / total | 4,096 / 65,536 |
| ELF runpaths per record / total | 256 / 4,096 |
| Path per record / total | 4,096 bytes / 2 MiB |
| Shipped content per file / total | 64 KiB / 256 KiB |
| Capability text | 256 bytes |
| Findings | 4,096 |
| Declared depends / units | 10,000 each |
| Declared install text / mode intent | 256 KiB / 1 KiB |
| Normalised aggregate text | 8 MiB |

A cap hit is `l9_partial`; the terminal prints the reasons and the JSON keeps
`limits`. A worker failure is `l9_unavailable`. Neither is a clean result,
and an incomplete empty inspection does not set `l9_divergence`.

---

## Threat context

When a parcel arrives you **open the box and look at what is inside**; the
order form and the packing slip are only claims. The artifact family is the
open box. It reads `$pkgdir` after the build: what was installed, where, with
what permissions, and whether it matches what the recipe declared. It is the
last checkpoint before the tarball ships, and it sees the result of every step
that came before.

This is why artifact findings often confirm what earlier families suspected:
an execution path named in the shell becomes a file in the package, a write to
`/etc` becomes an entry in the installed tree. The order form and the box
agree, or they do not, and only the box is the truth.

## Detection mechanisms

The rules that make up this category are listed below, each with the series that implements it and the severity it carries. Scoring, matching and identifier allocation are shared across every category: see [Rule Mechanics](mechanics.md).

## Individual rules

<!-- generated: page-index -->
| Rule | Name | Severity |
|---|---|---|
| [A001](#a001) | Setuid File In Artifact | HIGH |
| [A002](#a002) | Undeclared Unit In Artifact | MEDIUM |
| [A003](#a003) | Library Outside Depends | MEDIUM |
| [A004](#a004) | Install Hook Diverges From Declaration | HIGH |
| [A005](#a005) | Unusual Artifact Mode | INFO |
| [A006](#a006) | File Capabilities In Artifact | HIGH |
| [A007](#a007) | Privileged Surface In Artifact | MEDIUM |
| [A008](#a008) | eBPF Artifact In Package | HIGH |
| [A009](#a009) | Executable Binary In Source Archive | HIGH |
| [A010](#a010) | Setuid File In Source Archive | HIGH |
| [A011](#a011) | Hook Runs On Every Transaction | MEDIUM |
| [A012](#a012) | Shipped Hook Or Udev Fetches Or Runs A User Path | HIGH |
| [A013](#a013) | Udev Rule Runs A Program | MEDIUM |
| [A014](#a014) | Unsafe ELF Runpath | HIGH |
| [A015](#a015) | Packed Or Encrypted ELF Section | MEDIUM |
<!-- /generated: page-index -->

### A001: Setuid File In Artifact {#a001}

- **Target:** programmatic (built package manifest)
- **Severity:** HIGH
- **Category:** `artifact`

- **Condition:** A setuid/setgid file the recipe cannot justify (justification is a documented mode intent).

The conservative default fires and the reviewer decides.

### A002: Undeclared Unit In Artifact {#a002}

- **Target:** programmatic (built package manifest)
- **Severity:** MEDIUM
- **Category:** `artifact`

- **Condition:** A systemd unit, timer or tmpfiles entry the recipe's declared surface does not explain.

### A003: Library Outside Depends {#a003}

- **Target:** programmatic (built package manifest)
- **Severity:** MEDIUM
- **Category:** `artifact`

- **Condition:** A linked shared library of a shipped binary outside the declared `depends` closure.

### A004: Install Hook Diverges From Declaration {#a004}

- **Target:** programmatic (built package manifest)
- **Severity:** HIGH
- **Category:** `artifact`

- **Condition:** The built `.INSTALL` script's effective behavior differs from the recipe's `install=` file - a tampered or regenerated hook.

### A005: Unusual Artifact Mode {#a005}

- **Target:** programmatic (built package manifest)
- **Severity:** INFO
- **Category:** `artifact`

- **Condition:** World-writable files or executables in unusual paths.

The L1 C018 rule's artifact twin.

### A006: File Capabilities In Artifact {#a006}

- **Target:** programmatic (built package manifest)
- **Severity:** HIGH
- **Category:** `artifact`

- **Condition:** A file carrying Linux file capabilities (e.g. `cap_setuid`, `cap_sys_admin`), which grant privilege without the setuid bit.

### A007: Privileged Surface In Artifact {#a007}

- **Target:** programmatic (built package manifest)
- **Severity:** MEDIUM
- **Category:** `artifact`

- **Condition:** A file in a privilege/persistence surface the recipe does not declare: polkit rules, sudoers, PAM config, modprobe/modules-load, or a kernel module (`.ko`).

### A008: eBPF Artifact In Package {#a008}

- **Target:** programmatic (built package manifest)
- **Severity:** HIGH
- **Category:** `artifact`

- **Condition:** An eBPF object or loader shipped in the package - the Atomic Arch rootkit's artifact shape.

Inspection only; nothing is loaded or executed.

### A009: Executable Binary In Source Archive {#a009}

- **Target:** declared source archive (opt-in upstream lane)
- **Severity:** HIGH (weight 0)
- **Category:** `artifact`

- **Condition:** A regular file in the declared source archive (read by the
  opt-in `[upstream_scan]` lane) begins with the ELF magic.

A source archive normally ships source, not compiled objects. A committed ELF
binary is report-only (weight 0, anergic) until calibrated; the file is never
executed.

### A010: Setuid File In Source Archive {#a010}

- **Target:** declared source archive (opt-in upstream lane)
- **Severity:** HIGH (weight 0)
- **Category:** `artifact`

- **Condition:** A regular file in the declared source archive carries the
  setuid or setgid mode bit.

The bit is read from the archive header, not by executing anything. It is
report-only (weight 0, anergic) until calibrated; a source tree that ships a
setuid file is worth a look even before it is built.

### A014: Unsafe ELF Runpath {#a014}

- **Target:** ELF in the artifact/upstream lane
- **Severity:** HIGH (weight 0)
- **Category:** `artifact`

- **Condition:** A fetched or built ELF binary declares an `RPATH`/`RUNPATH`
  that is empty, relative, or points at a system-temp or user-owned
  directory (for example `.`, `/tmp`, `/dev/shm`, `/home`, `/root`).

The ELF header is read with a bounded parser; the binary is never mapped or
executed. `$ORIGIN` is relative to the binary's own package directory and is
not automatically unsafe. Weight 0 (anergic) until calibrated.

### A015: Packed Or Encrypted ELF Section {#a015}

- **Target:** ELF in the artifact/upstream lane
- **Severity:** MEDIUM (weight 0)
- **Category:** `artifact`

- **Condition:** A fetched or built ELF binary carries a known packer or
  encrypted-section marker: `UPX!`, or a section named `.upx`, `UPX0`,
  `UPX1`, `.packed`, `.aspack`, `.mpress`, `.nsp`, `.petite`, `.themida`,
  `.vmp0`, `.vmp1`, `.encrypted` or `.crypt`.

The section table is read with the bounded ELF parser; nothing is executed or
unpacked. Weight 0 (anergic) until calibrated.

### A011: Hook Runs On Every Transaction {#a011}

- **Target:** shipped libalpm hook / udev rule / install script (L9)
- **Severity:** MEDIUM (weight 0)
- **Category:** `artifact`

- **Condition:** A shipped libalpm `.hook` has a broad trigger
  (`Operation = *`) and an `Exec` command, so it runs as root on every pacman
  transaction.

The hook text is read from the artifact manifest; nothing is executed.
Weight 0 (anergic) until calibrated.

### A012: Shipped Hook Or Udev Fetches Or Runs A User Path {#a012}

- **Target:** shipped libalpm hook / udev rule / install script (L9)
- **Severity:** HIGH (weight 0)
- **Category:** `artifact`

- **Condition:** A shipped `.hook`, udev `.rules` file or `.install` script
  fetches (`curl`/`wget`/`aria2c`) or uses a user/temp path (`/tmp`,
  `/dev/shm`, `$HOME`, `/home`, `/root`). A plain `sh -c` that only runs a
  system helper is not itself a finding; wrapping a fetch or user path in
  `sh -c` remains in scope because the fetch/path check sees it.

These files run as root outside the package manager's checksum. The text is
read only; nothing is executed. Weight 0 (anergic) until calibrated.

### A013: Udev Rule Runs A Program {#a013}

- **Target:** shipped libalpm hook / udev rule / install script (L9)
- **Severity:** MEDIUM (weight 0)
- **Category:** `artifact`

- **Condition:** A shipped udev `.rules` file runs a program
  (`RUN+=`, `PROGRAM==`, `IMPORT{program}`).

A udev rule can launch a command as root whenever a device appears. Read-only
inspection; weight 0 (anergic) until calibrated.

## Interpretation

- The finding describes the installed file or permission and why it is
  notable (unexpected location, world-writable, outside declared `backup`).
- Artifact findings are concrete and low-ambiguity: the file is there, and
  the reviewer can decide whether it belongs.
- When an artifact finding matches an earlier shell finding, the pair is the
  strongest form of evidence TrustSight produces.

## Related documentation

- [Structural User Rules](../explanation/static-analysis-and-resolution.md)
