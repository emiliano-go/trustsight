<!-- description: A-series rules inspect the built package manifest in the optional L9 build lane - off by default, never blended into the static score. -->

# Artifact

Where these rules come from and what a finding means: [Rule Nature](../nature/artifact.md).

A rules inspect the **built package manifest**, not the diff. They are the
optional **L9 build lane**: off by default, run only inside the project's
rootless, networkless container, and never blended into the static score.

The static core never executes package code. A L9 finding is evidence from
*outside* the static analysis, reported alongside it; when the lane did not
run, the report says `l9_unavailable` rather than implying the artifact was
clean.

This is a reference page. For how weight and scope work, see
[Rule System](system.md).

## Reading an A finding

- It is L9 evidence, never folded into the L1-L8 score.
- When the lane is disabled or the container is unavailable, the run
  carries an `l9_unavailable` boundary (weight 0), which never reads as
  "malicious" or "clean".
- Disagreement between L9 and L1-L8 renders both profiles in full and
  carries an explicit `l9_divergence` notice.

---

<!-- generated: page-index -->
## Rules on this page

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
