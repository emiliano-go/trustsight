
!!! warning "Not implemented"

    There is no `trustsight sandbox` command. This page describes a
    design that was explored and not built. It also conflicts with the
    position stated in
    [What TrustSight Cannot See](../explanation/what-trustsight-cannot-see.md):
    TrustSight is a static analysis tool by design and does not execute
    PKGBUILDs, sandboxed or otherwise. Treat this page as a record of a
    rejected direction, not as documentation of behaviour.
---
description: Aspirational : running a PKGBUILD in an isolated sandbox before approving it.
---

# Running the Sandbox

> **Note:** The sandbox is not yet available in the current release.
> This page describes the planned design.

The sandbox executes a candidate PKGBUILD's build and install scripts in an isolated environment. The goal is to catch runtime behaviour that static analysis cannot: unexpected network connections, file writes outside the build directory, or shellcode concealed through obfuscation.

## Opt-in only

```bash
trustsight sandbox <package>
```

The sandbox is **never implicit in `trustsight review`**. It is an explicit, per-package step you opt into when the review raises a question that static analysis cannot answer.

## Isolation backends

Two isolation levels are planned:

| Backend | Boundary | Use case |
|---------|----------|----------|
| **Namespace** (best-effort) | Linux user / PID / mount namespace | Quick check : catches accidental writes and obvious network access. Rootless. |
| **VM** (categorical) | Full virtual machine boundary | Strong isolation. The guest cannot observe or affect the host. Requires root or a hypervisor. |

The namespace backend is best-effort: a determined sandbox escape is possible. The VM backend provides a categorical boundary; an escape lands in an empty, disposable box.

## Network default-deny

The sandbox enforces **default-deny networking**:

- Outbound connection attempts are **blocked by default**.
- A blocked attempt is a **signal in the report**: not a silent failure.
- If the PKGBUILD needs network access during build (e.g. `go mod download`), the sandbox records every destination and includes it in the evidence output.

## What the sandbox produces

After execution, the sandbox reports:

- **Files written**: every file created outside the build directory, with hashes.
- **Network connections**: every attempted outbound connection, blocked or allowed.
- **Process tree**: every subprocess spawned, with arguments.
- **Exit code**: whether the build succeeded.

This evidence feeds into the same [evidence tier](../reference/evidence-tiers.md) system as the static rules. Runtime findings contribute to tier A (structural) or tier D (verification).

## Ceiling: "observed clean" ≠ safe

A sandbox run that produces no suspicious output is **informative but not conclusive**. The sandbox observes a single execution trace. A malicious PKGBUILD can:

- Check for the sandbox environment and behave differently.
- Trigger only on a specific date, network condition, or dependency version.
- Use a timing bomb that activates after install.

The ceiling of sandbox analysis is "observed clean in this specific execution." Treat a clean sandbox as evidence, not proof.

## Security model


## When to use the sandbox

| Situation | Use sandbox? |
|-----------|-------------|
| Routine version bump, CLEAN verdict | No : static analysis is sufficient |
| FLAGGED, MEDIUM score, novelty only | Optional : inspect first, sandbox if uncertain |
| FLAGGED, HIGH or CRITICAL | Yes : especially if the diff contains new commands or obfuscation |
| FATAL rule (R012/R013) | Sandbox is not useful : do not install. Prompt injection cannot be safely executed. |
| INCONCLUSIVE, cold database | Consider sandbox : it adds runtime evidence the static model lacks |

## See also


- [Acting on a flag](acting-on-a-flag.md)
- [Evidence tiers](../reference/evidence-tiers.md)
