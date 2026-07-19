# Sandbox Security Model

> **GATED**: The sandbox is not yet available in the current release. This page describes the planned design.

## Threat-model inversion

The sandbox module runs untrusted code by design. This is the opposite of most security tooling : instead of analysing code from a safe distance, it executes it in an isolated environment and observes its behaviour. The observation is the signal.

## Network default-deny

The blocked attempt **is** the signal. If a PKGBUILD's build process attempts to contact a network endpoint that was not declared in the source array, that attempt is blocked and recorded. The report says: *"this package tried to reach X during build."* The mere attempt, regardless of success, is evidence.

Network policy is default-deny. Only explicitly declared sources are allowed. Everything else is blocked and logged.

## Namespace vs. VM isolation

The sandbox design supports two isolation boundaries:

| Boundary | Properties | Honest assessment |
|----------|-----------|-------------------|
| **Namespace isolation** | Linux user/mount/network/PID namespaces | Best-effort signal gathering. Lightweight, fast, but not a security boundary. A determined escape is possible. |
| **VM isolation** | Full virtual machine | Real boundary. The guest cannot observe or affect the host. Heavyweight, slow, but provides genuine isolation. |

The namespace path is optimised for signal quality; it allows the sandbox to observe build behaviour in near-native conditions. The VM path is optimised for containment. Documentation will be clear about which is active.

## Assume-breach

The sandbox environment is designed on an assume-breach model:

- **Empty**: no valuable data or credentials in the sandbox.
- **Network-dead**: no outbound network access (except to declared sources).
- **Secret-free**: no SSH keys, API tokens, or GPG keys.
- **Disposable**: the sandbox is destroyed after each audit. Nothing persists.

An escape must land in a box that contains nothing of value and can reach nothing of value. The blast radius of a successful sandbox escape is zero.

## Ceiling

Sandbox-aware malware is unwinnable. Code that detects it is running in a container or namespace and alters its behaviour (e.g., not phoning home, not unpacking the payload) will appear clean. "Observed clean" does not mean safe. The sandbox provides behavioral evidence; it does not provide certainty.
