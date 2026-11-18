<!-- description: A-series rules inspect the built package manifest in the optional L9 build lane - off by default, never blended into the static score. -->

# Artifact


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
