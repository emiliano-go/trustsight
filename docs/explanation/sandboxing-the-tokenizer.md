<!-- description: How the tokenizer is sandboxed: what the child process buys, what it costs, and why the renderer stays where it is. -->

# Sandboxing the Tokenizer

The tokenizer runs in a separate process. This page is why, what the
isolation does and does not buy, and why the other candidate evolution -
a subprocess-isolated renderer - was left alone. It began as a design note
and is now a description of something that exists; the [security
model](../security/program-under-attack.md#the-invariants) states the
invariant (A6) and `scripts/security_gates.py` enforces it.

## Why this component

The model's largest stated gap is architectural: a tool whose entire job is
reading untrusted text parses, renders and stores that text through
third-party code it does not audit. Two candidates were named for shrinking
that surface. They were not equally worth doing, and the tokenizer won.

The tokenizer is the second parser eating hostile input, and it is the one
with an amplification property the regex engine does not have. [A6](../security/program-under-attack.md#the-invariants)
describes it: `b=$a$a` doubles per level, and a chain grows as `2**depth`,
so a 517-byte PKGBUILD was once enough to exhaust memory unbounded. Four
bounds hold it (`_MAX_EXPANSION_PASSES`, `_MAX_VALUE_LEN`, `_MAX_LINE_LEN`,
`_MAX_TABLE_BYTES`) and they are effective; a substitution that would
multiply a value by its replacement is refused before `re.sub`, and a glob
is answered by a table pass bounded by `_MAX_GLOB_PATTERN_LEN` and
`_MAX_GLOB_STEPS`, never compiled into a backtracking regex. They live in
the shared `expansion.py`, so the parent's whole-PKGBUILD resolver obeys
the same values as the worker. But a bound found and applied to a known
amplification is a different assurance from "a defect here cannot reach
anything", and that is the gap isolation closes.

It also happens to be the component where isolation is a bounded project
rather than a rewrite:

- **It is self-contained.** One module, no network, no database, no
  filesystem. Its contract is a pure function: text in, resolved text and a
  set of unresolved markers out.
- **It is already fuzzed.** `tests/test_tokenizer_fuzz.py` and the
  `tokenizer hostile-input smoke is deterministic` gate characterise the
  behaviour that has to survive the boundary.
- **Its output is data, not objects.** Nothing downstream needs a live
  Python object from it, so a serialisation boundary costs little.

The renderer fails all three. It is `rich`, it is interleaved with terminal
state, and its output *is* the side effect. [A10](../security/program-under-attack.md#the-invariants)
already bounds the thing that matters there: package-controlled text passes
through `safe_text.clean` and `safe_markup` before it reaches a console. So
the renderer stays where it is.

## What isolation buys

The honest answer is narrower than "the tokenizer becomes safe".

**It bounds the blast radius of a defect in expansion, not the correctness
of expansion.** A logic bug that resolves `$payload` wrongly is a detection
bug, and it produces a wrong answer inside the sandbox exactly as it does
outside one. What changes is a memory-safety or resource defect: a bound
that turns out to be bypassable, an interpreter-level pathology, an
allocation pattern that survives the four ceilings. Today such a defect has
the whole process. Under isolation it has a subprocess with no descriptors
worth having and `RLIMIT_AS` over its address space.

**It makes a failed parser a refusal, not a quiet run.** This is the part
that fits the model rather than merely hardening it. The parent reaches the
tokenizer only through `trustsight.tokenizer`; the engine is imported by the
worker alone (the `tokenizer module is isolated` gate fails otherwise). A
child that cannot answer raises `TokenizerUnavailable`, and the package is
reported as not vetted through the same path as any other analysis failure,
so a dead sandbox can never read as a clean diff. A response that is not a
frame-shaped object, or that carries neither `result` nor `error`, is
treated the same way. That is strictly more honest than an analysis that
silently ran without its parser.

**It does not remove the Python runtime from the trust boundary.** The
interpreter, the standard library and the OS remain [assumptions](../security.md#assumptions).
A subprocess is the same interpreter with fewer privileges; it is a smaller
target, not a different one. The worker therefore also enters the shared
kernel sandbox in `sandbox/_linux_sandbox.py`: a user namespace, a private
network namespace, a Landlock filesystem ruleset and a seccomp allowlist
with no socket syscalls. Landlock ABI 6 (Linux 6.12+) is required; a kernel
that cannot provide that floor refuses the worker rather than analysing with
weaker confinement. This reuses the same primitives as the git worker, not a
new dependency: Landlock and seccomp are installed directly through
`ctypes`.

## What it costs

- **A process per worker.** The pool starts `WORKER_POOL_SIZE` (4) children and
  recycles each after 512 requests. A fresh interpreter per diff was
  measured at 26-48 ms against a 0.5 ms tokenizer on the locked benign
  corpus, so one-shot spawning was rejected; the pool amortises startup to
  nothing over a run.
- **A serialisation boundary, which is a new parser.** Isolating a parser
  requires a protocol between parent and child, and that protocol reads
  input it did not produce. It is therefore kept trivial: a four-byte
  big-endian length and JSON, never `pickle` (the `no interpreter or shell
  execution` gate forbids unpickling for exactly this reason). Every frame
  is capped, every read is sized, and every write is deadline-bounded.
- **Round-trips, unless they are cached.** The analysis makes ~97
  tokenizer entry-point calls per diff; the identity cache collapses them
  to about a dozen child round-trips, because the same diff object reaches
  many call sites. Without the cache the boundary would dominate the
  analysis.
- **A gate that proves the real path.** Per [reviewing a security
  control](../contributing/security-review.md), the checks exercise the
  path an attacker reaches: one asserts no `src/` module imports the
  engine, and one forces the spawn to fail and proves `scan_diff` raises
  rather than completing.

## Why it was built without a demonstrated bypass

The design note this page grew out of set three conditions for building it,
and none of them was met: no A6 bound has been demonstrated bypassable, the
expansion surface did not grow, and a one-shot child was measured at 26-48 ms
against a 0.5 ms tokenizer, so per-diff spawning was not free. It was built
anyway, as a deliberate choice: the cost is now carried by a persistent pool
and batched per-line ops rather than by the analysis, the failure path is a
refusal rather than a silent degradation, and the invariant is worth having
before a bypass exists rather than after one. The conditions remain the
things to watch if the design is revisited.

## If it changes

Waiting for a busy pool has a five-second deadline. Returning a worker,
retiring one, or shutting down wakes waiting callers; a saturated or stopped
pool raises `TokenizerUnavailable`. Dead idle workers are removed before
replacement, and cleanup closes the child's pipe handles. When a worker's
process group is gone, cleanup falls back to the child process's `kill()`
method. This does not provide Windows pipe polling or Linux resource limits on
Windows.

The request write and the response read share one deadline. The write goes
through `protocol.write_frame`, which puts the descriptor in non-blocking mode
and waits for writability with `select`, so a child that stops reading stdin
cannot hold the parent in a blocking write. Resource-limit setup returns the
limits that could not be applied. A failed `RLIMIT_AS`, `RLIMIT_CPU` or
`PR_SET_NO_NEW_PRIVS` is fatal: the worker exits before serving, and the
client reports the package as not vetted. The remaining limits arrive in
`degraded` and the client logs them once, so a swallowed `setrlimit` cannot
read as full protection. The response is serialised under
`MAX_RESPONSE_BYTES` and framed only if it fits: `protocol.encode_response`
stops at the cap while the body is built, so a wide projection is a contained
`TokenizerUnavailable` refusal rather than a frame the parent reads and
discards. The git worker uses the same encoder. Both workers now run behind the kernel
confinement described in A16: the tokenizer worker is a `read`-role sandbox
with no socket syscalls and no writable filesystem, and the git worker adds
the fetch-role proxy bridge. A missing Landlock ABI 6, seccomp, user
namespace or network namespace is a startup refusal, not a degraded run.

The sandbox covers the whole tokenizer module, so `split_lines` and
`join_line_continuations` are sandboxed too, not only the expansion
functions that carry the amplification risk. The per-line helpers
(`strip_leading_bom`, `collapse_traversal`) are applied in bulk by a single
op for the same reason: routing them per line would be one round-trip per
line. If the tokenizer grows arithmetic or brace expansion, the
amplification analysis has to be redone, and the bounds are then harder to
reason about than four constants; the sandbox means that work can proceed
without the analysis process as the blast radius.
