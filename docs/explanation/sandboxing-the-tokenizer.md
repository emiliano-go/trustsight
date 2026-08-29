<!-- description: Why the tokenizer is the one component worth isolating, what isolation would and would not buy, and the conditions under which it should be built. -->

# Sandboxing the Tokenizer

This is a **design note, not a plan of record**. Nothing here is scheduled, and no code has been written against it. The [security model](../security.md#what-this-part-does-not-protect) records a sandboxed tokenizer as a candidate evolution; this page is the analysis behind that one-line mention, written down so the decision is made from an argument rather than from an instinct that sandboxing is generally good.

## Why this component

The model's largest stated gap is architectural: a tool whose entire job is reading untrusted text parses, renders and stores that text through third-party code it does not audit. Two candidates were named for shrinking that surface - a sandboxed tokenizer, and a subprocess-isolated renderer. They are not equally worth doing, and it is worth being explicit about why the tokenizer wins.

The tokenizer is the second parser eating hostile input, and it is the one with an amplification property the regex engine does not have. [A6](../security.md#the-invariants) describes it: `b=$a$a` doubles per level, and a chain grows as `2**depth`, so a 517-byte PKGBUILD is enough to exhaust memory unbounded. Four bounds hold it (`_MAX_EXPANSION_PASSES`, `_MAX_VALUE_LEN`, `_MAX_LINE_LEN`, `_MAX_TABLE_BYTES`) and they are effective. But a bound found and applied to a known amplification is a different assurance from "a defect here cannot reach anything", and the gap between those two is what isolation would close.

It also happens to be the component where isolation is a bounded project rather than a rewrite:

- **It is self-contained.** One module, no network, no database, no filesystem. Its contract is already close to a pure function: text in, resolved text and a set of unresolved markers out.
- **It is already fuzzed.** `tests/test_tokenizer_fuzz.py` and the `tokenizer hostile-input smoke is deterministic` gate mean the behaviour to preserve across a boundary is characterised, which is the expensive part of any such move.
- **Its output is data, not objects.** Nothing downstream needs a live Python object from it, so a serialisation boundary costs little.

The renderer fails all three. It is `rich`, it is interleaved with terminal state, and its output *is* the side effect. Isolating it means isolating a third-party library mid-render, and [A10](../security.md#the-invariants) already bounds the thing that matters there: package-controlled text passes through `safe_text.clean` and `safe_markup` before it reaches a console. So the renderer stays where it is, and this note is about the tokenizer alone.

## What isolation would actually buy

Be precise, because the honest answer is narrower than "the tokenizer becomes safe".

**It bounds the blast radius of a defect in expansion, not the correctness of expansion.** A logic bug that resolves `$payload` wrongly is a detection bug, and it produces a wrong answer inside the sandbox exactly as it does outside one. What changes is a memory-safety or resource defect: a bound that turns out to be bypassable, an interpreter-level pathology, an allocation pattern that survives the four ceilings. Today such a defect has the whole process - the database handle, the config, the network-capable modules, the operator's filesystem permissions. Under isolation it has a subprocess with no descriptors worth having, and the parent observes a non-zero exit.

**It converts a class of crash into a coverage gap.** This is the part that fits the model rather than merely hardening it. A tokenizer that dies today takes the analysis with it, and [the uncertainty rule](../security.md#uncertainty-reaches-the-surface) is satisfied only because a failure is reported as a failure. A tokenizer that dies *in a subprocess* can be reported as `unresolved_expansion` - a gap on a result that still exists, carrying every finding the rules did produce, and forbidden by [B2](../security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete) from reading as clean. That is strictly more information than an aborted run, and it is the strongest argument on this page.

**It does not remove the Python runtime from the trust boundary.** The interpreter, the standard library and the OS remain [assumptions](../security.md#assumptions). A subprocess is the same interpreter with fewer privileges; it is a smaller target, not a different one.

## What it would cost

- **Per-analysis process spawn.** `full-aur` bootstraps tens of thousands of packages, so a fork per PKGBUILD is not free. The measurement to take before building anything is spawn overhead against current tokenizer time on the corpus. A long-lived worker with a request protocol avoids the per-package cost and gives back the property that made isolation attractive - a worker that has processed a hostile input and continues is a worker holding state from it, so it would have to be recycled per package, which is the spawn cost under another name.
- **A serialisation boundary is a new parser.** The irony is worth stating plainly: isolating a parser requires a protocol between parent and child, and that protocol is code reading input it did not produce. It must be trivially simple, length-prefixed, and never `pickle` - the `no interpreter or shell execution` gate forbids unpickling for exactly this reason, and a sandbox whose channel is a deserialiser has moved the problem rather than solved it.
- **Platform-specific confinement.** Real privilege reduction on Linux means `seccomp`, namespaces, or `landlock` - none of it in the standard library, all of it new dependency surface or new C-adjacent code in a project whose stated aim is to shrink that surface. A plain `fork` with closed descriptors and an `RLIMIT_AS` is most of the resource benefit for none of the dependency cost, and is where a first implementation should stop.
- **A gate that genuinely proves it.** Per [reviewing a security control](../contributing/security-review.md), the check would have to exercise the path an attacker reaches - the real `scan_diff` entry, not a direct call to the sandboxed helper. A gate that asserts "the sandbox module refuses X" while the analysis path still calls the in-process tokenizer is precisely the recurring failure that document catalogues.

## Conditions for building it

This should be built when one of these becomes true, and not before:

1. **A bypass of any A6 bound is demonstrated.** That converts the argument from theoretical to evidential, and it is the trigger that matters most.
2. **The expansion surface grows.** If the tokenizer takes on arithmetic expansion, brace expansion, or nested substitution resolution, the amplification analysis has to be redone and the bounds will be harder to reason about than four constants.
3. **Spawn overhead measures as negligible** against corpus-scale tokenizer time, removing the main cost objection while the benefit stands unchanged.

Absent all three, the four bounds plus the fuzz corpus plus the determinism gate are a defensible position, and this note exists so that position is a *choice* with its reasoning recorded rather than an omission.

## If it is built

The order is the same one the contributing guide requires for any invariant:

1. Write the sentence in the [security model](../security.md) first - probably an extension of A6 stating that expansion runs with no descriptors, no network and a hard memory ceiling.
2. Add `unresolved_expansion` to [the gap taxonomy](../security.md#b2-an-unflagged-verdict-is-never-issued-for-an-analysis-that-was-incomplete) and to `coverage.GAPS`, so a dead child is a reported gap and never a silent skip.
3. Enumerate every caller of the tokenizer before writing the gate, and write the gate against `scan_diff`.
4. Add the row to the [enforcement map](../security.md#part-c-the-enforcement-map).

And this page changes with it, from a design note into a description of something that exists.
