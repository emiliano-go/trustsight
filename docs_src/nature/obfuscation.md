<!-- description: Where the obfuscation rules come from (the recipe speaking a language only the shell reads) and what a finding means. -->

# Obfuscation

Mechanics live on the [Obfuscation category page](obfuscation.md).

## Where it comes from

Think of a **message written in a private cipher**: you are asked to deliver
it, but you cannot read it, and you are told not to worry about what it says.
Obfuscation in a recipe is exactly that. Fetch-and-execute is visible if a
reviewer can read the command, so obfuscation exists to defeat the reading:
base64 or hex decode before execution, string reassembly, `eval`, `printf`
into a shell, or an interpreter fed a blob.

In PKGBUILDs the honest cases are rare, because the source tarball and its
checksum already exist. A recipe that hides its text is hiding it from the one
person positioned to approve it, so the concealment itself is treated as the
evidence.

The rules therefore do **not** try to reverse the obfuscation, which would put
the analyser inside the payload. They flag that the recipe is reaching for a
decoder and let the reviewer decide.

## What a finding means

- The finding names the concealment technique (base64, hex, eval, string
  slicing), with the matched fragment. It is about the technique's presence,
  which is decidable statically, not about what the blob would do.
- Obfuscation next to a network call is the high-value pairing; obfuscation
  alone may still be a build quirk, but it is never nothing in a recipe whose
  checksums a reviewer is supposed to verify.
- Findings here frequently co-fire with fetch-and-execution; that pairing is
  the intended escalation, not a duplicate.

## See also

- [Why Static Analysis](../explanation/static-analysis-and-resolution.md); why the
  blob is not decoded
- [Obfuscation category page](obfuscation.md)
