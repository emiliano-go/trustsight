<!-- description: Where the upstream-manifest rules come from (a citation checked against the original) and what a finding means. -->

# Upstream Manifests

Mechanics live on the
[Upstream Manifests system page](../rules/upstream-manifests.md).

<!-- generated: nature-rules -->
**Rules in this nature:** [U001](../rules/upstream-manifests.md#u001), [U002](../rules/upstream-manifests.md#u002), [U003](../rules/upstream-manifests.md#u003), [U004](../rules/upstream-manifests.md#u004), [U005](../rules/upstream-manifests.md#u005), [U006](../rules/upstream-manifests.md#u006), [U011](../rules/upstream-manifests.md#u011), [U012](../rules/upstream-manifests.md#u012) (8 rules).
<!-- /generated: nature-rules -->

## Where it comes from

This is the discipline of **checking a citation against the original text**. A
paper can quote a source flawlessly and still be wrong, because the page it
cites was never printed. Upstream projects increasingly publish metadata about
themselves (release manifests, SBOMs, signature files, `.SRCINFO`-like
declarations), and the upstream-manifest rules compare what a recipe claims
about its source against what the upstream actually published: a version that
does not exist, a hash that does not match the manifest, a source name
upstream never released.

The point is to catch the recipe that is internally consistent but
*externally* wrong: checksums that verify against the wrong artifact, or a
`source` array naming a file no upstream release contains. This is the
supply-chain-integrity check turned outward - not "does this recipe agree with
itself?" but "does it agree with the world?".

## What a finding means

- The finding names the mismatch between the recipe and the upstream
  declaration, with both values.
- A manifest mismatch is often decisive: it means the thing being verified is
  not the thing the upstream intended, regardless of the recipe's own
  consistency.
- These rules need network access to the upstream manifest, so on an offline
  run they report reduced coverage rather than passing silently.

## See also

- [Integrity and Verification](integrity.md)
- [Upstream Manifests system page](../rules/upstream-manifests.md)
