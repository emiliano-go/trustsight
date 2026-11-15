<!-- description: Where the composition rules come from (chains that are only dangerous together) and what a finding means. -->

# Composition

Mechanics live on the [Composition category page](composition.md).

## Where it comes from

The analogy is **chemistry**. Two reagents that are inert on their own can
become something dangerous the moment they share a beaker; nothing about
either ingredient, read alone, tells you that. A composition finding is that
reaction: a *chain* of ordinary steps that is only dangerous together -
download to a temp file, make it executable, call it from a later phase, clean
up the evidence. Each step passes a naive rule; the sequence does not.

The chemical reaction is the whole point, not the elements. The rules detect
these chains by tracking state across the recipe: a file written in
`prepare()` and executed in `package()`, a variable set from a network call
and later expanded to a command, an interpreter invoked on something fetched
earlier. This is where TrustSight's cross-phase reasoning lives.

## What a finding means

- The finding names the chain and its links, so the reviewer sees the whole
  path rather than four unrelated lines.
- Composition findings score higher than their parts because the parts are
  only suspicious in combination; that is the point of the category.
- If a chain is read wrongly, the fix belongs in the chain definition, not
  in an exception for one package.

## See also

- [Cross-File Consistency](../explanation/architecture-and-pipeline.md)
- [Composition category page](composition.md)
