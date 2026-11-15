<!-- description: Where the artifact rules come from (inspecting the goods that actually arrive) and what a finding means. -->

# Artifact

Mechanics live on the [Artifact category page](artifact.md).

## Where it comes from

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

## What a finding means

- The finding describes the installed file or permission and why it is
  notable (unexpected location, world-writable, outside declared `backup`).
- Artifact findings are concrete and low-ambiguity: the file is there, and
  the reviewer can decide whether it belongs.
- When an artifact finding matches an earlier shell finding, the pair is the
  strongest form of evidence TrustSight produces.

## See also

- [Structural User Rules](../explanation/static-analysis-and-resolution.md)
- [Artifact category page](artifact.md)
