<!-- description: Where the staging-and-recon rules come from (reading the target before acting) and what a finding means. -->

# Staging and Reconnaissance

Mechanics live on the [Staging and Reconnaissance category page](staging-and-recon.md).

## Where it comes from

The analogy is **casing the joint**: the burglar walks the block before the
break-in, memorises the locks, notes where the valuables are and when no one
is home. It is the oldest military idea too - reconnaissance before the
assault, because knowing the terrain is half the operation.

Before an attacker exfiltrates or pivots, they look around in exactly this
way: environment variables, `whoami`, hostnames, cloud metadata endpoints, SSH
keys, wallets, browser stores. In a build container this reconnaissance is a
written-down step, so it is auditable. The rules cover the read-the-target
behaviours that have no place in building a package: probing the metadata
service, walking credential paths, and staging files for a later fetch.

Not every `env` is recon; the rules target the recognisable credential and
cloud-metadata shapes rather than generic introspection. The value is that a
recon step turns an otherwise-ambiguous fetch into a deliberate
look-then-take sequence.

## What a finding means

- The finding names the target being read (a metadata IP, a credential path,
  a wallet directory). Read it as intent evidence: the package is
  accumulating material it was not asked to touch.
- Recon alone may be weight of evidence rather than a verdict; recon followed
  by a network send is the pattern to escalate.
- Some of these rules co-fire with crossfire and exfiltration families by
  design; the pairing is the signal.

## See also

- [Cross-File Consistency](../explanation/architecture-and-pipeline.md)
- [Staging and Reconnaissance category page](staging-and-recon.md)
