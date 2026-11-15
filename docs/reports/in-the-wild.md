<!-- description: The watcher's incident reports: each campaign its diffs raised, what fired on it, and how to read the record. -->
# In the Wild

This section records AUR incidents whose diffs the TrustSight watcher raised,
what the analysis reported, and how to read those reports. It is a record, not
a receipt.

**A flag is a direction to review.** TrustSight does not install packages, block
builds, or clear anything. A finding names evidence and ends by asking the
reader to look; it never establishes that a package is safe, and the absence of
a finding never establishes it either. Every report below is written to that
standard: what the watcher observed and reported, not what it prevented.

## Reports

- [2026-10-14: AUR name-clone waves](2026-10-14-aur-name-clone-waves.md) -
  fifteen `yay` name-clones, fourteen `brave-beta-bin` name-clones, and one
  hijacked legitimate package in the same cluster.

## Reading a record here

Every report follows the same shape: what the watcher observed, what the
analysis reported and why, and the artifacts a reader can check the claim
against. Where a claim rests on a fixture or an indicator set, the artifact is
named so the reader can reproduce the analysis rather than take the prose on
trust. None of these records is a recall claim; what the tool *has* caught is
not what it *can* catch. See
[Benchmarks and Methodology](../explanation/detection-and-evidence.md) for
what the measured evidence does and does not support.
