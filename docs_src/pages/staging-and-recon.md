<!-- description: Rules for a packaging step writing outside `$srcdir` and `$pkgdir`, hiding what it wrote, or learning about the host it ran on. -->

# Staging and Reconnaissance


A packaging step may write inside `$srcdir` and `$pkgdir` and nowhere else.
These rules are the boundary (R058, H038, H076, H085), the hidden case
(H042, H007) and the question of what the build learned about the host it
ran on (H040).

One shared write-target resolver in `analysis/persistence.py` backs the
write rules: `install`/`cp`/`mv`/`ln` destinations including `-t DIR`, `>`
redirects, and the verb-substitution forms `tee`, `dd of=`, `mkdir -p`,
`touch`, `rsync` and `sed -i`. Every match is command-position anchored, so
a quoted string such as `'cp x ~/.zshrc'` never reads as a write.

See [Rule Mechanics](mechanics.md) for the field table, the
severity weights and the reserved identifier ranges.

---
