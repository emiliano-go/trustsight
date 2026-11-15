<!-- description: Rules for what survives the build: install hooks running as root, systemd units, pacman hooks and setuid bits that keep running after makepkg exits. -->

# Install and Persistence


Something survives the build. Install hooks run as root at install time,
which makes them the highest-privilege code a PKGBUILD carries (R007, H017,
H023, H035), and units, pacman hooks and setuid bits keep running long
after makepkg exits (R053, R054, R059, H039, H062, H084).

R017 and R053/R059 split the same operation by target: a setuid bit inside
`$pkgdir` is Electron packaging, the same bit on an absolute path is a
privilege change to the build host. R052 and H032 cover the user-profile
form, where the persistence is a dotfile rather than a unit.

See [Rule Mechanics](mechanics.md) for the field table, the
severity weights and the reserved identifier ranges.

---
