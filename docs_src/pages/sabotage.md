<!-- description: Rules for a payload that wrecks, exhausts or steals rather than exfiltrates, written against the distinction between the build sandbox and the system. -->

# Sabotage


A payload that wrecks, exhausts or steals rather than exfiltrates.

Every other family on these pages describes a *supply-chain* compromise:
code fetched from somewhere, credentials sent somewhere, persistence
installed, a maintainer taken over. All of them share an assumption - the
attacker wants something out of your machine, so there is a fetch or an
egress to notice, and most of the ruleset is built around noticing it.

A sabotage payload wants nothing out. It runs, and the machine is worse
off. It phones nobody, persists nothing and obfuscates little, because it
does not need to survive being noticed: by the time you notice, it is done.
The entire detection surface is the command itself.

## Sabotage, not destruction

The family is named for the broader idea on purpose. Deleting files is
destructive, but exhausting the CPU destroys nothing, stopping the services a
machine exists to run destroys nothing, and mining someone else's coin on
your hardware destroys nothing - and all three are attacks. A family called
"destructive" would have had no home for them.

What unites them is that the operator's machine is the target rather than the
route to somewhere else.

## The calibration problem is the neighbourhood, not the payload

None of these commands is rare in a PKGBUILD. `rm -rf` is *normal*: nearly
every recipe clears `$srcdir` or prunes `$pkgdir` before packaging. A rule on
`rm -rf` would fire on a large fraction of the corpus and have to be weighted
into uselessness, which is the same trap [H035](install-and-persist.md#h035)
avoids by staying out of build functions.

So every rule here is written against a distinction rather than a command:

- **The build sandbox is not the system.** `rm -rf "$srcdir/build"` is
  housekeeping; `rm -rf /` is an attack. Any line naming `$srcdir`,
  `$pkgdir`, `$builddir` or `$startdir` is exempt.
- **A mention is not an invocation.** `echo "never run rm -rf / on your box"`
  is a recipe being helpful. Every command name is anchored to command
  position, so a name inside a string, an array element or a comment does not
  fire.
- **A package's own service is not the system's.** Stopping a daemon before
  replacing its binary is standard packaging. Only *system* services count.

Against the v1 locked benign corpus, every rule in this family fires
on **zero** diffs. That is not a target that was aimed for; it is what the
distinctions above produce, and it is the reason these can carry CRITICAL and
HIGH weights without spending fire-rate budget the rest of the ruleset needs.

---
