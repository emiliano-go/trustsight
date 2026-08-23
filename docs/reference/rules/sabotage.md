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

Against the 3,246-diff locked benign corpus, every rule in this family fires
on **zero** diffs. That is not a target that was aimed for; it is what the
distinctions above produce, and it is the reason these can carry CRITICAL and
HIGH weights without spending fire-rate budget the rest of the ruleset needs.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [S001](#s001) | Recursive Self-Spawn | CRITICAL |
| [S002](#s002) | Recursive Deletion Outside The Build Tree | CRITICAL |
| [S003](#s003) | Raw Block Device Write | CRITICAL |
| [S004](#s004) | Secure Deletion Of User Data | HIGH |
| [S005](#s005) | Permission Change On A System Path | HIGH |
| [S006](#s006) | System Service Disruption | HIGH |
| [S007](#s007) | Cryptocurrency Miner | HIGH |
| [S008](#s008) | Shell History Or Log Destruction | MEDIUM |
<!-- /generated: page-index -->

### S001: Recursive Self-Spawn {#s001}

- **Severity:** CRITICAL (weight 40)
- **Category:** `sabotage`
- **Condition:** A function whose body pipes itself into itself and backgrounds the result, or an unbounded loop that backgrounds work.

The classic `:(){ :|:& };:` and its named variants. Detected structurally
rather than by literal: the pattern is a back-reference, so `bomb() { bomb |
bomb & }; bomb` matches for the same reason the `:` form does, and renaming
the function buys nothing.

`while true; do work & done` is the same attack written as a loop, and is
included. A loop that does *not* background its body is ordinary iteration
and does not fire.

### S002: Recursive Deletion Outside The Build Tree {#s002}

- **Severity:** CRITICAL (weight 40)
- **Category:** `sabotage`
- **Condition:** `rm -rf` (in either flag order) whose target is a system path or the operator's home, on a line that names no build-sandbox variable.

The conjunction is the rule. `rm -rf` alone is housekeeping; a target of `/`,
`/*`, `/etc`, `/usr`, `/var`, `/boot`, `/home`, `/root`, `~` or `$HOME` is
not. A line mentioning `$srcdir` or `$pkgdir` is exempt outright, because a
recursive delete inside the build tree is what makepkg expects.

`--no-preserve-root` is matched but not required: its absence does not make
`rm -rf /` safe, it makes it noisier.

### S003: Raw Block Device Write {#s003}

- **Severity:** CRITICAL (weight 40)
- **Category:** `sabotage`
- **Condition:** `dd of=`, `mkfs`, `wipefs`, `blkdiscard`, `sgdisk`, `fdisk`, `parted` or `shred` targeting a block device, or `dd of=/dev/mem`.

Nothing a package build legitimately does writes to `/dev/sda`. `dd` writing
to a *file* is ordinary (generating test data, padding an image) and does not
fire; only a device target does.

### S004: Secure Deletion Of User Data {#s004}

- **Severity:** HIGH (weight 25)
- **Category:** `sabotage`
- **Condition:** `shred`, `srm` or `wipe` targeting the operator's home, `/home/`, or a credential directory (`.ssh`, `.gnupg`, `.aws`, `.config`, `.local`), on a line naming no sandbox variable.

Separated from S002 because unrecoverable deletion is a different claim from
deletion: `rm` leaves data recoverable in principle and `shred` does not, so
the response differs even though the intent looks the same.

### S005: Permission Change On A System Path {#s005}

- **Severity:** HIGH (weight 25)
- **Category:** `sabotage`
- **Condition:** `chmod 777` on a system path or the operator's home, or `chown` of a system path, outside the build sandbox.

World-writable system directories are a privilege-escalation primitive left
behind for later rather than an attack that completes now, which is why this
is HIGH rather than CRITICAL. `chmod 777 "$pkgdir/var/run"` is sloppy
packaging, not this rule's business.

### S006: System Service Disruption {#s006}

- **Severity:** HIGH (weight 25)
- **Category:** `sabotage`
- **Condition:** `systemctl stop`/`disable`/`mask` of a **system** unit, `systemctl isolate`/`poweroff`/`reboot`/`halt`, `killall`/`pkill` of a system daemon, `ufw disable`, `firewall-cmd --panic-off`, or `setenforce 0`.

The unit list is the whole precision of this rule. A package stopping or
disabling **its own** service is standard packaging - you stop a daemon before
replacing its binary and disable it on removal - and four diffs in the locked
benign corpus do exactly that (`systemctl disable input-remapper`,
`systemctl disable --now mullvad-daemon`). Without the list, a rule on the
verbs alone flags every one of them.

Disrupting somebody else's service is a different act, so the rule names the
ones that keep a machine reachable, logged and firewalled: `sshd`,
`systemd-*`, `NetworkManager`, `firewalld`, `iptables`, `nftables`, `ufw`,
`auditd`, `rsyslog`, `apparmor`, `selinux`, `fail2ban`, `dbus`, `polkit`.

`systemctl enable` is deliberately absent: that is persistence, and
[H035](install-and-persist.md#h035) and H017 already claim it. `isolate` and
the power verbs are included whatever the target, because nothing a package
build legitimately does reboots the machine.

### S007: Cryptocurrency Miner {#s007}

- **Severity:** HIGH (weight 25)
- **Category:** `sabotage`
- **Condition:** A known miner binary in command position, a `stratum+tcp://` or `stratum+ssl://` URL, `--donate-level`, or a known mining-pool hostname.

Resource theft rather than damage, and the reason the family is called
sabotage: nothing is destroyed, the machine is simply working for someone
else. The pool URL and `--donate-level` are matched anywhere on the line
rather than in command position, because writing a pool URL into a config
file is how a miner is installed, not how one is mentioned.

### S008: Shell History Or Log Destruction {#s008}

- **Severity:** MEDIUM (weight 15)
- **Category:** `sabotage`
- **Condition:** `history -c`, deletion or truncation of a shell history file, `unset HISTFILE`, `set +o history`, `journalctl --vacuum-*`, or truncation of `/var/log/`.

Anti-forensics, and MEDIUM because on its own it is weak evidence: a
misguided recipe might clear history for tidiness. Its value is compositional
- erasing the record of what ran is a strong signal *beside* something that
ran, and H027 counts capability spread across families.
