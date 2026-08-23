# Install and Persistence

Something survives the build. Install hooks run as root at install time,
which makes them the highest-privilege code a PKGBUILD carries (R007, H017,
H023, H035), and units, pacman hooks and setuid bits keep running long
after makepkg exits (R053, R054, R059, H039, H062, H084).

R017 and R053/R059 split the same operation by target: a setuid bit inside
`$pkgdir` is Electron packaging, the same bit on an absolute path is a
privilege change to the build host. R052 and H032 cover the user-profile
form, where the persistence is a dotfile rather than a unit.

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [H017](#h017) | Install Hook Fetches Or Executes | HIGH |
| [H023](#h023) | Install Hook Present | INFO |
| [H032](#h032) | Write To User Home Or RC | HIGH |
| [H035](#h035) | Foreign Package Manager In Install Hook | HIGH |
| [H039](#h039) | Systemd ExecStart From Runtime-Writable Path | HIGH |
| [H062](#h062) | Pacman Hook Installed | MEDIUM |
| [H084](#h084) | Service ExecStart Targets Undeclared Binary | HIGH |
| [H089](#h089) | Packaged File Names A Build-Only Path | HIGH |
| [H093](#h093) | Committed Config Points At A Build-Only Path | HIGH |
| [H095](#h095) | Boot Or Image Artifact Built From The Source Tree | HIGH |
| [R007](#r007) | Install File Modification | MEDIUM |
| [R017](#r017) | Setuid/Setgid Permission | HIGH |
| [R052](#r052) | Dotfile Written To User Profile | HIGH |
| [R053](#r053) | Setuid Or Setgid Bit Set In Package Root | MEDIUM |
| [R054](#r054) | Persistence Unit Outside Package Root | HIGH |
| [R059](#r059) | Setuid Or Setgid Bit Set Outside Package Root | HIGH |
| [R144](#r144) | Packaged File Points At A World-Writable Path | HIGH |
<!-- /generated: page-index -->

### R007: Install File Modification {#r007}

- **Target:** `raw_line`
- **Severity:** MEDIUM (weight 15)
- **Category:** `installer`
- **Pattern:** `^\+.*\.install`
- **Scope:** All lines (no function-body restriction)
- **Description:** Fires when a `.install` file is added or modified in the diff. Install scripts run with root privileges and are a common vector for persistent backdoors.
- **Note:** The pattern was `\+.*\.install.*` before 0.13.2. The anchored form bounds the search to an added diff line and matches the same intended file paths. `trustsight config sync-rules --update` replaces the superseded pattern in an unmodified local rule file.

### R017: Setuid/Setgid Permission {#r017}

- **Target:** `raw_line`
- **Severity:** HIGH (weight 25)
- **Category:** `privilege`
- **Pattern:** `chmod.*\+s`
- **Description:** Detects symbolic `chmod ... +s` commands that set a setuid or setgid bit. A setuid binary runs with its owner's privileges, the shape of many local-privilege-escalation backdoors. R053 and R059 own the target-specific symbolic and octal forms, so R017 defers to them rather than scoring one command twice.

### R052: Dotfile Written To User Profile {#r052}

- **Target:** `raw_line`
- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Pattern:** `\b(?:install|cp|mv|tee)\s+[^;&|]*(?:\$HOME|~|/root|/home/[^/\s]+)/\.\w+`
- **Description:** Detects writes to a dotfile under `$HOME`, `~`, `/root`, or `/home/<user>`, the shape of shell-profile persistence. Dotfiles written inside `$pkgdir` (such as `/etc/skel` templates) are ordinary packaging and do not match.

### R053: Setuid Or Setgid Bit Set In Package Root {#r053}

- **Target:** `raw_line`
- **Severity:** MEDIUM (weight 15)
- **Category:** `privilege`
- **Pattern:** `\bchmod\s+(?:-\S+\s+)*(?:(?:--mode=)?(?:[2467][0-7]{3}\b|[ugoa]*\+s\b))(?:\s+--\s+(?!["\x27]?/)|\s+(?!--\s)(?!["\x27]?/))|\bsetcap\s+(?:-\S+\s+)*["\x27]?cap_\w+[^\s]*\s+(?!["\x27]?/)`
- **Description:** Setuid or setgid applied to a path being staged into the package. Detects both octal (`4755`, `2755`) and symbolic (`u+s`) forms; ordinary modes such as `644`, `755` and `+x` do not match. Chromium's sandbox helper legitimately requires `4755`, so this fires on essentially every Electron package. Measured across the benign corpus, MEDIUM changes **no** package's risk band; the evidence stays visible in the tiered breakdown without reclassifying routine updates. At HIGH it would have reclassified every Electron package as Medium.

### R059: Setuid Or Setgid Bit Set Outside Package Root {#r059}

- **Target:** `raw_line`
- **Severity:** HIGH (weight 25)
- **Category:** `privilege`
- **Pattern:** `\bchmod\s+(?:-\S+\s+)*(?:(?:--mode=)?(?:[2467][0-7]{3}\b|[ugoa]*\+s\b))(?:\s+--\s+["\x27]?/|\s+(?!--\s)["\x27]?/)|\bsetcap\s+(?:-\S+\s+)*["\x27]?cap_\w+[^\s]*\s+["\x27]?/`
- **Description:** The same operation against an absolute path. This touches the live filesystem rather than `$pkgdir`, so it is a privilege change on the build host and not packaging. Split from R053 because the two are materially different: `chmod u+s "$pkgdir/opt/x/chrome-sandbox"` is ordinary Electron packaging, while `chmod u+s "/usr/bin/helper"` is not.

### R054: Persistence Unit Outside Package Root {#r054}

- **Target:** `raw_line`
- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Pattern:** `(?:\b(?:install|cp|mv|ln|tee|dd|rsync|mkdir|cat|printf|echo)\b|>)[^;&|\n]*?(?:[\s"\x27]|\$\{?pkgdir\}?)(?:(?:/etc/(?:cron\.[a-z]+|cron\.d|systemd/(?:system|user)|profile\.d|bash\.bashrc\.d|zsh(?:/zshrc\.d|rc\.d)|X11/(?:Xsession|xinit/xinitrc)\.d|xdg/autostart|dbus-1/(?:system|session)\.d|sudoers\.d|ld\.so\.conf\.d|pam\.d|security/pam_\w+\.conf|NetworkManager/dispatcher\.d|xinetd\.d|(?:init|rc)\.d|logrotate\.d|tmpfiles\.d|sysusers\.d|binfmt\.d|sysctl\.d|environment\.d|polkit-1/(?:rules|actions)\.d|polkit-1/(?:rules|actions)|skel|update-motd\.d|systemd/(?:system|user)-preset)|/usr/lib/systemd/(?:system|user)|/usr/lib/systemd/(?:system|user)-(?:generators|sleep|shutdown)|/usr/share/dbus-1/(?:system|session)-services|/var/spool/cron)/|(?:/etc/(?:rc\.local|profile|bash\.bashrc|ld\.so\.preload|environment|csh\.cshrc|zsh/(?:zshrc|zprofile|zshenv)|X11/xinit/xinitrc|X11/Xsession))(?![\w./-]))`
- **Description:** Detects a cron job or systemd unit written to a system path. A unit staged into `$pkgdir` is flagged too, in any quoting style (`"${pkgdir}"/usr/lib/...`, `"${pkgdir}/usr/lib/..."`, `$pkgdir/usr/lib/...`): pacman installs what the recipe staged, so all three produce the same persistent root-level unit. Writing to the live filesystem during a build is the worse case of the same finding.

### H017: Install Hook Fetches Or Executes {#h017}

- **Target:** programmatic (defined in `src/trustsight/analysis/build.py`)
- **Severity:** HIGH (weight 25)
- **Category:** `installer`
- **Description:** A `.install` hook body (`post_install`, `post_upgrade`, `pre_install`, `pre_upgrade`, `pre_remove`, `post_remove`) downloads something or performs a privileged operation: `chmod u+s`, `systemctl enable`, `eval`, `useradd`.

Hooks run **as root at install time**, which makes them the highest-privilege code a PKGBUILD carries. `generate_diff()` already includes `*.install` patches, and `_classify_enclosing_function()` recognises `post_install()` exactly as it recognises `build()`, so no separate parser is involved.

Comments are stripped before matching: one of the corpus hits was the line `# systemctl enable input-remapper`.

Overlaps [R007](install-and-persist.md#r007), which matches any line mentioning `.install` at MEDIUM. R007 is left as it is because it is calibrated and in the baseline; H017 is the narrow, higher-severity companion.

### H023: Install Hook Present {#h023}

- **Target:** programmatic (diff-aware)
- **Severity:** INFO (weight 0)
- **Category:** `context`
- **Condition:** The PKGBUILD declares an `install=` file, or the diff touches
  a `*.install` file.

An `.install` scriptlet runs code **as root** at install time. H023 is pure
context - "this package has a root-time hook" - not an accusation. It is the
metadata a human wants when weighing other signals.

**Origin:** mirrors pnpm's `allowBuilds`/`strictDepBuilds` - every package
manager that distinguishes "declares a privileged post-install step" from
"does not" treats that distinction as primary metadata. pnpm blocks all build
scripts by default; H023 is the review-side equivalent - flagging `.install`
hooks so a human can weigh them.

**Overlap guard:** R007 already fires on *install added*. H023 fires on
*install present* (existing or added). If R007 fires, H023 is redundant for
that diff; the two must not both surface as separate findings for the same
event.

### H035: Foreign Package Manager In Install Hook {#h035}

- **Target:** programmatic (resolved install hook lines, position-scoped)
- **Severity:** HIGH (weight 25)
- **Category:** `installer`
- **Condition:** An added line inside an install hook body (`post_install`, `post_upgrade`, `pre_install`, `pre_upgrade`, `pre_remove`, `post_remove`) invokes a foreign package manager: `pip install`, `npm install`, `cargo install`, `gem install`, `go install`, `dnf install`, `yum install`, `apt-get install`, `pacman -S`/`-U`, or `make install` without `DESTDIR`.

Install hooks run as root at install time. Invoking another package manager
from inside an AUR package's install hook modifies system state outside pacman's
control, creating untracked dependencies and potential conflicts.

Kernel modules (`dkms`), initramfs rebuilds, and service restarts are the
expected scope of an install hook; foreign package managers are not.

### H032: Write To User Home Or RC {#h032}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** A build or install function writes into `$HOME`, `.bashrc`, `.zshrc`, `.profile` or `.config`, outside `$pkgdir` staging.

Fire rate: 1 of 3246 (0.03 %), a legitimate log path written from `post_upgrade`.

The severity is contextual. A write into a user's home during `build()` is
HIGH; the same write from an **install scriptlet** is CRITICAL, because pacman
runs scriptlets as root during the transaction. Nothing a package installs
belongs in somebody's home directory, and root reaching into one is
categorical rather than suspicious.

### H039: Systemd ExecStart From Runtime-Writable Path {#h039}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** A systemd unit the package installs has an `ExecStart` pointing into a runtime-writable path (`/tmp`, `/var/tmp`, `/dev/shm`, `$HOME`, `/run`).

The rule reads the unit's *content*, including a heredoc body, not the unit's
filename. A name proves nothing; the `ExecStart` line is the fact.

Fire rate: 0 of 3246.

### H062: Pacman Hook Installed {#h062}

- **Severity:** MEDIUM (weight 15)
- **Category:** `persistence`
- **Condition:** A file is placed under `/usr/share/libalpm/hooks/`.

A pacman hook runs on every later transaction, which is why it is reported;
packages legitimately ship them, which is why it is MEDIUM.

Fire rate: 4 of 3246 (0.12 %), all packages that legitimately ship hooks.

### H084: Service ExecStart Targets Undeclared Binary {#h084}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** A systemd service unit's `ExecStart` points at an absolute path, and the recipe installs an executable to that path whose source is neither declared in `source=()` nor present in the repository manifest.

Service units are read from the tree manifest when one is supplied, and from
added diff lines otherwise (a whole service file in the diff, parsed by
heuristic). The installed executable must come from an `install` with an
explicit `7xx` mode or no `-m` flag (install's default is 755). Such files
arrive through the unseen source tarball, so their content cannot be audited.
Detected by `_service_binary_findings()` in `src/trustsight/analysis/delivery.py`.

### R144: Packaged File Points At A World-Writable Path {#r144}

- **Target:** `raw_line`
- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Pattern:** `^\+?(?=[^\n]*\$\{?pkgdir\}?)(?=[^\n]*(?:/tmp/|/var/tmp/|/dev/shm/))\S`
- **Condition:** A line that both references `$pkgdir` and names a path under `/tmp`, `/var/tmp` or `/dev/shm`.
- **Description:** A file staged into the package root names a program under a world-writable directory. Anyone can replace the target after the package is built, so the installed path is not under the packager's control.

A file staged into the package root that names a program under a
world-writable directory. Those directories are writable by everyone, so
whatever the config names can be replaced by any local user between the
package being installed and the config being read - and the config is read
as root for a unit, a PAM line or a cron entry.

It is both halves at once: an attacker who ships this is arranging for their
own planted file to run, and a maintainer who ships it by accident has handed
the same lever to anyone with a shell on the machine. The target is never in
the diff, which is why every rule that looks for a payload found nothing
here - the observable is the *destination*, not the code.

Order-free, because the recipe may write the config and then name the path or
the reverse, and anchored at `^` so each lookahead runs once. Zero
occurrences in the 3,246-diff benign corpus: a package pointing its own
config at `/tmp` is not something the ecosystem does.

### H089: Packaged File Names A Build-Only Path {#h089}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** Content written into `$pkgdir` - a heredoc body or a
  `printf`/`echo`/`tee`/`cat` redirect - that names `$srcdir`,
  `$startdir`, `$PWD`, `$BUILDDIR` or `$pkgdir`.

The audit's largest silent family is a configuration file the recipe
*generates* into the package root whose exec slot names a script: an i3
`bindsym … exec`, a polybar `exec =`, a udev `RUN+=`, an acme `RELOADCMD=`,
a mutt `macro … !bash`. Every rule that looks for execution reads the
recipe's own commands, and none of these lines is a command the recipe
runs - they are text, and what runs them is the user's session, later, on a
different machine.

What separates them from the ordinary case is not the exec slot, which is
what those files are *for*: a `.desktop` with `Exec=/usr/bin/p` and a
`bindsym $mod+d exec dmenu_run` are exactly right, and both stay silent. It
is *which path* the slot names. `$srcdir`, `$startdir`, `$PWD` and
`$BUILDDIR` exist only while the package is being built, in a directory
pacman never ships and the user does not have. A shipped file naming one is
either broken on arrival - it points at nothing - or it is aimed at a
directory whoever wrote it expects to control at the moment it is read.

Neither reading is packaging. The rule is about the *pairing* of a write
into `$pkgdir` with content naming a build-only path, which is why it is not
a line pattern: `install -Dm755 "$srcdir/x" "$pkgdir/usr/bin/x"` names both
on one line and is the single most common line in the ecosystem. There
`$srcdir` is an argument to a copy; here it is inside the bytes being
written. The rule splits a single-line write at its redirect and reads only
the content half, and for a heredoc it reads the body against the target
named on the opener.

Zero occurrences in the 3,246-diff benign corpus.

### H093: Committed Config Points At A Build-Only Path {#h093}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** A committed `.service`, `.desktop`, `.rules`, `.conf` (and
  the rest of the carrier set H090 reads) holding a directive that runs
  something, whose value names `$srcdir`, `$startdir`, `$PWD`, `$BUILDDIR`
  or `$pkgdir`.

The symmetric half of [H089](#h089). That rule reads content the recipe
*generates* into `$pkgdir`; this one reads content the recipe *committed*
and then ships. The observable is identical and so is the reasoning: those
directories exist only while the package is being built, so a shipped file
naming one is either broken on arrival or aimed at a directory whoever wrote
it expects to control when it is read.

The value has to sit in a directive that runs something. A `.desktop` whose
`Comment=` mentions a build path is a cosmetic mistake; an `Exec=` naming one
is a command pointed at nothing.

**How the directive is recognised.** The rule does not carry a list of
exec-bearing keys. A shipped file that names a build directory is broken on
arrival whatever field holds the path, so the test is inverted: fields that
only *describe* are excluded, and those are few and stable - `Comment`,
`Description`, `Name`, `Icon`, `URL`, `X-*`, and comment lines. A `.desktop`
whose `Comment=` mentions the build tree is untidy; an `Exec=` naming one is
a command aimed at nothing.

The path, not the file extension, is the observable.
`ExecStart=/usr/share/p/launcher.sh` names a script the package itself
ships, and stays quiet.

**Carriers** include build manifests (`build.ninja`, `Makefile`,
`BUILD.bazel`, `*.mk`) for the same reason they include unit files: the
engine runs what they say. `make` spells its variables `$(srcdir)` with
parentheses, so an ordinary Makefile does not look like a build-only path.

Measured across all thirty audited verticals in their committed form: thirty
fire. Measured across 249 committed files in 81 real AUR repositories: none
does.

### H095: Boot Or Image Artifact Built From The Source Tree {#h095}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** `dracut`, `mkinitcpio`, `update-initramfs`,
  `grub-mkconfig`, `grub-install`, `guestfish`, `virt-customize` or
  `bootctl` invoked with an argument naming `$srcdir`, `$startdir`, `$PWD`
  or `$pkgdir`.

`dracut --include "$srcdir/x" /x` injects a path from the build tree into
the initramfs, which runs before userspace exists and before any filesystem
the user can inspect is mounted. `grub-mkconfig` writes the boot menu.
`guestfish` and `virt-customize` edit a disk image's contents.

A package may legitimately ship kernel modules or a bootloader, and those
are `install`ed like any other file. *Generating* boot material during a
build is different: the result captures the builder's machine, and any path
from the source tree that goes into it is code that will run at the earliest
moment there is.

The build-only path is the observable, as it is for [H089](#h089) and
[H093](#h093). A bare relative filename establishes no provenance - if it is
declared or committed, H090 and H093 read it; if it is neither, it is the
[W001](unverifiable.md#w001) boundary.

None of these tools appear in the benign corpus with a build-tree argument.
