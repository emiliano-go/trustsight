# Install and Persistence

Something survives the build. Install hooks run as root at install time,
which makes them the highest-privilege code a PKGBUILD carries (R007, R062,
R068, R081), and units, pacman hooks and setuid bits keep running long
after makepkg exits (R053, R054, R059, R085, R114, R139).

R017 and R053/R059 split the same operation by target: a setuid bit inside
`$pkgdir` is Electron packaging, the same bit on an absolute path is a
privilege change to the build host. R052 and R077 cover the user-profile
form, where the persistence is a dotfile rather than a unit.

See [the rule system reference](system.md) for the field table, the
severity weights and the reserved identifier ranges.

---

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
- **Pattern:** `\bchmod\s+(?:-\S+\s+)*(?:[2467][0-7]{3}\b|[ugoa]*\+s\b)\s+(?!["\x27]?/)`
- **Description:** Setuid or setgid applied to a path being staged into the package. Detects both octal (`4755`, `2755`) and symbolic (`u+s`) forms; ordinary modes such as `644`, `755` and `+x` do not match. Chromium's sandbox helper legitimately requires `4755`, so this fires on essentially every Electron package. Measured across the benign corpus, MEDIUM changes **no** package's risk band; the evidence stays visible in the tiered breakdown without reclassifying routine updates. At HIGH it would have reclassified every Electron package as Medium.

### R059: Setuid Or Setgid Bit Set Outside Package Root {#r059}

- **Target:** `raw_line`
- **Severity:** HIGH (weight 25)
- **Category:** `privilege`
- **Pattern:** `\bchmod\s+(?:-\S+\s+)*(?:[2467][0-7]{3}\b|[ugoa]*\+s\b)\s+["\x27]?/`
- **Description:** The same operation against an absolute path. This touches the live filesystem rather than `$pkgdir`, so it is a privilege change on the build host and not packaging. Split from R053 because the two are materially different: `chmod u+s "$pkgdir/opt/x/chrome-sandbox"` is ordinary Electron packaging, while `chmod u+s "/usr/bin/helper"` is not.

### R054: Persistence Unit Outside Package Root {#r054}

- **Target:** `raw_line`
- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Pattern:** `(?:[\s"\x27]|\$\{?pkgdir\}?)(?:/etc/(?:cron\.[a-z]+|cron\.d|systemd/system)|/usr/lib/systemd/system|/var/spool/cron)/`
- **Description:** Detects a cron job or systemd unit written to a system path. A unit staged into `$pkgdir` is flagged too, in any quoting style (`"${pkgdir}"/usr/lib/...`, `"${pkgdir}/usr/lib/..."`, `$pkgdir/usr/lib/...`): pacman installs what the recipe staged, so all three produce the same persistent root-level unit. Writing to the live filesystem during a build is the worse case of the same finding.

### R062: Install Hook Fetches Or Executes {#r062}

- **Target:** programmatic (defined in `src/trustsight/analysis/build.py`)
- **Severity:** HIGH (weight 25)
- **Category:** `installer`
- **Description:** A `.install` hook body (`post_install`, `post_upgrade`, `pre_install`, `pre_upgrade`, `pre_remove`, `post_remove`) downloads something or performs a privileged operation: `chmod u+s`, `systemctl enable`, `eval`, `useradd`.

Hooks run **as root at install time**, which makes them the highest-privilege code a PKGBUILD carries. `generate_diff()` already includes `*.install` patches, and `_classify_enclosing_function()` recognises `post_install()` exactly as it recognises `build()`, so no separate parser is involved.

Comments are stripped before matching: one of the corpus hits was the line `# systemctl enable input-remapper`.

Overlaps [R007](install-and-persist.md#r007), which matches any line mentioning `.install` at MEDIUM. R007 is left as it is because it is calibrated and in the baseline; R062 is the narrow, higher-severity companion.

### R068: Install Hook Present {#r068}

- **Target:** programmatic (diff-aware)
- **Severity:** INFO (weight 0)
- **Category:** `context`
- **Condition:** The PKGBUILD declares an `install=` file, or the diff touches
  a `*.install` file.

An `.install` scriptlet runs code **as root** at install time. R068 is pure
context - "this package has a root-time hook" - not an accusation. It is the
metadata a human wants when weighing other signals.

**Origin:** mirrors pnpm's `allowBuilds`/`strictDepBuilds` - every package
manager that distinguishes "declares a privileged post-install step" from
"does not" treats that distinction as primary metadata. pnpm blocks all build
scripts by default; R068 is the review-side equivalent - flagging `.install`
hooks so a human can weigh them.

**Overlap guard:** R007 already fires on *install added*. R068 fires on
*install present* (existing or added). If R007 fires, R068 is redundant for
that diff; the two must not both surface as separate findings for the same
event.

### R081: Foreign Package Manager In Install Hook {#r081}

- **Target:** programmatic (resolved install hook lines, position-scoped)
- **Severity:** HIGH (weight 25)
- **Category:** `installer`
- **Condition:** An added line inside an install hook body (`post_install`, `post_upgrade`, `pre_install`, `pre_upgrade`, `pre_remove`, `post_remove`) invokes a foreign package manager: `pip install`, `npm install`, `cargo install`, `gem install`, `go install`, `dnf install`, `yum install`, `apt-get install`, `pacman -S`/`-U`, or `make install` without `DESTDIR`.

Install hooks run as root at install time. Invoking another package manager
from inside an AUR package's install hook modifies system state outside pacman's
control, creating untracked dependencies and potential conflicts.

Kernel modules (`dkms`), initramfs rebuilds, and service restarts are the
expected scope of an install hook; foreign package managers are not.

### R077: Write To User Home Or RC {#r077}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** A build or install function writes into `$HOME`, `.bashrc`, `.zshrc`, `.profile` or `.config`, outside `$pkgdir` staging.

Fire rate: 1 of 3246 (0.03 %), a legitimate log path written from `post_upgrade`.

The severity is contextual. A write into a user's home during `build()` is
HIGH; the same write from an **install scriptlet** is CRITICAL, because pacman
runs scriptlets as root during the transaction. Nothing a package installs
belongs in somebody's home directory, and root reaching into one is
categorical rather than suspicious.

### R085: Systemd ExecStart From Runtime-Writable Path {#r085}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** A systemd unit the package installs has an `ExecStart` pointing into a runtime-writable path (`/tmp`, `/var/tmp`, `/dev/shm`, `$HOME`, `/run`).

The rule reads the unit's *content*, including a heredoc body, not the unit's
filename. A name proves nothing; the `ExecStart` line is the fact.

Fire rate: 0 of 3246.

### R114: Pacman Hook Installed {#r114}

- **Severity:** MEDIUM (weight 15)
- **Category:** `persistence`
- **Condition:** A file is placed under `/usr/share/libalpm/hooks/`.

A pacman hook runs on every later transaction, which is why it is reported;
packages legitimately ship them, which is why it is MEDIUM.

Fire rate: 4 of 3246 (0.12 %), all packages that legitimately ship hooks.

### R139: Service ExecStart Targets Undeclared Binary {#r139}

- **Severity:** HIGH (weight 25)
- **Category:** `persistence`
- **Condition:** A systemd service unit's `ExecStart` points at an absolute path, and the recipe installs an executable to that path whose source is neither declared in `source=()` nor present in the repository manifest.

Service units are read from the tree manifest when one is supplied, and from
added diff lines otherwise (a whole service file in the diff, parsed by
heuristic). The installed executable must come from an `install` with an
explicit `7xx` mode or no `-m` flag (install's default is 755). Such files
arrive through the unseen source tarball, so their content cannot be audited.
Detected by `_service_binary_findings()` in `src/trustsight/analysis/delivery.py`.
