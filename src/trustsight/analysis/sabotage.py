"""Sabotage: payloads that wreck, exhaust or steal rather than exfiltrate.

Every other rule family here describes a *supply-chain* compromise - code
fetched from somewhere, credentials sent somewhere, persistence installed,
a maintainer taken over. All of them share an assumption: the attacker wants
something out of your machine, so there is a fetch or an egress to notice.

A sabotage payload wants nothing out. It runs, and the machine is worse
off. It phones nobody, persists nothing, and obfuscates little, because it
does not need to survive being noticed - by the time you notice, it is done.
So the entire detection surface is the command itself, and before this module
existed a fork bomb in ``build()`` scored exactly zero.

**Sabotage, not destruction**, and the difference sets the scope. Deleting
files is disruptive; so is exhausting the CPU, so is stopping the services the
machine is there to run, so is mining somebody else's coin on your hardware.
None of those destroy anything in the second and third cases, and a family
called "destructive" would have had no home for them.

The calibration problem in this family is not the payload, it is the
neighbourhood. ``rm -rf`` is *normal* in a PKGBUILD - every other recipe
clears ``$srcdir`` or prunes ``$pkgdir`` before packaging - so a rule on
``rm -rf`` would fire on a large fraction of the corpus and have to be
weighted into uselessness. What is not normal is ``rm -rf`` pointed
**outside the build tree**. Every rule here is written against that
distinction: the dangerous form is the one whose target is the operator's
system rather than the package's own scratch space.
"""

from __future__ import annotations

import re

from ..deps import _strip_comment
from .base import _CMD
from ..tokenizer import join_line_continuations, resolve_added_lines
from ..rules import clamp_text

# ---------------------------------------------------------------------------
# The build sandbox.  makepkg gives a recipe these to work in, and touching
# them is the ordinary case every rule below has to stay away from.
# ---------------------------------------------------------------------------

_SANDBOX_VARS = (
    r"\$\{?srcdir\}?", r"\$\{?pkgdir\}?", r"\$\{?builddir\}?",
    r"\$\{?startdir\}?", r"\$\{?_builddir\}?", r"\$\{?BUILDDIR\}?",
)
_SANDBOX_RE = re.compile("|".join(_SANDBOX_VARS), re.IGNORECASE)

#: Absolute paths whose recursive removal is an attack on the operator, not
#: on a build tree.  ``/`` and ``/*`` are the headline; the rest are the
#: places a slightly subtler payload goes instead.
_SYSTEM_PATHS = (
    r"/", r"/\*", r"/etc", r"/usr", r"/var", r"/boot", r"/home", r"/root",
    r"/opt", r"/srv", r"/bin", r"/sbin", r"/lib", r"/lib64", r"/proc", r"/sys",
)
_SYSTEM_PATH_ALT = "|".join(p + r"/?\*?" for p in _SYSTEM_PATHS)

#: ``$HOME`` and ``~`` are the operator's data wherever it lives.
_HOME_ALT = r"~|\$\{?HOME\}?|\$\{?XDG_[A-Z_]+\}?"

# A command name only counts in command position.  PKGBUILDs legitimately
# *mention* these: `echo "never run rm -rf / on your box"` is a warning, not
# an attack, and matching a name inside a string would fire on the recipe
# that is trying to be helpful.  Same anchoring idea as
# ``config.DEFAULT_PARSE_TIME_FETCH``, and the reason a quoted *argument*
# still matches: only the command's own position is constrained, so
# `rm -rf "$HOME"` is caught while `echo "rm -rf /"` is not.
#: A command position: the start of the subject, or just after a separator.
#: The trailing whitespace is *horizontal* on purpose. It used to be `\s*`,
#: which matches a newline, so on a subject holding many of them the engine
#: re-scanned a run of newlines from every position - 8192 of them cost 2.4s
#: in `_SHRED_HOME_RE` and 5.8s in `_HISTORY_WIPE_RE`, quadratic in the line
#: length. Nothing reaches that today, because every caller matches one line
#: at a time and a line holds no newline; it was a loaded gun in a prefix a
#: dozen rules share, and it stayed invisible until the probe alphabet
#: learned to include a newline. A command word follows spaces or tabs on
#: its own line, and the newline boundary is already the lookbehind's job.


# ---------------------------------------------------------------------------
# S001: recursive self-spawn.
# ---------------------------------------------------------------------------

# The classic `:(){ :|:& };:` and its named variants.  The shape is a
# function whose body pipes itself into itself and backgrounds the result,
# followed by a call to it.  Written as two halves because the definition and
# the invocation are usually on one line but need not be.
# The spans are bounded on purpose.  Two unbounded lazy `[^}]*?` runs plus a
# backreference is a catastrophic-backtracking shape, and A5's clamp still
# leaves 8 KiB of line to backtrack across: unbounded, this took 2.4 seconds
# on one hostile line and failed the `rule matching is bounded on hostile
# input` gate. A fork bomb's body is a dozen characters.
_FORK_BOMB_DEF_RE = re.compile(
    # Possessive: without it the engine retries all 32 name lengths at
    # every start position, which is 262k attempts across an 8 KiB line.
    # A name longer than 32 never matched anyway, so giving back the
    # characters buys nothing.
    # The spans between the pieces are unbounded. `{0,120}` was a bypass for
    # anyone willing to pad the body - `:(){ true; x40 :|:& };:` is the same
    # fork bomb and read as clean - and the bound was there for backtracking
    # safety, which a lookahead gives without a length. The assertions run
    # once; the spans that follow are possessive and never give ground.
    r"(?P<name>[:\w]{1,32}+)\s*\(\s*\)\s*\{"
    # Two ways to double, and the pipe is only one of them. `:|:` is the
    # classic, and `boom & boom &` is the same bomb written without a
    # pipeline - the essential property is that the body reaches its own
    # name more than once and backgrounds, not which operator joins the
    # calls. Requiring the pipe made the second spelling read as clean.
    #
    # Both alternatives are single lookaheads over `[^}]`, so neither
    # nests a quantifier inside a repeat.
    r"(?=[^}]*(?P=name)\s*\|\s*(?P=name)"
    # The first call may sit immediately after the brace, which the
    # separator class cannot match because the brace is already consumed.
    r"|\s*(?P=name)\b[^}]*[;&|]\s*(?P=name)\b"
    r"|[^}]*[;&|{]\s*(?P=name)\b[^}]*[;&|]\s*(?P=name)\b)"
    r"(?=[^}]*&)"
    r"[^}]*+\}",
)

# A loop whose body backgrounds work with no bound.  The bound is the
# condition, and `while`/`until` test opposite polarity, so a loop is
# unbounded when `while`'s condition is constantly true or `until`'s is
# constantly false.  Matching the condition spelling alone was a bypass: the
# harness enumerated `while [ 0 ]`, `while [ 0 = 0 ]`, `while [ -z '' ]`,
# `while [[ -n x ]]`, `while test 1 = 1` and their `until` mirrors, only
# `while true` fired, and `until false; do : & done` - the same bomb from the
# other side - read as clean.  The condition is evaluated instead.
_LOOP_SHAPE_RE = re.compile(
    r"\b(?P<kw>while|until|for)\b(?P<cond>.*?)\bdo\b(?P<body>[^\n]*?)\bdone\b",
    re.IGNORECASE,
)


def _test_truth(expr: str) -> bool | None:
    """Constant truth of a ``test`` expression, or None if it is not constant."""
    tokens = expr.split()
    if not tokens:
        return False
    if len(tokens) == 1:
        return bool(tokens[0].strip("\"'"))
    if len(tokens) == 2:
        op, value = tokens[0], tokens[1].strip("\"'")
        if op == "-z":
            return value == ""
        if op == "-n":
            return value != ""
        return None
    if len(tokens) == 3:
        left, op, right = (tokens[0].strip("\"'"), tokens[1],
                           tokens[2].strip("\"'"))
        if op in ("=", "=="):
            return left == right
        if op == "!=":
            return left != right
        if (op in ("-eq", "-ne", "-lt", "-gt", "-le", "-ge")
                and left.lstrip("-").isdigit() and right.lstrip("-").isdigit()):
            x, y = int(left), int(right)
            return {"-eq": x == y, "-ne": x != y, "-lt": x < y,
                    "-gt": x > y, "-le": x <= y, "-ge": x >= y}[op]
    return None


def _condition_truth(cond: str) -> bool | None:
    """Constant truth of a ``while``/``until`` condition, or None if unknown."""
    c = cond.strip().rstrip(";").strip()
    if not c or re.search(r"[$`]", c):
        return None                      # expansion: not a constant
    if c in (":", "true", "/bin/true", "1"):
        return True
    if c in ("false", "/bin/false", "0"):
        return False
    m = re.fullmatch(r"\(\(\s*(.*?)\s*\)\)", c)
    if m:
        return bool(int(m.group(1))) if re.fullmatch(r"\d+", m.group(1)) else None
    m = re.fullmatch(r"\[\[?\s*(.*?)\s*\]\]?", c)
    if m:
        return _test_truth(m.group(1))
    if c.startswith("test "):
        return _test_truth(c[5:])
    return None


def _unbounded_spawn(body: str) -> bool:
    """A loop or function that backgrounds work with no way to stop."""
    if _FORK_BOMB_DEF_RE.search(body):
        return True
    for match in _LOOP_SHAPE_RE.finditer(body):
        if "&" not in match.group("body"):
            continue                     # no backgrounding: ordinary iteration
        kw = match.group("kw").lower()
        cond = match.group("cond")
        if kw == "for":
            parts = re.fullmatch(r"\(\(\s*(.*?);\s*(.*?);\s*(.*?)\s*\)\)",
                                 cond.strip().rstrip(";").strip())
            if parts and not parts.group(2).strip():
                return True              # `for ((init; ; step))` - no bound
            continue                     # `for x in words` is bounded
        truth = _condition_truth(cond)
        if truth is not None and ((kw == "while" and truth)
                                  or (kw == "until" and not truth)):
            return True
    return False


# ---------------------------------------------------------------------------
# S002: recursive deletion outside the build tree.
# ---------------------------------------------------------------------------

# Recursive and forced, in any order and in either spelling.  The old form
# matched only a single combined token (`-rf`/`-fr`), so `rm -r -f`, `rm -f -r`
# and `rm --recursive --force` all read as clean while `rm -rf` fired.  The
# flag is a *set*, not a token: two lookaheads over the option span require an
# r/R flag and an f flag independently.  Long options are matched whole, so
# `--no-preserve-root` (which contains an `r`) is not mistaken for
# `--recursive`.
_OPT_RECURSIVE = r"(?:-[A-Za-z]*[rR][A-Za-z]*|--recursive)"
_OPT_FORCE = r"(?:-[A-Za-z]*f[A-Za-z]*|--force)"
_OPT_BOUND = r"(?=[ \t]|$|;|&|\|)"
_RM_RF_RE = re.compile(
    _CMD + r"rm\b"
    + r"(?=[^\n;&|]*?(?:^|[ \t])" + _OPT_RECURSIVE + _OPT_BOUND + r")"
    + r"(?=[^\n;&|]*?(?:^|[ \t])" + _OPT_FORCE + _OPT_BOUND + r")",
    re.MULTILINE,
)
# `rm -r` deletes recursively whether or not `-f` is given, so the rule keys
# on the recursive flag alone; the force set `_RM_RF_RE` above stays as the
# FN3 helper.  Requiring both read `rm -r /etc/cron.d` as clean.
_RM_RECURSIVE_RE = re.compile(
    _CMD + r"rm\b"
    + r"(?=[^\n;&|]*?(?:^|[ \t])" + _OPT_RECURSIVE + _OPT_BOUND + r")",
    re.MULTILINE,
)
# `find` reaches the same recursive delete without `rm`.
_FIND_DELETE_RE = re.compile(
    _CMD + r"find\b[^\n;&|]*?(?:-delete\b|-exec\s+rm\b)", re.MULTILINE)
_RM_TARGET_SYSTEM_RE = re.compile(
    # Unbounded for the same reason: 201 characters of flags between `rm`
    # and its target used to be enough to walk past this, and the target is
    # what the rule is about.
    _CMD + r"rm\s[^\n;&|]*?\s(?:--no-preserve-root\s+)?"
    r"[\"']?(?:" + _SYSTEM_PATH_ALT + r"|" + _HOME_ALT + r")[\"']?(?:\s|$|;|&)",
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# S003: raw block device write.
# ---------------------------------------------------------------------------

_BLOCK_DEVICE = r"/dev/(?:sd[a-z]|nvme\d+n\d+|vd[a-z]|hd[a-z]|mmcblk\d+|loop\d+|md\d+|dm-\d+)"
_BLOCK_WRITE_RE = re.compile(
    _CMD + r"dd\b[^\n]*?\bof\s*=\s*[\"']?" + _BLOCK_DEVICE + r"|"
    + _CMD + r"mkfs(?:\.\w+)?\s+[^\n]*?" + _BLOCK_DEVICE + r"|"
    + _CMD + r"(?:wipefs|blkdiscard|sgdisk|fdisk|parted)\s+[^\n]*?" + _BLOCK_DEVICE + r"|"
    + _CMD + r"shred\s+[^\n]*?" + _BLOCK_DEVICE + r"|"
    + _CMD + r"dd\b[^\n]*?\bof\s*=\s*[\"']?/dev/(?:mem|kmem|port)",
    re.IGNORECASE | re.MULTILINE,
)


# ---------------------------------------------------------------------------
# S004: secure deletion of the operator's data.
# ---------------------------------------------------------------------------

_SHRED_HOME_RE = re.compile(
    _CMD + r"(?:shred|srm|wipe)\s+[^\n]*?"
    r"(?:" + _HOME_ALT + r"|/home/|\.ssh|\.gnupg|\.aws|\.config|\.local)",
    re.IGNORECASE | re.MULTILINE,
)


# ---------------------------------------------------------------------------
# S005: world-writable system path.
# ---------------------------------------------------------------------------

_CHMOD_WORLD_RE = re.compile(
    _CMD + r"chmod\s+(?:-[a-zA-Z]+\s+)*[0-7]?777\s+[\"']?(?:"
    + _SYSTEM_PATH_ALT + r"|" + _HOME_ALT + r")",
    re.MULTILINE,
)
_CHOWN_SYSTEM_RE = re.compile(
    _CMD + r"chown\s+(?:-[a-zA-Z]+\s+)*[\w.:]+\s+[\"']?(?:" + _SYSTEM_PATH_ALT + r")(?:\s|$|;)",
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# S006: service disruption (the act, within the sabotage family).
# ---------------------------------------------------------------------------

# `enable` is deliberately absent: that is persistence, and the install-hook
# rules already claim it.  These are the verbs that take a running system
# down.
#
# The unit list is the whole precision of this rule, and it is there because
# of what the benign corpus says. A package stopping or disabling **its own**
# service is standard packaging: you stop a daemon before replacing its
# binary, and you disable it on removal. Four diffs in the locked corpus do
# exactly that - `systemctl disable input-remapper`,
# `systemctl disable --now mullvad-daemon` - and an earlier version of this
# rule flagged all of them. Disrupting somebody *else's* service, and in
# particular the ones that keep a machine reachable, logged and firewalled,
# is a different act.
_CRITICAL_UNITS = (
    r"sshd?", r"systemd-\w+", r"NetworkManager", r"systemd-networkd",
    r"firewalld", r"iptables", r"ip6tables", r"nftables", r"ufw",
    r"auditd", r"rsyslog", r"syslog-ng", r"systemd-journald",
    r"apparmor", r"selinux", r"fail2ban", r"clamav-\w+",
    r"dbus", r"polkit", r"systemd-logind", r"systemd-resolved",
)
_CRITICAL_UNIT_ALT = "|".join(_CRITICAL_UNITS)

_SERVICE_DISRUPT_RE = re.compile(
    # Stopping, disabling or masking a *system* service.
    _CMD + r"systemctl\s+(?:--\S+\s+)*(?:stop|disable|mask)\s+"
    r"(?:--\S+\s+)*[\"']?(?:" + _CRITICAL_UNIT_ALT + r")(?:\.service|\.socket)?\b|"
    # `isolate`, and the power verbs, are disruptive whatever the target:
    # nothing a package build legitimately does reboots the machine.
    + _CMD + r"systemctl\s+(?:--\S+\s+)*(?:isolate|poweroff|reboot|halt)\b|"
    # Killing a system daemon by name.
    + _CMD + r"(?:killall|pkill)\s+(?:-\w+\s+)*(?:-9\s+)?"
    r"[\"']?(?:" + _CRITICAL_UNIT_ALT + r")\b|"
    # Turning the firewall off outright.
    + _CMD + r"(?:ufw\s+disable|firewall-cmd\s+[^\n]*?--(?:remove-service|panic-off))\b|"
    + _CMD + r"setenforce\s+0\b",
    re.IGNORECASE | re.MULTILINE,
)


# ---------------------------------------------------------------------------
# S007: resource theft.
# ---------------------------------------------------------------------------

_MINER_RE = re.compile(
    _CMD + r"(?:xmrig|ethminer|cgminer|bfgminer|minerd|cpuminer|nbminer|"
    r"t-rex|lolminer|phoenixminer|xmr-stak|nicehash)\b|"
    r"stratum\+(?:tcp|ssl)://|"
    r"--donate-level\b|--coin\s+monero\b|"
    r"\b(?:pool|mine)\.(?:minexmr|supportxmr|nanopool|ethermine|f2pool)\.\w+",
    re.IGNORECASE | re.MULTILINE,
)


# ---------------------------------------------------------------------------
# S008: anti-forensics.
# ---------------------------------------------------------------------------

_HISTORY_WIPE_RE = re.compile(
    _CMD + r"history\s+-c\b|"
    + _CMD + r"(?:rm|shred|truncate)\s+[^\n]*?(?:\.bash_history|\.zsh_history|\.history)\b|"
    + _CMD + r"unset\s+HISTFILE\b|" + _CMD + r"export\s+HISTFILE\s*=\s*/dev/null|"
    + _CMD + r"set\s+\+o\s+history\b|"
    + _CMD + r"journalctl\s+[^\n]*?--vacuum-(?:time|size)\s*=|"
    + _CMD + r"(?:truncate\s+-s\s*0|:\s*>)\s+[\"']?/var/log/",
    re.IGNORECASE | re.MULTILINE,
)


#: A target that is *itself* inside the build tree. The distinction the
#: line-wide stand-down could not draw: `rm -rf "$srcdir/.git" ~` clears a
#: build directory and the operator's home in one command, and testing the
#: whole line for a sandbox token silenced the second because of the first.
#: One `$srcdir` token was a licence to delete anything alongside it.
_SANDBOX_TARGET_RE = re.compile(
    r"\A[\"']?(?:" + "|".join(_SANDBOX_VARS) + r")", re.IGNORECASE)

_DANGEROUS_TARGET_RE = re.compile(
    r"\A[\"']?(?:" + _SYSTEM_PATH_ALT + r"|" + _HOME_ALT + r")[\"']?\Z")


def _rm_targets_outside_the_build_tree(body: str) -> str | None:
    """The first `rm` argument that names the operator's system, or None.

    Every `rm` command on the line is asked on its own. Arguments are read
    one at a time so a sandbox path exempts itself and nothing else. Flags
    are skipped; `--` ends them.
    """
    for m in re.finditer(r"(?:\A|[;&|]|\$\()\s*rm\b", body):
        rest = body[m.end():]
        # Stop at the end of this command: what a later command deletes is a
        # separate question, asked again when its own `rm` is reached.
        rest = re.split(r"[;&|]", rest, maxsplit=1)[0]
        flags_done = False
        for arg in rest.split():
            if not flags_done and arg == "--":
                flags_done = True
                continue
            if not flags_done and arg.startswith("-"):
                continue
            flags_done = True
            if _SANDBOX_TARGET_RE.match(arg):
                continue
            if _DANGEROUS_TARGET_RE.match(arg):
                return arg
    return None


def _find_outside_the_build_tree(body: str) -> str | None:
    """The path of a `find ... -delete`/`-exec rm` outside the build tree."""
    for m in re.finditer(r"(?:\A|[;&|]|\$\()\s*find\b", body):
        rest = re.split(r"[;&|]", body[m.end():], maxsplit=1)[0]
        if not re.search(r"-delete\b|-exec\s+rm\b", rest):
            continue
        for arg in rest.split():
            if arg.startswith("-"):
                continue
            if _SANDBOX_TARGET_RE.match(arg):
                break
            if _DANGEROUS_TARGET_RE.match(arg):
                return arg
            break
    return None


def _added_bodies(diff_text: str):
    """``(line_number, body)`` for each added line, comments stripped.

    Added only: a *removed* `rm -rf /` is a recipe being fixed, and reporting
    it as a finding would flag the cleanup rather than the damage.

    Resolved, not raw. Every rule in this file read the literal text, so a
    variable defeated all of them at once: `dd of="$D"`, `systemctl stop
    "$U"`, `rm -rf "$T"`. The name is chosen by the attacker and the value
    is right there in the diff - reading the text instead of the value made
    the whole family a spelling test. The fetch and delivery rules resolve
    for exactly this reason; the sabotage rules were the ones that did not.
    """
    lines = resolve_added_lines(clamp_text(diff_text))
    lines = join_line_continuations(lines)
    for index, line in enumerate(lines, start=1):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        body = _strip_comment(line[1:])
        if body.strip():
            yield index, body


def _sabotage_findings(diff_text, config, add) -> None:
    """Emit S001-S008.

    One command is reported once. The families here are disjoint by
    construction (a fork bomb is not a chmod), so unlike the fetch rules
    there is no precedence to arbitrate - but each rule reports only its
    first hit per diff, because the second `rm -rf /` on a line tells the
    reader nothing the first did not.
    """
    fired: set[str] = set()

    def once(rule_id, name, severity, match, line, **params):
        if rule_id in fired:
            return
        fired.add(rule_id)
        add(rule_id, name, severity, "sabotage", match, line=line, **params)

    for line_no, body in _added_bodies(diff_text):
        quoted = body.strip()[:120]

        if _unbounded_spawn(body):
            once("S001", "Recursive Self-Spawn", "CRITICAL",
                 f"a function pipes itself into itself and backgrounds it: {quoted}",
                 line_no, body=quoted)

        # The sandbox check is what keeps this off the ordinary case: almost
        # every PKGBUILD clears $srcdir or prunes $pkgdir.
        outside = None
        if _RM_RECURSIVE_RE.search(body):
            outside = _rm_targets_outside_the_build_tree(body)
        if outside is None and _FIND_DELETE_RE.search(body):
            outside = _find_outside_the_build_tree(body)
        if outside is not None:
            once("S002", "Recursive Deletion Outside The Build Tree", "CRITICAL",
                 f"recursive delete aimed outside the build tree: {quoted}",
                 line_no, body=quoted)

        if _BLOCK_WRITE_RE.search(body):
            once("S003", "Raw Block Device Write", "CRITICAL",
                 f"writes to a raw block device: {quoted}",
                 line_no, body=quoted)

        if _SHRED_HOME_RE.search(body) and not _SANDBOX_RE.search(body):
            once("S004", "Secure Deletion Of User Data", "HIGH",
                 f"unrecoverable delete of the operator's data: {quoted}",
                 line_no, body=quoted)

        if ((_CHMOD_WORLD_RE.search(body) or _CHOWN_SYSTEM_RE.search(body))
                and not _SANDBOX_RE.search(body)):
            once("S005", "Permission Change On A System Path", "HIGH",
                 f"loosens permissions outside the build tree: {quoted}",
                 line_no, body=quoted)

        if _SERVICE_DISRUPT_RE.search(body):
            once("S006", "System Service Disruption", "HIGH",
                 f"stops, masks or kills a system service: {quoted}",
                 line_no, body=quoted)

        if _MINER_RE.search(body):
            once("S007", "Cryptocurrency Miner", "HIGH",
                 f"invokes or configures a coin miner: {quoted}",
                 line_no, body=quoted)

        if _HISTORY_WIPE_RE.search(body):
            once("S008", "Shell History Or Log Destruction", "MEDIUM",
                 f"erases the record of what ran: {quoted}",
                 line_no, body=quoted)
