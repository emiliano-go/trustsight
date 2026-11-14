"""Fail-closed pre-build approval gate for yay and paru.

Both package managers expose a per-package-base hook that runs after the
PKGBUILD is checked out and before sources are downloaded or built:

* yay ``AURPreInstall`` (``~/.config/yay/init.lua``)
* paru ``PreBuildCommand`` (``[bin]`` in ``paru.conf``)

This module turns that hook into a TrustSight gate.  It inspects each target
with ``trustsight inspect --allow-uninstalled --depth <n>``, prints a compact
report, asks for a yes/no per package, and exits non-zero when the
transaction must stop.

The gate is deliberately a **hard** gate.  Neither package manager can drop a
single package from the transaction at this stage, and an AUR package may be a
pulled dependency of an approved one.  Exit codes:

* ``0``   every package approved
* ``10``  a user refused a package
* ``20``  inspection failed or produced unusable output
* ``30``  no answer was possible (no TTY and no explicit ``--yes``)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, TextIO

from .bounded_io import ReadTooLarge, read_file_capped
from .safe_text import clean
from .subproc import TRUSTED_PATH, minimal_env

EXIT_APPROVED = 0
EXIT_REFUSED = 10
EXIT_ERROR = 20
EXIT_NONINTERACTIVE = 30

MAX_TARGETS = 64
MAX_FINDINGS = 8
#: The checked-out .SRCINFO is package-controlled.  A split recipe can be
#: large, but not unbounded: the gate must not let a checkout decide how much
#: memory this process allocates before it can even inspect it.
MAX_SRCINFO_BYTES = 2 * 1024 * 1024
DEFAULT_DEPTH = 1
DEFAULT_TIMEOUT = 180
MAX_ANSWER_BYTES = 64
VERDICT_LINE_BYTES = 200

_SEVERITY_RANK = {
    "FATAL": 6, "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1,
}

__all__ = [
    "EXIT_APPROVED",
    "EXIT_ERROR",
    "EXIT_NONINTERACTIVE",
    "EXIT_REFUSED",
    "GateError",
    "Summary",
    "build_inspect_argv",
    "entrypoint",
    "main",
    "parse_srcinfo",
    "run_gate",
    "summarize",
    "targets_from_dir",
]


class GateError(RuntimeError):
    """Inspection could not produce a report the gate can trust."""


@dataclass(frozen=True)
class Summary:
    """The subset of an ``inspect --json`` body a gate decision needs."""

    package: str
    verdict: str = ""
    risk: str = ""
    score: int | None = None
    old_version: str = ""
    new_version: str = ""
    findings: tuple[dict, ...] = field(default_factory=tuple)
    coverage_gaps: tuple[str, ...] = field(default_factory=tuple)


def _dedupe(names: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def parse_srcinfo(text: str) -> list[str]:
    """Package names declared by a ``.SRCINFO`` body, bounded and ordered."""
    names: list[str] = []
    # ``\n`` is the SRCINFO record separator and the only line terminator a
    # shell sees.  Do not use splitlines(), which also splits on U+2028 and
    # friends and would invent records the format does not have.
    for line in (text or "").split("\n"):
        key, sep, value = line.partition("=")
        if not sep or key.strip() != "pkgname":
            continue
        name = value.strip()
        if name:
            names.append(name)
    return _dedupe(names)[:MAX_TARGETS]


def targets_from_dir(directory: str | Path, fallback: str = "") -> list[str]:
    """Target packages for a build directory, or the base name as fallback."""
    try:
        raw = read_file_capped(
            Path(directory) / ".SRCINFO", MAX_SRCINFO_BYTES, ".SRCINFO")
        text = raw.decode("utf-8", errors="replace")
    except ReadTooLarge:
        # Too large is a refusal, not a fallback: silently using --base would
        # let the file decide which package is inspected.
        return []
    except OSError:
        text = ""
    names = parse_srcinfo(text)
    if names:
        return names
    return [fallback] if fallback else []


def _as_text(value, default: str = "") -> str:
    return value if isinstance(value, str) else default


def _as_int(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _finding_rows(value) -> list[dict]:
    if not isinstance(value, (list, tuple)):
        return []
    rows = [
        dict(item) for item in value
        if isinstance(item, dict)
        # INFO is rendered as evidence by inspect; in a yes/no prompt it is
        # noise beside the scored findings and the coverage gaps.
        and _as_text(item.get("severity")).upper() != "INFO"
    ]
    rows.sort(
        key=lambda row: (
            _SEVERITY_RANK.get(_as_text(row.get("severity")).upper(), 0),
            _as_int(row.get("weight")) or 0,
            _as_text(row.get("rule_id")),
        ),
        reverse=True,
    )
    return rows[:MAX_FINDINGS]


def summarize(body: dict, *, fallback_package: str = "") -> Summary:
    """Read an ``inspect --json`` body without trusting its field types."""
    if not isinstance(body, dict):
        raise GateError("inspect returned a non-object body")
    package = _as_text(body.get("package"), fallback_package)
    if not package:
        raise GateError("inspect body names no package")
    gaps = body.get("coverage_gaps")
    gap_ids = tuple(
        _as_text(gap) for gap in (gaps if isinstance(gaps, (list, tuple)) else ())
        if _as_text(gap)
    )
    return Summary(
        package=package,
        verdict=_as_text(body.get("verdict")),
        risk=_as_text(body.get("risk")),
        score=_as_int(body.get("score")),
        old_version=_as_text(body.get("old_version")),
        new_version=_as_text(body.get("new_version")),
        findings=tuple(_finding_rows(body.get("findings"))),
        coverage_gaps=gap_ids,
    )


def _version_line(summary: Summary) -> str:
    old, new = summary.old_version, summary.new_version
    if old and new and old != new:
        return f"{new} (from {old})"
    return new or old or ""


def _one_line(text: str, limit: int = VERDICT_LINE_BYTES) -> str:
    """Collapse a report sentence onto one bounded prompt line."""
    collapsed = " ".join(clean(text).split())
    if len(collapsed) <= limit:
        return collapsed
    cut = collapsed[:limit]
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut.rstrip() + "..."


def _color_enabled(out: TextIO) -> bool:
    """Whether *out* is a terminal that should receive ANSI colour.

    ``NO_COLOR`` wins over a TTY, and ``FORCE_COLOR`` wins over a pipe, which
    is the same convention the rest of the CLI uses.  A manager that captures
    the hook's output gets plain text; a terminal gets the colour.
    """
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR") or os.environ.get("TRUSTSIGHT_FORCE_RICH"):
        return True
    try:
        return bool(out.isatty())
    except (AttributeError, OSError, ValueError):
        return False


_RISK_COLORS = {
    "FATAL": "1;31",
    "CRITICAL": "1;31",
    "HIGH": "31",
    "MEDIUM": "33",
    "LOW": "32",
    "INCONCLUSIVE": "35",
}
_SEVERITY_COLORS = {
    "FATAL": "1;31",
    "CRITICAL": "1;31",
    "HIGH": "31",
    "MEDIUM": "33",
    "LOW": "32",
}


_SPINNER_FRAMES = ("-", "\\", "|", "/")
_SPINNER_INTERVAL = 0.12
_SPINNER_WIDTH = 80


def _is_tty(out: TextIO) -> bool:
    try:
        return bool(out.isatty())
    except (AttributeError, OSError, ValueError):
        return False


@contextmanager
def _analysis_progress(out: TextIO, label: str = "analyzing"):
    """Show that the child inspection is running, without owning the TTY.

    The gate can spend minutes in one inspect call.  A terminal gets a small
    spinner; a pipe gets one plain line so a captured log still says work
    started.  The line is cleared before the report so it never mixes with a
    finding.
    """
    if not _is_tty(out):
        print(f"   {label} ...", file=out, flush=True)
        yield
        return
    stop = threading.Event()

    def spin() -> None:
        index = 0
        while not stop.wait(_SPINNER_INTERVAL):
            frame = _SPINNER_FRAMES[index % len(_SPINNER_FRAMES)]
            out.write(f"\r   {label} {frame}")
            out.flush()
            index += 1

    thread = threading.Thread(target=spin, daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=1)
        out.write("\r" + (" " * _SPINNER_WIDTH) + "\r")
        out.flush()


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if enabled else text


def render(summary: Summary, out: TextIO, *, show_score: bool = False,
           show_risk: bool = False) -> None:
    """Write the short report a human approves from.

    The numeric band and score are withheld unless the caller asks for them.
    A gate exists to answer "did this change what the recipe will do?", and a
    score invites a threshold debate at the approval prompt.

    Every value here came from the inspected package or from the analysis of
    it, so it is untrusted text at a terminal boundary.  Clean it once, here,
    rather than trusting the child's JSON to be inert.
    """
    colour = _color_enabled(out)
    print(_paint(f":: TrustSight gate: {clean(summary.package)}", "1;36", colour),
          file=out)
    version = _version_line(summary)
    if version:
        print(f"   version: {clean(version)}", file=out)
    facts = []
    if show_risk and summary.risk:
        risk_code = _RISK_COLORS.get(
            clean(summary.risk).upper(), "36")
        facts.append(_paint(f"risk: {clean(summary.risk)}", risk_code, colour))
    if show_score and summary.score is not None:
        facts.append(f"score: {summary.score}")
    if facts:
        print("   " + "   ".join(facts), file=out)
    if summary.verdict:
        print(f"   verdict: {_one_line(summary.verdict)}", file=out)
    for finding in summary.findings:
        rule = clean(_as_text(finding.get("rule_id"), "?"))
        severity = clean(_as_text(finding.get("severity"), ""))
        description = clean(_as_text(finding.get("description"), ""))
        where = clean(_as_text(finding.get("file"), ""))
        line = _as_int(finding.get("line"))
        location = f" [{where}:{line}]" if where and line else ""
        label = f"{rule} ({severity})" if severity else rule
        sev_code = _SEVERITY_COLORS.get(severity.upper(), "36")
        print(f"   - {_paint(label, sev_code, colour)}: "
              f"{description}{location}", file=out)
    if summary.coverage_gaps:
        gaps = [clean(gap) for gap in summary.coverage_gaps]
        shown = ", ".join(gaps[:4])
        extra = len(gaps) - 4
        suffix = f" (+{extra} more)" if extra > 0 else ""
        print(_paint(f"   coverage gaps: {shown}{suffix}", "33", colour),
              file=out)
    if "ruleset_drifted" in summary.coverage_gaps:
        print(_paint(
            "   note: rules.toml is behind the shipped set; run "
            "'trustsight config sync-rules --update'", "33", colour),
            file=out)


def build_inspect_argv(
    package: str,
    *,
    depth: int = DEFAULT_DEPTH,
    full_recipe: bool = True,
    binary: str | None = None,
) -> list[str]:
    """Argv for one read-only inspection.

    The package name is a single argv element, never interpolated into a
    shell.  ``--record`` is never passed: a gate must not rewrite history.
    """
    base = [binary] if binary else _trustsight_argv()
    argv = base + [
        "inspect", package,
        "--allow-uninstalled",
        "--json",
        "--score",
        "--risk",
        "--depth", str(int(depth)),
    ]
    if full_recipe:
        argv.append("--full-recipe")
    return argv


def _trustsight_argv() -> list[str]:
    """The interpreter and module that run the child inspection.

    ``TRUSTSIGHT_BIN`` is honoured only when it is an absolute path: a
    relative value would be resolved through the caller's ``PATH``, which is
    exactly how a directory earlier in a user's path can substitute the
    inspector the gate runs.  Without an explicit absolute binary the gate
    uses its own interpreter, so no ``PATH`` lookup happens at all.
    """
    binary = os.environ.get("TRUSTSIGHT_BIN", "")
    if binary and os.path.isabs(binary):
        return [binary]
    return [sys.executable, "-m", "trustsight"]


def _trustsight_binary() -> str | None:
    argv = _trustsight_argv()
    return argv[0] if len(argv) == 1 else None


def _pacman_says_installed(package: str) -> bool | None:
    pacman = shutil.which("pacman", path=TRUSTED_PATH)
    if pacman is None:
        return None
    try:
        result = subprocess.run(
            [pacman, "-Qq", "--", package],
            capture_output=True, text=True, timeout=15, check=False,
            env=minimal_env(),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.returncode == 0


def _child_env() -> dict[str, str]:
    """An allowlisted environment for the child inspection.

    ``minimal_env`` drops every startup-hook and loader variable.  The child
    TrustSight also needs its own XDG roots and runtime switches, so those are
    copied explicitly rather than inheriting the whole environment.
    """
    env = minimal_env()
    for key in (
        "HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR", "TRUSTSIGHT_OFFLINE", "TRUSTSIGHT_NO_UPDATE_CHECK",
        "TRUSTSIGHT_NO_PENDING_CHECK", "TRUSTSIGHT_LOG_LEVEL",
        "TRUSTSIGHT_SQLITE_SYNCHRONOUS", "TRUSTSIGHT_SQLITE_BUSY_TIMEOUT",
    ):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def _lint_body(
    package: str,
    directory: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> dict:
    """Turn ``trustsight lint --json`` into the gate's summary shape."""
    path = Path(directory) / "PKGBUILD"
    if not path.is_file():
        raise GateError(f"no local PKGBUILD for {package} in {directory}")
    argv = _trustsight_argv() + ["lint", "--json", str(path)]
    try:
        result = runner(
            argv, capture_output=True, text=True,
            timeout=max(1, int(timeout)), check=False,
            env=_child_env(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateError(f"could not lint {path}: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().split("\n")
        reason = detail[-1] if detail else f"exit {result.returncode}"
        raise GateError(f"lint of {path} failed: {reason}")
    try:
        doc = json.loads(result.stdout)
    except (TypeError, ValueError) as exc:
        raise GateError(f"lint of {path} returned invalid JSON") from exc
    if not isinstance(doc, dict):
        raise GateError(f"lint of {path} returned a non-object body")
    rules = doc.get("rules")
    findings = []
    for row in (rules if isinstance(rules, list) else ()):
        if not isinstance(row, dict):
            continue
        findings.append({
            "rule_id": _as_text(row.get("rule_id"), "?"),
            "severity": _as_text(row.get("severity"), ""),
            "description": _as_text(row.get("message"), ""),
            "file": path.name,
            "line": _as_int(row.get("line")),
        })
    return {
        "package": package,
        "verdict": "local recipe (no diff)",
        "findings": findings,
        "coverage_gaps": [],
    }


def run_inspect(
    package: str,
    *,
    depth: int = DEFAULT_DEPTH,
    timeout: int = DEFAULT_TIMEOUT,
    full_recipe: bool | None = None,
    directory: str = "",
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> dict:
    """Run one inspection and return its parsed JSON body, or raise GateError."""
    if full_recipe is None:
        installed = _pacman_says_installed(package)
        full_recipe = installed is not True
    argv = build_inspect_argv(
        package, depth=depth, full_recipe=bool(full_recipe),
        binary=_trustsight_binary(),
    )
    try:
        result = runner(
            argv, capture_output=True, text=True,
            timeout=max(1, int(timeout)), check=False,
            env=_child_env(),
        )
    except subprocess.TimeoutExpired as exc:
        raise GateError(f"inspection of {package} timed out") from exc
    except OSError as exc:
        raise GateError(f"could not run trustsight for {package}: {exc}") from exc
    if result.returncode != 0:
        # The child may print the reason on either stream: the AUR miss is a
        # JSON document on stdout, while the update notice lands on stderr and
        # used to be the only line read.  Search both before deciding the
        # local-recipe fallback does not apply.
        combined = "\n".join(
            part for part in (result.stderr, result.stdout) if part)
        detail = combined.strip().split("\n")
        reason = detail[-1] if detail else f"exit {result.returncode}"
        if directory and any(
                "not found in the AUR" in line for line in detail):
            return _lint_body(
                package, directory, timeout=timeout, runner=runner)
        raise GateError(f"inspection of {package} failed: {reason}")
    try:
        body = json.loads(result.stdout)
    except (TypeError, ValueError) as exc:
        raise GateError(f"inspection of {package} returned invalid JSON") from exc
    if isinstance(body, dict) and body.get("error"):
        reason = str(body["error"])
        if directory and "not found in the AUR" in reason:
            return _lint_body(
                package, directory, timeout=timeout, runner=runner)
        raise GateError(f"inspection of {package} failed: {reason}")
    if not isinstance(body, dict):
        raise GateError(f"inspection of {package} returned a non-object body")
    if directory:
        # The target names come from the checked-out .SRCINFO, which is
        # package-controlled.  A recipe can list a benign package there and
        # build something else, so the remote inspection answers for the
        # name while the local PKGBUILD is what actually runs.  Always lint
        # the local recipe too: the two views are merged before the prompt,
        # and a failing local lint fails the gate closed.
        local = _lint_body(package, directory, timeout=timeout, runner=runner)
        merged = dict(body)
        findings = [row for row in (body.get("findings") or ())
                    if isinstance(row, dict)]
        seen = {
            (str(row.get("rule_id") or ""), _as_int(row.get("line")),
             str(row.get("file") or ""))
            for row in findings
        }
        for row in local.get("findings", ()):
            key = (str(row.get("rule_id") or ""), _as_int(row.get("line")),
                   str(row.get("file") or ""))
            if key not in seen:
                saved = dict(row)
                saved["severity"] = saved.get("severity") or ""
                saved["weight"] = 0
                findings.append(saved)
                seen.add(key)
        merged["findings"] = findings
        gaps = list(body.get("coverage_gaps") or ())
        for gap in local.get("coverage_gaps", ()):
            if gap not in gaps:
                gaps.append(gap)
        merged["coverage_gaps"] = gaps
        return merged
    return body


def _tty_paths() -> list[str]:
    """Terminal paths to try, in order.

    ``/dev/tty`` is the controlling terminal and the first choice.  yay and
    paru can run a hook with a pty for stdio but no controlling terminal, so
    a tty on fd 0, 1 or 2 is also a valid prompt target and is tried next.
    """
    paths: list[str] = []
    seen: set[str] = set()

    def add(path: str) -> None:
        if path and path not in seen:
            seen.add(path)
            paths.append(path)

    add("/dev/tty")
    for fd in (0, 1, 2):
        try:
            if os.isatty(fd):
                add(os.ttyname(fd))
        except OSError:
            continue
    return paths


def _read_answer(prompt: str,
                 tty_paths: list[str] | None = None) -> str | None:
    """Read one line from a terminal; None when none can be opened.

    A terminal is a character device, not a seekable file.  Opening it
    ``r+`` builds a buffered random-access stream, which raises
    ``UnsupportedOperation`` before the prompt is ever written, so the gate
    opens the write and read sides separately.
    """
    for tty_path in (tty_paths if tty_paths is not None else _tty_paths()):
        try:
            with open(tty_path, "w", encoding="utf-8", errors="replace") as tty:
                tty.write(prompt)
                tty.flush()
            with open(tty_path, "r", encoding="utf-8", errors="replace") as tty:
                line = tty.readline(MAX_ANSWER_BYTES)
        except (OSError, ValueError):
            continue
        if len(line) >= MAX_ANSWER_BYTES and not line.endswith("\n"):
            return ""
        return line.strip()
    return None


def _approved(answer: str) -> bool:
    return answer.strip().lower() in ("y", "yes")


def run_gate(
    targets: list[str],
    *,
    inspect: Callable[[str], dict],
    answer: Callable[[str], str | None],
    out: TextIO = sys.stderr,
    approve_all: bool = False,
    refuse_all: bool = False,
    show_score: bool = False,
    show_risk: bool = False,
) -> int:
    """The decision loop, with inspection and prompting injected for tests."""
    colour = _color_enabled(out)
    if not targets:
        print(_paint("trustsight-gate: no target packages", "31", colour),
              file=out)
        return EXIT_ERROR
    for package in targets[:MAX_TARGETS]:
        try:
            with _analysis_progress(out):
                body = inspect(package)
            summary = summarize(body, fallback_package=package)
            if summary.package != package:
                raise GateError(
                    f"inspection answered for {summary.package!r}, not "
                    f"{package!r}; refusing to approve a different package")
        except GateError as exc:
            print(_paint(f"trustsight-gate: {exc}", "31", colour), file=out)
            return EXIT_ERROR
        render(summary, out, show_score=show_score, show_risk=show_risk)
        if approve_all:
            print(_paint(f"   approved (--yes): {clean(package)}", "32", colour),
                  file=out)
            continue
        if refuse_all:
            print(_paint(f"trustsight-gate: refused (--no): {clean(package)}",
                         "31", colour), file=out)
            return EXIT_REFUSED
        reply = answer(f"Continue with {clean(package)}? [y/N] ")
        if reply is None:
            print(_paint(
                "trustsight-gate: no terminal for approval; aborting "
                "(set --yes to approve non-interactively)", "31", colour),
                file=out)
            return EXIT_NONINTERACTIVE
        if not _approved(reply):
            print(_paint(f"trustsight-gate: refused: {clean(package)}",
                         "31", colour), file=out)
            return EXIT_REFUSED
    return EXIT_APPROVED


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustsight-gate",
        description=(
            "Inspect AUR targets and require a yes/no approval per package "
            "before yay/paru downloads sources or builds."
        ),
    )
    parser.add_argument("packages", nargs="*", help="target package names")
    parser.add_argument("--base", default="", help="package base (hook label)")
    parser.add_argument("--dir", default="", help="checked-out PKGBUILD directory")
    parser.add_argument(
        "--depth", type=int, default=DEFAULT_DEPTH,
        help="AUR dependency levels to inspect (default: 1)",
    )
    parser.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT,
        help="seconds allowed per inspection (default: 180)",
    )
    parser.add_argument(
        "--full-recipe", action=argparse.BooleanOptionalAction, default=None,
        help="analyse the whole recipe (default: auto, full when not installed)",
    )
    parser.add_argument(
        "--yes", action="store_true",
        help="approve every package without prompting (unattended use)",
    )
    parser.add_argument(
        "--no", action="store_true",
        help="refuse every package without prompting (test/automation)",
    )
    parser.add_argument(
        "--score", action="store_true",
        help="show the numeric score (hidden by default)",
    )
    parser.add_argument(
        "--risk", action="store_true",
        help="show the risk band (hidden by default)",
    )
    return parser


def main(argv: list[str] | None = None, *, out: TextIO = sys.stderr) -> int:
    args = _parser().parse_args(argv)
    if os.environ.get("TRUSTSIGHT_GATE_DISABLE") == "1":
        # A deliberate, visible bypass for an emergency (for example, a
        # broken TrustSight rollout).  It must be loud, never silent.
        print("trustsight-gate: disabled by TRUSTSIGHT_GATE_DISABLE=1", file=out)
        return EXIT_APPROVED
    targets = list(args.packages)
    if not targets and args.dir:
        targets = targets_from_dir(args.dir, args.base)
    if len(targets) > MAX_TARGETS:
        print(
            f"trustsight-gate: {len(targets)} targets exceeds the cap "
            f"({MAX_TARGETS})",
            file=out,
        )
        return EXIT_ERROR

    def inspect(package: str) -> dict:
        return run_inspect(
            package, depth=args.depth, timeout=args.timeout,
            full_recipe=args.full_recipe, directory=args.dir,
        )

    try:
        return run_gate(
            targets,
            inspect=inspect,
            answer=_read_answer,
            out=out,
            approve_all=args.yes,
            refuse_all=args.no,
            show_score=args.score,
            show_risk=args.risk,
        )
    except KeyboardInterrupt:
        print("trustsight-gate: cancelled by user", file=out)
        return EXIT_REFUSED


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":  # pragma: no cover - console wrapper
    entrypoint()
