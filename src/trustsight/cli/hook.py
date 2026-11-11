"""Install the yay and paru approval hooks.

``trustsight-gate`` is a console script; the managers need a hook that calls
it.  These commands write that hook, or remove it, without touching anything
else in the manager's configuration.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
from importlib.resources import files
from pathlib import Path
from typing import Optional

import typer

__all__ = ["register_commands"]

LUA_MARKER = "-- trustsight-hook:v1"
INI_MARKER = "# trustsight-hook:v1"
PARU_LINE = 'PreBuildCommand = trustsight-gate --base "$PKGBASE" --dir "$PWD"'
MAX_CONFIG_BYTES = 1024 * 1024


def _config_dir() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    return Path(xdg) if xdg else Path.home() / ".config"


def _target(explicit: Optional[str], default: Path) -> Path:
    return Path(explicit).expanduser() if explicit else default


def _operator_roots() -> list[Path]:
    return [Path.home(), _config_dir()]


def _inside_operator_roots(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return False
    for root in _operator_roots():
        try:
            resolved.relative_to(root.resolve())
            return True
        except (OSError, ValueError):
            continue
    return False


def _refuse(message: str) -> None:
    typer.echo(f"trustsight hook: {message}", err=True)
    raise typer.Exit(code=2)


def _check_target(path: Path, *, force: bool) -> None:
    if path.is_symlink():
        _refuse(f"{path} is a symlink; refusing to write through it")
    if path.exists() and not path.is_file():
        _refuse(f"{path} is not a regular file")
    if not force and not _inside_operator_roots(path):
        _refuse(f"{path} is outside the operator's config and home directories; "
                "pass --force to write it anyway")


def _read(path: Path) -> Optional[str]:
    if not path.exists():
        return None
    if path.stat().st_size > MAX_CONFIG_BYTES:
        _refuse(f"{path} is larger than {MAX_CONFIG_BYTES} bytes")
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as exc:
        _refuse(f"cannot read {path}: {exc}")
        return None  # unreachable; keeps the type checker happy


def _backup(path: Path) -> Path:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    candidate = path.with_name(f"{path.name}.bak.{stamp}")
    suffix = 1
    while candidate.exists():
        candidate = path.with_name(f"{path.name}.bak.{stamp}.{suffix}")
        suffix += 1
    shutil.copy2(path, candidate)
    return candidate


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = (path.stat().st_mode & 0o777) if path.exists() else 0o644
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".trustsight-hook-",
                               suffix=".tmp")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _yay_content() -> str:
    text = files("trustsight").joinpath("hooks/yay-init.lua").read_text(
        encoding="utf-8")
    return text if text.endswith("\n") else text + "\n"


def _newline_for(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def _lines_of(text: str) -> list[str]:
    """Split config text on newlines, preserving CRLF as a joined newline.

    Config is operator-owned, not attacker text, so the tokenizer's shell
    line splitting does not apply; a plain split also keeps ``\v``/``\f``
    inside a value instead of treating them as line boundaries.
    """
    raw = text.split("\n")
    if raw and raw[-1] == "":
        raw.pop()
    return [line[:-1] if line.endswith("\r") else line for line in raw]


def _section_bounds(lines: list[str], name: str) -> tuple[int, int]:
    start = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if start is not None:
                return start, index
            if stripped[1:-1].strip().lower() == name.lower():
                start = index
    return (start, len(lines)) if start is not None else (-1, -1)


def _paru_plan(text: str, *, force: bool) -> tuple[str, str]:
    """Return (new_text, action)."""
    lines = _lines_of(text)
    newline = _newline_for(text)
    start, end = _section_bounds(lines, "bin")
    if start < 0:
        block = ["[bin]", INI_MARKER, PARU_LINE]
        body = "\n".join(lines)
        if body and not body.endswith("\n"):
            body += "\n"
        new_text = body + ("\n" if body else "") + newline.join(block) + newline
        return new_text, "create"
    for index in range(start + 1, end):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key.strip().lower() != "prebuildcommand":
            continue
        if "trustsight-gate" in value:
            return text, "no-op"
        if not force:
            return text, "conflict"
        updated = lines[:index] + [INI_MARKER, PARU_LINE] + lines[index + 1:]
        return newline.join(updated) + newline, "update"
    insert = start + 1
    updated = lines[:insert] + [INI_MARKER, PARU_LINE] + lines[insert:]
    return newline.join(updated) + newline, "create"


def _paru_remove(text: str) -> tuple[str, bool]:
    lines = _lines_of(text)
    newline = _newline_for(text)
    for index, line in enumerate(lines):
        if line.strip() != INI_MARKER:
            continue
        following = lines[index + 1].strip() if index + 1 < len(lines) else ""
        if not following.startswith("PreBuildCommand") or "trustsight-gate" not in following:
            continue
        del lines[index:index + 2]
        return newline.join(lines) + (newline if lines else ""), True
    return text, False


def _setup_paru(path: Path, *, print_only: bool, dry_run: bool,
                force: bool, remove: bool) -> None:
    if print_only:
        typer.echo(f"[bin]\n{INI_MARKER}\n{PARU_LINE}")
        return
    _check_target(path, force=force)
    text = _read(path) or ""
    if remove:
        new_text, removed = _paru_remove(text)
        if not removed:
            typer.echo(f"no TrustSight hook in {path}")
            return
        if dry_run:
            typer.echo(f"remove: {path}")
            return
        backup = _backup(path)
        _write(path, new_text)
        typer.echo(f"backup: {backup}")
        typer.echo(f"removed: {path}")
        return
    new_text, action = _paru_plan(text, force=force)
    if action == "conflict":
        _refuse(f"{path} already sets PreBuildCommand to something else; "
                "pass --force to replace it (a backup is written)")
    if action == "no-op":
        typer.echo(f"already configured: {path}")
        return
    if dry_run:
        typer.echo(f"{action}: {path}")
        return
    if path.exists():
        backup = _backup(path)
        typer.echo(f"backup: {backup}")
    _write(path, new_text)
    typer.echo(f"configured: {path}")


def _setup_yay(path: Path, *, print_only: bool, dry_run: bool,
               force: bool, remove: bool) -> None:
    content = _yay_content()
    if print_only:
        typer.echo(content, nl=False)
        return
    _check_target(path, force=force)
    text = _read(path)
    if remove:
        if text is None or LUA_MARKER not in text:
            _refuse(f"{path} was not created by trustsight; remove it manually")
        if dry_run:
            typer.echo(f"remove: {path}")
            return
        backup = _backup(path)
        path.unlink()
        typer.echo(f"backup: {backup}")
        typer.echo(f"removed: {path}")
        return
    if text is not None:
        if LUA_MARKER in text and not force:
            typer.echo(f"already configured: {path}")
            return
        if LUA_MARKER not in text and not force:
            _refuse(f"{path} already exists and is not a TrustSight hook; "
                    "pass --force to overwrite it (a backup is written), or "
                    "use --print to merge it by hand")
        if dry_run:
            typer.echo(f"{'update' if LUA_MARKER in text else 'overwrite'}: {path}")
            return
        backup = _backup(path)
        typer.echo(f"backup: {backup}")
    if dry_run:
        typer.echo(f"create: {path}")
        return
    _write(path, content)
    typer.echo(f"configured: {path}")


def register_commands(app: typer.Typer) -> None:
    hook_app = typer.Typer(
        help="Install the yay/paru approval hooks that call trustsight-gate.")

    def _options(
        print_only: bool,
        dry_run: bool,
        force: bool,
        remove: bool,
    ) -> dict:
        if print_only and (dry_run or force or remove):
            _refuse("--print cannot be combined with --dry-run, --force or --remove")
        return {
            "print_only": print_only,
            "dry_run": dry_run,
            "force": force,
            "remove": remove,
        }

    @hook_app.command("paru")
    def paru_cmd(
        config: Optional[str] = typer.Option(
            None, "--config", help="paru.conf path (default: XDG config dir)"),
        print_only: bool = typer.Option(
            False, "--print", help="Print the snippet and change nothing"),
        dry_run: bool = typer.Option(
            False, "--dry-run", help="Report the action and change nothing"),
        force: bool = typer.Option(
            False, "--force", help="Replace a conflicting PreBuildCommand"),
        remove: bool = typer.Option(
            False, "--remove", help="Remove the TrustSight hook"),
    ):
        """Install the paru PreBuildCommand approval hook."""
        _setup_paru(_target(config, _config_dir() / "paru" / "paru.conf"),
                    **_options(print_only, dry_run, force, remove))

    @hook_app.command("yay")
    def yay_cmd(
        config: Optional[str] = typer.Option(
            None, "--config", help="yay init.lua path (default: XDG config dir)"),
        print_only: bool = typer.Option(
            False, "--print", help="Print the hook and change nothing"),
        dry_run: bool = typer.Option(
            False, "--dry-run", help="Report the action and change nothing"),
        force: bool = typer.Option(
            False, "--force", help="Overwrite an existing init.lua (backed up)"),
        remove: bool = typer.Option(
            False, "--remove", help="Remove the TrustSight hook"),
    ):
        """Install the yay AURPreInstall approval hook."""
        _setup_yay(_target(config, _config_dir() / "yay" / "init.lua"),
                   **_options(print_only, dry_run, force, remove))

    app.add_typer(hook_app, name="hook")
