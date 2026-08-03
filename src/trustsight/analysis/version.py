"""Phase 4 - Class B version rules (plan §6).

R115 is the only rule here for now: an ``epoch=`` that is newly present in
a diff.  The version parser shared with the VCS-local-rebuild work (plan
§13) will grow this module later.
"""

import re

from ..tokenizer import resolve_added_lines

_EPOCH_ASSIGN_RE = re.compile(
    r"^\s*epoch\s*=\s*['\"]?(\d+)['\"]?",
    re.IGNORECASE,
)


def _epoch_introduced(diff_text: str) -> tuple[bool, str | None]:
    """Return ``(introduced, value)``: was ``epoch=`` absent before the diff
    and present after it?

    Mirrors :func:`~trustsight.analysis.base._pkgver_changed_in_diff`: if an
    ``epoch=`` assignment appears on the ``+`` side and none did on the ``-``
    side, the diff introduced the field.  An unchanged ``epoch=`` is not part
    of any hunk and never surfaces here.
    """
    had_epoch = any(re.match(r"\s*-\s*epoch\s*=", line) for line in diff_text.splitlines())
    if had_epoch:
        return False, None
    for line in resolve_added_lines(diff_text):
        if not line.startswith("+") or line.startswith("+++"):
            continue
        match = _EPOCH_ASSIGN_RE.search(line[1:])
        if match:
            return True, match.group(1)
    return False, None


def _epoch_findings(diff_text: str, config, add) -> None:
    """A diff introduces ``epoch=`` where none existed (R115, MEDIUM).

    Introducing an epoch overrides the version ordering: a nonzero epoch
    makes the package sort above anything that shares its pkgver/pkgrel,
    which is how a package can be pushed ahead of an established one.
    ``epoch=0`` merely initialises the field and is closer to a no-op.
    """
    introduced, value = _epoch_introduced(diff_text)
    if not introduced:
        return
    severity = "MEDIUM" if value and value != "0" else "INFO"
    add("R115", "Epoch Introduced", severity, "version",
        f"epoch={value} newly introduced" if value else "epoch newly introduced",
        line=next(
            (
                i
                for i, line in enumerate(diff_text.splitlines(), 1)
                if line.startswith("+") and _EPOCH_ASSIGN_RE.search(line[1:])
            ),
            None,
        ),
        epoch=value or "0")
