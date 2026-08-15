"""Untrusted text reaching a terminal is sanitised at the render boundary.

`safe_text` states the design: sanitise where the value is *rendered*, so
the evidence stored in the database and the JSON report stays byte-exact.
That only holds if every render path uses it, and two did not.

The failure is not subtle once seen, but it is invisible in review, because
both spellings look like sanitising:

* `unicode.strip_ansi` removes CSI sequences and nothing else. C1 control
  bytes survive, and `\\x9b2J` is the 8-bit spelling of "clear the screen" -
  the exact forgery `safe_text` exists to prevent.
* A bare `str` handed to Rich is parsed as markup. A value holding `[/]`
  raises `MarkupError` and aborts the whole table, so one hostile entry
  makes a command unusable rather than merely ugly.
"""

import ast
import io
import pathlib
import re

import pytest
from rich.console import Console
from rich.table import Table

from trustsight.safe_text import clean
from trustsight.unicode import strip_ansi

CLI = pathlib.Path(__file__).resolve().parents[1] / "src" / "trustsight" / "cli"

HOSTILE = "ok\x1b[31mRED\x1b[0m\nforged\x07\x9b2J[/]" + "A" * 200


# ---------------------------------------------------------------------------
# The two sanitisers are not interchangeable.
# ---------------------------------------------------------------------------


def test_the_weaker_helper_leaves_what_a_terminal_acts_on():
    """Pins *why* the two must not be swapped, rather than that they differ."""
    out = strip_ansi(HOSTILE)
    assert "\x9b" in out, "C1 introducer survives strip_ansi"
    assert "\x07" in out, "BEL survives strip_ansi"
    assert "\n" in out, "newline survives strip_ansi"


def test_clean_removes_all_of_it():
    out = clean(HOSTILE)
    assert "\x1b" not in out
    assert "\x9b" not in out
    assert "\x07" not in out
    assert "\n" not in out


# ---------------------------------------------------------------------------
# Rich reads a bare string as markup.
# ---------------------------------------------------------------------------


def _render(cell) -> str:
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, width=100)
    table = Table()
    table.add_column("Value")
    table.add_row(cell)
    console.print(table)
    return buffer.getvalue()


def test_a_bare_string_with_an_unbalanced_tag_aborts_the_render():
    """The reason wrapping matters, demonstrated rather than asserted."""
    from rich.errors import MarkupError

    with pytest.raises(MarkupError):
        _render("https://example.invalid/x[/]")


def test_the_same_value_wrapped_renders_as_text():
    from rich.text import Text

    out = _render(Text(clean("https://example.invalid/x[/]")))
    assert "[/]" in out


# ---------------------------------------------------------------------------
# Every render path uses the right one.
# ---------------------------------------------------------------------------


def test_no_cli_module_sanitises_with_the_weaker_helper():
    """A comment naming the function is fine; a call is not.

    Asserted on calls and imports rather than on the substring, because the
    first version of this check tripped over a comment that explained the
    very thing it was checking for.
    """
    offenders = []
    for path in sorted(CLI.rglob("*.py")):
        text = path.read_text()
        if re.search(r"\bstrip_ansi\s*\(", text) or re.search(
            r"^from .*import .*\bstrip_ansi\b", text, re.M
        ):
            offenders.append(path.name)
    assert not offenders, f"these render with strip_ansi: {offenders}"


def test_every_ioc_render_value_is_wrapped():
    """IOC baselines are federated, so their fields are third-party text.

    `ioc.py` did not import `clean` at all, and rendered the indicator
    value, its source and its confidence straight into a Rich table.
    """
    tree = ast.parse((CLI / "ioc.py").read_text())
    unwrapped = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_row"
        ):
            continue
        for arg in node.args:
            if isinstance(arg, (ast.Name, ast.Attribute)):
                unwrapped.append(f"ioc.py:{node.lineno} {ast.unparse(arg)}")
    assert not unwrapped, f"unwrapped values reach a Rich table: {unwrapped}"


def test_a_hostile_finding_reason_survives_rendering_intact():
    """End to end: the corpus path puts tree member names into a reason.

    A snapshot tarball member name is chosen by the package author, is not
    bounded the way the git path bounds companion names, and lands in
    R118's reason text.
    """
    from trustsight.analysis import scan_diff

    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n"
        "+source=('payload.bin')\n"
        "+install -Dm755 payload.bin \"$pkgdir/usr/bin/x\"\n"
    )
    name = "pkg/\x1b[31mFAKE\x1b[0m\nSecond\x07[/]" + "A" * 300 + ".bin"
    manifest = [(name, b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56)]

    fact = scan_diff(diff, package_name="p", tree_manifest=manifest)
    reasons = [e.reason for e in fact.score_breakdown if "FAKE" in (e.reason or "")]
    assert reasons, "fixture did not reach a finding"

    # Stored evidence stays byte-exact, which is the documented contract.
    assert "\x1b" in reasons[0]

    # Rendering it is what must be safe, and must not raise.
    rendered = _render(__import__("rich.text", fromlist=["Text"]).Text(clean(reasons[0])))
    assert "\x1b" not in rendered
    assert "\x9b" not in rendered
