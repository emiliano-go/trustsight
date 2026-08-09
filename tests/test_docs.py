"""Documentation must describe what the code actually does.

These are cheap structural checks, not prose review. They exist because
the failures they catch are silent: a rule pattern quoted in the docs
drifts from the shipped one, or a command ships without a reference
entry, and nothing fails until a user is misled.
"""

import re
from pathlib import Path

import tomllib

import pytest

from trustsight.cli import app
from trustsight.config import DEFAULT_CONFIG, DEFAULT_RULES

ROOT = Path(__file__).resolve().parent.parent
RULES_MD = ROOT / "docs" / "reference" / "rules.md"
CLI_MD = ROOT / "docs" / "reference" / "cli.md"
CONFIG_MD = ROOT / "docs" / "reference" / "configuration.md"
API_MD = ROOT / "docs" / "reference" / "python-api.md"
CLI_SRC = ROOT / "src" / "trustsight" / "cli"

SHIPPED_RULES = tomllib.loads(DEFAULT_RULES)["rules"]
PROGRAMMATIC_RULES = ["R004", "R005", "C001", "C002", "C003",
                      "C004", "C005", "C006", "C007"]


@pytest.mark.parametrize("rule", SHIPPED_RULES, ids=lambda r: r["id"])
def test_every_shipped_rule_has_a_reference_entry(rule):
    assert f"### {rule['id']}:" in RULES_MD.read_text()


@pytest.mark.parametrize("rule_id", PROGRAMMATIC_RULES)
def test_every_programmatic_rule_has_a_reference_entry(rule_id):
    assert f"### {rule_id}:" in RULES_MD.read_text()


@pytest.mark.parametrize("rule", SHIPPED_RULES, ids=lambda r: r["id"])
def test_documented_pattern_matches_shipped_pattern(rule):
    """A quoted pattern that has drifted is worse than none: it tells the
    reader the tool does something it does not."""
    md = RULES_MD.read_text()
    section = re.search(rf"### {rule['id']}:.*?(?=\n### |\Z)", md, re.S)
    assert section, f"no section for {rule['id']}"
    quoted = re.search(r"\*\*Pattern:\*\* (?:`` (.+?) ``|`(.+?)`)\n", section.group(0), re.S)
    assert quoted, f"no pattern quoted for {rule['id']}"
    assert (quoted.group(1) or quoted.group(2)) == rule["pattern"]


@pytest.mark.parametrize("rule", SHIPPED_RULES, ids=lambda r: r["id"])
def test_documented_severity_matches_shipped_severity(rule):
    md = RULES_MD.read_text()
    section = re.search(rf"### {rule['id']}:.*?(?=\n### |\Z)", md, re.S)
    assert rule["severity"] in section.group(0), (
        f"{rule['id']} is {rule['severity']} but the docs say otherwise"
    )


def _cli_names() -> set[str]:
    names: set[str] = set()
    for cmd in app.registered_commands:
        name = cmd.name or cmd.callback.__name__.replace("_", "-")
        names.add(name)
    for group in app.registered_groups:
        if group.name:
            names.add(group.name)
    return names


def _cli_flags() -> set[str]:
    flags: set[str] = set()
    for py in sorted(CLI_SRC.glob("*.py")):
        text = py.read_text()
        flags.update(re.findall(r'typer\.Option\([^)]*"(--[a-z-]+)"', text))
    return flags


def test_every_command_and_subcommand_is_documented():
    md = CLI_MD.read_text()
    undocumented = sorted(n for n in _cli_names() if n not in md)
    assert undocumented == [], f"undocumented CLI names: {undocumented}"


def test_every_flag_is_documented():
    md = CLI_MD.read_text()
    undocumented = sorted(f for f in _cli_flags() if f not in md)
    assert undocumented == [], f"undocumented flags: {undocumented}"


def test_every_public_api_name_is_documented():
    """A public name nobody documented is one nobody meant to promise.

    The API surface is the thing callers pin to, so it may not grow by
    accident: adding an export without a reference entry fails here.
    """
    from trustsight import api

    md = API_MD.read_text()
    undocumented = sorted(n for n in api.__all__ if f"`{n}`" not in md)
    assert undocumented == [], f"undocumented API names: {undocumented}"


def test_the_package_root_reexports_exactly_the_api_surface():
    """`from trustsight import X` must mean the same X as `trustsight.api.X`."""
    import trustsight
    from trustsight import api

    assert sorted(api.__all__) == sorted(trustsight._API_NAMES)
    for name in api.__all__:
        assert getattr(trustsight, name) is getattr(api, name)


def test_every_config_section_is_documented():
    md = CONFIG_MD.read_text()
    sections = tomllib.loads(DEFAULT_CONFIG).keys()
    undocumented = sorted(
        k for k in sections if f"[{k}]" not in md and f"`{k}`" not in md
    )
    assert undocumented == [], f"undocumented config sections: {undocumented}"


def test_no_documented_command_is_missing_from_the_cli():
    """The inverse: docs must not promise a command that does not exist.
    `trustsight sandbox` was documented for a release without existing."""
    documented = set(re.findall(r"^## trustsight ([a-z-]+)", CLI_MD.read_text(), re.M))
    missing = sorted(c for c in documented if c not in _cli_names())
    assert missing == [], f"documented but not implemented: {missing}"


# --- prose conventions ----------------------------------------------------

# Standard punctuation only.  An em dash, an en dash and a spaced "--" all
# render inconsistently across the terminal, the rendered site and a plain
# `cat` of the file, and the project has settled on ":", ";", ",", "()" and
# "-" instead.  Pinned as a test because it has drifted back three times.
_BANNED_PUNCTUATION = {
    "—": "em dash",
    "–": "en dash",
    " -- ": "spaced double hyphen",
}


def test_docs_use_standard_punctuation():
    offenders = []
    for path in sorted((ROOT / "docs").rglob("*.md")):
        for lineno, line in enumerate(path.read_text().splitlines(), start=1):
            for char, name in _BANNED_PUNCTUATION.items():
                if char in line:
                    rel = path.relative_to(ROOT)
                    offenders.append(f"{rel}:{lineno} {name}: {line.strip()[:70]}")
    assert not offenders, "use : ; , () - instead\n" + "\n".join(offenders[:20])
