"""Documentation must describe what the code actually does.

These are cheap structural checks, not prose review. They exist because
the failures they catch are silent: a rule pattern quoted in the docs
drifts from the shipped one, or a command ships without a reference
entry, and nothing fails until a user is misled.
"""

import re
import tomllib
from pathlib import Path

import pytest

from trustsight.config import DEFAULT_CONFIG, DEFAULT_RULES

ROOT = Path(__file__).resolve().parent.parent
RULES_MD = ROOT / "docs" / "reference" / "rules.md"
CLI_MD = ROOT / "docs" / "reference" / "cli.md"
CONFIG_MD = ROOT / "docs" / "reference" / "configuration.md"
CLI_PY = ROOT / "src" / "trustsight" / "cli.py"

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
    return set(re.findall(r'add_parser\(\s*\n?\s*"([a-z-]+)"', CLI_PY.read_text()))


def _cli_flags() -> set[str]:
    return set(re.findall(r'add_argument\(\s*\n?\s*"(--[a-z-]+)"', CLI_PY.read_text()))


def test_every_command_and_subcommand_is_documented():
    md = CLI_MD.read_text()
    undocumented = sorted(n for n in _cli_names() if n not in md)
    assert undocumented == [], f"undocumented CLI names: {undocumented}"


def test_every_flag_is_documented():
    md = CLI_MD.read_text()
    undocumented = sorted(f for f in _cli_flags() if f not in md)
    assert undocumented == [], f"undocumented flags: {undocumented}"


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
