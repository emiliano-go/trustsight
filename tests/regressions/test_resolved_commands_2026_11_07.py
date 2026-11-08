"""Resolved commands are commands, not every resolved added line."""

from __future__ import annotations

from trustsight.analysis.pipeline._resolved import (
    is_command_line,
    split_resolved_lines,
)


def test_metadata_comments_and_braces_are_not_commands():
    resolved = [
        "pkgbase = neurafly",
        'pkgdesc = "Real audio in"',
        "# Maintainer: demo",
        "build() {",
        "  cargo build --release --locked",
        "}",
    ]
    raw = [
        "+pkgbase=neurafly",
        '+pkgdesc="Real audio in"',
        "+# Maintainer: demo",
        "+build() {",
        "+  cargo build --release --locked",
        "+}",
    ]
    indices = [3, 4, 5, 6, 7, 8]

    commands, recipe = split_resolved_lines(resolved, indices, raw, indices)

    assert commands == ["  cargo build --release --locked"]
    assert "pkgbase = neurafly" in recipe
    assert "build() {" in recipe
    assert "# Maintainer: demo" in recipe


def test_declarations_are_not_commands():
    assert not is_command_line("export PATH=/usr/bin")
    assert not is_command_line("local version=1")
    assert not is_command_line("fi")
    assert not is_command_line("}")


def test_a_declaration_with_a_substitution_keeps_its_command():
    assert is_command_line('local tag=$(git describe --tags)')


def test_an_ordinary_command_still_classifies_as_a_command():
    assert is_command_line("cargo build --release --locked")
    assert is_command_line('install -Dm644 LICENSE "$pkgdir/usr/share/licenses/demo"')
