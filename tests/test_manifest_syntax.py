"""The manifest syntax layer refuses hostile documents instead of loading them.

These are the shapes an attacker controls: a YAML anchor cycle that would spin
a reader, an alias bomb, an unsafe YAML tag, an XML entity declaration, a
document past the byte cap, and deep nesting.  Each must come back as a named
refusal or a bounded walk, never a hang, an object construction, or a crash.
"""

from __future__ import annotations

import time

import pytest

from trustsight.analysis.manifest_syntax import (
    MAX_MANIFEST_BYTES,
    ManifestSyntaxError,
    deep_items,
    load_ini,
    load_json,
    load_jsonc,
    load_toml,
    load_xml,
    load_yaml,
)


def test_yaml_anchor_cycle_is_walked_not_looped():
    doc = load_yaml("a: &x\n  b: *x\n")
    start = time.perf_counter()
    pairs = list(deep_items(doc))
    assert time.perf_counter() - start < 1.0
    # The self-reference is visited once; the walk terminates.
    assert any(key == "b" for key, _ in pairs)


def test_yaml_alias_bomb_stays_bounded():
    lines = ["a0: &a0 [1, 2, 3, 4, 5]"]
    for i in range(1, 40):
        lines.append(f"a{i}: &a{i} [*a{i-1}, *a{i-1}, *a{i-1}, *a{i-1}, *a{i-1}]")
    text = "\n".join(lines) + "\n"
    start = time.perf_counter()
    try:
        doc = load_yaml(text)
    except ManifestSyntaxError:
        # An alias budget refusal is as bounded as a bounded walk.
        assert time.perf_counter() - start < 2.0
        return
    pairs = list(deep_items(doc))
    assert time.perf_counter() - start < 2.0
    assert pairs  # bounded, not expanded


def test_yaml_merge_key_bomb_is_bounded():
    lines = ["L0: &L0 {k0: v0}"]
    for level in range(1, 19):
        lines.append(
            f"L{level}: &L{level} {{<<: [*L{level - 1}, *L{level - 1}]}}"
        )
    lines.append("target: {<<: [*L18, *L18]}")
    start = time.perf_counter()
    load_yaml("\n".join(lines) + "\n")
    assert time.perf_counter() - start < 2.0


def test_yaml_duplicate_keys_are_refused():
    with pytest.raises(ManifestSyntaxError):
        load_yaml("a: 1\na: 2\n")


def test_yaml_unsafe_tag_is_refused():
    with pytest.raises(ManifestSyntaxError):
        load_yaml("!!python/object/apply:os.system ['echo pwned']\n")


def test_xml_entity_declaration_is_refused():
    bomb = (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE lolz [\n'
        '  <!ENTITY lol "lol">\n'
        '  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">\n'
        ']>\n'
        "<lolz>&lol2;</lolz>\n"
    )
    with pytest.raises(ManifestSyntaxError):
        load_xml(bomb)
    with pytest.raises(ManifestSyntaxError):
        load_xml('<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x/>')


def test_xml_plain_doctype_is_allowed():
    # Maven POMs carry a DOCTYPE; only entity declarations are refused.
    xml = '<?xml version="1.0"?>\n<!DOCTYPE project>\n<project><a/></project>\n'
    root = load_xml(xml)
    assert root.tag == "project"


def test_deep_nesting_is_refused_or_walked_bounded():
    for text, loader in (
        ("[" * 5000 + "]" * 5000, load_json),
        ("a: " + "[" * 5000 + "]" * 5000, load_yaml),
    ):
        try:
            doc = loader(text)
        except ManifestSyntaxError:
            continue
        start = time.perf_counter()
        list(deep_items(doc))
        assert time.perf_counter() - start < 1.0


def test_oversized_documents_are_refused_before_parsing():
    big = "x: y\n" * (MAX_MANIFEST_BYTES // 2 + 10)
    for loader in (load_yaml, load_json, load_toml, load_xml):
        with pytest.raises(ManifestSyntaxError):
            loader(big)


def test_jsonc_strips_comments_but_not_string_contents():
    text = (
        "{\n"
        '  // a comment\n'
        '  "url": "https://evil.example//x",  /* inline */\n'
        '  "n": 1\n'
        "}\n"
    )
    data = load_jsonc(text)
    assert data == {"url": "https://evil.example//x", "n": 1}


def test_ini_does_not_interpolate():
    parser = load_ini("[x]\nkey = 100%\nother = %(key)s\n")
    assert parser["x"]["key"] == "100%"
    assert parser["x"]["other"] == "%(key)s"


def test_bom_is_stripped_for_every_loader():
    assert load_toml('\ufeff[dep]\nx = "1"\n') == {"dep": {"x": "1"}}
    assert load_json('\ufeff{"x": 1}') == {"x": 1}
    assert load_yaml('\ufeffa: 1\n') == {"a": 1}
    assert load_xml('\ufeff<a/>').tag == "a"
