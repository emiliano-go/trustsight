"""A016: release-asset vs tag-tree comparison."""

from trustsight.analysis.release_asset import compare_release_asset


def _inv(*pairs):
    return [(name, len(body), digest) for name, body, digest in pairs]


def test_a016_fires_on_a_build_input_missing_from_the_tag():
    finding = compare_release_asset(
        _inv(("Makefile.am", b"x", "a"), ("m4/evil.m4", b"x", "b")),
        _inv(("Makefile.am", b"x", "a")),
    )
    assert finding["rule_id"] == "A016"
    assert finding["weight_override"] == 0


def test_a016_fires_on_a_content_mismatch():
    finding = compare_release_asset(
        _inv(("src/a.c", b"one", "a")),
        _inv(("src/a.c", b"two", "b")),
    )
    assert finding["rule_id"] == "A016"


def test_a016_ignores_generated_files():
    assert compare_release_asset(
        _inv(("configure", b"x", "a")),
        _inv(("configure", b"y", "b")),
    ) is None


def test_a016_is_silent_when_the_tag_tree_was_not_read():
    assert compare_release_asset(_inv(("Makefile.am", b"x", "a")), []) is None
