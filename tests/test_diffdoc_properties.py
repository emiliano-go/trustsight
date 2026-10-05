"""Property tests for the DiffDoc parser contract (spec §12).

The locked-corpus parity harness proves the parser equivalent to the
legacy walkers; it cannot explore.  These tests assert the document
model's contract itself over arbitrary line sequences: hunk headers with
randomized/lying counts, content lines spelling headers, ``\\ No newline``
and binary markers, files without headers, interleaved files and empty
hunks.  Five invariants must hold on whatever comes out, and no exception
may escape the parser.

The example tests beside these pin known shapes (``test_diffdoc.py``);
these are the exploration layer that makes hunk-bookkeeping changes
(§2, §6, §9) safe to land.
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from trustsight.diffdoc import _DEFAULT_FILE, DiffDoc, parse_diff

_SETTINGS = settings(
    max_examples=300,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)

#: Arbitrary text without the characters that would silently split a
#: generated "line" into two.  Lone surrogates are outside the input
#: domain: the sandbox's documented contract is that analysis text was
#: decoded from bytes with ``errors=replace`` (``sandbox/protocol.py``).
_LINE_TEXT = st.text(
    alphabet=st.characters(exclude_characters="\r\n\0", exclude_categories=["Cs"]),
    max_size=24,
)

_FILENAMES = ["PKGBUILD", ".SRCINFO", "evil.install", "a b/c.txt", "/dev/null"]


@st.composite
def _diff_shaped_lines(draw) -> list[str]:
    """A line sequence biased toward diff structure and its near-misses."""
    count = draw(st.integers(min_value=0, max_value=80))
    lines: list[str] = []
    for _ in range(count):
        kind = draw(st.integers(min_value=0, max_value=7))
        if kind == 0:
            # A hunk header, honest or lying.
            old_start = draw(st.integers(min_value=0, max_value=10**6))
            new_start = draw(st.integers(min_value=0, max_value=10**6))
            if draw(st.booleans()):
                lines.append(f"@@ -{old_start} +{new_start} @@")
            else:
                old_count = draw(st.integers(min_value=0, max_value=40))
                declared = draw(st.integers(min_value=0, max_value=40))
                lines.append(
                    f"@@ -{old_start},{old_count} +{new_start},{declared} @@"
                )
        elif kind == 1:
            lines.append("+++ " + draw(st.sampled_from(_FILENAMES)))
        elif kind == 2:
            lines.append("--- " + draw(st.sampled_from(_FILENAMES)))
        elif kind == 3:
            lines.append(
                draw(
                    st.sampled_from(
                        [
                            "",
                            "++ still content",
                            "-- still content",
                            "+",
                            "-",
                            " ",
                            "\\ No newline at end of file",
                            "Binary files a/PKGBUILD and b/PKGBUILD differ",
                            "diff --git a/PKGBUILD b/PKGBUILD",
                            "index 0123456..abcdef0 100644",
                            "@@ junk that does not parse @@",
                        ]
                    )
                )
            )
        else:
            prefix = draw(st.sampled_from(["+", "-", " "]))
            lines.append(prefix + draw(_LINE_TEXT))
    return lines


def _assert_invariants(doc: DiffDoc) -> None:
    # 1. Line numbers are monotone non-decreasing within a hunk.  An add
    #    line has no old position (None) and is skipped on that side; a
    #    removal keeps the next post number on the new side.
    for file in doc.files:
        for hunk in file.hunks:
            for attr in ("old_lineno", "new_lineno"):
                previous = None
                for line in hunk.lines:
                    if not line.is_content:
                        continue
                    value = getattr(line, attr)
                    if value is None:
                        continue
                    assert previous is None or value >= previous, (
                        f"{attr} went backwards in {file.path}@{hunk.new_start}"
                    )
                    previous = value

    # 2. The post-line bookkeeping: the lines parsed into hunks equal the
    #    sum of each hunk's parsed post count.  Content outside a hunk is
    #    excluded from both sides.
    in_hunk_post = sum(
        1 for line in doc.lines
        if line.in_hunk and line.side in ("add", "context")
    )
    accounted = sum(
        hunk.actual_lines for file in doc.files for hunk in file.hunks
    )
    assert in_hunk_post == accounted

    # 3. Attribution: every content line names a non-empty file, and a
    #    line parsed into a hunk is one of that hunk's own lines.
    hunk_line_ids = {
        id(line)
        for file in doc.files
        for hunk in file.hunks
        for line in hunk.lines
    }
    known_paths = {file.path for file in doc.files}
    for line in doc.lines:
        if not line.is_content:
            continue
        assert line.file
        if line.in_hunk:
            assert id(line) in hunk_line_ids
        else:
            assert line.file in known_paths or line.file == _DEFAULT_FILE

    # 4. The legacy line map keys exactly the in-hunk content lines.
    expected_keys = {
        line.index for line in doc.lines if line.in_hunk and line.is_content
    }
    assert set(doc.line_map()) == expected_keys


@_SETTINGS
@given(lines=_diff_shaped_lines())
def test_parser_invariants_hold_on_diff_shaped_input(lines: list[str]) -> None:
    # 5. No exception escapes the parser (reaching the assertions at all).
    _assert_invariants(parse_diff("\n".join(lines)))


@_SETTINGS
@given(text=st.text(
    alphabet=st.characters(exclude_characters="\r\0", exclude_categories=["Cs"]),
    max_size=2000,
))
def test_parser_invariants_hold_on_arbitrary_text(text: str) -> None:
    _assert_invariants(parse_diff(text))


@_SETTINGS
@given(
    declared=st.integers(min_value=0, max_value=30),
    body=st.lists(st.sampled_from(["+x", "-y", " z", "+", "-", " "]),
                  max_size=40),
)
def test_declared_counts_never_fabricate_lines(
    declared: int, body: list[str]
) -> None:
    """A lying header must not make the parser synthesize or drop content.

    ``actual_lines`` counts what parsed, ``expected_lines`` records the
    claim, and both survive to the coverage layer without the parser
    bridging the difference.
    """
    text = f"@@ -1,1 +1,{declared} @@\n" + "\n".join(body)
    doc = parse_diff(text)
    assert len(doc.files) == 1
    hunk = doc.files[0].hunks[0]
    assert hunk.expected_lines == declared
    expected_actual = sum(1 for line in body if not line.startswith("-"))
    assert hunk.actual_lines == expected_actual
