"""Shared tokenizer operation dispatch.

Both the standalone tokenizer worker and the content worker use this table.
Keeping one copy means the two sandboxes cannot drift about which operations
exist or how a payload is shaped.
"""

from __future__ import annotations


class UnknownOp(Exception):
    """The request named an operation the dispatch table does not implement."""


def dispatch(op: str, payload: object) -> object:
    """Run one engine operation and return a JSON-serialisable result."""
    from trustsight import _tokenizer_engine as engine

    if op == "lines":
        return engine.split_lines(payload)
    if op == "join":
        return engine.join_line_continuations(payload)
    if op == "joined_indexed":
        return engine._joined_indexed(payload)
    if op == "resolve_added":
        return engine.resolve_added_lines(payload)
    if op == "resolve_removed":
        return engine.resolve_removed_lines(payload)
    if op == "indexed":
        resolved, unresolved, indices = engine.tokenize_and_resolve_indexed(payload)
        return [resolved, unresolved, indices]
    if op == "variable_table":
        variables, arrays = engine._variable_table(payload)
        return [variables, arrays]
    if op == "variable_table_spans":
        variables, arrays, spans = engine._variable_table_with_spans(payload)
        return [variables, arrays, spans]
    if op == "clean_lines":
        return [
            engine.collapse_traversal(engine.strip_leading_bom(line))
            for line in payload
        ]
    if op == "strip_boms":
        return [engine.strip_leading_bom(line) for line in payload]
    if op == "reconstruct_literals":
        return list(engine.reconstruct_literals(payload))
    if op == "reconstruct_lines":
        from ..line_lex import QuoteState
        from .._tokenizer_engine._quotes import reconstruct_literals_stateful

        state = QuoteState()
        out = []
        for line in payload:
            rebuilt, fully, state, _quoted = reconstruct_literals_stateful(
                line, state,
            )
            out.append([rebuilt, fully])
        return out
    if op == "reconstruct_lines_stateful":
        from ..line_lex import QuoteState
        from .._tokenizer_engine._quotes import reconstruct_literals_stateful

        state = QuoteState()
        out = []
        for line in payload:
            rebuilt, fully, state, quoted = reconstruct_literals_stateful(
                line, state,
            )
            out.append([rebuilt, fully, quoted])
        return out
    raise UnknownOp(f"unknown op: {op!r}")


