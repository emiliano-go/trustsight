"""The tokenizer sandbox: hostile text is parsed in a separate process.

The tokenizer is the second parser eating package-controlled input (A6),
and the one with an amplification property: a chain of ``b=$a$a``
assignments doubles per level.  The whole module now runs in a child
process with no inherited descriptors and a hard memory ceiling, so a
defect in a bound has a subprocess to spend rather than the analysis
process and everything it holds.

``expander`` is the parent-side client and ``expand_worker`` the child.
Nothing in the analysis imports the engine directly; see
``trustsight/_tokenizer_engine.py``.
"""
