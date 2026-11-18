"""The URL engine's table, dispatch and registry contract."""

from pathlib import Path

from trustsight import categories
from trustsight.analysis import url_engine
from trustsight.analysis.edges import build_context
from trustsight.analysis.pipeline import scan_diff
from trustsight.analysis.url_engine import (
    URLContext,
    URL_INSTANCES,
    run_url_instances,
)

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


def test_every_url_instance_is_a_registered_rule_with_docs_and_fixtures():
    for instance in URL_INSTANCES:
        assert instance.rule_id in categories.RULE_CATEGORIES, instance.rule_id
        assert (ROOT / instance.doc).exists(), (instance.rule_id, instance.doc)
        assert instance.fixtures, instance.rule_id
        for fixture in instance.fixtures:
            assert (ROOT / fixture).exists(), (instance.rule_id, fixture)


def test_run_url_instances_honours_only():
    seen: list[str] = []

    def add(rule_id, *_args, **_kwargs):
        seen.append(rule_id)

    ctx = URLContext(_diff("source=('gopher://x/y')\n"), {})
    run_url_instances(ctx, add, only=frozenset({"H034"}))
    assert seen == ["H034"]


def test_every_url_emitter_is_dispatched():
    called: list[str] = []

    def spy(ctx, add):
        called.append("spy")

    original = url_engine.URL_INSTANCES
    url_engine.URL_INSTANCES = tuple(
        url_engine.URLInstance("H034", "spy", "scheme", "MEDIUM",
                               "docs/rules/fetch-and-execution.md",
                               ("tests/test_url_engine.py",), spy)
        for _ in range(3)
    )
    try:
        url_engine.run_url_instances(
            URLContext(_diff("source=('https://x/y')\n"), {}),
            lambda *a, **k: None)
    finally:
        url_engine.URL_INSTANCES = original
    assert called == ["spy", "spy", "spy"]


def test_exotic_scheme_fires_h034():
    assert "H034" in _ids("source=('gopher://evil.invalid/x')\n")


def test_insecure_http_without_checksums_fires_h003():
    assert "H003" in _ids("source=('http://evil.invalid/x.tar.gz')\n")


def test_build_context_shares_the_install_hook_context():
    ctx = build_context(_diff("build() {\n  curl x\n}\n"), {})
    assert ctx.line_context is not None
    assert isinstance(ctx.printed_heredoc, frozenset)


def test_a_registry_endpoint_is_not_a_source_artifact():
    """A registry URL resolves a dependency; it is not a fetched artifact.

    The electron-wrapper template sets
    ``YARN_NPM_REGISTRY_SERVER="${...:-https://registry.yarnpkg.com}"`` and
    the URL was charged SOURCE_BUCKET (unknown, +20) and novelty as though
    the package had begun downloading from an unknown host.
    """
    from trustsight.differ import extract_urls_from_diff

    body = (
        "build() {\n"
        '  export YARN_NPM_REGISTRY_SERVER="${YARN_NPM_REGISTRY_SERVER:-'
        'https://registry.yarnpkg.com}"\n'
        "  npm install\n"
        "}"
    )
    changes = extract_urls_from_diff(_diff(body))
    declared = set(changes.declared_urls)
    # Exact set membership, not a URL substring probe: the URL is declared
    # and every added URL is declared, so no undeclared source is left to
    # be bucketed.
    assert declared == {"https://registry.yarnpkg.com"}
    assert set(changes.added_urls) <= declared
    assert "SOURCE_BUCKET" not in _ids(body)
