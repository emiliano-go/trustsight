"""Spec §4: the document cache.

``from_dict(to_dict(doc))`` must project identically for every projection,
and a cache entry must never become an authority: a version change, a
tokenizer change, or a corrupt payload is a miss that re-parses.
"""

import json
import pathlib

from trustsight.diffdoc import (
    DIFFDOC_SCHEMA_VERSION,
    DiffDoc,
    parse_diff,
    tokenizer_version,
)
from trustsight.doc_cache import (
    document_key,
    parse_diff_cached,
    parse_recipe_cached,
)
from trustsight.recipedoc import RecipeDoc, parse_recipe

_CORPUS = pathlib.Path(__file__).resolve().parent / "fixtures" / "benign-corpus"

_PKGBUILD = """\
pkgname=demo
pkgver=1.0
pkgrel=1
depends=('glibc' 'zlib')
source=('https://example.invalid/demo-1.0.tar.gz')
sha256sums=('abc')
build() {
  cd "$srcdir/demo-$pkgver"
  make
}
"""


def _sample_corpus(count=100):
    paths = sorted(_CORPUS.glob("*.diff"))
    step = max(1, len(paths) // count)
    return paths[::step][:count]


def _projections(doc: DiffDoc) -> dict:
    return {
        "files": doc.files,
        "lines": doc.lines,
        "line_map": doc.line_map(),
        "post_lines": doc.post_lines(),
        "pre_lines": doc.pre_lines(),
        "post_origins": doc.post_origins(),
        "pre_origins": doc.pre_origins(),
        "added": [line.index for line in doc.added_lines()],
        "removed": [line.index for line in doc.removed_lines()],
        "post_text": doc.post_text(),
        "pre_text": doc.pre_text(),
        "cut_hunks": doc.cut_hunks(),
    }


def test_diff_round_trip_projects_identically_over_the_corpus():
    for path in _sample_corpus():
        text = path.read_text(encoding="utf-8", errors="replace")
        doc = parse_diff(text)
        rebuilt = DiffDoc.from_dict(doc.to_dict())
        assert rebuilt is not None, path.name
        assert rebuilt == doc, path.name
        assert _projections(rebuilt) == _projections(doc), path.name


def test_recipe_round_trip_projects_identically():
    recipe = parse_recipe(_PKGBUILD, file="PKGBUILD")
    rebuilt = RecipeDoc.from_dict(recipe.to_dict())
    assert rebuilt == recipe
    assert rebuilt.to_dict() == recipe.to_dict()


def test_a_version_mismatch_is_a_miss_not_a_partial_read():
    doc = parse_diff("--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-x\n+y\n")
    payload = doc.to_dict()
    payload["schema_version"] = DIFFDOC_SCHEMA_VERSION + 1
    assert DiffDoc.from_dict(payload) is None
    payload["schema_version"] = DIFFDOC_SCHEMA_VERSION
    payload["tokenizer_version"] = "not-the-parser"
    assert DiffDoc.from_dict(payload) is None
    assert DiffDoc.from_dict({"files": []}) is None


def test_cached_parse_matches_a_fresh_parse_and_survives_a_corrupt_entry(tmp_path):
    text = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-x\n+y\n"
    fresh = parse_diff(text)
    first = parse_diff_cached(text, directory=tmp_path)
    assert first == fresh
    entry = tmp_path / f"diff-{document_key(text)}.json"
    assert entry.exists()
    # A valid entry is served.
    assert parse_diff_cached(text, directory=tmp_path) == fresh
    # A corrupt entry falls back to a fresh parse rather than raising.
    entry.write_text("{not json", encoding="utf-8")
    assert parse_diff_cached(text, directory=tmp_path) == fresh
    # An old-schema entry is a miss too.
    entry.write_text(json.dumps({"schema_version": 0, "files": [], "lines": []}))
    assert parse_diff_cached(text, directory=tmp_path) == fresh


def test_cached_recipe_matches_a_fresh_parse(tmp_path):
    fresh = parse_recipe(_PKGBUILD, file="PKGBUILD")
    assert parse_recipe_cached(_PKGBUILD, file="PKGBUILD", directory=tmp_path) == fresh
    assert parse_recipe_cached(_PKGBUILD, file="PKGBUILD", directory=tmp_path) == fresh


def test_the_tokenizer_digest_is_available():
    assert tokenizer_version() != ""
