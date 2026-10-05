"""Spec §11: corpus as documents.

Per observed version, the RecipeDoc's arrays and scalars are indexed, and
``array_seen_before`` / ``tuple_observation_count`` answer exact history
questions.  Bounded like every other corpus table; reserved names refused.
"""

import pathlib

import pytest

from trustsight.db import (
    MAX_RECIPE_OBSERVATIONS_PER_PACKAGE,
    array_seen_before,
    init_db,
    record_recipe_document,
    tuple_observation_count,
)
from trustsight.diffdoc import parse_diff
from trustsight.recipedoc import recipe_states

_CORPUS = pathlib.Path(__file__).resolve().parent / "fixtures" / "benign-corpus"


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setattr("trustsight.db.DATA_DIR", tmp_path)
    init_db()
    yield
    (tmp_path / "trustsight.db").unlink(missing_ok=True)


def test_an_observed_tuple_is_seen_and_a_novel_one_is_not(db):
    record_recipe_document(
        "demo", {"pkgver": "1.0"}, {"source": ("https://a.example/x",)},
        observed_at="2026-01-01 00:00:00",
    )
    assert array_seen_before("demo", "source", ("https://a.example/x",))
    assert not array_seen_before("demo", "source", ("https://b.example/y",))
    assert not array_seen_before("other", "source", ("https://a.example/x",))


def test_observation_count_tracks_distinct_observations(db):
    entries = ("https://a.example/x",)
    for stamp in ("2026-01-01 00:00:00", "2026-01-02 00:00:00"):
        record_recipe_document(
            "demo", {"pkgver": "1.0"}, {"source": entries}, observed_at=stamp)
    assert tuple_observation_count("demo", "source", entries) == 2


def test_the_index_is_bounded_per_package(db):
    for i in range(MAX_RECIPE_OBSERVATIONS_PER_PACKAGE + 5):
        record_recipe_document(
            "demo", {"pkgver": str(i)},
            {"source": (f"https://a.example/{i}",)},
            observed_at=f"2026-01-01 00:00:{i:02d}",
        )
    # The oldest tuples were pruned; the newest are still answerable.
    assert not array_seen_before("demo", "source", ("https://a.example/0",))
    newest = f"https://a.example/{MAX_RECIPE_OBSERVATIONS_PER_PACKAGE + 4}"
    assert array_seen_before("demo", "source", (newest,))


def test_reserved_names_are_refused(db):
    with pytest.raises(ValueError):
        record_recipe_document("__seed__", {}, {})


def test_the_index_answers_from_real_corpus_recipes(db):
    """Burn-in: index a sampled package's observed versions from the
    corpus and check the index answers exactly what was observed."""
    if not sorted(_CORPUS.glob("*.diff")):
        pytest.skip("the locked corpus is not present in this checkout")
    by_package: dict[str, list] = {}
    for path in sorted(_CORPUS.glob("*.diff")):
        package = path.name.split("__", 1)[0]
        if len(by_package.setdefault(package, [])) >= 3:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        doc = parse_diff(text)
        _pre, post = recipe_states(doc)
        by_package[package].append(post)

    checked = 0
    for package, recipes in by_package.items():
        for index, recipe in enumerate(recipes):
            record_recipe_document(
                package, recipe.scalars, recipe.arrays,
                observed_at=f"2026-02-01 00:00:0{index}",
            )
        for recipe in recipes:
            for name, entries in recipe.arrays.items():
                if entries:
                    assert array_seen_before(package, name, entries)
            checked += 1
        # A tuple never observed is not seen.
        assert not array_seen_before(
            package, "source", ("https://never.example/absent",))
    assert checked
