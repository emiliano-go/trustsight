"""Property tests for bounded diff generation.

The example tests beside these pin known shapes. These assert the
*invariants* over randomised deltas, because the failure that matters here
is not "a case I thought of breaks" but "some combination of sizes, counts
and text lengths lets content through without a truncation flag".

The generator is driven through stubs rather than real repositories on
purpose: a real one cannot be made to produce a delta whose declared size
disagrees with its patch text, and that disagreement is exactly what an
attacker controls.
"""

import random

import pytest

from trustsight import differ

SEEDS = list(range(24))


class _Side:
    def __init__(self, path: str, size: int):
        self.path = path
        self.size = size


class _Delta:
    def __init__(self, path: str, size: int, status: int = 1):
        self.old_file = _Side(path, size)
        self.new_file = _Side(path, size)
        self.status = status


class _Patch:
    def __init__(self, delta: _Delta, text: str):
        self.delta = delta
        self._text = text
        self.read = False

    @property
    def text(self) -> str:
        self.read = True
        return self._text


class _Diff:
    def __init__(self, patches):
        self._patches = patches
        self.deltas = [p.delta for p in patches]
        self.stats = type("S", (), {"insertions": 0, "deletions": 0})()

    def __iter__(self):
        return iter(self._patches)


class _Repo:
    def __init__(self, diff):
        self._diff = diff

    def get(self, _oid):
        return type("C", (), {"tree": object()})()

    def diff(self, *_args, **_kwargs):
        return self._diff


def _random_patches(rng, count):
    patches = []
    for index in range(count):
        # Metadata paths, because the filter only reads those.
        path = rng.choice(["PKGBUILD", ".SRCINFO", f"h{index}.install"])
        # Sizes that straddle the pre-materialisation ceiling.
        size = rng.choice([
            0, 12, 4096,
            differ.MAX_PATCH_SOURCE_BYTES - 1,
            differ.MAX_PATCH_SOURCE_BYTES + 1,
            differ.MAX_PATCH_SOURCE_BYTES * 8,
        ])
        # Text length deliberately unrelated to the declared size: an
        # attacker controls both independently.
        length = rng.choice([0, 10, 5000, differ.MAX_PATCH_BYTES + 500])
        text = "@@ -1 +1 @@\n+" + ("x" * length)
        patches.append(_Patch(_Delta(path, size, rng.choice([1, 2, 3])), text))
    return patches


@pytest.mark.parametrize("seed", SEEDS)
def test_retained_output_never_exceeds_the_budget(seed):
    rng = random.Random(seed)
    patches = _random_patches(rng, rng.randint(1, 40))
    max_bytes = rng.choice([1, 1000, 65536, differ.MAX_GENERATED_DIFF_BYTES])

    text, summary, _truncated = differ.generate_diff_bounded(
        _Repo(_Diff(patches)), "a", "b", max_bytes=max_bytes
    )

    assert len(text.encode("utf-8")) <= max_bytes + len(patches)
    assert len(summary.files_changed) <= differ.MAX_DIFF_SUMMARY_FILES
    assert len(summary.file_changes) <= differ.MAX_DIFF_SUMMARY_FILES


@pytest.mark.parametrize("seed", SEEDS)
def test_dropping_anything_always_sets_the_flag(seed):
    """The invariant the whole design rests on.

    A patch that was skipped or cut, and a flag that stayed False, is the
    silent skip B2 forbids: the assembled text is then under the cap, so a
    caller measuring it concludes the analysis was complete.
    """
    rng = random.Random(seed)
    patches = _random_patches(rng, rng.randint(1, 40))
    max_bytes = rng.choice([1, 500, 65536, differ.MAX_GENERATED_DIFF_BYTES])

    text, _summary, truncated = differ.generate_diff_bounded(
        _Repo(_Diff(patches)), "a", "b", max_bytes=max_bytes
    )

    metadata = [p for p in patches
                if differ._is_metadata_path(p.delta.new_file.path)]
    dropped = any(not p.read for p in metadata)
    cut = any(p.read and p._text not in text for p in metadata)

    if dropped or cut:
        assert truncated is True, "content was dropped with no truncation flag"


@pytest.mark.parametrize("seed", SEEDS)
def test_an_oversized_delta_is_never_read(seed):
    """The pre-materialisation ceiling holds for every combination."""
    rng = random.Random(seed)
    patches = _random_patches(rng, rng.randint(1, 40))

    differ.generate_diff_bounded(
        _Repo(_Diff(patches)), "a", "b",
        max_bytes=differ.MAX_GENERATED_DIFF_BYTES,
    )

    for patch in patches:
        declared = max(patch.delta.old_file.size, patch.delta.new_file.size)
        if declared > differ.MAX_PATCH_SOURCE_BYTES:
            assert not patch.read, (
                f"a {declared}-byte delta had its text requested"
            )


@pytest.mark.parametrize("seed", SEEDS)
def test_output_is_deterministic(seed):
    """Same deltas, same bytes: a report a reader can diff between runs."""
    rng = random.Random(seed)
    spec = _random_patches(rng, rng.randint(1, 30))

    def run():
        patches = [_Patch(p.delta, p._text) for p in spec]
        return differ.generate_diff_bounded(
            _Repo(_Diff(patches)), "a", "b", max_bytes=65536
        )

    first_text, first_summary, first_flag = run()
    for _ in range(3):
        text, summary, flag = run()
        assert text == first_text
        assert summary.files_changed == first_summary.files_changed
        assert summary.file_changes == first_summary.file_changes
        assert flag == first_flag


@pytest.mark.parametrize("seed", SEEDS)
def test_patch_count_is_bounded(seed):
    """A repository is free to hold any number of `.install` files."""
    rng = random.Random(seed)
    count = differ.MAX_DIFF_PATCHES + rng.randint(1, 50)
    patches = [
        _Patch(_Delta(f"h{i}.install", 10), "@@ -1 +1 @@\n+x")
        for i in range(count)
    ]

    _text, _summary, truncated = differ.generate_diff_bounded(
        _Repo(_Diff(patches)), "a", "b",
        max_bytes=differ.MAX_GENERATED_DIFF_BYTES,
    )

    assert sum(1 for p in patches if p.read) <= differ.MAX_DIFF_PATCHES
    assert truncated is True


def test_an_invalid_budget_is_refused_before_repository_work():
    """A bad limit fails at the boundary, not halfway through a diff."""
    touched = []

    class _Watching(_Repo):
        def diff(self, *_a, **_k):
            touched.append(True)
            return _Diff([])

    for bad in (0, -1, True, "5", 2.5, None.__class__):
        with pytest.raises(ValueError):
            differ.generate_diff_bounded(
                _Watching(None), "a", "b", max_bytes=bad
            )
    assert not touched, "repo.diff ran before the limit was validated"
