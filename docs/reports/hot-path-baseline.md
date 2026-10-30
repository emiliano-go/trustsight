# Hot-path baseline and first optimization

Measured on the checkout, serial, against the fetched locked benign corpus
(`tests/fixtures/benign-corpus`, 8,393 diffs).

Reproduce:

```bash
uv run python scripts/profile_hot_path.py corpus --sample 50 --limit 25
uv run python tests/harness/finding_parity.py --check /tmp/fp-baseline.json --sample 50 --jobs 2
```

## Baseline (sample=50, 167 diffs)

| Metric | Value |
|---|---|
| Wall | 94.26 s |
| Per diff | 0.564 s |
| Tokenizer sandbox requests | 16,344 (98/diff) |
| Child round-trips (`_send`) | 3,873 (23/diff) |
| `tokenize_and_resolve_indexed` | 60.9 s cumulative |
| `resolve_added_lines` | 36.2 s (3,685 calls = 22/diff) |
| `recipedoc.parse_recipe` | 18.4 s (1,897 calls = 11/diff) |
| `change_delta` | 22.1 s |
| `line_lex` | 14.7 s |
| `apply_rules` | 7.0 s |

The dominant cost is the tokenizer sandbox round-trips, not rule matching.
`apply_rules` is ~7% of the serial corpus scan; the process-pool rule plan is
therefore lower priority than memoization.

## First change

Parent-side, per-thread memos in `tokenizer.py` for the pure tokenizer
answers (`resolve_added_lines`, `resolve_removed_lines`, indexed resolution,
joined lines, variable tables, reconstruction, clean/strip) plus
`recipedoc.parse_recipe` / `recipe_states`. Each cache keeps a private copy
so a caller cannot mutate the cached value. The sandbox still computes every
distinct input; equal inputs are served once per thread.

## After memoization (same sample)

| Metric | Baseline | After |
|---|---|---|
| Wall | 94.26 s | 50.06 s |
| Per diff | 0.564 s | 0.300 s |
| Sandbox requests | 16,344 | 5,071 |
| `parse_recipe` calls | 1,897 | 831 |
| `resolve_added_lines` cumulative | 36.2 s | 15.5 s |

Finding parity on the same sample: **377 replays, 0 mismatched**.

## Next

- Share one resolved rule/config snapshot per package (watcher path still
  calls `load_rules()` per analysis).
- Cache URL classification (`_prepare`, `tldextract`) and reuse the cycle's
  parsed PKGBUILD in the corpus sweep.
- SQLite `mmap_size` and `executemany` for `triggered_rules`.
- Consider a combined tokenizer operation (one child parse for both
  `resolve_added` and `indexed`, and for recipe joins/tables) if the
  remaining `select` wait justifies the engine change.
