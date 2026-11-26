# L9 acceptance corpus

The diff corpus cannot reach an artifact rule, so the L9 lane is held honest by
this data instead. `expected.json` is the assertion table; the tests in
`tests/test_l9_corpus.py` run every fixture and compare the exact rule set.

- `rule-fixtures/` — one positive and one near-miss negative per A rule. A rule
  that fires on the negative is a shape defect, not a detection.
- `benign/` — manifests produced from real built packages on an Arch host. They
  may carry only the known census-shaped rules (A003, A005); anything else is a
  regression.
- `built/l9-clinic/` — a real `makepkg` artifact, its `PKGBUILD`, and the
  manifest produced from it. The producer parity test rebuilds the manifest from
  the archive.

Regenerate:

```bash
python scripts/build_l9_corpus.py --write-fixtures
python scripts/build_l9_corpus.py --import-benign bash curl git
```

The producer is `scripts/artifact_manifest.py`; it streams the archive and never
extracts or executes package code.
