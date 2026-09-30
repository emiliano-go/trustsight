# Compromised AUR package exposure list - Atomic Arch (2026-06)

A point-in-time snapshot of the AUR packages reported compromised during the
June 2026 "Atomic Arch" campaign. **This is an exposure reference, not an IOC
list.** These package names are *not* in the IOC layer and are never matched by
H056: the malicious commits were reverted and the packages re-published, so a
`package` indicator on them would flag a clean package forever. Use this to
audit a machine's install history, not to score a PKGBUILD.

## Files

| File | Rows | Contents |
|---|---|---|
| `packages.tsv` | 1,913 | Waves 1-2 and wave 3, merged and deduped. Columns: `package`, `waves`, `confidence`, `sources`. |
| `spam-packages.tsv` | 144 | The **separate** shell-rc-injection spam campaign. All 144 are defacement, none weaponized. Kept apart so it is never confused with the credential-stealer campaign. |

`confidence` is `primary-source` (corroborated by the aur-general thread or the
AUR git-mirror analysis) or `single-source`. `sources` names the upstream source
tags preserved from the primary list.

## Provenance and licensing

The lists are a merged derivative of the **MIT-licensed**
[`jasonherald/atomic-arch-check`](https://github.com/jasonherald/atomic-arch-check)
data files (`compromised-packages.tsv`, `compromised-packages-wave3.tsv`,
`aur-spam-2026-06.tsv`), compiled from the aur-general "AUR REPORT THREAD",
force-push analysis of the read-only AUR git mirror, the community cscs list, the
CachyOS forum, and published analyses (ioctl.fail, Sonatype, socket.dev).
See `NOTICE`.

**Deliberately not merged**, because we may not combine them into this
MIT-licensed project:

- [`lenucksi/aur-malware-check`](https://github.com/lenucksi/aur-malware-check) -
  **GPL-3.0**, a copyleft license this project cannot incorporate.
- `gbaker1/Atomic-Arch-Check` - no license file, so all rights reserved.
- `nightdevil00/AUR-Malware` - repository unavailable at build time.

They remain useful references for an operator checking a host; consult them
directly under their own terms.

## Caveats

- **No canonical list exists.** Arch published an incident notice but not a
  package list; every list is community-compiled, overlapping and point-in-time.
  The count moved from 400+ to roughly 1,700 (waves 1-2), plus wave 3, plus a
  later July 30 wave not captured here.
- The list may be incomplete and, because it errs toward catching exposure, may
  over-include. Treat a match as "investigate", not "proof".
- The official Arch repositories were never affected; only AUR content was.

## Refreshing

`scripts/refresh_aur_compromised.py` re-downloads the MIT upstream files and
regenerates `packages.tsv` and `spam-packages.tsv`. It makes network calls by
design and is **not** run in CI or tests.

```
python scripts/refresh_aur_compromised.py --check   # show what would change
python scripts/refresh_aur_compromised.py --apply    # write the files
```
