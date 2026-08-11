# IOC baseline source data

Curated indicator lists that `scripts/build_ioc_baseline.py` turns into signed
IOC federation baselines (see [the IOC reference](../../docs/reference/ioc.md)
and A13b in [the security model](../../docs/security.md)).

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
| `type` | yes | `domain`, `hash`, or `package`. |
| `value` | yes | The indicator. Domains are normalised to the registered domain and IDNA-folded; hashes must be hex of a known length; package names are matched case-insensitively. |
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
   is guaranteed to import. Publish `ioc-baselines/<incident>/` and pin the
   curator's public key in `[baselines.ioc]` config.

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
