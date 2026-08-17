# IOC Federation

An IOC (Indicator of Compromise) list is a versioned inventory of known-bad
artifacts: confirmed-malicious domains, file hashes, and package names. It sits
**outside** the heuristic score. When a PKGBUILD matches an IOC entry,
TrustSight emits a definitive, attributed finding ("this source domain is on
`emiliano-go`'s known-bad list, incident `atomic-arch-2026-06`") with no score,
no band, and no probability language. This is detection, not inference.

The design rests on four principles:

- **State, not rules.** IOCs are observations about the world, so they live in
  the baseline layer next to the corpus baseline ([A13/A13b](../security.md#part-a-trustsight-as-a-program-under-attack)),
  never in the rule config. An override or a weight cannot reach them.
- **Attribution, not aggregation.** Every match names the curator that flagged
  the artifact. The user sees who called it bad, and can follow the incident
  and evidence.
- **Federation, not centralization.** Independent curators publish signed
  baselines; TrustSight verifies, imports, and reports with source labels.
- **Expiration, not permanence.** IOCs carry a time-to-live. An expired
  indicator is reported as expired, never silently ignored and never
  permanently flagged.

---

## The baseline format

A baseline is a directory:

```
ioc-baseline/
├── manifest.json
└── iocs.jsonl
```

### `manifest.json`

```json
{
  "version": 1,
  "source": "emiliano-go",
  "created_at": "2026-08-09T00:00:00Z",
  "expires_at": "",
  "signature": "<hex ed25519 signature, or empty>",
  "public_key": "<hex ed25519 public key, or empty>"
}
```

### `iocs.jsonl`

One JSON object per line:

```json
{"type": "domain", "value": "evil-cdn.xyz", "source": "emiliano-go", "confidence": "high", "provenance": "ASA-2026-06", "campaign": "atomic-arch-2026-06", "expires_at": "2026-09-15T00:00:00Z"}
{"type": "hash", "value": "deadbeef...", "source": "emiliano-go", "confidence": "high", "provenance": "vendor report"}
{"type": "package", "value": "malicious-aur-pkg", "source": "emiliano-go", "provenance": "ASA-2026-06"}
```

Any entry with an unknown `type`, an unusable `value`, or no `source` is
dropped with a warning; the rest import.

### Indicator types and normalization

| Type | Match target | Normalization |
|------|--------------|---------------|
| `domain` | Host of a `source=` URL (or any referenced host) | Lowercased, IDNA/punycode-folded, reduced to the registered domain, so a subdomain and the `xn--` and unicode spellings all collapse to one value. |
| `hash` | Digests inside `sha256sums` / `sha512sums` / `md5sums` (and any other hex digest in the visible text) | Lowercased; must be a hex digest of a known length (32/40/56/64/96/128). |
| `package` | `pkgname` / `pkgbase` and declared dependency names | Lowercased, exact match. |

### Signature

`signature` is a detached Ed25519 signature over the canonical
`manifest.json` (with the `signature` field emptied) concatenated with
`iocs.jsonl` byte-for-byte. Verification uses the `public_key` carried in the
manifest; IOC curator keys are not pinned in configuration. An unsigned
baseline imports only with `--allow-unsigned`, which is for a baseline you
built and trust locally.

---

## How matching works

A dedicated **IOC Match** stage runs after rule matching and before scoring:

```
Parse -> Tokenize -> Rule Match -> IOC Match -> Score -> Verdict
```

It reads the diff's added lines (or the whole PKGBUILD text when available)
and queries the stored indicators for every source-URL host, every checksum
and hex digest, and the package/pkgbase/dependency names. Hits are attached to
`PackageFact.ioc_matches`; see the [report schema](report-schema.md).

Each `IocMatch` carries `type`, `value`, `source`, `confidence`, `provenance`,
`campaign`, the `surface` it was found on (`source_host`, `checksum_array`,
`package_name`, a dependency field, ...), the `line`, and `expired`.

### What an IOC match does not do

- **It never changes the score.** Matches live on `ioc_matches`, never in
  `score_breakdown`; the same PKGBUILD scores identically with or without a
  hit. IOCs are attribution the reviewer can verify, not a number.
- **It is not downgraded by a coverage gap, positive evidence, or an
  override.** If an indicator matched in the analysed text, it is reported.
- **It does not disappear when it expires.** An expired indicator is still
  reported, labelled expired, so a lapsed indicator never reads as clean. Only
  `trustsight ioc list` hides expired entries by default (pass
  `--include-expired`).

These properties are enforced by the gates `an IOC match carries its source`,
`IOC matches never contribute to the score`, `an expired IOC is never silent`,
and `IOCs are not in the rule config layer` (see the
[enforcement map](../security.md#part-c-the-enforcement-map)).

---

## Configuration and commands

The `[baselines.ioc]` section and its feeds are documented in
[configuration](configuration.md#baselinesioc). The
`trustsight ioc {sources,import,update,list,export}` commands are documented
in the [CLI reference](cli.md#trustsight-ioc).

Storage is the `ioc_entries` table, keyed by `(type, value, source)`.
Importing a baseline for a source replaces that source's rows and leaves other
sources (and expired rows) untouched, so imports are idempotent and
attributable.

---

## Harvesting

Turning advisories and community reports into signed baselines is the job of a
separate project, not TrustSight's codebase: a harvester proposes candidate
entries, human curators review and sign, and TrustSight only ever consumes the
signed output. Keeping the harvester out of the tool is what keeps the IOC gate
non-evadable by construction: a hash either matches or it does not, and no code
in TrustSight decides what belongs on the list.
