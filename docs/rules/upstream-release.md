<!-- description: Upstream-release rules: what the declared upstream repository and its build automation do, read over the signed federated indicator channel rather than fetched, plus the unauditable source transports a local read cannot reach. -->

# Upstream Release Integrity

## Overview


These rules ask what the upstream this recipe trusts is actually shipping.
[Temporal](temporal.md) already reports that an update *arrived*; this page asks
what arrived.

The split is enforced by what TrustSight is allowed to read. [Upstream
Manifests](upstream-manifests.md) reads the declared repository tree. Here, the
build automation of a foreign repository is exactly what A2 forbids a local
read of, so U007 and U008 do not fetch: they are **indicator** rules, matched
against a publisher's signed `upstream_repo` set over
[IOC Federation](../reference/ioc.md). U009 is the one local surface, a weight-0 ledger
entry for a workflow committed beside the recipe, and U010 is a local read of
the `source=()` array for transports the public cannot inspect.

A federation miss is uninformative and never lowers a score. An
`upstream_repo` match carries no points and is alerted at maximum priority, the
same as any other indicator; see [Indicator](indicator.md).

See [Rule Mechanics](mechanics.md) for the field table, the severity
weights and the reserved identifier ranges.

---

## Threat context

A recipe names the upstream it trusts: a `url=`, a set of `source=()`
entries, sometimes a `validpgpkeys=`. That declaration is a promise about
code the reviewer usually cannot see. The upstream-release family is the
reading of that promise at the border.

Two of its rules look at build automation. The workflow lives in the
upstream repository, and A2 forbids a local analyser from fetching it, so a
scanner with legitimate access publishes a signed `upstream_repo` shape over
the federation channel. U007 and U008 consume that shape; they never read
the workflow themselves. When the channel is cold, a miss is reported as a
boundary rather than as absence of malice.

The other two read only the recipe the diff already carries. U009 notes a
workflow committed beside the package, and U010 reads the access mode of a
source the diff gained: SSH, `file://`, a private-network literal, or an
embedded credential.

The same signed channel carries `upstream_hash`: an exact
`url|version|checksum` triple a scanner observed at the vendor. C001 reads
it to corroborate a checksum change the local source cannot explain: a
match reports the change at weight 0, a miss leaves the HIGH weight alone.

The spec's flagship, a release re-tagged under an unchanged URL and
version, is already [C001 Checksum Changed Without Source
Change](integrity.md). This family does not file it twice. On the
8,393-diff benign corpus C001 fires on 5 (0.13%), the false-positive floor the
re-tag reading carries against ordinary package churn.

## Detection mechanisms

The rules that make up this category are listed below, each with the series that implements it and the severity it carries. Scoring, matching and identifier allocation are shared across every category: see [Rule Mechanics](mechanics.md).

## Individual rules

<!-- generated: page-index -->
| Rule | Name | Severity |
|---|---|---|
| [U007](#u007) | CI Exfil Shape | MEDIUM |
| [U008](#u008) | Git-History Credential Sweep | MEDIUM |
| [U009](#u009) | New CI Surface Committed | LOW |
| [U010](#u010) | Unauditable Upstream | MEDIUM |
| [U013](#u013) | CI Exfil Shape (Local) | MEDIUM |
| [U014](#u014) | Git-History Credential Sweep (Local) | MEDIUM |
<!-- /generated: page-index -->

### U007: CI Exfil Shape {#u007}

- **Target:** declared upstream repository (federation-fed)
- **Severity:** MEDIUM
- **Category:** `upstream-ci`

- **Condition:** A signed federation finding reports that the repository this
  recipe declares as its upstream (`url=`) gained a workflow matching the
  GhostAction exfil shape: a `${{ secrets.` reference paired with an outbound
  transfer to an IP literal or an unknown host.

The workflow content lives upstream, where A2 forbids a local read, so the
shape arrives over the signed `upstream_repo` federation channel and is never
fetched. A `pkgver` bump in the same diff is reported as context - the update
is about to distribute whatever the upstream now builds - but is not required.
A miss is uninformative, as with every indicator.

### U008: Git-History Credential Sweep {#u008}

- **Target:** declared upstream repository (federation-fed)
- **Severity:** MEDIUM
- **Category:** `upstream-ci`

- **Condition:** The same federation channel, the history-sweep shape: a
  workflow that materializes full history (`fetch-depth: 0`) and greps the
  commit history for credential patterns.

Independent of U007's exfil clause, so a repo reported for one shape does not
imply the other. The workflow content is upstream and unreadable locally (A2);
the signed `upstream_repo` entry is the only source.

### U009: New CI Surface Committed {#u009}

- **Target:** committed .github/workflows/* files
- **Severity:** LOW (weight 0)
- **Category:** `upstream-ci`

- **Condition:** The diff adds a file under `.github/workflows/`
  (`*.yml` or `*.yaml`) to the package repository.

A new automation surface in the AUR repository. Rare (most AUR repositories
carry no CI), so it is emitted as `ci_surface_gained` at **weight 0** and never
scored: it is a corroboration feed for U007/U008 and for IOC hits, not a claim
on its own. AUR repositories are not where a package builds, but a workflow
committed beside the recipe is a surface worth naming.

### U010: Unauditable Upstream {#u010}

- **Target:** declared source=() transport and access mode
- **Severity:** MEDIUM
- **Category:** `source`

- **Condition:** A gained `source=()` entry the public cannot inspect, in one
  of these shapes: embedded credentials in the authority
  (`scheme://user:token@host/...`); a private access transport
  (`git+ssh://`, `ssh://`, scp-style `git@host:path`); a private-network or
  local literal (`localhost`, RFC 1918, loopback, `file://`).

A malicious package wants payload nobody checks, and an authenticated or
private-network upstream guarantees exactly that for every reviewer who is not
the maintainer. Legitimate intranet and corporate AUR packages exist, which is
why the verdict is a review-queue entry and the severity sits at MEDIUM.

A credential-bearing public web URL is [C020](integrity.md#c020)'s finding, and
a public IP-literal host is [C023](integrity.md#c023)'s; U010 stands down on
both and keeps the transports they cannot see. When the recipe also carries no
`validpgpkeys`, the finding calls that out explicitly: no third party can see
the source and no signature vouches for it. This is corroborating evidence,
not a score change.

Measured on the v1 benign corpus, U010 fires on none: the transports it
reads are deliberate choices, not background churn.

### U013: CI Exfil Shape (Local) {#u013}

- **Target:** fetched upstream workflow
- **Severity:** MEDIUM (weight 0)
- **Category:** `upstream-ci`

- **Condition:** A fetched upstream workflow (`.github/workflows/*`) that
  references a repository secret (`${{ secrets.`) and sends it to an IP
  literal or to a host outside the small known-egress set.

This is the local counterpart of U007. It runs only when the operator enabled
`[upstream_scan]`, the declared archive's checksum verified, and the workflow
was read from that archive. It is anergic (weight 0) until the corpus
calibrates it, so it is a report-only signal rather than a scored claim.

### U014: Git-History Credential Sweep (Local) {#u014}

- **Target:** fetched upstream workflow
- **Severity:** MEDIUM (weight 0)
- **Category:** `upstream-ci`

- **Condition:** A fetched upstream workflow that checks out full history
  (`fetch-depth: 0`) and greps that history for credential-shaped patterns.

This is the local counterpart of U008. It runs only on a workflow read by the
opt-in `[upstream_scan]` lane and is anergic (weight 0) until calibrated.

## Interpretation

- A U007/U008 finding attributes an upstream repository to a published,
  signed shape. It is evidence from the federation channel, not a local
  fetch, and it never lowers a score.
- U009 is a weight-0 ledger entry: a new automation surface in the package
  repository is worth noting, not scoring. It corroborates U007/U008 or an
  IOC hit when they co-occur.
- U010 says the public cannot inspect a declared source. Without
  `validpgpkeys` the finding is amplified: nobody can see the source and no
  signature vouches for it. Corporate intranet packages legitimately look
  like this, which is why it is a review-queue signal and not a verdict.
- None of these rules reads upstream content. A finding is about a
  declaration or a signed observation, never about the cargo inside the
  box.

## Related documentation

- [Upstream Manifests](upstream-manifests.md); the declared repository tree
- [Indicators](indicator.md); the signed-data mechanism the federation rules use
- [Integrity and Verification](integrity.md); the checksum promise C001 reads
