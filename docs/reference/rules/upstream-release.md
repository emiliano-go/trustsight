<!-- description: Upstream-release rules: what the declared upstream repository and its build automation do, read over the signed federated indicator channel rather than fetched, plus the unauditable source transports a local read cannot reach. -->

# Upstream Release Integrity

Where these rules come from and what a finding means: [Rule Nature](../nature/upstream-release.md).

These rules ask what the upstream this recipe trusts is actually shipping.
[Temporal](temporal.md) already reports that an update *arrived*; this page asks
what arrived.

The split is enforced by what TrustSight is allowed to read. [Upstream
Manifests](upstream-manifests.md) reads the declared repository tree. Here, the
build automation of a foreign repository is exactly what A2 forbids a local
read of, so U007 and U008 do not fetch: they are **indicator** rules, matched
against a publisher's signed `upstream_repo` set over
[IOC Federation](../ioc.md). U009 is the one local surface, a weight-0 ledger
entry for a workflow committed beside the recipe, and U010 is a local read of
the `source=()` array for transports the public cannot inspect.

A federation miss is uninformative and never lowers a score. An
`upstream_repo` match carries no points and is alerted at maximum priority, the
same as any other indicator; see [Indicator](indicator.md).

See [the rule system reference](system.md) for the field table, the severity
weights and the reserved identifier ranges.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [U007](#u007) | CI Exfil Shape | MEDIUM |
| [U008](#u008) | Git-History Credential Sweep | MEDIUM |
| [U009](#u009) | New CI Surface Committed | LOW |
| [U010](#u010) | Unauditable Upstream | MEDIUM |
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
