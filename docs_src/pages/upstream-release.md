<!-- description: Upstream-release rules: what the declared upstream repository and its build automation do, read over the signed federated indicator channel rather than fetched, plus the unauditable source transports a local read cannot reach. -->

# Upstream Release Integrity


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
