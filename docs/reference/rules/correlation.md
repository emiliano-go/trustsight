<!-- description: G-series rules correlate across packages - a shared gained host, a shared added literal, or a coordinated adopter - one alert for a campaign rather than N identical findings. -->

# Correlation

G rules take the **set** of recent analyses as their input. D walks one
package's dependency graph; T reads one package's history; G asks what
several packages share.

This is what makes a campaign visible: a "new CDN" is plausible once and
damning when five unrelated packages add it in the same week. G finds the
join, names the members, and fires **one** alert instead of N.

G runs at cycle end in the full-AUR sweep, never on a single `review`; the
input is collective and a single package cannot supply it.

This is a reference page. For how weight and scope work, see
[Rule System](system.md).

!!! warning "Not yet live: G002 and G004"

    The G002 (added-literal) and G004 (upstream-dependency) engines ship and
    are unit-tested, but the corpus views that would supply them
    (`added_literals`, `upstream_dep_additions`) are not yet connected to the
    live `full-aur` sweep. On a real cycle today only **G001, G003 and G005**
    can fire. Treat G002/G004 in any rule list as planned coverage, not active
    watcher coverage.

## Reading a G finding

- The evidence names the members (package names), never the shared
  content's meaning; for a shared literal it names the class and length,
  not the literal.
- One firing covers the whole cluster, so the alert count is the campaign
  count.

---

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [G001](#g001) | Shared Gained Host | HIGH |
| [G002](#g002) | Shared Added Literal | HIGH |
| [G003](#g003) | Coordinated Adoption | MEDIUM |
| [G004](#g004) | Shared Upstream Dependency | HIGH |
| [G005](#g005) | Impersonation Campaign | HIGH |
| [G006](#g006) | Neighborhood Under Campaign Alert | INFO |
| [G007](#g007) | Campaign Corroboration | INFO |
<!-- /generated: page-index -->

### G001: Shared Gained Host {#g001}

- **Target:** programmatic (cycle records)
- **Severity:** HIGH (weight 25)
- **Category:** `correlation`
- **Condition:** The same gained canonical host appears in `[thresholds] g_host.min_packages` (default 5) distinct packages within the cycle window.

atomic-arch's signature: a new CDN added by many unrelated packages at once.

### G002: Shared Added Literal {#g002}

- **Target:** programmatic (cycle records)
- **Severity:** HIGH (weight 25)
- **Category:** `correlation`
- **Condition:** An identical added literal above `[thresholds] g_blob.min_length` (default 256) characters appears in `g_blob.min_packages` (default 2) unrelated packages in the window.

The literal's content is never printed - only its length and the members.

**Feed pending.** The engine ships and is unit-tested, but the corpus
literal-hash view that would supply `added_literals` in the live sweep is not
yet connected, so G002 does not fire on a `full-aur` cycle today.

### G003: Coordinated Adoption {#g003}

- **Target:** programmatic (cycle records)
- **Severity:** MEDIUM (weight 15)
- **Category:** `correlation`
- **Condition:** One maintainer key adopts at least `[thresholds] g_adopt.min_members` (default 3) packages in the window.

Adoption is the temporal engine's own predicate - H044 (ownership transition) or H086 (orphan-to-maintained) - recorded per package, not a bare maintainer-change. The finding's `predicates` names which T instance the group joined on; H074 (mass adoption) is the cross-package aggregation this rule performs.

### G004: Shared Upstream Dependency {#g004}

- **Target:** programmatic (cycle records)
- **Severity:** HIGH (weight 25)
- **Category:** `correlation`
- **Condition:** The same upstream dependency (and host), added to a committed manifest, appears in at least `[thresholds] g_dep.min_packages` (default 2) packages in the window.

The committed-manifest counterpart to G001: a dependency name and remote host that many packages gain in the same window is the same-new-upstream-dependency campaign shape. It reads the recorded `upstream_dep_additions` view (the U-series dependency additions); the engine ships and is unit-tested, and the corpus feed that fills the view is the same pending work G002's literal feed is.

### G005: Impersonation Campaign {#g005}

- **Target:** programmatic (cycle records)
- **Severity:** HIGH (weight 25)
- **Category:** `correlation`
- **Condition:** One maintainer publishes at least `[thresholds] g_impersonation.min_members` (default 3) packages in the window whose names resemble a *far* more popular AUR package (the corpus H029 check over AUR vote counts).

The registry-impersonation campaign shape: many near-identical name-clones of popular packages under a fresh account (`yyay`/`yay`, `parru`/`paru`, …). Where H029 reports one clone, G005 names the campaign - its maintainer, the member count, and the impersonated targets - so a flood of typosquats reads as one alert, not N. It fires only on the per-package impersonation evidence, so a maintainer updating their own legitimate variant family is not a campaign.

### G006: Neighborhood Under Campaign Alert {#g006}

- **Target:** programmatic (cycle records)
- **Severity:** INFO (weight 0)
- **Category:** `correlation`
- **Condition:** While a campaign is active (see [Campaign Alert Mode](../../explanation/campaign-alert-mode.md)), a package in the window *gains* a host or domain in that campaign's scope, without itself being corroborated.

The cytokine effect: an alerted neighborhood raises the surrounding tissue's readiness. It is reported, never scored, in v1 - "touches an alerted neighborhood" names a context, not a behaviour - and it never forbids a clean verdict. Only *gained* hosts count.

### G007: Campaign Corroboration {#g007}

- **Target:** programmatic (a run inside an active campaign)
- **Severity:** INFO, weight 0 to 5 (the bounded bonus)
- **Category:** `correlation`
- **Condition:** A review run whose package, or a host it newly gained, stands in the scope of an active campaign.

Trained immunity, scored: while a campaign is primed, a package in its scope earns `+min(5, corroboration_count)` points, once, as one attributable breakdown entry carrying `campaign_id`. Bounded so a wide campaign cannot inflate a run, and inert when no campaign is active (the calibration corpus carries none). See [Campaign Alert Mode](../../explanation/campaign-alert-mode.md).
