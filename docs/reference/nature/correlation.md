<!-- description: Where the correlation rules come from (the immune-import model of campaigns) and what a G finding means. -->

# Correlation

Mechanics (target, severity, weight, condition) live on the
[Correlation system page](../rules/correlation.md). This page is the other
half: where the G rules come from and how to read one.

<!-- generated: nature-rules -->
**Rules in this nature:** [G001](../rules/correlation.md#g001), [G002](../rules/correlation.md#g002), [G003](../rules/correlation.md#g003), [G004](../rules/correlation.md#g004), [G005](../rules/correlation.md#g005), [G006](../rules/correlation.md#g006), [G007](../rules/correlation.md#g007), [G008](../rules/correlation.md#g008), [G009](../rules/correlation.md#g009), [G010](../rules/correlation.md#g010), [G011](../rules/correlation.md#g011), [G012](../rules/correlation.md#g012), [G013](../rules/correlation.md#g013), [G014](../rules/correlation.md#g014) (14 rules).
<!-- /generated: nature-rules -->

## Where it comes from

The G-series is TrustSight's immune system, imported wholesale from the
campaign-alert design ("Spec B: Immune Imports"). A single package doing
something odd is a local event; several unrelated packages doing the same new
thing at once is an **infection**, and the body's answer to an infection is
not "inspect each cell harder" but "raise the whole neighbourhood's
readiness, then stand it down".

Three immune ideas are borrowed:

- **Clonal recognition (the joins).** G001 to G004 are shared-antigen
  detectors: one gained host, one added literal, one adopted maintainer, one
  upstream dependency, seen across enough unrelated packages in a window.
  This is what turns N identical findings into one campaign alert. Plausible
  once, damning five times.
- **Cytokine signalling (the neighbourhood).** When a campaign is active,
  G006 marks packages that newly touch its scope. An alerted neighbourhood
  raises the surrounding tissue's readiness without attacking it.
- **Trained immunity (the corroboration).** G007 names a run that stands
  inside an active campaign's scope. The state is primed for a while, then it
  expires on its own (see [Campaign Alert Mode](../../explanation/campaign-alert-mode.md)).

The failure mode the design is built around is chronic inflammation: an alarm
that never switches off becomes the disease. Every part of the mechanism -
observation-clock TTL, structural expiry, the alert budget - exists to make
the primed state end.

## What a finding means

- A G finding is a claim about a **set**, never about one package. The
  members still get the cluster alert and the campaign state, but membership
  must not inflate any member's own score. G005 (impersonation) and G008
  (first-seen adoption burst) are the sharp, scoring signals; the
  host/literal/dependency/adopter joins score the cluster, and the
  neighbourhood, corroboration, watchlist, first-seen-host and multi-account
  payload joins (G006, G007, G009, G010, G011-G014) are weight 0 on the
  member. G011-G014 still prime campaign state; the escalation is the
  campaign alert, not an inflated member score.
- The evidence names the members and the shared **class** (a host, a literal
  length, a maintainer), never the shared content's meaning: a literal is
  reported by class and length, not printed.
- One firing is one alert. If you see several G findings, you are looking at
  several distinct campaigns.
- G runs at cycle end in the full-AUR sweep: the input is collective, and one
  package cannot supply it. G007 is the exception, reading an active
  campaign's stored scope on a single `review` run.

### What each G rule means

| Rule | Spec-B mechanism | A finding means |
|---|---|---|
| G001 Shared Gained Host | clonal recognition (shared antigen) | enough unrelated packages gained the same host this window |
| G002 Shared Added Literal | clonal recognition | the same large literal appeared in unrelated packages |
| G003 Coordinated Adoption | clonal recognition | one maintainer key adopted several packages in the window |
| G004 Shared Upstream Dependency | clonal recognition | the same new upstream dependency, and host, entered several packages |
| G005 Impersonation Campaign | the trigger | one account published many name-clones of far more popular packages |
| G006 Neighborhood Under Campaign Alert | cytokine signalling | a package newly touched an active campaign's scope; weight 0, report-only |
| G007 Campaign Corroboration | trained immunity | a run stands inside an active campaign's scope; weight 0 |
| G008 First-Seen Account Adoption Burst | clonal recognition | a first-seen account adopted many dormant packages at once |
| G009 Watchlisted Subject | operator memory | a package, or its maintainer, is on the operator's curated watchlist; weight 0 |
| G010 Shared First-Seen Host | clonal recognition (novelty join) | enough unrelated packages gained the same host the corpus had not met before; weight 0 |
| G011 Maintainer Package Creation Burst | clonal recognition (creation window) | a first-seen account created many unrelated brand-new packages; an H104 placeholder majority escalates it |
| G012 Shared Payload Signal | clonal recognition (shared rule) | several maintainers' unrelated packages fired the same specific payload rule |
| G013 Shared Fetch Target | clonal recognition (shared endpoint) | several maintainers' unrelated packages fetched the same canonical URL |
| G014 Shared Adoption Window | clonal recognition (multi-account) | several maintainers adopted unrelated dormant packages in one window |

## See also

- [Campaign Alert Mode](../../explanation/campaign-alert-mode.md); how the primed state arms, expires, and is capped
- [Neighborhood Elevation](../../explanation/neighborhood-elevation.md); the cytokine rule in full
- [Alert Budget](../../explanation/alert-budget.md); why a campaign must not become noise
- [Correlation system page](../rules/correlation.md); fields and conditions
