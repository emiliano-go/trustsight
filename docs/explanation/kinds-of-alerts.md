<!-- description: TrustSight uses the word "alert" for several different things. This page tells them apart. -->

# Kinds of Alerts

"Alert" is an overloaded word in TrustSight. This page spells out the
different things that name can mean, so a report is never read as the wrong
one.

## Findings (the payload)

The ordinary result of a rule matching. A finding has a rule id, a severity,
and - where it can - a file and line. Findings score according to their
severity weight. Everything else on this page either *describes* findings or
describes the run, rather than adding new suspicions.

## Boundaries (what the run could not read)

Some W-series rules and coverage gaps are **weight-0 boundaries**: statements
that something ran, or was skipped, that the analysis could not fully read.
They are always shown, they never score, and a gap among them forbids a clean
verdict. See [What TrustSight Cannot See](what-trustsight-cannot-see.md).

**W010 (Alert Volume Capped)** is a boundary of a different flavour - it
records that the terminal was capped, not that anything was unread, so it
never forbids a clean verdict. See [Alert Budget](alert-budget.md).

## Corpus cluster findings (a campaign shape)

When TrustSight runs over the whole AUR (`full-aur`), several rules look
*across* packages at once: **H045/H052/H055/H073** and the **G-series**. One
firing covers the whole cluster and names its members - a campaign is one
alert, not N. Most of these score; the burst rules (`H052`/`H055`) only score
when a member actually impersonates a popular package.

**G005 (Impersonation Campaign)** is the sharp end of this family: many
name-clones of popular packages under one account. Not every G rule is live
yet: **G002** and **G004** ship and are unit-tested, but their corpus feeds are
pending, so on a real cycle only G001, G003 and G005 fire. See the
[correlation reference](../reference/rules/correlation.md).

## Campaign alerts (primed state)

When a campaign is corroborated, TrustSight enters **campaign alert mode** for
a bounded number of observations. While primed, a package in the campaign's
scope is flagged (**G006**, weight 0). This is state, not a new finding. See
[Campaign Alert Mode](campaign-alert-mode.md).

## The watch webhook (something to read now)

`full-aur --watch` POSTs one JSON document per cycle that had something new.
It is a *notification*, not a finding: it carries counts, the flagged
packages, IOC matches, campaign clusters, and any impersonation campaign. Its
priority is deliberately mild - the urgent tier pages at night, which is
worse than a quiet panel in the morning.

## Heartbeat

A once-a-day "still watching" message, priority low. Its whole job is to tell
apart "nothing found" from "the watcher is dead".

## Expiry notices (state that lapsed)

Two things can lapse and are reported once rather than silently dropped: an
**expired indicator** and an **expired override** (a suppression past its
observation TTL). In both cases silence is never allowed to mean both "never
existed" and "ended". Overrides are covered in
[Override Tolerance](override-tolerance.md).

## Tool-health (M-series)

A few M-series entries describe the **instrument**, not the package - for
example a rule that is expected to co-fire and did not. They are weight-0,
never scored, and go to the harness/calibration output rather than a
package's finding list.

## Related

- [Alert Budget](alert-budget.md)
- [Campaign Alert Mode](campaign-alert-mode.md)
- [Override Tolerance](override-tolerance.md)
