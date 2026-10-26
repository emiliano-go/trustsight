<!-- description: How TrustSight stays briefly primed around a corroborated attack campaign - and why that primed state is designed to expire. -->

# Campaign Alert Mode

Most findings are about one package. A **campaign** is the opposite: several
packages moving together in a way that only makes sense when you look at them
all at once.

Campaign alert mode is what TrustSight does when it sees one. For a short,
bounded stretch it treats the packages a campaign touched as *primed* - more
worth a second look - and then it lets that state **expire on its own**.

## Where it comes from

The idea is borrowed from the immune system, specifically **trained
immunity**. A strong infection leaves the innate immune layer temporarily on
higher alert, so the next brush with the same threat is met faster. That is
useful.

The failure mode is just as important. If the state never switches off, the
alert *becomes* the disease - chronic inflammation, where the body attacks
itself because it forgot how to stand down. So the design is less about
switching alert mode *on* and more about making sure it switches itself
*off*.

## What counts as a campaign

TrustSight turns on campaign mode only when independent evidence already
agrees that something is a campaign. Today that is the correlation family:

- **G005 - Impersonation Campaign.** One account publishing many name-clones
  of popular packages (`yyay` next to `yay`). This is the strongest trigger.
- **G001/G002/G003/G004/G008/G011.** Many unrelated packages sharing a gained
  host, an added literal, an upstream dependency, or an adopter, a first-seen
  account sweeping dormant packages, or a first-seen account creating many
  brand-new packages.

Only those corroborating rules prime campaign state. The report-only members
of the family never do: **G006/G007** are context, **G009** is the operator's
watchlist note, and **G010** is a first-seen-host census. A weight-0
observation must not take one of the bounded campaign slots a real cluster may
need.

Each G rule reads a bounded transition window. G001/G002/G003/G004 feeds are
cleared at cycle start, so a host, literal or adoption recorded in an earlier
cycle cannot re-fire the join or keep a lapsed campaign primed. G011 reads the
recorded `cycle_events` window instead, because a creation burst can span
several cycles. A G002 campaign
is keyed by a digest of the shared literal (never its content); a G004 campaign
by the dependency *and* its host.

A single publisher's campaign tag on an indicator is *corroboration*, not a
campaign on its own. One source saying "campaign" is exactly the lane a
poisoner would use; agreement is what raises the alarm.

## What "primed" means

While a campaign is active, a package that ever touches the campaign's scope
- for G005, a name-clone of an impersonated target; for the host rules, a
host in the shared set - is flagged as standing in an alerted neighborhood
(rule **G006**, weight 0). This is a *report*, not a score. "Touches a hot
host" is a context, not a behaviour, so it never moves a number and never
blocks a clean verdict on its own.

## Why it expires, and how that is enforced

The lifetime is measured in **observations**, not seconds or days. One
observation is one recorded analysis. Two consequences follow:

- The tool never consults a clock it does not control. A campaign cannot be
  kept alive by a future-dated commit or a skewed machine clock.
- Expiry is **structural**, not a cleanup job. A campaign whose
  `activated_at_obs + ttl_obs` is behind the current observation count is
  simply never returned by the query that reads campaigns. There is no
  sweeper to forget to run.

When a campaign does lapse, TrustSight says so once - the way an expired
indicator is reported rather than quietly dropped. Silence is never allowed
to mean both "there was no campaign" and "the campaign ended".

## The caps that keep it from becoming chronic

- **`[alerts] max_active_campaigns`** limits how many campaigns can be primed
  at once. A new one evicts the oldest *only if its own lifetime has already
  lapsed*. A live campaign's window is never shortened.
- **`[alerts] campaign_ttl_observations`** keeps the default lifetime short -
  tens of observations, not thousands.
- A campaign class that re-arms far too often is surfaced as a tool-health
  note (`M006`, weight 0), not silently re-armed. The window is still
  refreshed; only the churn is reported.

None of this state is stored in a report or a config fingerprint. Like
recorded history, it is **instrument state**: it changes what TrustSight
knows, not what it is. Two machines with the same configuration and the same
observations stay in step.

## Related

- [Alert Budget](alert-budget.md) - the other guard against a run becoming
  noise the reviewer learns to ignore.
- [Kinds of Alerts](kinds-of-alerts.md) - where a campaign alert sits among
  everything else TrustSight reports.
