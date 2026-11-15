<!-- description: G-series rules correlate across packages - a shared gained host, a shared added literal, or a coordinated adopter - one alert for a campaign rather than N identical findings. -->

# Correlation


G rules take the **set** of recent analyses as their input. D walks one
package's dependency graph; T reads one package's history; G asks what
several packages share.

This is what makes a campaign visible: a "new CDN" is plausible once and
damning when five unrelated packages add it in the same week. G finds the
join, names the members, and fires **one** alert instead of N.

G runs at cycle end in the full-AUR sweep; the input is collective and a
single package cannot supply it. G007 is the exception: a `review` run inside
an active campaign reads that campaign's stored scope, so it fires there too.

This is a reference page. For how weight and scope work, see
[Rule Mechanics](mechanics.md).

## Reading a G finding

- The evidence names the members (package names), never the shared
  content's meaning; for a shared literal it names the class and length,
  not the literal.
- One firing covers the whole cluster, so the alert count is the campaign
  count.

---
