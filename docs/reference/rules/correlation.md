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

## Reading a G finding

- The evidence names the members (package names), never the shared
  content's meaning; for a shared literal it names the class and length,
  not the literal.
- One firing covers the whole cluster, so the alert count is the campaign
  count.

<!-- generated: page-index -->
## Rules on this page

| Rule | Name | Severity |
|---|---|---|
| [G001](#g001) | Shared Gained Host | HIGH |
| [G002](#g002) | Shared Added Literal | HIGH |
| [G003](#g003) | Coordinated Adoption | MEDIUM |
<!-- /generated: page-index -->

### G001: Shared Gained Host {#g001}

**HIGH** (weight 25) · category `correlation`

Fires when the same gained canonical host appears in `[thresholds]
g_host.min_packages` (default 5) distinct packages within the cycle window.
atomic-arch's signature: a new CDN added by many unrelated packages at once.

### G002: Shared Added Literal {#g002}

**HIGH** (weight 25) · category `correlation`

Fires when an identical added literal above `[thresholds]
g_blob.min_length` (default 256) characters appears in `g_blob.min_packages`
(default 2) unrelated packages in the window. The literal's content is
never printed - only its length and the members.

### G003: Coordinated Adoption {#g003}

**MEDIUM** (weight 15) · category `correlation`

Fires when one maintainer key adopts at least `[thresholds]
g_adopt.min_members` (default 3) packages in the window.
