<!-- description: G-series rules correlate across packages - a shared gained host, a shared added literal, or a coordinated adopter - one alert for a campaign rather than N identical findings. -->

# Correlation

Where these rules come from and what a finding means: [Rule Nature](../nature/correlation.md).

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
[Rule System](system.md).

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
| [G008](#g008) | First-Seen Account Adoption Burst | HIGH |
| [G009](#g009) | Watchlisted Subject | INFO |
| [G010](#g010) | Shared First-Seen Host | INFO |
| [G011](#g011) | Maintainer Package Creation Burst | MEDIUM |
| [G012](#g012) | Shared Payload Signal | HIGH |
| [G013](#g013) | Shared Fetch Target | HIGH |
| [G014](#g014) | Shared Adoption Window | HIGH |
<!-- /generated: page-index -->

### G001: Shared Gained Host {#g001}

- **Target:** programmatic (cycle records)
- **Severity:** HIGH (weight 25)
- **Category:** `correlation`

- **Condition:** The same gained canonical host appears in `[thresholds] g_host.min_packages` (default 5) distinct packages within the cycle window.

atomic-arch's signature: a new CDN added by many unrelated packages at once.
The feed is the hosts each package gained **this cycle**; it is cleared at
cycle start, so a host gained months ago cannot re-join a later cycle. Split
outputs of one pkgbase are one project, not several unrelated packages.

### G002: Shared Added Literal {#g002}

- **Target:** programmatic (cycle records)
- **Severity:** HIGH (weight 25)
- **Category:** `correlation`

- **Condition:** An identical added literal above `[thresholds] g_blob.min_length` (default 256) characters appears in `g_blob.min_packages` (default 2) unrelated packages in the window.

The literal's content is never printed - only its length and the members.

The live sweep records each analysed package's added literals in the
`added_literal_hashes` view, and G002 joins them at cycle end. The feed is
**cycle-local**: the sweep clears it before analysing anything, so a literal
recorded by an earlier cycle or a `review` run does not survive into this one
and cannot re-fire the join. The join key is a digest of the full literal; the
stored text is a bounded diagnostic copy, so two distinct long literals that
share a prefix are not treated as identical. At most 256 literals per package
are kept in one cycle; a larger set is logged and the excess is not joined.
Split outputs of one pkgbase are one project, not several unrelated packages.
The finding's `params` carries `literal_length` and `literal_sha256` (the
digest, never the content) so the campaign can be keyed without printing the
shared literal.

### G003: Coordinated Adoption {#g003}

- **Target:** programmatic (cycle records)
- **Severity:** MEDIUM (weight 15); HIGH (weight 25) when escalated
- **Category:** `correlation`

- **Condition:** Among the packages processed in a cycle, one maintainer key is joined to at least `[thresholds] g_adopt.min_members` (default 3) packages with a recorded adoption predicate.

Adoption is the temporal engine's own predicate - H044 (ownership transition) or H086 (orphan-to-maintained) - recorded per package, not a bare maintainer-change. A package absent from the previous snapshot is a first observation, not an adoption, so a newly published package cannot join the group. The finding's `predicates` names which T instance the group joined on; H074 (mass adoption) is the cross-package aggregation this rule performs.

Only this cycle's maintainer transitions are adoptions: re-processing a
package with an unchanged maintainer (or one whose adoption was recorded in an
earlier cycle) does not join the group or re-arm its campaign. The
naming-relatedness stand-down is bounded at 64 members; above that the group is
not proven to be one family and stays a finding (fail-open to the alert).

**Novelty/dormancy escalation.** When the adopting maintainer is globally novel (its earliest recorded maintainer-event falls within `[thresholds] g003.novel_days`, default 30) and at least `[thresholds] g003.min_dormant` (default 2) of the adopted targets are dormant (AUR LastModified older than `[thresholds] g003.dormant_days`, default 180), the finding is escalated to HIGH - the fennekuiper shape, where a first-seen account sweeps up dormant orphans. The bare N-adoption shape stays MEDIUM, so an established maintainer keeps the old posture. The escalation changes the alert's severity and evidence, not member scores: like every G finding but G005, a correlation cluster does not score its own members.

### G004: Shared Upstream Dependency {#g004}

- **Target:** programmatic (cycle records)
- **Severity:** HIGH (weight 25)
- **Category:** `correlation`

- **Condition:** The same upstream dependency (and host), added to a committed manifest, appears in at least `[thresholds] g_dep.min_packages` (default 2) packages in the window.

The committed-manifest counterpart to G001: a dependency name and remote host that many packages gain in the same window is the same-new-upstream-dependency campaign shape. It reads the recorded `upstream_dep_additions` view, which the corpus writer clears at cycle start and repopulates with the dependencies each processed package added; a prior cycle's row cannot re-fire the join. Split outputs of one pkgbase are one project, not several unrelated packages.

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
- **Severity:** INFO, weight 0 (report-only)
- **Category:** `correlation`

- **Condition:** A review run whose package, or a host it newly gained, stands in the scope of an active campaign.

Trained immunity, reported: while a campaign is primed, a package in its scope is named as corroborated - one `G007` entry carrying `campaign_id`, weight 0. It adds no points: the bonus it replaced measured scope *breadth*, not corroboration, and the benign corpus carries no active campaign, so the points were never measured against the false-positive rate. Inert when no campaign is active. See [Campaign Alert Mode](../../explanation/campaign-alert-mode.md).

### G008: First-Seen Account Adoption Burst {#g008}

- **Target:** programmatic (cycle records)
- **Severity:** HIGH (weight 25)
- **Category:** `correlation`

- **Condition:** An account with no prior maintainer history in the local database adopts at least `[thresholds] g008.min_packages` (default 5) packages within `[thresholds] g008.window_days` (default 7) days, and at least `[thresholds] g008.min_dormant` (default 3) of those targets are dormant (last git activity older than `[thresholds] g008.dormant_days` (default 180) days).

The fennekuiper signature: a throwaway account sweeping up orphans in its first cycle. "First-seen" replaces "registered 3 days ago" because registration date is not in the RPC metadata and chasing profile pages would be a new fetch. First-seen is the deterministic, self-contained approximation: a throwaway account has, by definition, no prior maintainer events in the database.

The dormant-target clause is the FP killer. A legitimate new maintainer adopts a package or two they care about (active packages). Nobody's first act is sweeping up 13 orphans including a high-value one. The conjunction of first-seen, many targets, and dormant targets is near-zero FP.

### G009: Watchlisted Subject {#g009}

- **Target:** programmatic (cycle records)
- **Severity:** INFO (weight 0)
- **Category:** `correlation`

- **Condition:** A package whose name, or whose maintainer's salted hash, appears on the operator's watchlist (`[thresholds] g009`, enabled by default; `~/.config/trustsight/watchlist.json` unless `g009.path` names another file).

Report-only, weight 0, like G006. Registration date, "Inactive since" and suspension state are AUR profile-page facts the pipeline never fetches, so no machine rule can compute them. Where a human has established such a fact - the pattern a triager reads by hand, "Inactive-since ~ Last Updated and Last Packager = Package Maintainer" - the watchlist records it and this rule names the package instead of guessing from RPC metadata. A package can also be named directly, for the same report-only reason: the operator wants it surfaced without asserting a machine-computable signal.

Maintainer entries are keyed by the same salted SHA-256 the `maintainers_hashed` table uses, so no plaintext identity is stored; the salt is per-installation and the file is absent by default, so G009 is silent until an operator curates a list. G009 is report-only and never primes a campaign: it is a human note, not a corroborated cluster. Package entries are kept under `packages` as written, because a package name is already public in every record, report and AUR page. Add a maintainer with `python -c "from trustsight.watchlist import add_entry; add_entry('name', 'note')"`, or a package with `add_package('pkgname', 'note')`.

The operator's file is unioned with an imported, signed `watchlist-*` release (`trustsight watchlist update`), which carries public package names and salted maintainer hashes under its own salt. A local entry wins on collision, so the hand-curated list is never overwritten. The release hashes match only when the database uses the released salt; otherwise the import keeps the packages and skips the hashes, exactly as a baseline seed does.

### G010: Shared First-Seen Host {#g010}

- **Target:** programmatic (cycle records)
- **Severity:** INFO (weight 0)
- **Category:** `correlation`

- **Condition:** The same canonical source host, first seen in the corpus at or after `[thresholds] g010.window_days` (default 7) days ago, is gained by at least `[thresholds] g010.min_packages` (default 5) packages within the window.

The G001 shape with the novelty join instead of the gained-host join: only a host the corpus has not met before counts, so one honest newcomer per window is the AUR being the AUR and five is a distribution infrastructure. Trusted-forge and official hosts stand down, as do split outputs of one pkgbase and one maintainer's long-prefix name family. Weight 0 and never campaign-priming: a first contact is a statement about newness, never about intent, so G010 names the coordination and never scores, gates, notifies alone, or escalates a member (the Contact Ledger's plural-contact rule: strangers in company are a signal, strangers alone are a census).

### G011: Maintainer Package Creation Burst {#g011}

- **Target:** programmatic (cycle events + latest H021/H104)
- **Severity:** MEDIUM (weight 0); HIGH when the placeholder share is met
- **Category:** `correlation`

- **Condition:** A first-seen maintainer creates at least `[thresholds] g011.min_packages` (default 5) unrelated brand-new packages (H021) within `[thresholds] g011.window_days` (default 7) days. The finding is MEDIUM; it escalates to HIGH when H104 placeholders are at least `[thresholds] g011.placeholder_share` (default 0.5) of the members.

The burst is read from the recorded `cycle_events` window and each package's latest analysis, not from one cycle's processed set: the observed placeholder burst was spread over several cycles, so a current-cycle-only join would miss most of it. H021 keeps the membership to packages that are actually new to the AUR; a package this watcher has only just seen is not a creation burst.

Established maintainers are silent. The account must have no prior cycle event and must be new to the seed, which keeps a long-standing maintainer's legitimate multi-package launch out of the finding. A single package and a naming/variant family also stand down; the latter uses the same relatedness pass as G003.

This is the cross-package signal H104 exists for. Individually a placeholder is inert; a first-seen account reserving many names at once is the shape worth review. The finding is alert-only: it names the maintainer and members, primes campaign state, and does not inflate a member's score. A bare burst stays MEDIUM; the placeholder majority is the escalation, never a bare count.

### G012: Shared Payload Signal {#g012}

- **Target:** programmatic (cycle records)
- **Severity:** HIGH (weight 25)
- **Category:** `correlation`

- **Condition:** The same specific payload rule fired in at least `[thresholds] g012.min_packages` (default 3) unrelated packages from at least `g012.min_maintainers` (default 2) distinct maintainers in one cycle.

A per-package rule names one package's payload. This is the cross-account join: three unrelated maintainers shipping the same payload technique in one window is a campaign, not three coincidences. Only the curated payload allowlist counts (`R001`, `R002`, `R003`, `R008`, `H017`, `H035`, `H041`, `H075`, `H090`, `C016`, `C032`, `S001`-`S008`); broad practice rules such as `R010` (uses curl) or `H001` (checksum `SKIP`) are deliberately excluded so ordinary ecosystem churn cannot read as coordination.

The join runs over this cycle's recorded rule ids, so a prior cycle cannot re-fire it. Split outputs of one pkgbase and one naming family stand down, the same way G003 refuses a variant family. The finding names the members, the shared rule and the maintainer count. It is alert-only: a member's own score is not inflated by belonging to the cluster, and the campaign is what escalates (G006/G007), not the member's number.

### G013: Shared Fetch Target {#g013}

- **Target:** programmatic (cycle records)
- **Severity:** HIGH (weight 25)
- **Category:** `correlation`

- **Condition:** The same canonical URL reported by a payload finding appears in at least `[thresholds] g013.min_packages` (default 2) unrelated packages from at least `g013.min_maintainers` (default 2) distinct maintainers in one cycle.

G012 joins on the rule; this joins on the endpoint. Two different payload rules that fetch the same URL meet here. The URL is read from the finding's already-bounded `reason` and `evidence` text - nothing is fetched and nothing is resolved - and a URL that cannot be parsed is dropped rather than guessed at. The canonical key keeps the scheme, lower-cased host, non-default port and path, and drops the query and fragment: that is the part an attacker can vary for free, and two packages pointing at the same endpoint should meet.

This is the build-time complement to G001/G010, which read `source=` host transitions only. A payload URL inside `build()` or an installed scriptlet is invisible to those joins. Like G012, G013 is alert-only and does not score its members; the campaign state G006/G007 reads is the escalation.

### G014: Shared Adoption Window {#g014}

- **Target:** programmatic (cycle records)
- **Severity:** HIGH (weight 25)
- **Category:** `correlation`

- **Condition:** At least `[thresholds] g014.min_packages` (default 3) unrelated dormant packages were adopted in one cycle by at least `g014.min_maintainers` (default 2) distinct maintainers.

G003 groups adoptions under one maintainer and G008 watches one first-seen account. This is the multi-account adoption window: different maintainers taking unrelated dormant packages in the same cycle. The dormant-target clause (`g014.min_dormant`, default 2 targets older than `g014.dormant_days`, default 180) keeps the ordinary "a new maintainer adopts an active package they care about" case out, in the same way G008's dormant clause does.

The finding names the members, the maintainer count and the dormant count. Split outputs of one pkgbase and one naming family stand down. It is alert-only: membership does not inflate a member's own score; the campaign state G006/G007 reads is the escalation.
