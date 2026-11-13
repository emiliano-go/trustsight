"""Extracted from config.py: _default_config."""

import tomllib
from ._defaults_executor import DEFAULT_ANTI_ANALYSIS_PROBES, DEFAULT_CONFUSABLE_CHARS, DEFAULT_CONFUSABLE_DOMAINS, DEFAULT_COVERT_EGRESS_CLIENTS, DEFAULT_COVERT_EGRESS_ENDPOINTS, DEFAULT_ECOSYSTEM_PREFIXES, DEFAULT_FOREIGN_PKG_MANAGERS, DEFAULT_FREE_HOSTING_DOMAINS, DEFAULT_FREE_REGISTRAR_TLDS, DEFAULT_H029_MIN_OBSERVATIONS, DEFAULT_H029_PLAIN_MIN_OBSERVATIONS, DEFAULT_KNOWN_SUFFIXES, DEFAULT_MANIFEST_FILENAMES, DEFAULT_NETWORK_TOOLS, DEFAULT_OBFUSCATION_INDICATORS, DEFAULT_PARSE_TIME_FETCH, DEFAULT_PASTE_HOSTS, DEFAULT_RECON_COMMANDS, DEFAULT_SECURITY_RELEVANT_FLAGS, DEFAULT_SECURITY_RELEVANT_LIBRARIES, DEFAULT_SOURCE_SCHEMES, DEFAULT_STANDARD_PORTS, DEFAULT_UPLOAD_FLAGS, DEFAULT_VARIANT_SUFFIXES

__all__ = ['DEFAULT_BASELINE_TAG', 'DEFAULT_CONFIG', 'DEFAULT_HOSTS', 'DEFAULT_IOCS', 'DEFAULT_IOC_TAG', 'DEFAULT_NAMING', 'DEFAULT_NOVELTY_WEIGHTS', 'DEFAULT_PATTERNS', 'DEFAULT_RELEASE_CHANNEL', 'DEFAULT_RELEASE_KEY', 'DEFAULT_SOURCE_DIVERGENCE_ALLOW', 'DEFAULT_THRESHOLDS', 'DEFAULT_WATCHLIST_TAG', 'STRUCTURAL_MATCHES', 'STRUCTURAL_SEVERITY_CEILING', '_STRUCTURAL_CLAMPED', '_toml_escape_str', '_toml_str_list', '_toml_value']

DEFAULT_CONFIG = """\
[severity_weights]
FATAL = 0
CRITICAL = 40
HIGH = 25
MEDIUM = 15
LOW = 5
INFO = 0

[source_bucket_weights]
trusted_forge = 0
official = 0
declared_upstream = 5
raw_hosting = 15
unknown = 20
homograph_attack = 30

[novelty_weights]
# Calibrated once tier C actually became live.  The previous 10/15/20 was
# set while maturity was permanently 0, so the weights had never been
# exercised: at full maturity a novel URL plus a novel maintainer took a
# borderline 15-point package to 60 (High).  These values keep that case
# in Medium (45) while leaving maintainer novelty the strongest signal,
# since a maintainer change is the xz-utils attack vector.
url_first_in_package = 5
url_first_globally = 10
maintainer_first_in_package = 15

[review]
# Controls which scored packages enter the review workload. This does not
# change score arithmetic or risk bands. A package is flagged above its
# selected profile's threshold.
profile = "default"

[review.profiles]
default = 20
quiet = 40
strict = 10

[deep]
# Deep analysis. ``inspect`` analyses the full AUR dependency closure when the
# mode is on, and requests the optional L9 lane for a package whose static
# score reaches ``threshold`` - only when ``[verify] enabled`` is set.  The
# L9 result is reported separately and never changes the static score;
# TrustSight does not build the package, so the lane inspects only a manifest
# an external build supplied.
enabled = false
threshold = 80

[depth]
# How far into a package's AUR dependency closure to analyse.  0 disables
# it, 1 (the default) analyses direct AUR dependencies, n analyses n levels,
# and -1 walks every level there is - bounded by depth.MAX_DEPTH_LEVELS and
# depth.MAX_DEPTH_NODES, because the dependency graph is written by the
# party under review.  Overridden per run by --depth.
levels = 1

[diff]
max_context_lines = 3
max_diff_bytes = 5242880

[limits]
# How many packages `trustsight review` reads when no --limit is given.
# 0 means all of them, which is the default because a review that stops
# early has not looked at the rest, and this tool does not report on what
# it did not read.  Any other value is honoured and the packages left over
# are named in the summary rather than dropped quietly.
#
# This key shipped set to 20 and was never read by anything: the flag's own
# default (0) won every time, so the documented setting did nothing.
default_review_limit = 0
# Seconds libgit2 may spend connecting to, and waiting for data from, the
# AUR before it aborts a clone/fetch.  These are enforced inside libgit2's
# transport; without them a silently stalled connection hangs a worker
# thread forever, because the progress callbacks that carry TrustSight's
# own deadline only run while bytes are arriving.
network_connect_timeout = 10
network_transfer_timeout = 30
# Seconds the review prefetch phase waits for the whole batch.  What has
# not arrived by then is abandoned and fetched again during analysis.
prefetch_timeout = 120
# Seconds between cycles of `trustsight full-aur --watch`.  The AUR's own
# metadata dump is regenerated every few minutes, so anything under a
# minute only re-downloads the same snapshot; the floor is enforced.
watch_interval = 3600
watch_min_interval = 60

[alerts]
# How many findings the terminal renders in full before it groups the
# remainder.  The JSON is never filtered - nothing is dropped - but a
# campaign that makes every package noisy can train a reviewer to skim, and
# the attack is the raised noise floor, not any single finding.  Beyond the
# cap the render shows a `...and N more findings (see --json)` line per
# severity band and a weight-0 W010 (Alert Volume Capped) boundary.
max_rendered_findings = 50
# How many flagged packages a single watch-cycle webhook names before it
# degrades to counts-per-band plus the top-K by score.  The full list is in
# the stored record; 0 disables the cycle cap.
max_cycle_alerts = 0
# Campaign alert mode: how many campaigns may be active at once.  A new
# activation beyond the cap evicts the oldest only if its TTL has also
# lapsed; a live TTL is never shortened.
max_active_campaigns = 8
# Campaign alert mode: how long a corroborated campaign stays primed, in
# observations (recorded analyses), not seconds.  Small on purpose - expiry
# measured in observations is what keeps a primed state from becoming
# chronic.
campaign_ttl_observations = 40
# Campaign alert mode: minimum spacing, in observations, between
# re-activations of the SAME campaign class (a G-rule id).  A class that
# re-arms faster than this is still refreshed, but the over-frequent
# re-arming is surfaced as an M006 tool-health note rather than passed over
# in silence.  0 disables the check.
campaign_min_reactivation_observations = 5

[verify]
# The optional L9 artifact-inspection lane.  TrustSight does not
# build packages: `trustsight verify-build --manifest PATH` inspects a
# manifest an external build produced (A001-A008).  Off by default, explicit,
# and never blended into the static score.  When it is disabled or no manifest
# is supplied, the run reports `l9_unavailable` - a weight-0 boundary, never a
# clean or malicious verdict.
enabled = false

[layers]
# Override a rule's assurance layer. The layer names the
# kind of evidence the rule represents, L1 (structural coherence) to L8
# (campaign correlation).  The shipped per-series default and per-rule
# overrides apply unless a rule id is named here.  A value outside L1-L8 is
# ignored, never applied.  Example:
#   H099 = "L1"

[notify]
# With `full-aur --watch`, a cycle that produced new alerts POSTs one JSON
# document to this URL.  It carries counts, package names, rule ids, scores,
# maintainers and finding reasons - and the analysed PKGBUILD diff, which is
# package-controlled recipe content.  Point it at a destination you trust
# with that content; the separate `trustsight.scans` stream has no diff.
# Any receiver that accepts a JSON POST works; ntfy shows the document as the
# message text.  Empty means no notifications.  A dead receiver is logged
# and swallowed, so a webhook outage cannot kill the watch loop.
# webhook = "https://ntfy.sh/your-topic"
#
# A second, independent sink: the TrustSight watcher feed, which ingests the
# same document directly instead of polling ntfy.  Every POST is signed with
# an Ed25519 key the receiver holds only the public half of, so a leaked feed
# secret cannot forge a document.  The private key is the base64 PKCS#8 value
# of TRUSTSIGHT_FEED_KEY (TRUSTSIGHT_FEED_KEY_ID names it); with no key the
# feed sink is skipped.  Empty means no feed.
# feed = "https://watcher.trustsight.org/api/ingest"

[seed]
# Import the novelty seed the first time TrustSight runs against
# an empty database.  The seed is a signed release asset
# (baseline-seed.tar.gz) fetched from the release channel; the fetch
# is verified against the pinned key and skipped silently when
# offline.  Without it every source URL looks novel and maturity stays
# at zero, which downgrades every Medium verdict to INCONCLUSIVE.  The
# seed is public AUR data and is additive; it can never overwrite
# something learned from a real analysis.
auto_import = true

# Fallback release tag for the seed when the GitHub releases API cannot
# be reached (offline or rate-limited).  The seed lives only on
# baseline-* releases, so "latest" - a version tag that carries no
# baseline assets - can never serve it; without this the fetch 404s the
# moment the unauthenticated API quota is spent.  Bumped in the same
# release that publishes a new baseline.
baseline_tag = "baseline-2026-10-22"

[release]
# The release channel the baseline seed and corpus are pulled from, as a
# GitHub "owner/repo" slug.  Empty means the official channel
# (emiliano-go/trustsight), whose ed25519 key is pinned inside the package.
# Point it at another repository to follow that publisher's baselines; doing so
# MUST be paired with the publisher's key in ``key`` below, and every import
# from a non-official channel warns that you are trusting that publisher.
channel = ""

# The ed25519 public key that signs the chosen channel's baseline assets: a
# path to a raw 32-byte key file, or 64 hex characters.  Required when
# ``channel`` names a non-official repo, ignored for the official channel.
key = ""

[baselines.ioc]
# IOC Federation baselines (v0.12.0).  ``enabled`` gates the match stage
# during analysis; ``sources`` is a list of baseline source names to
# consult.  An empty list means "all imported sources".  Baselines are
# imported with ``trustsight ioc import <dir>``.
enabled = true
sources = []

# Fallback release tag for the dedicated IOC channel when the GitHub
# releases API cannot be reached (offline or rate-limited).  Empty means
# "resolve the newest ioc-* release", refused if unreachable.  The pairs
# live only on ioc-* releases, never on a baseline-* release.
# Set it to pin an exact channel, e.g. tag = "ioc-2026-10-18".  A feed's own
# `tag` overrides this.
tag = ""

[[baselines.ioc.feeds]]
# Example feed entry.  TrustSight ships with no default feeds; operators
# add trusted sources here and import them explicitly.  A feed whose url
# is a release-channel URL is updated by `trustsight ioc update`, which
# downloads baseline-ioc-<asset>-manifest.json/-iocs.jsonl from the newest
# ioc-* release (the dedicated IOC channel), verifies the distribution
# signature, and imports with the curator-key check.  Any other http(s) url
# is read as a publisher's federation directory (manifest.json + iocs.jsonl)
# and needs that publisher's ed25519 key in ``key``; a non-http url is
# refused.  `asset` defaults to `name`; `tag` pins an exact channel release.
name = "example-feed"
url = "https://example.org/trustsight/ioc-baseline/"
enabled = false

[baselines.watchlist]
# The imported watchlist (v0.23.0).  A signed ``watchlist-*`` release carries
# public package names and salted maintainer hashes; ``trustsight watchlist
# update`` downloads it, verifies the distribution signature, and imports it.
# The imported set is unioned with the operator's hand-curated file
# (``~/.config/trustsight/watchlist.json``) at load, so a release import never
# clobbers a local entry.  ``enabled`` gates both the import and the pre-command
# "a newer watchlist is available" notice.
enabled = true

# Fallback release tag for the watchlist channel when the GitHub releases API
# cannot be reached (offline or rate-limited).  Empty means "resolve the newest
# watchlist-* release", refused if unreachable.  Set it to pin an exact
# channel, e.g. tag = "watchlist-2026-10-20".
tag = ""

[discovery]
# Default repositories to scan when no --repo/--foreign/--all-repos CLI
# flags are given.  Only packages found on the AUR are reviewed.
default_repos = []
include_foreign = false
all_repos = false
# When reviewing with --all, include packages not found in the AUR
# metadata snapshot (orphaned, very new, removed from AUR, etc.).
# Set to false to skip unmatched packages entirely.
show_unmatched = true
# Minutes before the AUR RPC response cache expires.  A repeat review
# within this window reuses cached version data instead of re-querying
# the AUR server.  Set to 0 to disable caching entirely.
cache_ttl_minutes = 60
# Minutes before the offline AUR metadata snapshot is refetched.  A
# snapshot older than this reports every installed package as current,
# so `review` downloads a fresh dump (~60 MB) before comparing.  Set to
# 0 to never refresh automatically, which means version comparisons are
# only as current as the last snapshot on disk.
metadata_ttl_minutes = 60

[rules]
# Run rules marked experimental in rules.toml.  The R039+ set is now
# calibrated and runs unconditionally; this gates future additions whose
# false-positive rate has not been measured yet.  It does NOT reach the
# code-emitted rules in [code_rules] below.
experimental = false

[code_rules]
# Rules emitted from code rather than rules.toml, so the [rules]
# experimental flag above cannot reach them.  They are not experimental:
# all default to true since v0.7.0 after each was measured against the
# 3739-diff benign corpus (see docs/explanation/fire-rates.md).  The
# pre-rename name of this table was [experimental_rules], still read as a
# fallback.
#
# D001  novel dependency: a name never seen anywhere in the AUR
# D002  typosquatted dependency: a novel name one or two edits from a
#       popular one (refines D001, so enabling it alone is meaningful)
# D003  new network-using makedepends: the build can now fetch code that
#       no checksum covers
# D004  provides/replaces claims an established, unrelated package, which
#       installs this package in front of it
# H016  a download inside build() whose URL is not in source=()
# H017  a .install hook, which runs as root, fetches or executes
# H018  a patch applied from outside the build tree (a URL, an absolute
#       path, or process substitution)
# H019  a source= URL downgraded from https to http
# H106  build/install code points a package manager at another registry
D001 = true
D002 = true
D003 = true
D004 = true
H016 = true
H017 = true
H018 = true
H019 = true
H106 = true
H108 = true

# H015 reports that a critical build function was modified.  It is INFO
# severity, so it carries weight 0 and cannot move a score: it fires on
# 19.7% of benign diffs and is context for a reviewer, not a signal.  That
# is why it is the one rule here safe to leave on.
H015 = true

[ports]
# Standard ports excluded from R047 (source URL uses non-standard port).
standard = [80, 443, 8080, 8443]

[domains]
# Free-registrar TLDs flagged by R048 (source URL on free registrar TLD).
free_registrar_tlds = ["tk", "ml", "ga", "cf", "gq", "pw"]
# Free-hosting / dynamic-DNS / tunnel domains flagged by R152 (source URL on
# an attacker-controllable host). Overridden by hosts.toml free_hosting_domains.
free_hosting_domains = []

[tools]
# Package names that grant network access in makedepends (D003).
network_makedepends = [
    "curl", "wget", "aria2", "git", "subversion", "mercurial", "rsync",
    "python-requests", "python-httpx", "python-urllib3", "python-aiohttp",
    "ruby-net-http", "nodejs", "npm", "yarn", "cargo", "go",
]

[source_host_divergence]
# C011 reports a prebuilt (-bin) package whose source host is not the
# registered domain of its declared upstream `url=` and is not already in a
# trusted, official or raw-hosting bucket.  Add registrable domains here to
# exempt a legitimate non-forge distribution CDN or mirror.
#
# The shipped entries are projects that publish their own prebuilt binaries
# from their official site while the AUR `url=` names a source repository, so
# the host is a project's own, not a third party's.  Measured against the
# 3,739-diff benign corpus: with these listed, C011's benign rate is 0.05%.
allow = [
    "waterfox.com",
    "torproject.org",
    "arduino.cc",
    "cachyos.org",
    "freedesktop.org",
    "archlinux.org",
    "winehq.org",
    # Vendors that publish a prebuilt binary from their own CDN on a
    # different registered domain than the `url=` they declare
    # (code.visualstudio.com declares, *.prss.microsoft.com serves).
    "microsoft.com",
    # secureblue declares its source repo (github.com/secureblue/trivalent)
    # and serves the hardened-chromium build from its own repo host
    # (repo.secureblue.dev), the download named by the project's own docs.
    "secureblue.dev",
    # Anomaly publishes the Hex dictation build from its own release host
    # (anoma.ly) while `url=` names the GitHub source repository.  This is a
    # C011-only exemption: the host is deliberately not in
    # [official_projects], so SOURCE_BUCKET and novelty still report it
    # (hex-bin, 2026-10-31).  Wyrd Company's repo.wyrd.foo was considered
    # and is not listed: a new, zero-vote vendor host does not meet the
    # official-domain trust bar.
    "anoma.ly",
]

[contacts]
# The Contact Ledger (weight 0, warm-only).  enabled = false is the cold
# replay lane: no first-contact fact is recorded and the report renders the
# standing contact_ledger_unavailable note instead of the panel.  The
# determinism gate runs the corpus with this off and proves the score is
# identical.
enabled = true
"""

DEFAULT_NOVELTY_WEIGHTS = tomllib.loads(DEFAULT_CONFIG)["novelty_weights"]

DEFAULT_SOURCE_DIVERGENCE_ALLOW = (
    tomllib.loads(DEFAULT_CONFIG).get("source_host_divergence", {}).get("allow", [])
)

DEFAULT_BASELINE_TAG = (
    tomllib.loads(DEFAULT_CONFIG).get("seed", {}).get("baseline_tag") or None
)

DEFAULT_IOC_TAG = (
    tomllib.loads(DEFAULT_CONFIG)
    .get("baselines", {})
    .get("ioc", {})
    .get("tag")
    or None
)

DEFAULT_WATCHLIST_TAG = (
    tomllib.loads(DEFAULT_CONFIG)
    .get("baselines", {})
    .get("watchlist", {})
    .get("tag")
    or None
)

DEFAULT_RELEASE_CHANNEL = (
    tomllib.loads(DEFAULT_CONFIG).get("release", {}).get("channel") or None
)

DEFAULT_RELEASE_KEY = (
    tomllib.loads(DEFAULT_CONFIG).get("release", {}).get("key") or None
)

def _toml_escape_str(val: str) -> str:
    """Escape a string for use as a TOML basic string value."""
    escaped = val.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    return f'"{escaped}"'

def _toml_str_list(values) -> str:
    """Render a list of values as a multi-line TOML array."""
    return "[\n" + "".join(f"    {_toml_value(v)},\n" for v in values) + "]"

def _toml_value(val) -> str:
    """format a value for TOML output"""
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, str):
        if val.lower() in ("true", "false"):
            return val.lower()
        try:
            int(val)
            return val
        except ValueError:
            pass
        return _toml_escape_str(val)
    return str(val)

DEFAULT_PATTERNS = (
    "[patterns]\n"
    "# H035 - foreign package managers invoked from an install hook.  A\n"
    "# PKGBUILD that hands installation to another package manager installs\n"
    "# that payload outside pacman's control and its checksums.  Each entry\n"
    "# is a case-insensitive regex fragment matched against reconstructed\n"
    "# text.\n"
    "foreign_pkg_managers = " + _toml_str_list(DEFAULT_FOREIGN_PKG_MANAGERS) + "\n"
    "\n"
    "# H036 - obfuscation indicators counted on a single raw line.  A line\n"
    "# carrying at least [thresholds] h036_obfuscation_density distinct\n"
    "# forms fires; the reconstruction rules (H065) decide whether the\n"
    "# resolved line reveals an executable action.\n"
    "obfuscation_indicators = " + _toml_str_list(DEFAULT_OBFUSCATION_INDICATORS) + "\n"
    "\n"
    "# H067 - anti-analysis probes run from a build/install function.  A build\n"
    "# recipe checking whether it is being debugged, virtualized, sandboxed, or\n"
    "# running on CI has no packaging purpose.  Each entry is a regex fragment\n"
    "# matched against reconstructed text; legitimate arch/feature checks\n"
    "# (uname -m, getconf) never match these.\n"
    "anti_analysis_probes = " + _toml_str_list(DEFAULT_ANTI_ANALYSIS_PROBES) + "\n"
    "\n"
    "# H040 - host-profiling commands run from a build/install function.  Host\n"
    "# reconnaissance (who am I / what machine am I on) has no packaging\n"
    "# purpose; it is the recon stage of the kill-chain H043 composes.  Each\n"
    "# entry is a regex fragment matched against reconstructed text.  Fragments\n"
    "# carry a command-position anchor so bare mentions in strings, sed\n"
    "# expressions or variable values never fire; `env`, `dmidecode` and\n"
    "# systemd-detect-virt are deliberately absent (they belong to H067 or\n"
    "# produce benign false positives).  A lone `uname -m` fires H040 at INFO.\n"
    "# The getent fragment is the keyless-enumeration shape only: `getent\n"
    "# passwd <name>` is the standard provisioning lookup before useradd and\n"
    "# must not fire.\n"
    "recon_commands = " + _toml_str_list(DEFAULT_RECON_COMMANDS) + "\n"
    "\n"
    "\n"
    "# H041 - curl/wget invocation shapes that send a request body.  An\n"
    "# upload to a paste or file-drop host from a build or install function\n"
    "# is the exfil direction; a download from one is H016's undeclared\n"
    "# fetch.  Matched after the client name on a command-position line.\n"
    "upload_flags = " + _toml_str_list(DEFAULT_UPLOAD_FLAGS) + "\n"
    "\n"
    "# H077 - network clients invoked at parse time (the top level of the\n"
    "# PKGBUILD, outside every function).  makepkg sources the recipe before\n"
    "# any build step runs, so these lines execute on a metadata refresh, not\n"
    "# only on a build.  Fragments carry a command-position anchor.\n"
    "parse_time_fetch = " + _toml_str_list(DEFAULT_PARSE_TIME_FETCH) + "\n"
    "\n"
    "# D003 - package names that grant network access from makedepends.  A\n"
    "# new network-capable build dependency is code the checksum array does\n"
    "# not cover.\n"
    "network_tools = " + _toml_str_list(DEFAULT_NETWORK_TOOLS) + "\n"
    "\n"
    "# H047 - security-relevant build flags.  A hardening flag dropping out of\n"
    "# (or appearing in) a long-stable configure_flags set is an attack-surface\n"
    "# change that the diff alone would not surface.\n"
    "security_relevant_flags = " + _toml_str_list(DEFAULT_SECURITY_RELEVANT_FLAGS) + "\n"
    "\n"
    "# H048 - security-relevant libraries.  When a package stops depending on\n"
    "# one of these and starts vendoring a matching source copy, it bypasses\n"
    "# the distribution's security updates.\n"
    "security_relevant_libraries = " + _toml_str_list(DEFAULT_SECURITY_RELEVANT_LIBRARIES) + "\n"
    "\n"
    "# U-series - committed upstream dependency manifests.  Each entry is\n"
    "# 'format::name'; a name containing '/' matches as a path suffix, a bare\n"
    "# name matches a basename.  The table is configuration, not a code\n"
    "# constant: which files count as a manifest is a policy choice, visible\n"
    "# in the config fingerprint.\n"
    "manifest_filenames = " + _toml_str_list(DEFAULT_MANIFEST_FILENAMES) + "\n"
)

DEFAULT_NAMING = (
    "[naming]\n"
    "# Suffixes that mark a variant of the same upstream project rather than\n"
    "# a different project (D002/D004 relatedness).\n"
    "variant_suffixes = " + _toml_str_list(DEFAULT_VARIANT_SUFFIXES) + "\n"
    "\n"
    "# Prefixes shared by thousands of unrelated packages; never evidence of\n"
    "# a common project (D004).\n"
    "ecosystem_prefixes = " + _toml_str_list(DEFAULT_ECOSYSTEM_PREFIXES) + "\n"
    "\n"
    "# Suffixes denoting expected package variants, stripped before\n"
    "# edit-distance comparison so foo-git is never confused with foo\n"
    "# (H029).\n"
    "known_suffixes = " + _toml_str_list(DEFAULT_KNOWN_SUFFIXES) + "\n"
    "\n"
    "# Confusable character groups (H029): a differing character pair drawn\n"
    "# from one group is a homoglyph/digit edit, not a coincidence.\n"
    "confusable_chars = " + _toml_str_list(DEFAULT_CONFUSABLE_CHARS) + "\n"
    "\n"
    "# H029 candidate popularity floors (dependency observation count).  The\n"
    "# lower floor gates every candidate; the higher one gates non-confusable\n"
    "# edits, which are weaker evidence.\n"
    "h029_min_candidate_observations = " + str(DEFAULT_H029_MIN_OBSERVATIONS) + "\n"
    "h029_plain_min_observations = " + str(DEFAULT_H029_PLAIN_MIN_OBSERVATIONS) + "\n"
    "\n"
    "# H029 name length floors.  The dependency path (git review) needs four\n"
    "# characters; the AUR popularity path (corpus) admits three so short\n"
    "# clones of a popular helper (yau/yay) are still seen.  A package's own\n"
    "# AUR vote count is a candidate floor too: below it the candidate list\n"
    "# is trimmed, and only a name-clone of a genuinely popular package is\n"
    "# compared at all.\n"
    "h029_min_name_length = 4\n"
    "h029_popularity_min_length = 3\n"
    "h029_popularity_floor = 100\n"
)

DEFAULT_HOSTS = (
    "[hosts]\n"
    "# Paste and ephemeral file-drop hosts (H041).  Bucket classification\n"
    "# in trusted_domains.toml [raw_hosting] already weights these; this\n"
    "# list backs the dedicated detection rule shipped with H041.\n"
    "paste_hosts = " + _toml_str_list(DEFAULT_PASTE_HOSTS) + "\n"
    "\n"
    "# Source schemes allowed by H034 (source URL uses exotic protocol).\n"
    "source_schemes = " + _toml_str_list(DEFAULT_SOURCE_SCHEMES) + "\n"
    "\n"
    "# Covert-egress / tunneling clients invoked in build/install (H071).\n"
    "covert_egress_clients = " + _toml_str_list(DEFAULT_COVERT_EGRESS_CLIENTS) + "\n"
    "\n"
    "# DoH endpoints flagged by H071 (covert egress).\n"
    "covert_egress_endpoints = " + _toml_str_list(DEFAULT_COVERT_EGRESS_ENDPOINTS) + "\n"
    "\n"
    "# Popular domains that R013b treats as homoglyph targets.\n"
    "confusable_domains = " + _toml_str_list(DEFAULT_CONFUSABLE_DOMAINS) + "\n"
    "\n"
    "# Standard ports excluded from R047 (source URL uses non-standard port).\n"
    "standard_ports = " + _toml_str_list(DEFAULT_STANDARD_PORTS) + "\n"
    "\n"
    "# Free-registrar TLDs flagged by R048 (source URL on free registrar TLD).\n"
    "free_registrar_tlds = " + _toml_str_list(DEFAULT_FREE_REGISTRAR_TLDS) + "\n"
    "\n"
    "# Free-hosting / dynamic-DNS / tunnel domains flagged by R152.\n"
    "free_hosting_domains = " + _toml_str_list(DEFAULT_FREE_HOSTING_DOMAINS) + "\n"
)

DEFAULT_THRESHOLDS = (
    "# Expected co-fire pairs (M004 tool health): [precursor, expected].  A\n"
    "# construct whose rule fired while its usual partner did not flags the\n"
    "# instrument, never the package.  Ships empty until a pair is measured.\n"
    "cofire_pairs = []\n"
    "\n"
    "[e001]\n"
    "# Added text that compresses below this gzip ratio is repetitive or\n"
    "# padded.  Calibrated on the locked benign corpus: the point below which\n"
    "# 0.5% of 8,302 measurable diffs sit.  Empty until calibrated.\n"
    "max_ratio = 0.2302\n"
    "\n"
    "[e002]\n"
    "# Fraction of added tokens that are base64/base32/hex runs of at least\n"
    "# min_length characters.  Calibrated at the 0.5% upper tail.\n"
    "min_fraction = 0.8889\n"
    "min_length = 64\n"
    "\n"
    "[e003]\n"
    "# Unigram and bigram entropy of newly assigned identifier names.  The\n"
    "# calibrated 0.5% upper tail catches packed/generated names; the lower\n"
    "# bounds stay zero because most diffs assign no identifier at all.\n"
    "min_entropy = 0.0\n"
    "max_entropy = 4.9535\n"
    "min_bigram = 0.0\n"
    "max_bigram = 7.0039\n"
    "\n"
    "[h036]\n"
    "# H036 fires when a single line carries at least this many distinct\n"
    "# obfuscation indicators from [patterns] obfuscation_indicators.\n"
    "obfuscation_density = 3\n"
    "\n"
    "[h043]\n"
    "# H043 annotates a diff whose rule hits span at least this many distinct\n"
    "# kill-chain stages from the H043 stage map (recon, staging, persistence,\n"
    "# foreign_fetch, payload, install_hook, write_then_exec, obfuscation,\n"
    "# anti_analysis, hidden_drop, exfil, takeover, mass_adoption).\n"
    "attack_chain_stages = 3\n"
    "\n"
    "[h064]\n"
    "# H064 fires when a diff newly claims a provides/replaces entry naming a\n"
    "# package the corpus shows this many packages depend on (established,\n"
    "# official-repo membership fires regardless).\n"
    "widely_provided_observations = 25\n"
    "\n"
    "[h045]\n"
    "# H045 (mass adoption) fires when a single maintainer submits at least\n"
    "# this many packages with the whole cluster landing within this many days.\n"
    "# The no-baseline gate keeps it silent on a first bootstrap.\n"
    "min_packages = 10\n"
    "window_days = 7\n"
    "\n"
    "[h052]\n"
    "# H052 (shared source repo cluster) fires when at least this many\n"
    "# unrelated packages (distinct package bases) declare the same normalized\n"
    "# upstream source URL.\n"
    "min_packages = 3\n"
    "\n"
    "[h055]\n"
    "# H055 (attribute burst) fires when at least this many packages by one\n"
    "# maintainer are modified within this many hours.  Added packages are\n"
    "# excluded: H045 already claims the adoption clusters.\n"
    "min_packages = 5\n"
    "window_hours = 24\n"
    "\n"
    "[h073]\n"
    "# H073 (introduction-rate deviation) compares a cycle's new-package count\n"
    "# to the prior cycles; it only fires once this many prior cycles exist and\n"
    "# the rate exceeds the mean by at least this many standard deviations.\n"
    "min_history_cycles = 3\n"
    "z_score = 3.0\n"
    "min_introduced = 3\n"
    "\n"
    "[h074]\n"
    "# H074 (adopt-then-modify) fires on a package adopted this cycle whose\n"
    "# modify time still falls within this many days.\n"
    "window_days = 14\n"
    "\n"
    "[h057]\n"
    "# H057 (transitive exposure) only reports a package whose transitive\n"
    "# dependency closure reaches an adopted-from-orphan package at this many\n"
    "# hops or deeper.  Context only; weight 0.\n"
    "min_hops = 2\n"
    "\n"
    "[h060]\n"
    "# H060 (transitive orphan risk) only reports a package whose transitive\n"
    "# dependency closure reaches a currently-orphaned package at this many\n"
    "# hops or deeper.  Context only; weight 0.\n"
    "min_hops = 2\n"
    "\n"
    "[h061]\n"
    "# H061 (dependency centrality) flags a package depended on by at least\n"
    "# this many AUR packages.  Prioritisation only; weight 0.\n"
    "min_dependents = 50\n"
    "\n"
    "[h058]\n"
    "# H058 (maintainer baseline deviation) is maturity- and z-gated like H073,\n"
    "# but per maintainer against that maintainer's own prior activity.  The\n"
    "# thresholds are raised over H073's: a bulk packager whose ordinary\n"
    "# cadence is high already sits far above a short baseline, so a low z on a\n"
    "# short history reads a normal batch as a deviation.  A longer minimum\n"
    "# history and a wider z keep the rule for a quiet account that suddenly\n"
    "# surges (the xz-utils shape).\n"
    "min_history_cycles = 4\n"
    "z_score = 3.0\n"
    "min_activity = 3\n"
    "# Absolute batch floor: the z-test alone reads a three-package tidy as a\n"
    "# surge when the baseline has no variance.  A real account surge\n"
    "# publishes a whole package set at once, well above this.\n"
    "min_surge = 6\n"
    "\n"
    "[longitudinal]\n"
    "# H047-H051/H054/H037 gate on a property holding at least this many\n"
    "# consecutive observations before its break is reported.  Below it the\n"
    "# stability_weight is 0 and no PropertyBreak is emitted, so a cold or\n"
    "# immature database never fires the longitudinal rules.\n"
    "stability_floor = 10\n"
    "\n"
    "[h098]\n"
    "# H098 annotates a package whose findings carry at least this many\n"
    "# distinct naming/deception signals (name resemblance, novel or\n"
    "# typosquatted dependency, dependency hijack, provides scope expansion,\n"
    "# source-domain lookalike, name/host or name/repo divergence, untrusted\n"
    "# maintainer takeover).  One signal can be a coincidence; two is a\n"
    "# method.\n"
    "min_signals = 2\n"
    "\n"
    "[u005]\n"
    "# U005 (dependency surface jump) reports a manifest whose dependency\n"
    "# count multiplies past this factor in one update.  Weight 0; the\n"
    "# correlation feed is its primary consumer, not the reader.\n"
    "jump_factor = 3.0\n"
    "\n"
    "[g003]\n"
    "# G003 (coordinated adoption) escalates from MEDIUM to HIGH when the\n"
    "# adopting maintainer is globally novel - its earliest recorded\n"
    "# maintainer-event falls within this many days - and at least this many\n"
    "# of the adopted targets are dormant (AUR LastModified older than this\n"
    "# many days).  Membership itself stays g_adopt.min_members; only the\n"
    "# weighting knobs live here.  The escalation changes alert severity and\n"
    "# evidence, not member scores.\n"
    "novel_days = 30\n"
    "min_dormant = 2\n"
    "dormant_days = 180\n"
    "\n"
    "[g008]\n"
    "# G008 (first-seen account adoption burst) fires when an account with\n"
    "# no prior maintainer history in the local database adopts at least\n"
    "# this many packages within this many days, and at least this many\n"
    "# of those targets are dormant (last git activity older than this many\n"
    "# days).  The dormant-target clause is the FP killer: legit new\n"
    "# maintainers adopt active packages they care about.\n"
    "min_packages = 5\n"
    "window_days = 7\n"
    "min_dormant = 3\n"
    "dormant_days = 180\n"
    "\n"
    "[g009]\n"
    "# G009 (watchlisted maintainer) reports a package whose maintainer is on\n"
    "# the operator's hand-curated watchlist (~/.config/trustsight/watchlist.json\n"
    "# by default), keyed by salted maintainer hash.  Report-only, weight 0.\n"
    "# Set enabled = false to silence it, or path to another watchlist file.\n"
    "enabled = true\n"
    "path = \"\"\n"
    "\n"
    "[g010]\n"
    "# G010 (shared first-seen host) fires when a canonical source host new\n"
    "# to the corpus at or after this window start is gained by at least\n"
    "# this many packages.  The G001 shape with the first-seen join: one\n"
    "# honest newcomer per window is the AUR being the AUR, five is a\n"
    "# distribution infrastructure.  Weight 0, always.\n"
    "min_packages = 5\n"
    "window_days = 7\n"
    "\n"
    "[g011]\n"
    "# G011 (maintainer package creation burst) fires when a first-seen account\n"
    "# creates at least this many brand-new packages (H021) in the window.  A\n"
    "# bare burst is MEDIUM; when at least placeholder_share of the members are\n"
    "# H104 placeholders it escalates to HIGH.  Established accounts are silent.\n"
    "min_packages = 5\n"
    "window_days = 7\n"
    "placeholder_share = 0.5\n"
    "placeholder_escalation = true\n"
    "\n"
    "[g012]\n"
    "# G012 (shared payload signal) joins a specific payload rule that fired\n"
    "# in at least this many unrelated packages from at least this many\n"
    "# distinct maintainers in one cycle.  Alert-only: members are not scored.\n"
    "min_packages = 3\n"
    "min_maintainers = 2\n"
    "\n"
    "[g013]\n"
    "# G013 (shared fetch target) joins a canonical URL reported by payload\n"
    "# findings in at least this many unrelated packages from at least this\n"
    "# many distinct maintainers.  Alert-only: members are not scored.\n"
    "min_packages = 2\n"
    "min_maintainers = 2\n"
    "\n"
    "[g014]\n"
    "# G014 (shared adoption window) joins unrelated dormant packages adopted\n"
    "# by at least this many distinct maintainers in one cycle.  The dormant\n"
    "# clause keeps ordinary active-package adoption out.  Alert-only.\n"
    "min_packages = 3\n"
    "min_maintainers = 2\n"
    "min_dormant = 2\n"
    "dormant_days = 180\n"
    "\n"
    "[g015]\n"
    "# G015 (sleeper adoption campaign) joins dormant packages adopted over\n"
    "# a long window by several maintainers when the same accounts reactivate\n"
    "# most of the cohort in one short push.  MEDIUM is an alert and campaign\n"
    "# signal; a payload or takeover finding on a member escalates it to HIGH.\n"
    "# Alert-only: membership never adds to a member's score.\n"
    "min_packages = 3\n"
    "min_maintainers = 2\n"
    "min_push_share = 0.5\n"
    "push_window_days = 7\n"
    "min_adoption_age_days = 30\n"
    "max_adoption_age_days = 365\n"
    "adoption_window_days = 180\n"
    "min_dormant = 2\n"
    "dormant_days = 180\n"
    "orphan_only = true\n"
    "\n"
    "[tender]\n"
    "# Tender point: unresolved review verdicts over the window produce a\n"
    "# header note asking a human to look once.  Never a score.\n"
    "min_unresolved = 3\n"
    "window_months = 6\n"
    "\n"
    "[tags]\n"
    "# Tag convergence: N distinct weight-0 tag kinds on one diff emits one\n"
    "# INFO TAG_CONVERGENCE ledger entry.  Escalation-only, weight 0.\n"
    "convergence_kinds = 4\n"
    "\n"
    "[t004]\n"
    "# T004 (vouch surface removal) fires when a partial validpgpkeys\n"
    "# removal leaves at least this many keys removed and none gained.  The\n"
    "# whole-array case stays H024; a rotation stays T003/H078.\n"
    "min_removed_keys = 1\n"
    "\n"
    "[c033]\n"
    "# C033 (context bleed) fires when a diff deletes at least\n"
    "# min_deleted_comment_lines comment lines and that is at least\n"
    "# min_deleted_comment_ratio of the diff's pre-state comment prose.\n"
    "# The ratio is adjudicated against the locked benign corpus, not guessed.\n"
    "min_deleted_comment_ratio = 0.50\n"
    "min_deleted_comment_lines = 8\n"
    "\n"
    "[t008]\n"
    "# T008 (delayed payload adoption) reports a payload rule appearing at\n"
    "# least this many days after the package's latest maintainer adoption.\n"
    "# Full-AUR history/cycle context only; INFO and anergic pending benign replay.\n"
    "min_delay_days = 14\n"
    "\n"
    "[t009]\n"
    "# T009 (high-value dormant takeover) reports a maintainer transition when\n"
    "# the previous LastModified is older than dormant_days and at least one\n"
    "# exposure floor is met: votes, popularity, or direct dependents.\n"
    "# Full-AUR history/cycle context only; INFO and anergic pending benign replay.\n"
    "dormant_days = 180\n"
    "min_votes = 100\n"
    "min_popularity = 1.0\n"
    "min_dependents = 10\n"
    "\n"
    "[t006]\n"
    "# T006 (metadata-git divergence) fires when the AUR LastModified timestamp\n"
    "# is ahead of the git tip commit date by at least this many hours.  In\n"
    "# aurweb, pushes set both, so divergence means commits were pushed and\n"
    "# later stripped (history rewrite).\n"
    "min_divergence_hours = 24\n"
)

DEFAULT_IOCS = (
    "# H056 - Class E indicators of compromise.\n"
    "#\n"
    "# An entry is a confirmed artefact of a real incident: a package name\n"
    "# that was published as malware, a host a payload was fetched from, the\n"
    "# digest of a dropped binary.  H056 matches by exact equality and\n"
    "# nothing else - 'evil.example' does not match 'notevil.example' or\n"
    "# 'cdn.evil.example', and a truncated digest matches nothing.\n"
    "#\n"
    "# A MISS IS UNINFORMATIVE.  This list records what has already been\n"
    "# reported; it says nothing about a package it does not name.  An\n"
    "# attacker with fresh infrastructure is not on it by definition.\n"
    "#\n"
    "# The list ships empty: TrustSight does not invent indicators.  Add\n"
    "# entries from an advisory you can cite, and keep the provenance with\n"
    "# them - the confidence tier decides the severity, so an unsourced\n"
    "# entry must not sit at 'confirmed'.\n"
    "\n"
    "[meta]\n"
    "# Bump when the entry list changes; reports name the version they were\n"
    "# matched against.\n"
    "version = 1\n"
    "\n"
    "# Each indicator is one [[entries]] table:\n"
    "#\n"
    "# [[entries]]\n"
    "# type = \"domain\"              # domain | package | hash | file_path |\n"
    "#                             # pkgbuild_pattern\n"
    "# value = \"malicious.example\"  # matched exactly, case-insensitively\n"
    "# confidence = \"confirmed\"     # confirmed -> FATAL, high -> CRITICAL,\n"
    "#                              # medium -> HIGH (an entry with no known\n"
    "#                              # tier still matches, at MEDIUM)\n"
    "#                              # 'confirmed' scores the package 100 on\n"
    "#                              # its own - use it only for an artefact\n"
    "#                              # a report you can cite named as malware\n"
    "# provenance = \"https://security.archlinux.org/ASA-...\"\n"
    "# campaign = \"2026-06-aur-install-hook\"\n"
    "# added = \"2026-08-03\"\n"
)

STRUCTURAL_MATCHES = frozenset({
    "entry_added",
    "entry_removed",
    "host_added",
    "scalar_changed",
    "renamed",
})

STRUCTURAL_SEVERITY_CEILING = "HIGH"

_STRUCTURAL_CLAMPED = {"FATAL": STRUCTURAL_SEVERITY_CEILING,
                       "CRITICAL": STRUCTURAL_SEVERITY_CEILING}
