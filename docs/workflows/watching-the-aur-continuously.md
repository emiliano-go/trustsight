<!-- description: How to run TrustSight as an always-on AUR watcher: the watch loop, the bootstrap cost, systemd and Docker service setups, and webhook alerting for new clusters. -->

# Watching the AUR Continuously

`trustsight full-aur --watch` turns the tool into a scanner: every cycle
refreshes the AUR metadata snapshot, diffs what moved, analyses the changed
packages, and reports new alert clusters. A cluster is announced the first
time it is seen and then counted, not re-announced, so a quiet night prints
nothing.

## What a cycle costs

The AUR holds about 120,000 packages. The first run is a bootstrap: two
requests per package (PKGBUILD and .SRCINFO), throttled to 5 requests per
second with exponential backoff, so a from-scratch pass takes most of a day
and must be asked for with `--bootstrap`. Every cycle is capped
(`limits.corpus_max_per_cycle`) and resumes automatically, so the bootstrap
advances in gentle chunks across as many cycles as it needs.

After that, a cycle is nearly free: one conditional GET for the metadata
(zero bytes when the snapshot has not moved) plus two requests per changed
package. That is the whole load on the AUR, at any watch interval.

## Choosing an interval

```bash
trustsight full-aur --watch            # one cycle per hour (default)
trustsight full-aur --watch --interval 1800
```

The interval sets alert latency, not politeness: the load is the same
metadata GET plus actual churn either way. Below about 15 minutes you are
mostly re-downloading a snapshot the AUR has not regenerated; the floor is 60
seconds (`limits.watch_min_interval`), because a shorter interval only spins.

At startup the watch syncs `rules.toml` to the shipped ruleset the safe way
(adds missing rules, repairs a `match_target`/`severity`/`category`/`scope`
that moved, adopts a superseded shipped pattern, never touches a pattern you
edited) and logs what it changed, so an unattended watcher never analyses with
a stale ruleset. Set `TRUSTSIGHT_NO_SYNC_RULES` to skip it.

## Replaying the past with `--since`

A fresh watcher only sees what changes from now on. To scan for a campaign
that already happened, replay history instead:

```bash
trustsight full-aur --watch --since 2026-06-01 --notify https://ntfy.sh/mytopic
```

Each cycle analyses the packages whose AUR `LastModified` falls in one day
of AUR time, empty days are skipped inside the cycle, and the replay joins
the live delta stream when it catches up. The clock is the AUR's own
timestamps, not wall time, so a replay of June 2026 walks June 2026 no
matter when you start it. The cursor persists in the database: interrupt
it, restart the container, and the replay continues from the day it
reached.

Two things to expect on a replay. It alerts through the same
`over_threshold` bar as the live stream; and the sweep and the adoption
feed stay out of replay cycles, because they model the live stream and two
years of history would only distort their baselines. A package that was
cleaned up after the campaign scores by its *current* recipe: what
persists is what gets flagged.

## Alerting over a webhook

A watcher nobody reads is a log file. Give it a push channel and new alert
clusters arrive as one HTTPS POST of a JSON document per cycle:

```bash
trustsight full-aur --watch --notify https://example.invalid/hooks/aur
```

or permanently in `config.toml`:

```toml
[notify]
webhook = "https://example.invalid/hooks/aur"
```

A second, independent sink posts the same document to the TrustSight feed,
which ingests it directly instead of polling ntfy:

```toml
[notify]
feed = "https://watcher.trustsight.org/api/ingest"
```

Every feed POST is signed with an Ed25519 key (`TRUSTSIGHT_FEED_KEY`, base64
PKCS#8; `TRUSTSIGHT_FEED_KEY_ID` names it), and the feed holds only the public
half. In the container the key lives in the separate `feed-signer` service and
the watcher asks it through `TRUSTSIGHT_FEED_SIGNER_SOCKET`; the watcher never
reads the private key. ntfy and the feed are independent: one failing never
stops the other, and with no key or signer the feed sink is skipped.

The document carries the cycle counts and the alerts. Every
`over_threshold` entry says what happened, not only that it did: the
version transition, the AUR change date, the current and previous
maintainer and the rules that fired. Each `alerts` entry names the
package and rule, and an ownership rule (H044/H026) also carries `old`
and `new`; a `campaign_cluster` carries its stable `campaign_id` and
`members_detail` with the same ownership and version context for each member,
so a reader can see which maintainer adopted which package and follow the
campaign across cycles. An alert may also carry `pkgbuild_sha256`,
`previous_pkgbuild_sha256` and a bounded `diff` of the exact recipe change;
when the diff exceeds the cap, `diff_truncated` and `diff_sha256` remain. While a `--since` replay runs, `day`
names the AUR day being analysed. The alerting bar is `--over-threshold
N` (the `over_threshold` argument on `refresh_corpus`/`watch`); the
default is 30, the benign corpus's measured 95th percentile
(`calibration.benign_p95`), and a package alerts when its score is
**strictly above** it.

```json
{
  "event": "trustsight.alerts",
  "tool": "trustsight",
  "title": "TrustSight: hot-pkg scored 45 (H001) (2026-05-01)",
  "priority": "default",
  "day": "2026-05-01",
  "cycle": {"added": 3, "changed": 41, "removed": 2, "processed": 44},
  "alerts": [
    {"package": "adopted-pkg", "rule_id": "H044",
     "maintainer": "newm", "old": "oldm", "new": "newm"}
  ],
  "over_threshold": [
    {
      "package": "hot-pkg",
      "score": 45,
      "aur": "https://aur.archlinux.org/packages/hot-pkg",
      "version": "1.0 -> 1.1",
      "last_modified": "2026-05-01 12:40 UTC",
      "maintainer": "hotm",
      "previous_maintainer": "oldhotm",
      "rules": ["H001", "R001"]
    }
  ],
  "campaign_cluster": [
    {
      "rule_id": "G003",
      "members": ["adopted-pkg", "other-pkg"],
      "count": 2,
      "members_detail": [
        {"package": "adopted-pkg", "maintainer": "newm",
         "previous_maintainer": "oldm", "version": "1.0 -> 2.0"}
      ]
    }
  ],
  "ioc_matches": []
}
```

The corpus path downloads each recipe's snapshot tarball (the GitHub AUR
mirror first, the AUR's cgit second) rather than cloning, so there is no
commit id to report; the AUR `LastModified` and the version transition are
the anchors that carry the same information. `title` lands in the notification header on ntfy, with a tag for the
level. Alerts never carry a priority: an over-threshold package is worth a
quiet read in the morning, not a page at night; only the daily heartbeat
sets one (Priority 2, low).

Once a day the watcher also sends a low-priority heartbeat
(`trustsight.heartbeat`, ntfy `Priority: 2`) with the cycle counts and,
while replaying, the day it has reached. Silence then has only one
meaning: nothing found, not "the watcher died".

Any receiver that accepts a JSON POST works. ntfy accepts the same POST and
shows the document as the message text, so `--notify https://ntfy.sh/mytopic`
is a working phone notification with no further setup. A dead receiver is
logged and swallowed: a notification must never kill the watch loop. Cycles
with no new alerts send nothing. A package matching an IOC baseline entry
is listed in the document's `ioc_matches` whatever it scored: the IOC tier
reports outside the heuristic score, so it would otherwise never cross the
bar, and the match is a fact to read rather than a higher priority.
When the upstream lane is active, the fetched manifest and workflow texts are
IOC surfaces too, so campaign indicators such as GhostAction's injected
workflow addresses are enforced even when the PKGBUILD diff is clean.
Single-shot cycles (a bootstrap chunk, a plain `full-aur` run) notify like
watch cycles.

## Health and delivery

A failed cycle is not a dead watcher, and a quiet channel is not proof of
life. `trustsight full-aur health` reads the recorded last start, last success,
consecutive failures, outbox and database size; `--json` is the machine form.
The container healthcheck uses `full-aur health --optional`, so a database with
no watcher state is healthy and a stale or repeatedly failing watcher is not.

Alerts are written to a durable outbox before any POST. If ntfy or the feed is
down, the document stays queued and is retried with capped exponential backoff
on later cycles; an alert that cannot be delivered within 24 hours is parked
and `health` reports it. This is at-least-once delivery: ntfy may show a
duplicate after a crash between the POST and the delivery mark, while the feed
dedupes on the persisted `webhook-id`.

`SIGTERM` stops the loop between packages, saves the resume state and
checkpoints the WAL. Only one watcher may own a data directory; a second
start fails with the lock path instead of interleaving cycles.

For a container, mount the feed key as a secret into the `feed-signer`
service and point `TRUSTSIGHT_FEED_KEY_FILE` at it there; the watcher only
gets the signer socket. The shipped compose file runs read-only with a tmpfs for `/tmp`
and the cache, drops all capabilities, sets `no-new-privileges`, and permits
the parser workers' `unshare` and mount operations with the shipped
`docker/seccomp-watcher.json` profile. The watcher keeps
`apparmor=unconfined` because those workers need `mount`; the fetcher, proxy
and signer use Docker's `docker-default` profile. A custom AppArmor profile
is shipped as `docker/apparmor/trustsight-watcher`; load it and opt in:

```bash
sudo apparmor_parser -r docker/apparmor/trustsight-watcher
docker compose -f docker-compose.watcher.yml \
  -f docker-compose.watcher.apparmor.yml up -d
```

The default stays `unconfined` until the overlay is used, so a host without
AppArmor support still starts. With the overlay, the entrypoint checks
`/proc/self/attr/current` and refuses to run unless the profile is active. The profile allows only the mount/userns the
parser workers need and limits the rest of the filesystem to the read-only
app, config and runtime paths.

## As a systemd service

```ini
# ~/.config/systemd/user/trustsight-watch.service
[Unit]
Description=TrustSight AUR watcher
After=network-online.target

[Service]
ExecStart=/usr/bin/trustsight full-aur --watch --interval 1800
Restart=on-failure
RestartSec=300
KillSignal=SIGTERM
TimeoutStopSec=120

[Install]
WantedBy=default.target
```

State is durable at every cycle boundary (the snapshot and the resume file
are saved before a cycle returns), so `Restart=on-failure` loses at most the
cycle in flight. Enable with:

```bash
systemctl --user enable --now trustsight-watch.service
loginctl enable-linger "$USER"   # keep it running without a login session
```

## As a Docker container

The image is published to the GitHub Container Registry on every release:

```bash
docker run -d --name trustsight-watch \
  --user 1000:1000 \
  --security-opt seccomp="$PWD/docker/seccomp-watcher.json" \
  --security-opt apparmor=unconfined \
  -e TRUSTSIGHT_UPSTREAM_SCAN_ENABLED=1 \
  -e TRUSTSIGHT_UPSTREAM_SCAN_ARCHIVE_FETCH=1 \
  -e TRUSTSIGHT_CONFIG_SRC=/config-src \
  -e TRUSTSIGHT_CONFIG_DIR=/tmp/trustsight-config \
  -v trustsight-data:/home/ts/.local/share/trustsight \
  -v $PWD/trustsight-config:/config-src:ro \
  --restart unless-stopped \
  ghcr.io/emiliano-go/trustsight:latest \
  full-aur --watch --interval 1800 --depth -1
```

The volume holds the database, the corpus state and the resume file, so a
container restart (or a new image) continues where the last cycle ended.
Mount a config directory carrying your `config.toml` (and `[notify] webhook`)
to keep settings out of the image. The source is mounted read-only; the
entrypoint copies it into `/tmp/trustsight-config`, where the startup ruleset
sync can write. That copy lives in the container's tmpfs and disappears on
restart, so an RCE cannot persist by editing config or rules. The data volume
is the only path that survives, and it holds only database/corpus state. The
container runtime must allow unprivileged user namespaces: if it does not, the
parser workers refuse and the package is reported as not vetted rather than
analysed with weaker confinement. With Docker, pass the shipped custom
`--security-opt seccomp=$PWD/docker/seccomp-watcher.json` (from the repository
root) and `--security-opt apparmor=unconfined`, because the stock profiles
deny the namespace and mount syscalls. The process needs no
privileges. See
[Reducing Blast Radius](reducing-blast-radius.md) for the boundary around the
auditor and what it does not cover.

A compose file with the same settings - a fixed container name, log
rotation, the timestamped log format, a read-only root filesystem, dropped
capabilities, resource limits and the watcher healthcheck - ships as
`docker-compose.watcher.yml`:

```bash
mkdir -p trustsight-config
docker compose -f docker-compose.watcher.yml up -d
docker compose -f docker-compose.watcher.yml logs -f trustsight-watch
```

### Deploying a digest-pinned image

`latest` is mutable. Resolve and optionally verify the image once, then use
the pinned overlay so a moved tag cannot change what the watcher runs:

```bash
export TRUSTSIGHT_IMAGE=$(python scripts/pin_watcher_image.py \
  --cosign-key /path/to/cosign.pub --require-signature)
docker compose -f docker-compose.watcher.yml \
  -f docker-compose.watcher.pinned.yml up -d
```

The overlay refuses to start without `TRUSTSIGHT_IMAGE`. The helper prints
`repo@sha256:...`; `--cosign-key` requires the signature check to pass, and
`--require-signature` refuses to pin at all when no key is supplied.
The pinned overlay also sets `TRUSTSIGHT_REQUIRE_PINNED=1`, so the watcher
entrypoint itself refuses to start from a mutable tag even if one is passed
through the environment.

### Upstream reads and deep dependencies

The shipped compose file runs `full-aur --watch --interval 1800 --depth -1`,
so a cycle walks each root's reachable AUR dependency closure (bounded by the
existing 8-level and 200-node per-root ceilings).  It also adds a separate
`upstream-fetcher` service and points the watcher at its Unix socket:

```yaml
environment:
  TRUSTSIGHT_UPSTREAM_SCAN_ENABLED: "1"
  TRUSTSIGHT_UPSTREAM_SCAN_ARCHIVE_FETCH: "1"
  TRUSTSIGHT_UPSTREAM_FETCHER_SOCKET: "/run/trustsight/upstream.sock"
```

The fetcher owns the HTTP/TLS path and the provider token; the watcher has
neither. Create the shared socket directory before starting the watcher:

```bash
mkdir -p run/trustsight run/trustsight-token
```

The watcher, fetcher and signer have no default route: they sit on
`watcher-internal` and reach the internet only through `egress-proxy`.
The proxy accepts CONNECT on 443 to the exact forge/CDN plus AUR, release and
default feed/ntfy hosts; the watcher's `HTTPS_PROXY` routes AUR, release,
feed and ntfy traffic through it, and the parser worker remains networkless.
An operator webhook or custom ntfy host must be added to
`TRUSTSIGHT_EGRESS_ALLOW` on the proxy; it is an exact-host allowlist, never
a wildcard.

Every CONNECT, allowed or refused, is appended to
`trustsight-egress-audit` (`proxy.jsonl`), so a denied destination or an
unexpected host is visible after the fact. An allowed CONNECT is refused if
its audit record cannot be written; the log rotates at 64 MiB.

`TRUSTSIGHT_REQUIRE_HARDENED=1` also checks `/proc/net/route` and
`/proc/net/ipv6_route`; the watcher refuses to start if it finds a default
route. Running it on a bridge with direct internet access therefore fails
closed instead of silently bypassing the proxy.
It also refuses a writable `/config-src`, so the operator config mount must
really be read-only rather than merely intended to be.

### Rotating provider tokens through the broker

The compose file includes a networkless `token-broker` service. Mount a
directory of `0600` files into it:

```
secrets/tokens/github.token
secrets/tokens/github.expires   # optional Unix timestamp
```

Then set
`TRUSTSIGHT_GITHUB_TOKEN_SOCKET=/run/trustsight-token/token-broker.sock`
on the fetcher. The token-broker socket lives on its own volume, not the
watcher's; rotate a file and its expiry without restarting anything, and an
absent, expired, or unreadable token fails closed.

The lane reads a declared source archive only when the recipe names an
allowlisted forge host and a checksum at or above 256 bits pins it.  It never
fetches on the local `review`/`inspect` path, and those two environment
variables are the only settings a container needs; setting them in a shell
profile would enable the lane for every local command too.

GitHub rate-limits anonymous source reads, so a token is strongly recommended
for an AUR-wide watcher.  Mount a `0600` token file read-only into the
`upstream-fetcher` service (not the watcher) and point that service at it:

```yaml
services:
  upstream-fetcher:
    volumes:
      - ./secrets/github-token:/run/secrets/github_token:ro
    environment:
      TRUSTSIGHT_GITHUB_TOKEN_FILE: "/run/secrets/github_token"
```

Do not put the token itself in `docker-compose.watcher.yml` or the
environment: `docker inspect` exposes it.  A token issued for a different
provider uses the matching `TRUSTSIGHT_<PROVIDER>_TOKEN_FILE`.  A locked or
refusing keyring fails closed: the package records
`upstream_scan_token_unavailable` and the archive is skipped rather than read
anonymously.

The same settings can live in the mounted `config.toml`:

```toml
[upstream_scan]
enabled = true
archive_fetch = true
```

### Stronger isolation with gVisor

An optional overlay runs every watcher service under `runsc`:

```bash
docker compose -f docker-compose.watcher.yml \
  -f docker-compose.watcher.gvisor.yml up -d
```

Install and register `runsc` as a Docker runtime first, and validate
`unshare`/`mount` for the parser workers on the target version. The overlay
covers the watcher, fetcher, proxy and signer; it changes the kernel boundary,
not the service configuration. Each service also sets
`TRUSTSIGHT_REQUIRE_GVISOR=1`; the entrypoint refuses to start unless
`/proc/version` identifies gVisor/runsc, so a silently missing runtime does
not downgrade the deployment.

`docker-compose.watcher.kata.yml` is the equivalent microVM overlay for the
watcher and its parser workers (`runtime: kata-runtime`). Install Kata and
register the runtime first; the other services keep their container
boundaries.

### Anchoring the signer audit head

The signer publishes `head.json` on the signer-audit volume. A monitor should
compare it with an off-host value it already trusts:

```bash
python scripts/check_audit_anchor.py /data/signer/head.json \
  --expected "$ANCHORED_CHAIN"
```

Exit `2` means the head moved without the anchor being updated, or the head
is unreadable. Publish the new value only after the signer's audit log has
been reviewed.

The compose file also has an opt-in `anchor-monitor` profile that polls every
five minutes, mounts the signed audit volume read-only, and has no network:

```bash
docker compose -f docker-compose.watcher.yml \
  --profile anchor-monitor up -d anchor-monitor
```

It exits non-zero when the head no longer matches the mounted
`./anchor/expected` file.

### Reading the logs

The watcher logs every cycle to stderr, so `docker logs -f trustsight-watch`
(or the compose command above) is the watcher's whole history. A watch opens
with a banner naming the build, the database path, the interval and whether an
alert webhook is configured; each cycle then reports what moved, the packages
over the alerting bar, and any new cluster alert. The output is unbuffered
(`PYTHONUNBUFFERED=1` in the image), so lines appear as they are written.

`TRUSTSIGHT_LOG_TIMESTAMPS=1` prefixes each line with a timestamp and level -
useful when the container is the only record. `TRUSTSIGHT_LOG_LEVEL` raises or
lowers verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`). Log records are rendered
inert like every other terminal surface: a maintainer name, URL, path or
exception message cannot inject control sequences or forge an extra log line.

The image runs rootless and ships no pacman, which makes it the
cold-environment reference: every measurement inside it is the reproducible
one.

## Feeding the watcher the baselines

The watcher is sharpest with the signed channel data in place:

```bash
trustsight seed fetch        # known URLs, maintainers, dependency names
trustsight ioc update        # federated known-bad indicators
```

Both verify against the pinned distribution key. Neither refreshes itself:
re-run both on your own schedule (a cron entry next to the service is fine;
they are cheap conditional fetches).

## Reading what it found

New alerts also land in the log and in `--json` output (one JSON object per
cycle). For the history of what moved, `trustsight corpus pivot` and
`trustsight history <package>` read the same database the watcher writes.
