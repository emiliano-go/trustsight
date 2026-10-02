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
`over_threshold` bar as the live stream, so a genuinely compromised
package pings at maximum priority; and the sweep and the adoption feed
stay out of replay cycles, because they model the live stream and two
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

The document carries the cycle counts and the alerts. Every
`over_threshold` entry says what happened, not only that it did: the
version transition, the AUR change date and the rules that fired. While a
`--since` replay runs, `day` names the AUR day being analysed.

```json
{
  "event": "trustsight.alerts",
  "tool": "trustsight",
  "title": "TrustSight: 1 package(s) over threshold (2026-05-01)",
  "priority": "urgent",
  "day": "2026-05-01",
  "cycle": {"added": 3, "changed": 41, "removed": 2, "processed": 44},
  "alerts": [{"package": "some-pkg", "rule_id": "H088"}],
  "over_threshold": [
    {
      "package": "hot-pkg",
      "score": 45,
      "aur": "https://aur.archlinux.org/packages/hot-pkg",
      "version": "1.0 -> 1.1",
      "last_modified": "2026-05-01 12:40 UTC",
      "rules": ["H001", "R001"]
    }
  ]
}
```

The corpus path fetches recipes over cgit rather than cloning, so there is
no commit id to report; the AUR `LastModified` and the version transition
are the anchors that carry the same information. The document is `urgent`
whenever `over_threshold` is non-empty, which is what sends ntfy
`Priority: 5`; `title` lands in the notification header on ntfy, with a tag
for the level.

Once a day the watcher also sends a low-priority heartbeat
(`trustsight.heartbeat`, ntfy `Priority: 2`) with the cycle counts and,
while replaying, the day it has reached. Silence then has only one
meaning: nothing found, not "the watcher died".

Any receiver that accepts a JSON POST works. ntfy accepts the same POST and
shows the document as the message text, so `--notify https://ntfy.sh/mytopic`
is a working phone notification with no further setup. A dead receiver is
logged and swallowed: a notification must never kill the watch loop. Cycles
with no new alerts send nothing. A package matching an IOC baseline entry is
always urgent, whatever it scored: the IOC tier reports outside the
heuristic score, so it would otherwise never cross the bar. Single-shot
cycles (a bootstrap chunk, a plain `full-aur` run) notify like watch cycles.

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
  -v trustsight-data:/home/ts/.local/share/trustsight \
  -v $PWD/trustsight-config:/home/ts/.config/trustsight:ro \
  --restart unless-stopped \
  ghcr.io/emiliano-go/trustsight:latest \
  full-aur --watch --interval 1800
```

The volume holds the database, the corpus state and the resume file, so a
container restart (or a new image) continues where the last cycle ended.
Mount a config directory carrying your `config.toml` (and `[notify] webhook`)
to keep settings out of the image. The tokenizer's network-namespace
isolation is not available in a default container; the process resource
limits still apply, and the analysis itself needs no privileges.

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
