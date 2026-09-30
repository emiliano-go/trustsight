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

The document carries the cycle counts and the alerts:

```json
{
  "event": "trustsight.alerts",
  "tool": "trustsight",
  "cycle": {"added": 3, "changed": 41, "removed": 2, "processed": 44},
  "alerts": [{"package": "some-pkg", "rule_id": "H088"}]
}
```

Any receiver that accepts a JSON POST works. ntfy accepts the same POST and
shows the document as the message text, so `--notify https://ntfy.sh/mytopic`
is a working phone notification with no further setup. A dead receiver is
logged and swallowed: a notification must never kill the watch loop. Cycles
with no new alerts send nothing.

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
