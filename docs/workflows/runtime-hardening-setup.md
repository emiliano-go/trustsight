<!-- description: Install and validate optional AppArmor, gVisor and Kata boundaries for the watcher, with host checks and rollback steps. -->

# Runtime Hardening Setup: AppArmor, gVisor and Kata

These are optional, stronger runtime boundaries for the watcher. The base
Docker profile already uses seccomp, `cap_drop: ALL`, `no-new-privileges`, a
read-only root, a non-root user, the internal network and the egress proxy.

Choose one extra boundary for the watcher:

| Host | Recommended |
|------|-------------|
| Normal Linux VPS, AppArmor enabled | custom AppArmor profile |
| VPS without KVM, AppArmor unavailable | gVisor (`runsc`) |
| Host with `/dev/kvm` and nested virtualization | Kata Containers |
| Cannot change the host | keep `docker-default`; do not claim the optional profiles |

Do not stack AppArmor inside gVisor or Kata: the inner runtime does not expose
the host LSM the same way. Use one boundary at a time.

Validate the result in the container:

```bash
docker exec trustsight-watch /app/.venv/bin/trustsight containment status --json
```

`uid` must not be `0`, `root_readonly` must be `true`, and `default_route` must
be `false`. `seccomp_filter` must be `true` under `runc` and AppArmor. Under
gVisor it is `false` because gVisor does not expose Docker's seccomp status;
the gVisor syscall layer is the boundary there. The database writer is a
separate networkless service; its socket is on `./run/trustsight-db`.

---

## AppArmor

### Check the host

```bash
cat /sys/module/apparmor/parameters/enabled
sudo aa-status
grep -E 'apparmor|security=' /proc/cmdline
```

`enabled` must be `Y`. If it is `N`, add
`apparmor=1 security=apparmor` to the kernel command line, rebuild the
bootloader configuration and reboot. The exact file depends on the
bootloader: GRUB uses `/etc/default/grub`, systemd-boot uses
`/etc/kernel/cmdline` or the UKI preset, and Limine uses
`/etc/default/limine`. On Omarchy/Limine the drop-in directory is ignored
when `/etc/default/limine` defines `KERNEL_CMDLINE[default]`; edit that file
and run `sudo limine-update`.

### Load the profile

Install the profile into the host policy directory so it survives a reboot,
then load it:

```bash
sudo install -Dm644 docker/apparmor/trustsight-watcher \
  /etc/apparmor.d/trustsight-watcher
sudo apparmor_parser -r /etc/apparmor.d/trustsight-watcher
sudo aa-status | grep trustsight-watcher
```

### Start the watcher

```bash
docker compose -f docker-compose.watcher.yml \
  -f docker-compose.watcher.apparmor.yml up -d
```

The entrypoint refuses to start unless
`/proc/self/attr/current` contains `trustsight-watcher`.

### Validate the parser path

```bash
docker exec trustsight-watch sh -c \
  'printf "pkgname=fixture\npkgver=1\npkgrel=1\narch=(any)\n" \
     > /tmp/PKGBUILD && /app/.venv/bin/trustsight lint /tmp/PKGBUILD --json'
```

The parser needs `mount`/`unshare`; if the profile denies them, the worker
must fail closed rather than fall back unconfined.

### Rollback

```bash
sudo apparmor_parser -R /etc/apparmor.d/trustsight-watcher
docker compose -f docker-compose.watcher.yml up -d
```

---

## gVisor

gVisor works without KVM, but its Linux compatibility is not perfect. **The
current parser worker is not compatible with gVisor:** it requires user,
network and mount namespaces plus Landlock, and gVisor does not provide those
inner sandbox primitives. The watcher can start, but parser/manifest work
fails closed with `OS sandbox not applied`. Do not deploy this overlay for the
full watcher until an alternate gVisor-compatible worker exists.

If you only want gVisor for commands that do not use the parser, the overlay
still starts. Otherwise use AppArmor on the host.

### Install `runsc`

gVisor publishes a tarball, not a standalone `runsc` download:

```bash
cd /tmp
arch="$(uname -m)"
base="https://storage.googleapis.com/gvisor/releases/release/latest/${arch}"
curl -fsSLO "${base}/gvisor.tar.zstd"
curl -fsSLO "${base}/gvisor.tar.zstd.sha512"
sha512sum -c gvisor.tar.zstd.sha512
sudo tar --zstd -xf gvisor.tar.zstd -C /usr/local/bin
```

Then register it:

```bash
sudo /usr/local/bin/runsc install
sudo systemctl reload docker
docker info --format '{{json .Runtimes}}'
```

`runsc` must appear in the runtime list.

### gVisor overlay status

Do not start the full watcher with the gVisor overlay. The services start, but
the watcher’s parser will refuse to process a recipe. Use the overlay only
for commands that do not need the parser until an alternate
gVisor-compatible worker exists. The entrypoint still refuses to start unless
`/proc/version` identifies gVisor/runsc.

### Validate

```bash
docker run --rm --network none --runtime=runsc \
  --read-only --cap-drop ALL --user 1000:1000 \
  --tmpfs /tmp:size=64m,noexec,nosuid,nodev \
  -e TRUSTSIGHT_REQUIRE_GVISOR=1 \
  ghcr.io/emiliano-go/trustsight:latest \
  containment status --json
```

The parser/manifest smoke will fail with `OS sandbox not applied` until an
alternate worker exists. Use the base `runc` profile or AppArmor for the full
watcher.

### Rollback

```bash
docker compose -f docker-compose.watcher.yml up -d
```

---

## Kata Containers

Kata needs `/dev/kvm` and nested virtualization. It is the wrong choice for a
cheap VPS without KVM.

### Check the host

```bash
ls -l /dev/kvm
```

### Docker support

Kata 3.x ships a containerd shim, not a Docker OCI runtime. Docker invokes
the runtime with `create`, which Kata 3's `kata-runtime` does not implement;
it fails with `Invalid command "create"`. Do not use the Kata overlay with a
Kata 3 package.

The overlay is usable only with a Kata 2.x runtime that still implements the
Docker OCI-v1 commands. If you have one, register it and restart Docker:

```bash
sudo systemctl restart docker
docker info --format '{{json .Runtimes}}'
```

`kata-runtime` must appear. For Kata 3, use containerd/CRI instead of Docker
Compose.

### Start the watcher (Kata 2 OCI runtime only)

```bash
docker compose -f docker-compose.watcher.yml \
  -f docker-compose.watcher.kata.yml up -d
```

Only the watcher uses the microVM in that overlay; the auxiliary services stay
on `runc`.

### Validate

Run the parser and manifest-worker smokes with `--runtime=kata-runtime`. Watch
for slower start-up and memory pressure. The gVisor section is not a template
for this step; its parser path is intentionally unsupported.

### Rollback

```bash
docker compose -f docker-compose.watcher.yml up -d
```

---

## Operating an existing watcher deployment

These are the failures seen when the watcher was moved from
`apparmor=unconfined` to the shipped profile on Debian 13. They are properties
of the profile, not optional tuning.

- **SQLite locks:** `/data/**` and `/tmp/**` need AppArmor's `k` permission.
  A rule that grants only `rw` produces `operation="file_lock"` denials on
  `trustsight.db`.
- **DNS:** allow `network inet dgram`, `network inet6 dgram` and
  `network netlink raw`, plus reads of `/etc/hosts`, `/etc/host.conf` and
  `/etc/gai.conf`. Stream-only network rules make the seed fetch fail with
  `Temporary failure in name resolution`.
- **User namespaces:** the parser workers write `/proc/<pid>/uid_map`,
  `gid_map` and `setgroups`; those paths need write permission.
- **CPU discovery:** `/sys/fs/cgroup/**` and `/sys/fs/cgroup/cpu.max` need
  read permission.
- **Signals:** Docker's runtime needs `signal` permission for stop and
  restart.
- **Bytecode:** Python imports `encodings` before `-B` takes effect. The
  image precompiles the standard library, and workers launch with both `-I`
  and `-B`; do not grant write access to the stdlib to silence `mknod`
  denials.

Reload after changing the profile and recreate the container. Reloading the
profile alone does not change an already-created container:

```bash
sudo /usr/sbin/apparmor_parser -r /etc/apparmor.d/trustsight-watcher
docker compose up -d --force-recreate watcher
```

### Watchtower

Do not let Watchtower update the watcher automatically. A local
`trustsight:0.29.0` image has no registry tag to pull, and a mutable
`ghcr.io/...:latest` tag can replace the image under a running profile and
upstream configuration. The host AppArmor profile and compose environment
survive a container recreation, but the image bytes do not.

Set the watcher label to `false` or remove it, and update deliberately:

```yaml
labels:
  - "com.centurylinklabs.watchtower.enable=false"
```

Then pull or rebuild, run `docker compose config`, and recreate the watcher
in a maintenance window.

### Upstream and full dependency depth

The upstream lane and the full dependency walk are opt-in settings on the
watcher service:

```yaml
environment:
  - TRUSTSIGHT_UPSTREAM_SCAN_ENABLED=1
  - TRUSTSIGHT_UPSTREAM_SCAN_ARCHIVE_FETCH=1
command:
  - |
    exec /app/.venv/bin/trustsight full-aur --watch \
      --interval 900 --depth -1 --notify ...
```

`--depth -1` means "walk every level, up to the existing 8-level and 200-node
ceilings", not unbounded. The upstream lane needs a 0.29.0 or newer image;
0.28.x ignores the environment flags.

---

## Notes

- These profiles do not replace the watcher's own sandbox; they add a
  second boundary.
- A profile that is selected but not actually active must fail startup. The
  `TRUSTSIGHT_REQUIRE_*` guards implement that.
- Re-run the parser tests after every runtime or kernel upgrade.
- Record the runtime and kernel version with the deployment; a green
  `containment status` on the wrong runtime is not evidence.
