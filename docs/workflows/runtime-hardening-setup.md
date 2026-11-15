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

`seccomp_filter` must be `true`, `uid` must not be `0`, `root_readonly` must be
`true`, and `default_route` must be `false`. The database writer is a separate
networkless service; its socket is on `./run/trustsight-db` and it is not
affected by the runtime overlay except for gVisor, which covers it too.

---

## AppArmor

### Check the host

```bash
cat /sys/module/apparmor/parameters/enabled
sudo aa-status
grep -E 'apparmor|security=' /proc/cmdline
```

`enabled` must be `Y`. If it is `N`, enable AppArmor in the kernel command line
(`apparmor=1 security=apparmor`), rebuild the bootloader configuration and
reboot. The exact grubby/`/etc/default/grub` command depends on the
distribution.

### Load the profile

From the repository root:

```bash
sudo apparmor_parser -r docker/apparmor/trustsight-watcher
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
docker exec trustsight-watch /app/.venv/bin/trustsight lint /app/PKGBUILD --json
```

Use a real fixture path. The parser needs `mount`/`unshare`; if the profile
denies them, the worker must fail closed rather than fall back unconfined.

### Rollback

```bash
sudo apparmor_parser -R docker/apparmor/trustsight-watcher
docker compose -f docker-compose.watcher.yml up -d
```

---

## gVisor

gVisor works without KVM, but its Linux compatibility is not perfect. Test the
parser and manifest worker before trusting it.

### Install `runsc`

Follow the official gVisor install for your distribution, then register it:

```bash
sudo runsc install
sudo systemctl restart docker
docker info --format '{{json .Runtimes}}'
```

`runsc` must appear in the runtime list.

### Start the watcher

```bash
docker compose -f docker-compose.watcher.yml \
  -f docker-compose.watcher.gvisor.yml up -d
```

Every service in that overlay sets `TRUSTSIGHT_REQUIRE_GVISOR=1`; the
entrypoint refuses to start unless `/proc/version` identifies gVisor/runsc.

### Validate

```bash
docker run --rm --network none --runtime=runsc \
  -v "$PWD:/work:ro" \
  ghcr.io/emiliano-go/trustsight:latest \
  lint /work/PKGBUILD --json
```

Also run the manifest-worker smoke from `docker.yml`. If mount/unshare or a
needed syscall is unimplemented, use the base `runc` profile instead.

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

### Install and register

Install the Kata Containers packages for your distribution, configure Docker
with a `kata-runtime` entry, and restart Docker:

```bash
sudo systemctl restart docker
docker info --format '{{json .Runtimes}}'
```

`kata-runtime` must appear.

### Start the watcher

```bash
docker compose -f docker-compose.watcher.yml \
  -f docker-compose.watcher.kata.yml up -d
```

Only the watcher uses the microVM in that overlay; the auxiliary services stay
on `runc`.

### Validate

Run the same parser and manifest-worker smokes as the gVisor section, with
`--runtime=kata-runtime`. Watch for slower start-up and memory pressure.

### Rollback

```bash
docker compose -f docker-compose.watcher.yml up -d
```

---

## Notes

- These profiles do not replace the watcher's own sandbox; they add a
  second boundary.
- A profile that is selected but not actually active must fail startup. The
  `TRUSTSIGHT_REQUIRE_*` guards implement that.
- Re-run the parser tests after every runtime or kernel upgrade.
- Record the runtime and kernel version with the deployment; a green
  `containment status` on the wrong runtime is not evidence.
