# Watcher deployment profiles

`seccomp-watcher.json` is Docker's default seccomp profile (Moby v28.0.0)
with one added allow rule: the namespace and mount calls the parser workers
need (`unshare`, `setns`, `clone`, `clone3`, `mount`, `umount2`,
`mount_setattr`, `move_mount`, `open_tree`, `fsopen`, `fsconfig`, `fsmount`,
`fspick`, `pivot_root`). Docker's stock profile allows those only with
`CAP_SYS_ADMIN`, which the watcher drops; the workers create a user namespace
and gain the capability inside it instead.

The profile keeps every other Docker default denial, including `bpf`,
`perf_event_open`, `ptrace`, `keyctl`, and `open_by_handle_at`.
It also adds an explicit `SCMP_ACT_ERRNO` rule for `ptrace`,
`process_vm_readv/writev`, `bpf`, `perf_event_open`, `keyctl`,
`userfaultfd`, the `io_uring` calls, `open_by_handle_at`, `kcmp` and
`pidfd_getfd`, so a future Docker default that permits one of them still
cannot reopen it here.

`apparmor=unconfined` remains in the compose file: the stock AppArmor profile
also blocks the worker mount path. A custom AppArmor profile or a gVisor
runtime is the next replacement; do not treat the current profile as complete
container confinement.

Validate a change with:

```bash
docker run --rm --cap-drop ALL --security-opt no-new-privileges \
  --security-opt seccomp="$PWD/docker/seccomp-watcher.json" \
  python:3.12-slim python -c "import ctypes; l=ctypes.CDLL(None,use_errno=True); print(l.unshare(0x10020000))"
```

Run the compose file from the repository root so the relative profile path
resolves.

`seccomp-fetcher.json` starts from the stock default and denies the
namespace/mount calls altogether: the fetcher never needs them. It also
denies the same dangerous calls as the watcher profile. The fetcher keeps
socket syscalls so it can perform the bounded HTTPS read.

Only the watcher keeps `apparmor=unconfined`, because its parser workers
need `mount`; the fetcher, proxy and signer use Docker's `docker-default`
AppArmor profile. Under `docker-default`, `unshare` still works but `mount`
is denied, which is why the watcher is the exception.

`apparmor/trustsight-watcher` is the optional watcher profile. Load it with
`apparmor_parser -r` and set `TRUSTSIGHT_APPARMOR_PROFILE=trustsight-watcher`;
the compose default remains `unconfined` for hosts without AppArmor.
