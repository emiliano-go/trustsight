<!-- description: How to run TrustSight with a smaller blast radius: a dedicated unprivileged account or an ephemeral container, what each boundary protects, and which workflows it cannot carry. -->

# Reducing TrustSight's Blast Radius

TrustSight is built so that hostile AUR text cannot reach the machine through
the parsers: the tokenizer, the committed manifests and libgit2 all run in
resource-bounded, kernel-confined subprocesses (A6, A16, A17). What remains
inside the analysis process is TrustSight itself plus the third-party
libraries it imports, and those are trusted substrate the project does not
audit. That residual is stated in
[What this part does not protect](../security/program-under-attack.md#what-this-part-does-not-protect).

This guide is the operator-side boundary around that residual. Running the
auditor under a separate UID or in a disposable container bounds what a defect
in the process could read, write or signal. It does not change detection, it
does not make a clean report trustworthy, and it does not protect the package
you build afterwards with `makepkg`: once makepkg runs, that package has your
account's access by design.

Most of the hardening advice you may have read is already true of TrustSight:

- The input is not code: no `eval`, no `exec`, no `os.system`, no
  `shell=True`, no unpickling.
- TrustSight never uses sudo and never writes system configuration. Its own
  config, database and cache are created `0700` under `$HOME`.
- Declared source URLs are never fetched; the network reach is a fixed set of
  AUR and release endpoints.
- The watcher has a container deployment with a read-only root filesystem,
  dropped capabilities, `no-new-privileges`, resource limits and no host home
  mount. See [As a Docker container](watching-the-aur.md#as-a-docker-container).

The sections below add an account or container boundary around the interactive
CLI. Pick one; they are alternatives, not layers to stack blindly.

## What the isolated account still needs

A dedicated account needs only what an audit actually uses:

- Its own `$HOME` for `~/.config/trustsight`, `~/.local/share/trustsight`
  and `~/.cache/trustsight`.
- Read access to the local pacman databases, so `pacman -Qm`, `pacman -Sl`
  and `pacman-conf` answer. On Arch these are world-readable by default.
- Outbound HTTPS to the AUR for the package under review, and optionally to
  the release channel for `seed fetch` and `ioc update`.

It does not need your SSH keys, your GPG keys, your browser profile, your
personal files, an SSH or GPG agent socket, the `wheel` group, or the
`docker` group. A newly created account has none of these. Do not bind them
into a container either.

One workflow is deliberately excluded: `trustsight-gate` runs inside yay or
paru, needs the installing user's controlling terminal for the approval
prompt, and writes the hook under that user's
`~/.config/yay` or `~/.config/paru`. Keep the gate in your own account. The
dedicated account is for `review`, `inspect` and `preinstall` runs, not for
the install-time hook.

## Option 1: a dedicated unprivileged account

Create the account with no login shell:

```bash
sudo useradd --create-home --shell /usr/bin/nologin trustsight
```

The account does not need a password. A nologin shell prevents interactive
login; you run commands as the UID with `sudo -u`, `runuser` or a transient
systemd unit. The account itself gets no sudo rights from this.

Set the environment explicitly. `sudo -H` fixes `HOME`, which is what
TrustSight's config and data paths use, but the document cache reads
`XDG_CACHE_HOME`, and that variable can survive the switch from your session.
A wrapper keeps every path inside the account:

```bash
run_as_trustsight() {
  sudo -u trustsight -H env \
    HOME=/home/trustsight \
    XDG_CONFIG_HOME=/home/trustsight/.config \
    XDG_CACHE_HOME=/home/trustsight/.cache \
    "$@"
}
```

Then use it for every command:

```bash
run_as_trustsight trustsight --version
run_as_trustsight pacman -Qm >/dev/null && echo "pacman database readable"
run_as_trustsight trustsight review
run_as_trustsight trustsight inspect PACKAGE_NAME \
  --allow-uninstalled --full-recipe
```

Do not make the first invocation as root. `ensure_dirs()` creates the config,
data and cache directories with the UID that runs the command; root-owned
directories make the account's next run fail to sync rules and migrate the
database.

If the pacman probe fails, grant read-only access rather than adding the
account to a privileged group. On a default Arch install the paths are already
readable, so this is normally unnecessary:

```bash
sudo setfacl -m u:trustsight:rX /etc/pacman.conf
sudo setfacl -R -m u:trustsight:rX /etc/pacman.d /var/lib/pacman
```

### Keep state with the account

The observation database records novelty and history, so its location is
functional state, not a cache. Running as `trustsight` means the state lives
under `/home/trustsight`, separate from your own history. That is the point of
the boundary. If you want the existing history in the new account, copy it
once while nothing is running, then fix ownership:

```bash
sudo install -d -m 700 -o trustsight -g trustsight \
  /home/trustsight/.config/trustsight \
  /home/trustsight/.local/share/trustsight \
  /home/trustsight/.cache/trustsight
sudo cp -a ~/.local/share/trustsight/. /home/trustsight/.local/share/trustsight/
sudo cp -a ~/.config/trustsight/. /home/trustsight/.config/trustsight/
sudo chown -R trustsight:trustsight /home/trustsight
```

Do not point two live accounts at one SQLite database. A split history is
safer than a shared write path, and novelty signals are per-account by
design.

### Network

The account still needs AUR egress for a fresh package. Once the release
channel data is imported, `TRUSTSIGHT_OFFLINE=1` prevents outbound requests
to the release channel and the AUR RPC, serving what the local cache holds.
It is not a general network sandbox: the analysis channel still needs the AUR
for a package it has not cached, and the watcher still needs its metadata
snapshot. For a hard host allowlist, enforce it in the account's network
policy (nftables, a container network, or a dedicated network namespace), not
in TrustSight.

## Option 2: an ephemeral container

The published image is the reference container. It runs as a non-root `ts`
user with UID 1000, ships no pacman, and is built for the corpus and watcher
workflows. You can also use it for a one-off remote inspection with a
disposable or named volume for state:

```bash
docker run --rm -it \
  --read-only \
  --tmpfs /tmp:rw,size=64m,mode=1777 \
  --tmpfs /home/ts/.cache:size=64m \
  --user 1000:1000 \
  --cap-drop=all \
  --security-opt=no-new-privileges \
  --security-opt=seccomp=unconfined \
  --security-opt=apparmor=unconfined \
  --pids-limit=512 --memory=2g --cpus=2 \
  -v trustsight-data:/home/ts/.local/share/trustsight \
  -v trustsight-config:/home/ts/.config/trustsight \
  --pull=always \
  ghcr.io/emiliano-go/trustsight:latest \
  inspect PACKAGE_NAME --allow-uninstalled --full-recipe
```

Podman accepts the same flags; rootless Podman usually needs no seccomp
override. The data and config volumes and the two tmpfs mounts (`/tmp` and
`/home/ts/.cache`) are the writable paths; the root filesystem stays
read-only, and nothing from your home directory is mounted. `--user
1000:1000` matches the image and the watcher compose file, so a volume
created by one run is writable by the next. `--pull=always` keeps a floating
`:latest` from staying at the image first pulled; if you pin a digest instead,
update it deliberately.

`review` of your installed packages and `trustsight-gate` are not container
workflows: the image has no pacman database, and the gate needs the installing
user's terminal and AUR helper config. Use the dedicated account for those.

Container details that matter:

- Docker's built-in seccomp and AppArmor profiles deny `unshare` and `mount`,
  which the parser workers need to enter their user, network and mount
  namespaces. `--security-opt seccomp=unconfined --security-opt
  apparmor=unconfined` removes those outer filters; the workers still install
  their own seccomp allowlist, drop every capability and enter the namespaces
  and private mount tree themselves. Without the flag the workers refuse and the package is reported
  as not vetted. If you cannot relax the outer filter, use a custom profile
  that permits `unshare`, or the account route instead.
- The container kernel must also allow unprivileged user namespaces. On a
  kernel with the AppArmor restriction, allow them for the container or use
  the account route.
- The container needs AUR egress. If your threat model requires a network
  allowlist, enforce it at the container network layer; TrustSight cannot do
  it from inside.

## After an update

An update replaces the installed program; it does not touch the account's
state. Run the first command after an update as the account, because that run
adds missing shipped rules and migrates the database. Back up first if the
update crosses a major version:

```bash
run_as_trustsight trustsight db backup
run_as_trustsight trustsight status
run_as_trustsight trustsight db check
```

`status` names rules that are stale or absent. Missing rules are added on any
run. A shipped pattern fix reaches `rules.toml` only through an explicit sync,
which is safe because rules you edited are not replaced:

```bash
run_as_trustsight trustsight config sync-rules --update
```

For the container, pull the new image, rerun the read-only command above with
the same data and config volumes, and repeat `status` and `db check` inside
it:

```bash
docker pull ghcr.io/emiliano-go/trustsight:latest
```

If a future image changes the `ts` UID, keep the documented `--user 1000:1000` and
verify the volumes are still writable by that UID, or recreate the volumes.
The CI smoke test runs this recipe twice against one set of volumes, so a
change that breaks persistence fails the release before the image is
published.

## What this boundary does not cover

- **The build.** `makepkg` runs as your user, not as `trustsight`. The
  boundary ends when the review ends.
- **The report.** Detection limits are unchanged. A clean verdict still means
  no known signal fired, not that the package is safe.
- **Configuration you import.** A hostile or careless `overrides.json` or
  suppression file can hide findings in the account's config. Treat config
  as trusted input; the threat model does.
- **The kernel and the interpreter.** A kernel or Python defect is below both
  the account and the container.
- **Your own network and filesystem policy.** A bind mount, an agent socket or
  a shared volume reopens exactly the access this boundary removes.

## Verifying the boundary

```bash
id trustsight                     # no wheel, no docker, no extra groups
run_as_trustsight trustsight --version
run_as_trustsight pacman -Qm >/dev/null && echo ok
run_as_trustsight trustsight status
run_as_trustsight trustsight db check
run_as_trustsight ls -la /home/trustsight    # only the account's own files
```

If any of those show access you did not intend, fix the account before
trusting the isolation.
