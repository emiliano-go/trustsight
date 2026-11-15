#!/bin/sh
# Copy the operator's read-only config into a tmpfs before starting.
#
# The watcher needs to write rules.toml at startup (shipped-rule sync), but a
# writable bind mount would also let an RCE persist across restarts.  The
# source mount is read-only; this copy is the only writable config path and
# it disappears with the container.
set -eu

if [ "${TRUSTSIGHT_REQUIRE_APPARMOR:-}" = "1" ]; then
    attr="${TRUSTSIGHT_PROC_SELF_ATTR:-/proc/self/attr/current}"
    if [ ! -r "$attr" ] || ! grep -q 'trustsight-watcher' "$attr"; then
        echo "trustsight-entrypoint: AppArmor profile trustsight-watcher is not active" >&2
        exit 2
    fi
fi

if [ "${TRUSTSIGHT_REQUIRE_PINNED:-}" = "1" ]; then
    case "${TRUSTSIGHT_IMAGE:-}" in
        *@sha256:*) ;;
        *)
            echo "trustsight-entrypoint: image is not digest-pinned" >&2
            exit 2
            ;;
    esac
fi

_has_default_route() {
    route="${TRUSTSIGHT_PROC_NET_ROUTE:-/proc/net/route}"
    if [ -r "$route" ] && awk 'NR > 1 && $2 == "00000000" && $8 == "00000000" { found = 1 } END { exit found ? 0 : 1 }' "$route"; then
        return 0
    fi
    route6="${TRUSTSIGHT_PROC_NET_IPV6_ROUTE:-/proc/net/ipv6_route}"
    if [ -r "$route6" ] && awk '$1 ~ /^0+$/ && $2 == "00" { found = 1 } END { exit found ? 0 : 1 }' "$route6"; then
        return 0
    fi
    return 1
}

if [ "${TRUSTSIGHT_REQUIRE_HARDENED:-}" = "1" ]; then
    if _has_default_route; then
        echo "trustsight-entrypoint: watcher has a default route" >&2
        exit 2
    fi
    if [ "$(id -u)" = "0" ]; then
        echo "trustsight-entrypoint: refusing to run as root" >&2
        exit 2
    fi
    if [ -w / ]; then
        echo "trustsight-entrypoint: root filesystem is writable" >&2
        exit 2
    fi
    if [ -n "${TRUSTSIGHT_UPSTREAM_FETCHER_SOCKET:-}" ] \
        && env | grep -q '^TRUSTSIGHT_.*_TOKEN'; then
        echo "trustsight-entrypoint: provider token in the watcher; use the fetcher" >&2
        exit 2
    fi
    if [ -n "${TRUSTSIGHT_FEED_SIGNER_SOCKET:-}" ] \
        && env | grep -q '^TRUSTSIGHT_FEED_KEY'; then
        echo "trustsight-entrypoint: feed key in the watcher; use the signer" >&2
        exit 2
    fi
fi

src="${TRUSTSIGHT_CONFIG_SRC:-}"
dst="${TRUSTSIGHT_CONFIG_DIR:-}"
if [ -n "$src" ] && [ -n "$dst" ] && [ -d "$src" ]; then
    if [ "$src" = "$dst" ]; then
        echo "trustsight-entrypoint: config source and destination are the same" >&2
        exit 2
    fi
    umask 077
    mkdir -p "$dst"
    cp -R "$src"/. "$dst"/
    # The copy is operator-owned input, but it must be writable by the
    # unprivileged runtime so the shipped-rule sync can append missing rules.
    chmod -R u+rwX "$dst"
fi

exec "$@"
