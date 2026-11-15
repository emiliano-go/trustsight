#!/usr/bin/env python3
"""Render or install a host nftables guard for the watcher bridge.

The Docker network policy keeps the watcher on an internal bridge; this guard
is the host-level backstop: only the proxy's CONNECT port is reachable from
that bridge, and all other new forwarded traffic is dropped.
"""

from __future__ import annotations

import argparse
import ipaddress
import subprocess
import sys

TABLE = "trustsight_host_guard"


def render(bridge: str, proxy_ip: str, *, proxy_ip6: str | None = None,
           port: int = 3128) -> str:
    ipaddress.ip_address(proxy_ip)
    if proxy_ip6:
        ipaddress.ip_address(proxy_ip6)
    lines = [
        f"table inet {TABLE} {{",
        "  chain forward {",
        "    type filter hook forward priority -10; policy accept;",
        "    ct state established,related accept",
        f'    iifname "{bridge}" ip daddr {proxy_ip} tcp dport {port} accept',
    ]
    if proxy_ip6:
        lines.append(
            f'    iifname "{bridge}" ip6 daddr {proxy_ip6} '
            f"tcp dport {port} accept")
    lines += [
        f'    iifname "{bridge}" drop',
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bridge", required=True)
    parser.add_argument("--proxy-ip", required=True)
    parser.add_argument("--proxy-ip6", default=None)
    parser.add_argument("--port", type=int, default=3128)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    rules = render(args.bridge, args.proxy_ip,
                   proxy_ip6=args.proxy_ip6, port=args.port)
    if not args.apply:
        print(rules, end="")
        return 0
    result = subprocess.run(
        ["nft", "-f", "-"], input=rules, text=True,
        capture_output=True, check=False,
    )
    if result.returncode != 0:
        print(result.stderr.strip() or "nft failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
