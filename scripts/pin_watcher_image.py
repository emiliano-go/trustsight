#!/usr/bin/env python3
"""Resolve the watcher image to a digest-pinned reference.

`latest` is a mutable tag: a moved tag silently changes what the watcher runs.
This resolves the tag once, optionally verifies the signature with cosign, and
prints the immutable `repo@sha256:...` reference for the pinned compose
override.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

DEFAULT_REF = "ghcr.io/emiliano-go/trustsight:latest"


def repository(ref: str) -> str:
    """The repository part of a tag or digest reference."""
    if "@" in ref:
        return ref.split("@", 1)[0]
    head, sep, tail = ref.rpartition(":")
    # A colon in the last path element is a tag; one in an earlier element is
    # a registry port.
    if sep and "/" not in tail:
        return head
    return ref


def resolve_digest(ref: str, *, runner=subprocess.run) -> str:
    result = runner(
        ["docker", "buildx", "imagetools", "inspect", ref,
         "--format", "{{.Manifest.Digest}}"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or f"could not inspect {ref}")
    digest = result.stdout.strip()
    if not digest.startswith("sha256:"):
        raise RuntimeError(f"unexpected digest {digest!r}")
    return digest


def verify(ref: str, key: str, *, runner=subprocess.run) -> None:
    result = runner(
        ["cosign", "verify", "--key", key, ref],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "signature check failed")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ref", nargs="?", default=DEFAULT_REF)
    parser.add_argument("--cosign-key", help="verify the image before pinning")
    parser.add_argument(
        "--require-signature", action="store_true",
        help="refuse to pin unless --cosign-key is supplied and verifies")
    parser.add_argument("--output", help="write TRUSTSIGHT_IMAGE=... here")
    args = parser.parse_args(argv)
    try:
        digest = resolve_digest(args.ref)
        pinned = f"{repository(args.ref)}@{digest}"
        if args.require_signature and not args.cosign_key:
            raise RuntimeError(
                "refusing to pin without a cosign key "
                "(--cosign-key or drop --require-signature)")
        if args.cosign_key:
            verify(pinned, args.cosign_key)
    except Exception as exc:  # noqa: BLE001 - a one-line refusal
        print(f"pin-watcher-image: {exc}", file=sys.stderr)
        return 2
    line = f"TRUSTSIGHT_IMAGE={pinned}"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(line + "\n")
    print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
