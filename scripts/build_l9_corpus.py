#!/usr/bin/env python3
"""Build the L9 acceptance corpus: rule pairs, benign controls, lane bounds.

The corpus exists because the diff corpus can never exercise an artifact
rule.  Each fixture is small, reviewed data:

* ``rule-fixtures/``  one positive and one near-miss negative per A rule, so a
  rule that fires on the negative is caught as a shape defect;
* ``benign/``        real manifests produced from built packages, which must
  stay quiet outside the two rules already known to be census-shaped;
* ``built/``         a real ``makepkg`` artifact plus the manifest extracted
  from it, proving the producer and the lane agree on a real build.

``expected.json`` is the assertion table the test runner reads.  It records
the lane (``manifest``, ``upstream`` or ``release``) and the exact rule set.

Usage:
    python scripts/build_l9_corpus.py --write-fixtures
    python scripts/build_l9_corpus.py --import-benign PKG [PKG ...]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

from artifact_manifest import build_manifest  # noqa: E402

OUT = ROOT / "tests" / "fixtures" / "l9-corpus"
RULES = OUT / "rule-fixtures"
BENIGN = OUT / "benign"
CACHE = Path("/var/cache/pacman/pkg")

_HOOK = "/usr/share/libalpm/hooks/00-l9.hook"
_RULES = "/usr/lib/udev/rules.d/99-l9.rules"

#: Known-shape noise a benign control may carry.  A003 compares sonames to
#: package names and A005 is an INFO census; both are being recalibrated.
BENIGN_ALLOW = ["A003", "A005"]


def _manifest(path: str, mode: int = 0o644, **fields) -> dict:
    return {"path": path, "mode": mode, **fields}


#: Every fixture: relative name -> (lane, kind, expected ids, note, body).
FIXTURES: dict[str, tuple[str, str, list[str], str, dict]] = {
    "a001-positive.json": ("manifest", "positive", ["A001"],
        "Setuid bit recorded in the mode, the documented contract.",
        {"manifest": [_manifest("/usr/bin/l9-suid", 0o4755)], "declared": {}}),
    "a001-negative.json": ("manifest", "negative", [],
        "Same file with the setuid bit absent.",
        {"manifest": [_manifest("/usr/bin/l9-suid", 0o755)], "declared": {}}),
    "a002-positive.json": ("manifest", "positive", ["A002"],
        "A shipped unit the declared surface does not name.",
        {"manifest": [_manifest("/usr/lib/systemd/system/l9.service")],
         "declared": {"units": []}}),
    "a002-negative.json": ("manifest", "negative", [],
        "The same unit, declared.",
        {"manifest": [_manifest("/usr/lib/systemd/system/l9.service")],
         "declared": {"units": ["/usr/lib/systemd/system/l9.service"]}}),
    "a003-positive.json": ("manifest", "positive", ["A003"],
        "A linked library whose stem is not in depends.",
        {"manifest": [_manifest("/usr/bin/l9-app", 0o755,
                                elf={"needed": ["libl9evil.so.2"]})],
         "declared": {"depends": ["glibc"]}}),
    "a003-negative.json": ("manifest", "negative", [],
        "The same link, with the provider named in depends.",
        {"manifest": [_manifest("/usr/bin/l9-app", 0o755,
                                elf={"needed": ["libl9evil.so.2"]})],
         "declared": {"depends": ["glibc", "libl9evil"]}}),
    "a004-positive.json": ("manifest", "positive", ["A004"],
        "The built .INSTALL differs from the recipe's install= file.",
        {"manifest": [],
         "declared": {"install_text": "post_install() { :; }",
                      "built_install_text": "post_install() { exec bash; }"}}),
    "a004-negative.json": ("manifest", "negative", [],
        "The built .INSTALL matches the declaration.",
        {"manifest": [],
         "declared": {"install_text": "post_install() { :; }",
                      "built_install_text": "post_install() { :; }"}}),
    "a005-positive.json": ("manifest", "positive", ["A005"],
        "A world-writable shipped file, recorded only in the mode.",
        {"manifest": [_manifest("/etc/skel/l9-note", 0o666)], "declared": {}}),
    "a005-negative.json": ("manifest", "negative", [],
        "The same file with no world-write bit.",
        {"manifest": [_manifest("/etc/skel/l9-note", 0o644)], "declared": {}}),
    "a006-positive.json": ("manifest", "positive", ["A006"],
        "A file capability recorded on the shipped binary.",
        {"manifest": [_manifest("/usr/bin/l9-cap", 0o755,
                                caps="cap_net_raw+ep")], "declared": {}}),
    "a006-negative.json": ("manifest", "negative", [],
        "The same binary with no capabilities.",
        {"manifest": [_manifest("/usr/bin/l9-cap", 0o755)], "declared": {}}),
    "a007-positive.json": ("manifest", "positive", ["A007"],
        "A sudoers drop-in inside the package.",
        {"manifest": [_manifest("/etc/sudoers.d/99-l9", 0o440)],
         "declared": {}}),
    "a007-negative.json": ("manifest", "negative", [],
        "An ordinary /etc configuration file.",
        {"manifest": [_manifest("/etc/l9.conf", 0o644)], "declared": {}}),
    "a008-positive.json": ("manifest", "positive", ["A008"],
        "An eBPF object shipped in the package.",
        {"manifest": [_manifest("/usr/lib/l9/tracker.bpf.o")],
         "declared": {}}),
    "a008-negative.json": ("manifest", "negative", [],
        "An ordinary object file with the same name stem.",
        {"manifest": [_manifest("/usr/lib/l9/tracker.o")], "declared": {}}),
    "a009-positive.json": ("upstream", "positive", ["A009"],
        "An ELF binary inside a declared source archive.",
        {"artifacts": [{"path": "vendor/l9-tool", "elf": True}]}),
    "a009-negative.json": ("upstream", "negative", [],
        "A source file, not an ELF.",
        {"artifacts": [{"path": "src/main.c", "elf": False}]}),
    "a010-positive.json": ("upstream", "positive", ["A010"],
        "A setuid entry inside a declared source archive.",
        {"artifacts": [{"path": "vendor/l9-suid", "mode": 0o4755,
                        "setuid": True, "elf": False}]}),
    "a010-negative.json": ("upstream", "negative", [],
        "The same entry without the setuid bit.",
        {"artifacts": [{"path": "vendor/l9-suid", "mode": 0o755,
                        "setuid": False, "elf": False}]}),
    "a011-positive.json": ("manifest", "positive", ["A011"],
        "A hook whose trigger covers every transaction.",
        {"manifest": [_manifest(_HOOK, content=(
            "[Trigger]\nOperation = *\nExec = /usr/bin/true\n"))],
         "declared": {}}),
    "a011-negative.json": ("manifest", "negative", [],
        "A hook scoped to one operation.",
        {"manifest": [_manifest(_HOOK, content=(
            "[Trigger]\nOperation = Install\nExec = /usr/bin/true\n"))],
         "declared": {}}),
    "a012-positive.json": ("manifest", "positive", ["A012"],
        "A shipped hook that fetches.",
        {"manifest": [_manifest(_HOOK, content=(
            "[Trigger]\nOperation = Install\n"
            "Exec = /usr/bin/curl https://example.invalid/x\n"))],
         "declared": {}}),
    "a012-negative.json": ("manifest", "negative", [],
        "A shipped hook that runs a system helper.",
        {"manifest": [_manifest(_HOOK, content=(
            "[Trigger]\nOperation = Install\nExec = /usr/bin/true\n"))],
         "declared": {}}),
    "a013-positive.json": ("manifest", "positive", ["A013"],
        "A udev rule that runs a program.",
        {"manifest": [_manifest(_RULES, content=(
            'ACTION=="add", RUN+="/usr/bin/true"\n'))], "declared": {}}),
    "a013-negative.json": ("manifest", "negative", [],
        "A udev rule that only creates a symlink.",
        {"manifest": [_manifest(_RULES, content=(
            'ACTION=="add", SYMLINK+="l9-%k"\n'))], "declared": {}}),
    "a014-positive.json": ("upstream", "positive", ["A009", "A014"],
        "An ELF with a /tmp runpath (A009 co-fires: it is an ELF).",
        {"artifacts": [{"path": "vendor/l9-tool", "elf": True,
                        "elf_info": {"runpath": ["/tmp/lib"]}}]}),
    "a014-negative.json": ("upstream", "negative", ["A009"],
        "The same ELF with an $ORIGIN-relative runpath.",
        {"artifacts": [{"path": "vendor/l9-tool", "elf": True,
                        "elf_info": {"runpath": ["$ORIGIN/../lib"]}}]}),
    "a015-positive.json": ("upstream", "positive", ["A009", "A015"],
        "A packed ELF (A009 co-fires: it is an ELF).",
        {"artifacts": [{"path": "vendor/l9-tool", "elf": True,
                        "elf_info": {"packed": True}}]}),
    "a015-negative.json": ("upstream", "negative", ["A009"],
        "The same ELF, not packed.",
        {"artifacts": [{"path": "vendor/l9-tool", "elf": True,
                        "elf_info": {"packed": False}}]}),
    "a016-positive.json": ("release", "positive", ["A016"],
        "The release asset carries a build input the tag tree lacks.",
        {"asset": [["l9-1.0/Makefile.am", 10, "a" * 64],
                   ["l9-1.0/README", 5, "b" * 64]],
         "tag": [["l9-1.0/README", 5, "b" * 64]]}),
    "a016-negative.json": ("release", "negative", [],
        "The asset differs only by a generated file.",
        {"asset": [["l9-1.0/configure", 10, "a" * 64],
                   ["l9-1.0/README", 5, "b" * 64]],
         "tag": [["l9-1.0/README", 5, "b" * 64]]}),
}

#: The real build's expected set, recorded beside the archived manifest.
BUILT = {
    "built/l9-clinic/manifest.json": {
        "lane": "manifest",
        "kind": "positive",
        "expect": ["A001", "A002", "A005", "A007", "A008", "A011", "A013"],
        "note": ("Real makepkg build: setuid mode, undeclared unit, "
                 "world-writable file, sudoers, .bpf.o, broad hook, udev RUN+=."),
    },
}


def _load_expected() -> dict:
    path = OUT / "expected.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def write_fixtures() -> int:
    RULES.mkdir(parents=True, exist_ok=True)
    expected = _load_expected()
    for name, (lane, kind, ids, note, body) in FIXTURES.items():
        path = RULES / name
        path.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        expected[f"rule-fixtures/{name}"] = {
            "lane": lane, "kind": kind, "expect": ids, "note": note,
        }
    expected.update(BUILT)
    (OUT / "expected.json").write_text(
        json.dumps(dict(sorted(expected.items())), indent=2, sort_keys=True)
        + "\n")
    print(f"l9 corpus: {len(FIXTURES)} rule fixtures, {len(BUILT)} built")
    return 0


def _unit_paths(manifest: list[dict]) -> list[str]:
    out = []
    for entry in manifest:
        path = entry.get("path") or ""
        lower = path.lower()
        if (lower.endswith((".service", ".timer", ".socket", ".mount",
                            ".target", ".tmpfiles"))
                or "/tmpfiles.d/" in lower):
            out.append(path)
    return sorted(out)


def import_benign(packages: list[str]) -> int:
    from trustsight.analysis.artifact import inspect_manifest

    BENIGN.mkdir(parents=True, exist_ok=True)
    expected = _load_expected()
    imported = 0
    for package in packages:
        archives = sorted(CACHE.glob(f"{package}-[0-9]*.pkg.tar.zst"))
        if not archives:
            print(f"skip {package}: no cached archive")
            continue
        doc = build_manifest(archives[-1])
        doc["declared"]["units"] = _unit_paths(doc["manifest"])
        fired = {f["rule_id"] for f in inspect_manifest(
            doc["manifest"], doc["declared"])}
        unexpected = fired - set(BENIGN_ALLOW)
        if unexpected:
            print(f"skip {package}: fires {sorted(unexpected)}")
            continue
        name = f"{package}.json"
        compact = {
            "package": doc["package"],
            "manifest": doc["manifest"],
            "declared": doc["declared"],
            "provenance": doc["provenance"],
        }
        (BENIGN / name).write_text(
            json.dumps(compact, separators=(",", ":"), sort_keys=True) + "\n")
        expected[f"benign/{name}"] = {
            "lane": "manifest", "kind": "benign",
            "allow": BENIGN_ALLOW,
            "note": f"Official build, {len(doc['manifest'])} entries; "
                    "known census rules only.",
        }
        imported += 1
    (OUT / "expected.json").write_text(
        json.dumps(dict(sorted(expected.items())), indent=2, sort_keys=True)
        + "\n")
    print(f"l9 corpus: imported {imported} benign controls")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the L9 acceptance corpus")
    parser.add_argument("--write-fixtures", action="store_true")
    parser.add_argument("--import-benign", nargs="+", metavar="PKG")
    args = parser.parse_args()
    if args.write_fixtures:
        return write_fixtures()
    if args.import_benign:
        return import_benign(args.import_benign)
    parser.error("pass --write-fixtures or --import-benign")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
