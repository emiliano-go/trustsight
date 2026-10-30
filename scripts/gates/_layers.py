"""Extracted from security_gates.py: _layers."""

import re
import time
from scripts.gates._core import Gate, ROOT, SRC, _python_files, _rel

__all__ = ['gate_archive_listing_adds_no_extraction', 'gate_boundaries_are_the_coverage_view', 'gate_boundaries_forbid_clean_exactly_when_gaps', 'gate_docs_layer_mapping_matches_registry', 'gate_every_history_diff_is_scored_independently', 'gate_every_report_key_is_documented', 'gate_every_rule_carries_exactly_one_layer', 'gate_every_rule_names_shared_dependencies', 'gate_indicator_tier_mirrors_ioc_matches', 'gate_layer_detection_and_coverage_are_independent', 'gate_layer_overrides_stay_within_the_closed_set', 'gate_layer_profile_is_gap_precise_and_additive', 'gate_libgit2_is_not_the_vulnerable_version', 'gate_manifest_ledger_stays_weight_zero', 'gate_manifest_parses_are_bounded_and_refusing', 'gate_manifest_table_is_configuration', 'gate_release_artifacts_share_commit', 'gate_transcendence_table_is_wellformed', 'gate_u003_joins_the_host_view', 'gate_yaml_is_only_safe_load']

def gate_every_history_diff_is_scored_independently() -> Gate:
    """B1: the --last path does not aggregate scores."""
    text = "\n".join(
        p.read_text(encoding="utf-8")
        for p in sorted((SRC / "cli" / "inspect").rglob("*.py"))
    )
    # The path should use analyze_package_text per-commit, not any
    # aggregate scoring function.
    has_agg = "aggregate_score" in text or "combined_score" in text
    return Gate("every history diff is scored independently", not has_agg,
                has_agg and ["aggregate score found"] or "no aggregate score in inspect.py")

def gate_release_artifacts_share_commit() -> Gate:
    """The tag, the archives and the checksum describe one verified tree.

    ``$GITHUB_SHA`` is the commit the workflow file sits on (the default
    branch), not the requested target, so an archive built from it can
    describe a different tree than the tag it is released under.  The
    preflight builds from the checked-out target, and the publish job
    requires the pushed tag to resolve to that target before creating the
    release.

    ``gh release create`` deliberately omits ``--target``: the Releases API
    materializes a tag named by ``target_commitish`` and, once the default
    branch has moved past the release commit, additionally requires a
    ``workflows: write`` scope that ``GITHUB_TOKEN`` cannot carry - the
    failure is a bare 403.  Creating the release from the pre-existing,
    verified tag is not subject to that guard.
    """
    workflow = (ROOT / ".github/workflows/publishing.yml").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts/verify_release.py").read_text(encoding="utf-8")
    required = (
        'run: echo "sha=$(git rev-parse HEAD)" >> "$GITHUB_OUTPUT"',
        'target: ${{ steps.head.outputs.sha }}',
        '--rev "${{ steps.head.outputs.sha }}"',
        'TARGET: ${{ needs.preflight.outputs.target }}',
        'tag_sha=$(gh api "repos/$GITHUB_REPOSITORY/commits/$TAG"',
        '[ "$tag_sha" != "$TARGET" ]',
        'tag $TAG does not exist',
        'gh release create "$TAG" --draft',
    )
    problems = [f"missing workflow constraint: {item}" for item in required
                if item not in workflow]
    if '--rev "$GITHUB_SHA"' in workflow or '--rev "${{ github.sha }}"' in workflow:
        problems.append("release artifacts are built from the event commit, not the target")
    if any("gh release create" in line and "--target" in line
           for line in workflow.splitlines()):
        problems.append(
            "the release is created with --target, which needs workflows:write "
            "once the default branch moves past the release commit")
    if '"--rev", "HEAD"' not in verifier or "sys.executable" not in verifier:
        problems.append("release verification does not rebuild the checked-out commit")
    return Gate("release artifacts and tags use the verified commit", not problems,
                problems or "checkout SHA, committed rebuild, verified tag target")

def gate_docs_layer_mapping_matches_registry() -> Gate:
    """The Part 1 series-to-category table is generated from ``layers.py``."""
    import re as _re

    from trustsight.layers import RULE_LAYER_OVERRIDES, SERIES_LAYER

    doc = ROOT / "docs" / "assurance-layers" / "evidence-categories.md"
    if not doc.exists():
        return Gate("docs layer mapping matches the registry", False, "missing")
    lines = ["| Series | Default category |", "|---|---|"]
    for series in sorted(SERIES_LAYER):
        lines.append(f"| `{series}` | {SERIES_LAYER[series].value} |")
    lines += ["", "| Rule | Category override |", "|---|---|"]
    for rule_id in sorted(RULE_LAYER_OVERRIDES):
        lines.append(f"| `{rule_id}` | {RULE_LAYER_OVERRIDES[rule_id].value} |")
    expected = "\n".join(lines)
    match = _re.search(
        r"<!-- generated: series-layer -->\n(.*?)\n<!-- /generated: series-layer -->",
        doc.read_text(encoding="utf-8"), _re.S)
    problems = []
    if not match:
        problems.append("generated block missing")
    elif match.group(1) != expected:
        problems.append("table drifted from layers.py; run scripts/build_layers_doc.py")
    return Gate("docs layer mapping matches the registry", not problems, problems)

def gate_layer_detection_and_coverage_are_independent() -> Gate:
    """A finding must not hide that the same layer was also unread.

    ``detection`` and ``coverage`` are separate dimensions per layer; a
    firing rule at a blinded layer reports both.
    """
    from trustsight.layers import layer_profile
    from trustsight.schema import PackageFact, ScoreEntry

    problems: list[str] = []
    fact = PackageFact(
        package_name="demo", coverage_gaps=["diff_truncated"],
        score_breakdown=[ScoreEntry(rule_id="R001", severity="CRITICAL", weight=40)],
    )
    profile = layer_profile(fact, [{"rule_id": "R001"}])
    if profile["L3"]["detection"] != "fired":
        problems.append("L3 detection did not fire")
    if profile["L3"]["coverage"] != "incomplete":
        problems.append("L3 coverage did not read incomplete")
    plain = layer_profile(PackageFact(package_name="demo"), [])
    if plain["L8"]["coverage"] != "not_applicable":
        problems.append("L8 coverage was not not_applicable on a single-package run")
    if plain["L1"]["coverage"] != "complete":
        problems.append("a clean L1 coverage was not complete")
    return Gate("layer detection and coverage are independent", not problems, problems)

def gate_every_rule_names_shared_dependencies() -> Gate:
    """Every rule names its mechanism, subject, evidence and shared
    dependencies (review remediation).

    Different algorithms do not imply independent failure modes; a rule whose
    series has no shared-dependency entry would hide the common-mode risk.
    """
    from trustsight.categories import RULE_CATEGORIES
    from trustsight.detectors import detector_metadata

    missing: list[str] = []
    for rule_id in RULE_CATEGORIES:
        meta = detector_metadata(rule_id)
        if (meta is None or not meta["mechanism"] or not meta["subject"]
                or not meta["shared_dependencies"]):
            missing.append(rule_id)
    return Gate("every rule names its shared dependencies", not missing, missing)

def gate_layer_overrides_stay_within_the_closed_set() -> Gate:
    """A ``[layers]`` override cannot leave the closed L1-L8 set.

    ``parse_overrides`` applies a valid override and drops an out-of-range
    value or an unknown rule; the set of layer values is exactly L1..L8.
    """
    from trustsight.layers import LAYER_VALUES, Layer, layer_of, parse_overrides

    problems: list[str] = []
    if LAYER_VALUES != frozenset(f"L{i}" for i in range(1, 9)):
        problems.append(f"layer value set is not L1-L8: {sorted(LAYER_VALUES)}")
    good = parse_overrides({"layers": {"R001": "l1"}})
    if good.get("R001") is not Layer.L1:
        problems.append("a valid override was not applied")
    bad = parse_overrides({"layers": {"R001": "L9", "R002": "nonsense"}})
    if bad:
        problems.append(f"out-of-range overrides were accepted: {bad}")
    if layer_of("R001", {"R001": Layer.L1}) is not Layer.L1:
        problems.append("layer_of ignored a valid override")
    return Gate("layer overrides stay within the closed set", not problems, problems)

def gate_boundaries_are_the_coverage_view() -> Gate:
    """``boundaries`` is the one representation of the coverage gaps (W1).

    Every coverage gap maps to a boundary whose ``gap`` is that id, for every
    id in ``coverage.GAPS``, so ``coverage_gaps`` and the boundary list cannot
    drift: one is a view of the other.
    """
    from trustsight.boundaries import boundaries_from_fact
    from trustsight.coverage import GAPS
    from trustsight.schema import PackageFact

    problems: list[str] = []
    for gap in GAPS:
        fact = PackageFact(package_name="demo", coverage_gaps=[gap])
        got = {b.gap for b in boundaries_from_fact(fact) if b.gap}
        if got != {gap}:
            problems.append(f"{gap} -> {sorted(got)}")
    empty = boundaries_from_fact(PackageFact(package_name="demo"))
    if any(b.forbids_clean for b in empty):
        problems.append("an empty run produced a forbidding boundary")
    return Gate("boundaries are the coverage view", not problems, problems)

def gate_every_report_key_is_documented() -> Gate:
    """Every report-body key has a row in ``docs/reference/report-schema.md``.

    A new body key that ships without a schema row is a field a consumer
    cannot discover - the ``layers``/``boundaries``/``comparison_base`` shape.
    """
    from trustsight.reporting import REPORT_KEYS, SCORE_KEYS, VERBOSE_KEYS

    text = (ROOT / "docs" / "reference" / "report-schema.md").read_text(
        encoding="utf-8")
    missing = sorted(
        key for key in (set(REPORT_KEYS) | set(SCORE_KEYS) | set(VERBOSE_KEYS))
        if f"`{key}`" not in text
    )
    return Gate("every report body key is documented", not missing, missing)

def gate_transcendence_table_is_wellformed() -> Gate:
    """The coverage-complementarity table names real series.

    The table is a set of hypotheses, but each row still refers to real
    evidence families.  A row naming a series that does not exist, or a
    status that is neither ``hypothesis`` nor a shipped fixture, would be an
    unbacked claim in the doc that reads as a result.
    """
    import re

    from trustsight.layers import SERIES_LAYER

    # M (fires at its inputs' layer) and A (the reserved L9 lane) have no
    # static layer but are shipped series.
    allowed = set(SERIES_LAYER) | {"M", "A"}
    fixtures = ROOT / "tests" / "fixtures"
    text = (ROOT / "docs" / "assurance-layers" / "diversity.md").read_text(
        encoding="utf-8")
    rows = []
    for line in text.splitlines():
        match = re.match(
            r"^\|\s*([A-Z](?:/[A-Z])?)\s*\([^)]*\)\s*\|"
            r"\s*([A-Z](?:/[A-Z])?)\s*\([^)]*\)\s*\|"
            r"\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*$", line)
        if match:
            rows.append((match.group(1), match.group(2), match.group(3),
                         match.group(4)))
    problems: list[str] = []
    if len(rows) < 5:
        problems.append(f"expected at least 5 rows, found {len(rows)}")
    for evades, caught, why, status in rows:
        for token in (evades, caught):
            for letter in token.split("/"):
                if letter not in allowed:
                    problems.append(f"{letter} is not a shipped series")
        if not why:
            problems.append(f"{evades}->{caught}: no mechanism named")
        if status != "hypothesis" and not list(fixtures.rglob(status)):
            problems.append(f"{evades}->{caught}: unknown status {status!r}")
    return Gate("transcendence table names real series",
                not problems, {"rows": len(rows)}, detail="\n".join(problems))

def gate_every_rule_carries_exactly_one_layer() -> Gate:
    """Every rule has exactly one layer.

    layer_of returns one layer or none; M (fires at its inputs' layer) and
    A (the reserved L9 build lane) have no static layer by design. Every
    other categorised rule has exactly one, and L1-L7 are non-empty.
    """
    from trustsight.categories import RULE_CATEGORIES
    from trustsight.layers import LAYER_ORDER, layer_of

    problems: list[str] = []
    for rule_id in RULE_CATEGORIES:
        if rule_id[:1] in ("M", "A"):
            if layer_of(rule_id) is not None:
                problems.append(f"{rule_id} has a static layer (M/A must not)")
            continue
        layer = layer_of(rule_id)
        if layer is None or layer not in LAYER_ORDER:
            problems.append(f"{rule_id} has no single layer")
    for layer in LAYER_ORDER[:7]:
        if not any(layer_of(rid) is layer for rid in RULE_CATEGORIES):
            problems.append(f"{layer} has no rules")
    return Gate("every rule carries exactly one layer", not problems, problems)

def gate_boundaries_forbid_clean_exactly_when_gaps() -> Gate:
    """W1: the boundary view equals the coverage-gap view.

    ``forbids_clean(boundaries_from_fact(fact))`` is the verdict's view and
    equals ``bool(coverage_gaps)`` by construction; a W-only boundary (a
    rendering with no gap) does not forbid a clean verdict.
    """
    from trustsight.boundaries import boundaries_from_fact, forbids_clean
    from trustsight.schema import PackageFact, ScoreEntry

    problems: list[str] = []
    for gaps in ([], ["diff_truncated"], ["parent_baseline", "ruleset_drifted"]):
        fact = PackageFact(package_name="demo", coverage_gaps=list(gaps))
        if forbids_clean(boundaries_from_fact(fact)) != bool(gaps):
            problems.append(f"forbids_clean != bool(coverage_gaps) for {gaps}")
    w_only = PackageFact(
        package_name="demo",
        score_breakdown=[ScoreEntry(rule_id="W001", severity="INFO", weight=0)],
    )
    if forbids_clean(boundaries_from_fact(w_only)):
        problems.append("a W-only boundary forbade a clean verdict")
    return Gate("boundaries forbid clean exactly when coverage gaps exist",
                not problems, problems)

def gate_indicator_tier_mirrors_ioc_matches() -> Gate:
    """/ B1: the promoted indicator tier mirrors IOC matches
    and never touches the score."""
    from trustsight.ioc_baseline import IocMatch
    from trustsight.reporting import REPORT_KEYS, evaluate_fact, report_body
    from trustsight.schema import PackageFact

    problems: list[str] = []
    if "indicators" not in REPORT_KEYS:
        problems.append("indicators is not in REPORT_KEYS")
    fact = PackageFact(
        package_name="demo",
        ioc_matches=[IocMatch(type="domain", value="evil.example",
                              source="curator", surface="source", line=3)],
    )
    body = report_body(evaluate_fact(fact))
    if body["indicators"] != body["ioc_matches"]:
        problems.append("indicators does not mirror ioc_matches")
    if fact.final_score != 0:
        problems.append("an IOC match moved the score")
    if any(str(e.rule_id).startswith("I") for e in fact.score_breakdown):
        problems.append("an indicator appeared in score_breakdown")
    return Gate("the indicator tier mirrors ioc_matches", not problems, problems)

def gate_layer_profile_is_gap_precise_and_additive() -> Gate:
    """The layer profile is gap-precise and changes nothing.

    A history gap blinds only L6; a tokenizer refusal blinds L1-L4; content
    truncation blinds L1-L7; L8 is ``not_exercised`` on a single-package
    run; a finding marks its own layer fired.
    """
    from trustsight.layers import layer_profile
    from trustsight.schema import PackageFact, ScoreEntry

    problems: list[str] = []
    history = layer_profile(
        PackageFact(package_name="demo", coverage_gaps=["parent_baseline"]), [])
    if history["L6"]["status"] != "unreadable":
        problems.append("a history gap did not blind L6")
    if history["L1"]["status"] != "passed":
        problems.append("a history gap blinded L1")

    refusal = layer_profile(
        PackageFact(package_name="demo",
                    coverage_gaps=["unresolved_source"]), [])
    for layer in ("L1", "L2", "L3", "L4"):
        if refusal[layer]["status"] != "unreadable":
            problems.append(f"a refusal gap did not blind {layer}")

    truncated = layer_profile(
        PackageFact(package_name="demo",
                    coverage_gaps=["diff_truncated"]), [])
    for i in range(1, 8):
        if truncated[f"L{i}"]["status"] != "unreadable":
            problems.append(f"truncation did not blind L{i}")
    if truncated["L8"]["status"] != "not_exercised":
        problems.append("L8 was not not_exercised on a single-package run")

    fired = layer_profile(
        PackageFact(package_name="demo", score_breakdown=[
            ScoreEntry(rule_id="X001", severity="CRITICAL", weight=40)]),
        [{"rule_id": "X001"}])
    if fired["L4"]["status"] != "fired":
        problems.append("an L4 finding did not mark L4 fired")
    return Gate("the layer profile is gap-precise and additive",
                not problems, problems)

def gate_manifest_parses_are_bounded_and_refusing() -> Gate:
    """Every manifest parser is bounded on hostile input and refuses.

    Bombed TOML, an oversized line-class file and unbalanced JSON must each
    return quickly with either dependencies or a named refusal, never raise
    and never hang (A4b/A5 extended).  The syntax layer is probed directly
    too: a YAML alias bomb, a self-referential anchor, an XML entity bomb and
    an oversized document must be refused or walked bounded, never loaded.
    """
    from trustsight.analysis.manifest_syntax import (
        MAX_MANIFEST_BYTES,
        ManifestSyntaxError,
        deep_items,
        load_json,
        load_toml,
        load_xml,
        load_yaml,
    )
    from trustsight.analysis.manifests import parse_manifest

    fixtures = {
        "Cargo.toml": "[dependencies\nbroken = ",
        "requirements.txt": "x==1\n" * 200000,
        "package.json": "{" * 100000,
        "go.mod": "require (\n" + "a b v1.0.0\n" * 100000,
        "environment.yml": "dependencies:\n" + "  - x\n" * 100000,
        "pylock.toml": "[[packages]]\n" + "name = \"x\"\n" * 100000,
    }
    hits: list[str] = []
    for path, text in fixtures.items():
        start = time.monotonic()
        doc = parse_manifest(path, text)
        elapsed = time.monotonic() - start
        if elapsed > 5.0:
            hits.append(f"{path}: parse took {elapsed:.1f}s")
        if doc is None:
            hits.append(f"{path}: not recognised")
        elif not doc.unresolved and not doc.dependencies:
            hits.append(f"{path}: neither parsed nor refused")

    bomb_yaml = ["a0: &a0 [1, 2, 3]"]
    for i in range(1, 40):
        bomb_yaml.append(f"a{i}: &a{i} [*a{i-1}, *a{i-1}, *a{i-1}, *a{i-1}]")
    start = time.monotonic()
    try:
        walk = list(deep_items(load_yaml("\n".join(bomb_yaml) + "\n")))
        assert walk
    except ManifestSyntaxError:
        pass
    if time.monotonic() - start > 2.0:
        hits.append("yaml alias bomb was not bounded")

    start = time.monotonic()
    try:
        list(deep_items(load_yaml("a: &x\n  b: *x\n")))
    except ManifestSyntaxError:
        pass
    if time.monotonic() - start > 2.0:
        hits.append("yaml anchor cycle was not bounded")

    xml_bomb = ('<!DOCTYPE l [<!ENTITY e "x"><!ENTITY e2 "&e;&e;&e;">]><l>&e2;</l>')
    try:
        load_xml(xml_bomb)
        hits.append("xml entity bomb was loaded")
    except ManifestSyntaxError:
        pass

    oversized = "x: y\n" * (MAX_MANIFEST_BYTES // 2 + 10)
    for loader in (load_yaml, load_json, load_toml, load_xml):
        try:
            loader(oversized)
            hits.append(f"{loader.__name__} loaded an oversized document")
        except ManifestSyntaxError:
            pass

    if MAX_MANIFEST_BYTES > 512 * 1024:
        hits.append("MAX_MANIFEST_BYTES exceeds the existing tree cap")
    return Gate("manifest parses are bounded and refusing", not hits, hits)

def gate_manifest_table_is_configuration() -> Gate:
    """The manifest filename table lives in patterns.toml, not in code."""
    from trustsight import config as config_module
    from trustsight.analysis.manifests import manifest_filenames

    hits: list[str] = []
    default = getattr(config_module, "DEFAULT_MANIFEST_FILENAMES", None)
    if not default:
        hits.append("no DEFAULT_MANIFEST_FILENAMES in config")
    if "manifest_filenames" not in config_module.DEFAULT_PATTERNS:
        hits.append("manifest_filenames is not written to patterns.toml")
    if not manifest_filenames():
        hits.append("manifest_filenames() returns an empty table")
    return Gate("manifest table is configuration", not hits, hits)

def gate_u003_joins_the_host_view() -> Gate:
    """A manifest-introduced git host joins the run's ``hosts_gained``."""
    from trustsight.changes import change_delta

    diff = (
        "--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -1,1 +1,2 @@\n"
        " [dependencies]\n"
        '+serde = { git = "https://evil.example/serde.git" }\n'
    )
    hosts = change_delta(diff).hosts_gained
    return Gate("U003 joins the host view", "evil.example" in hosts, sorted(hosts))

def gate_manifest_ledger_stays_weight_zero() -> Gate:
    """U001/U002/U005/U006 are INFO; U009 is a feed-only LOW. All weigh 0."""
    from trustsight.analysis.pipeline import scan_diff

    diff = (
        "--- a/Cargo.toml\n+++ b/Cargo.toml\n@@ -1,1 +1,6 @@\n"
        " [dependencies]\n"
        '+a = "1"\n+b = "1"\n+c = "1"\n+d = "1"\n'
        '+evil = { git = "https://evil.example/x.git" }\n'
    )
    fact = scan_diff(diff, package_name="p")
    severity = {}
    for entry in fact.score_breakdown:
        severity.setdefault(entry.rule_id, entry.severity)
    hits: list[str] = []
    for rule_id in ("U001", "U002", "U005", "U006"):
        if severity.get(rule_id, "INFO") != "INFO":
            hits.append(f"{rule_id} is {severity.get(rule_id)}")

    # U009 renders a committed CI workflow at LOW but is feed-only: the
    # severity is the reader's label, the weight must stay zero.
    ci = (
        "diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml\n"
        "new file mode 100644\n--- /dev/null\n+++ b/.github/workflows/ci.yml\n"
        "@@ -0,0 +1,1 @@\n+name: CI\n"
    )
    ci_fact = scan_diff(ci, package_name="p")
    u009 = [e for e in ci_fact.score_breakdown if e.rule_id == "U009"]
    if not u009:
        hits.append("U009 did not fire on a committed workflow")
    elif u009[0].weight != 0:
        hits.append(f"U009 weighs {u009[0].weight}")
    return Gate("manifest ledger stays weight 0", not hits, hits)

def gate_archive_listing_adds_no_extraction() -> Gate:
    """The manifest layer reads committed files; it never extracts archives."""
    src = "\n".join(
        p.read_text(encoding="utf-8")
        for p in sorted((ROOT / "src" / "trustsight" / "analysis" / "manifests").rglob("*.py"))
    )
    hits = [tok for tok in ("tarfile", "extractfile", "extractall", "zipfile")
            if re.search(rf"\b{tok}\b", src)]
    return Gate("archive listing adds no extraction", not hits, hits)

def gate_yaml_is_only_safe_load() -> Gate:
    """PyYAML parses package-controlled bytes, so the loader is pinned safe.

    `yaml.load` with a non-safe loader can construct arbitrary Python objects
    from a manifest an attacker wrote.  Only `yaml.safe_load` is permitted
    anywhere under ``src/``; the check is structural so a new parser cannot
    reintroduce the unsafe call.
    """
    hits: list[str] = []
    offenders = ("yaml.load(", "yaml.full_load(", "yaml.unsafe_load(",
                 "yaml.load_all(", "yaml.full_load_all(", "yaml.unsafe_load_all(",
                 "Loader=", "UnsafeLoader", "FullLoader")
    for path in _python_files():
        if path.name == "security_gates.py":
            continue
        text = path.read_text(encoding="utf-8")
        for token in offenders:
            if token in text:
                hits.append(f"{_rel(path)} {token}")
    return Gate("yaml is only ever safe_load", not hits, hits)

def gate_libgit2_is_not_the_vulnerable_version() -> Gate:
    """The bundled libgit2, and every declared floor, must carry 1.9.7.

    Two remote-code paths are in scope. libgit2 before 1.8.6 / 1.9.5 trusts
    a sender-controlled delta result size in ``git_delta_apply`` and
    allocates it before reading any delta instruction (GHSA-27m5-gxxh-x79j /
    CVE-2026-53585).  libgit2 1.9.0-1.9.6 built with the libssh2 backend
    pastes the remote repository path into a shell command unescaped, so a
    crafted URL runs commands on the SSH host (CVE-2026-5917); 1.8.7 and
    1.9.7 carry the fix.  TrustSight clones AUR repositories with pygit2, so
    the pin must bundle a patched libgit2 *and* the declared floors must not
    let a fresh install resolve an older one.  The runtime version alone is
    not enough: a lowered pyproject/PKGBUILD floor reproduces the vulnerable
    dependency even on a machine whose current wheel is fixed.
    """
    name = "libgit2 is not the vulnerable version"
    try:
        import pygit2
    except Exception as exc:  # noqa: BLE001 - a missing dep is the failure
        return Gate(name, False, f"pygit2 not importable: {exc}", ">= 1.9.7")
    raw = str(getattr(pygit2, "LIBGIT2_VERSION", "") or "")
    parts: list[int] = []
    for token in raw.split("."):
        digits = ""
        for ch in token:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    major, minor, patch = parts[0], parts[1], parts[2]
    patched = ((major, minor, patch) >= (1, 10, 0)
               or (major == 1 and minor == 9 and patch >= 7)
               or (major == 1 and minor == 8 and patch >= 7))

    # A floor is the other half of the pin.  If it is lowered, a new install
    # resolves the affected bundle even though this machine reports a fixed
    # one.  Check the package metadata the release and AUR actually read.
    floors = (
        ("pyproject.toml", "pygit2>=1.20.1"),
        ("packaging/aur/PKGBUILD", "python-pygit2>=1.20.1"),
        ("packaging/local/PKGBUILD", "python-pygit2>=1.20.1"),
        ("packaging/aur/.SRCINFO", "python-pygit2>=1.20.1"),
    )
    problems: list[str] = []
    for rel, expected in floors:
        try:
            text = (ROOT / rel).read_text(encoding="utf-8")
        except OSError as exc:
            problems.append(f"{rel}: {type(exc).__name__}")
            continue
        if expected not in text:
            problems.append(f"{rel} does not declare {expected}")
    measured = raw if not problems else f"{raw}; {'; '.join(problems)}"
    return Gate(name, patched and not problems, measured,
                ">= 1.9.7 (or >= 1.8.7); pygit2>=1.20.1 floors")
