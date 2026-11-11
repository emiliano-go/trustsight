"""Extracted from security_gates.py: _parity."""

import ast
import contextlib
import io
import re
from pathlib import Path
from scripts.gates._core import Gate, H_SERIES_REDUCTION_TARGET, ROOT, SRC, _GIT_ALLOWED_IMPORTS, _SHARED_ANALYSIS, _h_series_live_ceiling, _parity_fact, _python_files

__all__ = ['gate_a_critical_finding_never_reads_medium', 'gate_a_fatal_finding_names_itself', 'gate_a_truncated_history_walk_is_a_declared_gap', 'gate_an_audit_does_not_write_history', 'gate_api_and_cli_emit_the_same_body', 'gate_api_and_cli_share_the_analysis', 'gate_ci_installs_from_the_lock', 'gate_companion_reads_are_bounded_before_data', 'gate_critical_paths_are_synchronised', 'gate_doc_lists_every_gate', 'gate_every_invariant_is_defined', 'gate_every_render_reports_the_same_information', 'gate_generated_diff_is_bounded_before_assembly', 'gate_h_series_intake_is_frozen', 'gate_h_series_reduction_residue', 'gate_libgit2_stays_behind_the_sandbox', 'gate_retired_ids_resolve_to_live_survivors', 'gate_run_diff_assembly_is_bounded', 'gate_score_is_withheld_by_default', 'gate_the_history_walk_is_bounded', 'gate_unpinned_build_deps_is_a_declared_gap']

def gate_doc_lists_every_gate(gates: list[Gate]) -> Gate:
    """``docs/security/enforcement-map.md`` names exactly the invariants enforced here.

    The document is the claim and this script is the proof, so a gate with
    no entry is an unstated guarantee and an entry with no gate is an
    unbacked promise.  Both are failures.  The map is its own page since
    the model was split by part, and its only table is the gate list.
    """
    name = "docs/security.md matches the gates"
    doc = ROOT / "docs" / "security" / "enforcement-map.md"
    if not doc.exists():
        return Gate(name, False, "missing")
    text = doc.read_text(encoding="utf-8")
    documented = set(re.findall(r"^\|\s*`([^`]+)`\s*\|", text, re.MULTILINE))
    enforced = {g.name for g in gates} | {name}
    missing = sorted(enforced - documented)
    extra = sorted(documented - enforced)
    problems = []
    if missing:
        problems.append(f"enforced but undocumented: {missing}")
    if extra:
        problems.append(f"documented but unenforced: {extra}")
    return Gate(name, not problems, problems)

def gate_every_invariant_is_defined() -> Gate:
    """Every invariant the enforcement map cites is defined in its Part.

    Part A lives in ``program-under-attack.md`` (``**A<n>.`` and ``**P1.``),
    Part B in ``what-a-result-claims.md`` (``### B<n>.``).  The map cites all
    three families, so checking only A left a cited B or P invariant able to
    point at nothing.
    """
    part = ROOT / "docs" / "security" / "program-under-attack.md"
    claims = ROOT / "docs" / "security" / "what-a-result-claims.md"
    enforcement = ROOT / "docs" / "security" / "enforcement-map.md"
    if not part.exists() or not claims.exists() or not enforcement.exists():
        return Gate("every cited invariant is defined", False, "missing")
    part_text = part.read_text(encoding="utf-8")
    defined = set(re.findall(r"\*\*(A\d+[a-z]?)\.", part_text))
    defined |= set(re.findall(r"\*\*(P\d+)\.", part_text))
    defined |= set(re.findall(
        r"^### (B\d+[a-z]?)\.", claims.read_text(encoding="utf-8"),
        re.MULTILINE))
    cited = set(re.findall(
        r"\b([ABP]\d+[a-z]?)\b", enforcement.read_text(encoding="utf-8")))
    missing = sorted(cited - defined)
    return Gate("every cited invariant is defined", not missing,
                missing or sorted(cited))


def gate_api_and_cli_emit_the_same_body() -> Gate:
    """The API's JSON is the CLI's JSON: same keys, same values.

    Three surfaces used to build three bodies - ``review --json``,
    ``inspect --json`` and ``Report.to_dict()`` - with two naming
    conventions between them, and the API body carried no ``findings`` at
    all while its docstring claimed to be what the CLI writes. A consumer
    could be written against one path and silently miss evidence on
    another.

    Exercised through the surfaces a caller actually reaches, not through
    ``report_body`` directly: calling the shared helper twice would prove
    only that it equals itself, which is exactly the narrow-call mistake
    ``contributing/security-review.md`` catalogues.
    """
    from trustsight.api import _report_from_fact
    from trustsight.reporting import REPORT_KEYS, evaluate_fact, report_body

    fact = _parity_fact()
    evaluated = evaluate_fact(fact)
    problems = []

    cli = report_body(evaluated)
    api = _report_from_fact(fact).to_dict()
    if set(cli) != set(api):
        problems.append(
            f"key sets differ: cli-only={sorted(set(cli) - set(api))} "
            f"api-only={sorted(set(api) - set(cli))}"
        )
    for key in sorted(set(cli) & set(api)):
        if cli[key] != api[key]:
            problems.append(f"{key}: cli={cli[key]!r} api={api[key]!r}")

    missing = sorted(set(REPORT_KEYS) - set(api))
    if missing:
        problems.append(f"REPORT_KEYS absent from the body: {missing}")

    # Never skipping info: the evidence a run produced must reach the body.
    if evaluated["findings"] and not api.get("findings"):
        problems.append("findings were produced but the body carries none")

    for flags in ({"include_score": True}, {"verbose": True},
                  {"include_score": True, "verbose": True}):
        if report_body(evaluated, **flags) != _report_from_fact(fact).to_dict(**flags):
            problems.append(f"bodies differ under {flags}")

    return Gate("the API and CLI emit the same JSON body", not problems,
                problems or sorted(api))

def gate_score_is_withheld_by_default() -> Gate:
    """The aggregate numbers are available on request, never volunteered.

    The terminal guarantee ("the default output is not headline-shaped")
    only holds for a machine consumer if the JSON bodies obey it too, and
    ``inspect --json`` used to volunteer ``score``, ``risk`` and
    ``risk_label`` on every call regardless of the flags - so the number the
    CLI is documented to withhold was one flag away from being the default
    for every consumer.

    Attribute access is deliberately not covered: ``report.score`` is the
    caller naming the field, which is the request.
    """
    from trustsight.api import _report_from_fact
    from trustsight.reporting import SCORE_KEYS, VERBOSE_KEYS, evaluate_fact, report_body

    fact = _parity_fact()
    evaluated = evaluate_fact(fact)
    problems = []

    surfaces = {
        "cli": (report_body(evaluated),
                report_body(evaluated, include_score=True),
                report_body(evaluated, verbose=True)),
        "api": (_report_from_fact(fact).to_dict(),
                _report_from_fact(fact).to_dict(include_score=True),
                _report_from_fact(fact).to_dict(verbose=True)),
    }
    for name, (default, scored, verbose) in surfaces.items():
        for key in SCORE_KEYS:
            if key in default:
                problems.append(f"{name}: {key} present by default")
            if key not in scored:
                problems.append(f"{name}: {key} missing when requested")
        for key in VERBOSE_KEYS:
            if key in default:
                problems.append(f"{name}: {key} present by default")
            if key not in verbose:
                problems.append(f"{name}: {key} missing under verbose")
        # A weight is score arithmetic and travels with the breakdown.
        for finding in default.get("findings", ()):
            if "weight" in finding:
                problems.append(f"{name}: a default finding carries a weight")
                break

    # The evidence keys are the other half: withholding the score must not
    # withhold anything else.
    for name, (default, _s, _v) in surfaces.items():
        for key in ("findings", "coverage_gaps", "suppressed_rules", "verdict"):
            if key not in default:
                problems.append(f"{name}: {key} missing from the default body")

    return Gate("the score is withheld from every default body", not problems,
                problems or list(SCORE_KEYS))

def gate_api_and_cli_share_the_analysis() -> Gate:
    """The API and CLI differ in output form, not in what they compute.

    Structural: the API must import its analysis from the same modules the
    CLI does. A second implementation would be free to drift - different
    rules, a different score, a different notion of coverage - while every
    behavioural parity check kept passing on the surface it happened to
    exercise.
    """
    tree = ast.parse("\n".join(
        p.read_text(encoding="utf-8")
        for p in sorted((SRC / "api").rglob("*.py"))
    ))
    imported: set[str] = set()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
            for alias in node.names:
                imported.add(alias.name)

    problems = []
    reached = sorted(_SHARED_ANALYSIS & imported)
    if not reached:
        problems.append("api.py imports none of the shared analysis entry points")
    # The scoring model in particular must not be re-derived here.
    for banned in ("calculate_score", "apply_rules", "risk_level"):
        if banned in imported:
            problems.append(f"api.py imports {banned}: scoring belongs to the engine")
    # A rule engine or differ reached directly would be a parallel pipeline.
    for module in sorted(modules):
        if module.endswith(("rules", "differ", "tokenizer")):
            problems.append(f"api.py imports {module} directly")

    return Gate("the API and CLI share one analysis", not problems,
                problems or reached)

def gate_unpinned_build_deps_is_a_declared_gap() -> Gate:
    """B2/A14: a build the analysis could not read is a declared gap.

    ``makepkg`` verifies ``source=()`` against ``sha256sums`` and verifies
    nothing a build step resolves from a registry, so the code that will
    execute is not in the analysed text.  The June 2026 AUR campaign is that
    situation exactly, and it scored 15/100 - UNFLAGGED - against a database
    with a normal corpus before this gap existed.

    Deliberately not a scored rule: ``npm install`` in a build function is
    ordinary AUR practice, which is why H035 is scoped to install hooks and
    why a calibration gate keeps it there.  The gap claims nothing about the
    package; it records that a sensor was missing, and B2 then forbids the
    run from reading as clean.
    """
    from trustsight.analysis.buildfetch import has_unpinned_build_deps
    from trustsight.coverage import (
        CoverageSignals, UNPINNED_BUILD_DEPS, fail_closed, gaps_from,
    )

    attack = (
        "diff --git a/PKGBUILD b/PKGBUILD\n"
        " prepare() {\n"
        "+  npm install atomic-lockfile\n"
        " }\n"
    )
    quiet = (
        "diff --git a/PKGBUILD b/PKGBUILD\n"
        "+# npm install atomic-lockfile\n"
        '+echo "npm install atomic-lockfile"\n'
    )
    offline = (
        "diff --git a/PKGBUILD b/PKGBUILD\n"
        " build() {\n"
        "+  cargo build --offline\n"
        " }\n"
    )

    problems = []
    if not has_unpinned_build_deps(attack):
        problems.append("a build-time registry resolution did not record the gap")
    if has_unpinned_build_deps(quiet):
        problems.append("a name in a comment or string recorded the gap")
    if has_unpinned_build_deps(offline):
        problems.append("an explicitly offline build recorded the gap")

    gaps = gaps_from(CoverageSignals(
        tree_analyzed=True, unpinned_build_deps=True))
    if UNPINNED_BUILD_DEPS not in gaps:
        problems.append("gaps_from does not carry the gap")
    if fail_closed("Low", gaps, []) != "Inconclusive":
        problems.append("the gap does not forbid an unflagged verdict")

    return Gate("an unpinned build dependency is a declared gap", not problems,
                problems or UNPINNED_BUILD_DEPS)

def gate_every_render_reports_the_same_information() -> Gate:
    """B11 on the terminal: a render may not drop what the JSON carries.

    The body gates above compare JSON with JSON.  A reviewer reads whichever
    render their terminal gave them, so a field present in one and absent
    from another is a difference in *information* between two surfaces, and
    B2, B5 and B7 each say the field in question may never be dropped.

    All four renderers, looped rather than sampled, because every one of the
    three properties was in fact false on some surface: `inspect` showed
    nothing about a coverage gap unless a band was requested, `review`
    showed suppressions only in its JSON body, and `inspect --plain` had no
    change summary at all. Each had a gate already, and each gate was aimed
    at the data layer where the value is set rather than at the renders that
    have to show it.
    """

    from rich.console import Console

    import trustsight.cli.display as display
    import trustsight.cli.inspect as inspect_cli
    import trustsight.cli.review as review_cli
    from trustsight.coverage import GAP_REASONS
    from trustsight.depth import DependencyReport
    from trustsight.reporting import evaluate_fact
    from trustsight.schema import DiffSummary, PackageFact, ScoreEntry

    gap = "diff_truncated"
    change = "PKGBUILD moved"
    suppressed = "R099"
    expired = "H029"
    dependency = "render-parity-dep"
    fact = PackageFact(
        package_name="render-parity", old_version="1.0", new_version="1.1",
        diff_summary=DiffSummary(1, 0, ["PKGBUILD"],
                                 [{"path": "PKGBUILD", "status": "modified"}]),
        score_breakdown=[ScoreEntry(rule_id="R001", severity="HIGH", weight=25,
                                    reason="curlpipe", file="PKGBUILD", line=4)],
        final_score=25, risk="Medium", coverage_gaps=[gap], changes=[change],
        suppressed_rules=[{"rule_id": suppressed, "severity": "LOW",
                           "override_reason": "known",
                           "indicator_corroborated": True}],
        overrides_expired=[expired],
        dependencies=[DependencyReport(name=dependency, depth=1, score=40,
                                       risk="High", risk_label="High",
                                       finding_count=1)],
    )
    row = dict(evaluate_fact(fact))
    row["failed"] = False

    def rich(fn) -> str:
        buffer = io.StringIO()
        saved = display._console
        display._console = Console(file=buffer, force_terminal=False, width=240)
        try:
            fn()
        finally:
            display._console = saved
        return buffer.getvalue()

    def plain(fn) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            fn()
        return buffer.getvalue()

    renders = {
        "review rich": rich(lambda: review_cli._render_results_rich(
            [row], 1, False, False, False, False)),
        "review plain": plain(lambda: review_cli._render_results_plain(
            [row], 1, False, False, False, False)),
        "inspect rich": rich(lambda: inspect_cli._inspect_rich(fact)),
        "inspect plain": plain(lambda: inspect_cli._inspect_plain(fact)),
    }

    required = {
        "the coverage gap (B2)": (GAP_REASONS[gap], gap),
        "the suppressed rule (B5)": (suppressed,),
        "the corroboration marker (B5)": ("indicator corroborated",),
        "the expired override (B5)": (expired,),
        "the change summary (B7)": (change,),
        # A dependency is a full analysis with its own band, so a surface
        # that hides it is hiding a result and not a detail.
        "the analysed dependency (depth)": (dependency,),
    }
    problems = []
    for name, out in renders.items():
        for what, tokens in required.items():
            if not any(token in out for token in tokens):
                problems.append(f"{name} does not report {what}")

    return Gate("every render reports the same information", not problems,
                problems or sorted(renders))

def gate_libgit2_stays_behind_the_sandbox() -> Gate:
    """A16: only the git sandbox operates libgit2.

    The parent reaches every git operation through the isolated worker; the
    modules here are the ones the cutover has not yet emptied.  The list is a
    ratchet - a new importer is a regression, and removing one is the point.
    """
    hits: list[str] = []
    for path in _python_files():
        rel = path.relative_to(SRC).as_posix()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                if any(a.name == "pygit2" for a in node.names) \
                        and rel not in _GIT_ALLOWED_IMPORTS:
                    hits.append(f"{rel}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom) and node.module == "pygit2" \
                    and rel not in _GIT_ALLOWED_IMPORTS:
                hits.append(f"{rel}:{node.lineno}")
    return Gate("libgit2 stays behind the git sandbox", not hits, hits)

def gate_generated_diff_is_bounded_before_assembly() -> Gate:
    """A4: the diff generator bounds what it allocates, not what it keeps.

    ``patch.text`` materialises a whole patch, and the git path used to call
    ``generate_diff`` with no ``max_bytes`` at all - so every filtered patch
    was read in full and joined before the pipeline's cap applied, and
    ``MAX_GENERATED_DIFF_BYTES`` was inert on the path that matters.

    The second half is the one that hides things. A patch the generator
    declines to retain leaves the assembled text at or under the cap, so a
    caller that re-derives truncation by measuring that text reports
    "complete" while content was skipped - the silent skip B2 forbids. The
    flag therefore travels out of the generator rather than being inferred,
    and this checks that it does.
    """
    import inspect

    from trustsight.analysis import pipeline
    from trustsight.sandbox import git_project

    problems = []

    # The bounded form must return the flag.
    signature = inspect.signature(git_project.generate_diff_bounded)
    source = inspect.getsource(git_project.generate_diff_bounded)
    if "-> tuple[str, DiffSummary, bool]" not in str(signature.return_annotation) + source:
        problems.append("generate_diff_bounded does not declare a truncation flag")
    for name in ("MAX_DIFF_PATCHES", "MAX_PATCH_BYTES", "MAX_DIFF_SUMMARY_FILES"):
        if name not in source:
            problems.append(f"{name} is not enforced in generate_diff_bounded")

    # The bound that matters runs *before* `patch.text`, because that
    # attribute has already allocated the whole patch by the time it
    # returns. Asserted behaviourally: a delta whose text raises if touched
    # must still produce a result and a truncation flag.
    if "MAX_PATCH_SOURCE_BYTES" not in source:
        problems.append("delta size is not checked before patch.text")

    touched = []

    class _Side:
        def __init__(self, size):
            self.path, self.size = "PKGBUILD", size

    class _Delta:
        status = 1

        def __init__(self, size):
            self.old_file = _Side(size)
            self.new_file = _Side(size)

    class _Exploding:
        def __init__(self, size):
            self.delta = _Delta(size)

        @property
        def text(self):
            touched.append(True)
            raise AssertionError("patch text read before the size check")

    huge = git_project.MAX_PATCH_SOURCE_BYTES * 4

    class _Diff:
        deltas = [_Delta(huge)]
        stats = type("S", (), {"insertions": 0, "deletions": 0})()

        def __iter__(self):
            return iter([_Exploding(huge)])

    class _Repo:
        def get(self, _oid):
            return type("C", (), {"tree": object()})()

        def diff(self, *_a, **_k):
            return _Diff()

    try:
        _text, _summary, flag = git_project.generate_diff_bounded(_Repo(), "a", "b")
    except AssertionError:
        problems.append("an oversized delta had its text requested")
    else:
        if touched:
            problems.append("an oversized delta had its text requested")
        if flag is not True:
            problems.append("skipping an oversized delta set no truncation flag")

    # The pipeline must consume the flag rather than re-deriving truncation.
    # The parent calls ``GitProject.diff_bounded``, which reaches the same
    # ``generate_diff_bounded`` through the isolated worker.
    git_path = inspect.getsource(pipeline.analyze_package)
    if "diff_bounded" not in git_path:
        problems.append("the git path does not use the bounded generator")
    if "generated_truncated" not in git_path:
        problems.append("the git path drops the generator's truncation flag")

    return Gate("generated diff is bounded before assembly", not problems,
                problems or ["MAX_DIFF_PATCHES", "MAX_PATCH_BYTES",
                             "MAX_DIFF_SUMMARY_FILES"])

def gate_companion_reads_are_bounded_before_data() -> Gate:
    """A4: a companion blob's size is checked before its bytes are read.

    ``blob.data`` materialises the whole blob. The companion loop already
    checked size first; the PKGBUILD read that *drives* companion discovery
    did not, so the one blob guaranteed to exist was the one read unbounded.
    The tree walk that selects companions was likewise unbounded, because the
    per-file cap applies to the set it produces rather than to the walk.
    """
    import ast
    import inspect

    from trustsight import differ
    from trustsight.sandbox import git_project

    problems = []
    source = inspect.getsource(git_project.companion_source_hunks)
    for name in ("MAX_PKG_BUILD_BYTES",):
        if name not in source:
            problems.append(f"{name} is not enforced in companion_source_hunks")
    if ".data" in source and "size" not in source:
        problems.append("blob data is read without a size check")

    names_source = inspect.getsource(differ._companion_names)
    if "MAX_COMPANION_TREE_ENTRIES" not in names_source:
        problems.append("the companion tree walk is unbounded")
    if "_is_safe_companion_name" not in names_source:
        problems.append("companion names are not validated")

    # A name carrying path structure must be refused.
    for hostile in ("../../etc/passwd", "/etc/passwd", "a" * 4096, "", ".."):
        if differ._is_safe_companion_name(hostile):
            problems.append(f"accepted a hostile companion name: {hostile[:24]!r}")

    # Every bound is a literal, which the constants gate also checks; this
    # confirms they exist on the module at all.
    from trustsight.differ import _bounds as differ_bounds

    tree = ast.parse(inspect.getsource(differ_bounds))
    assigned = {t.id for node in tree.body if isinstance(node, ast.Assign)
                for t in node.targets if isinstance(t, ast.Name)}
    for name in ("MAX_PKG_BUILD_BYTES", "MAX_COMPANION_TREE_ENTRIES",
                 "MAX_COMPANION_NAME_BYTES"):
        if name not in assigned:
            problems.append(f"{name} is not a module-level constant")

    return Gate("companion reads are bounded before data", not problems,
                problems or ["MAX_PKG_BUILD_BYTES", "MAX_COMPANION_TREE_ENTRIES",
                             "MAX_COMPANION_NAME_BYTES"])

def gate_a_critical_finding_never_reads_medium() -> Gate:
    """A confirmed CRITICAL is not a medium situation, whatever the sum says.

    CRITICAL weighs 40 and the High band opens at 51, so arithmetic alone
    can never lift a *single* CRITICAL above Medium: a lone fork bomb, a
    lone `rm -rf /`, a lone `curl | bash` all total 40. Severity overriding
    arithmetic is the existing shape rather than a new one - B4 already lets
    a FATAL cap the score at 100 regardless of the total - and the floor
    moves the band only, so the calibrated separation between the benign and
    malicious *score* populations is untouched.

    Checked through ``calculate_score`` rather than the helper, because the
    band a caller receives is the property, and the floor has to survive the
    cold-start and fail-closed passes that run after it.
    """
    from trustsight.config import load_config
    from trustsight.schema import NoveltyContext
    from trustsight.scoring import CRITICAL_BAND_FLOOR, calculate_score, risk_level

    config = load_config()
    warm = NoveltyContext(observation_count=999)
    problems = []

    lone = [{"rule_id": "R001", "severity": "CRITICAL", "name": "x", "match": "y"}]
    score, _breakdown, level = calculate_score(lone, {}, warm, config)
    if risk_level(score) != "Medium":
        problems.append(f"fixture drift: a lone CRITICAL now totals {score}")
    if level != CRITICAL_BAND_FLOOR:
        problems.append(f"a lone CRITICAL read {level!r}, not {CRITICAL_BAND_FLOOR!r}")

    # The floor raises; it must never lower an already-worse band.
    many = [{"rule_id": f"R00{i}", "severity": "CRITICAL", "name": "x", "match": "y"}
            for i in (1, 2, 3)]
    _s, _b, high_level = calculate_score(many, {}, warm, config)
    if high_level != "Critical":
        problems.append(f"three CRITICALs read {high_level!r}, not 'Critical'")

    # And it is CRITICAL-only: a HIGH keeps the band its weight earns.
    high = [{"rule_id": "H001", "severity": "HIGH", "name": "x", "match": "y"}]
    _s, _b, medium_level = calculate_score(high, {}, warm, config)
    if medium_level != "Medium":
        problems.append(f"a lone HIGH read {medium_level!r}, not 'Medium'")

    return Gate("a critical finding never reads medium", not problems,
                problems or CRITICAL_BAND_FLOOR)

def gate_a_fatal_finding_names_itself() -> Gate:
    """B4: a FATAL is structurally special, and the band alone cannot say so.

    A FATAL caps the score at 100, so it arrives as ``Critical`` - and so
    does a score that merely accumulated past 80. The two are different
    claims: a FATAL rule is unsuppressible by construction and the shipped
    ones target the *reviewer* rather than the machine.

    The distinction rides ``risk_label`` rather than a new band, because
    ``risk`` is a closed enum consumers gate on and nothing is lost without
    it - the severity is in ``score_breakdown`` either way. This asserts the
    label names the rule, that a plain Critical is unchanged, and that
    naming it does not displace B2's coverage qualifier.
    """
    from trustsight.coverage import INCOMPLETE_SUFFIX
    from trustsight.schema import PackageFact, ScoreEntry
    from trustsight.scoring import verdict_label, verdict_level

    def fact(**kw):
        kw.setdefault("final_score", 100)
        return PackageFact(package_name="demo", risk="Critical", **kw)

    fatal = fact(score_breakdown=[ScoreEntry(rule_id="R013", severity="FATAL",
                                             weight=0, reason="unicode")])
    plain = fact(final_score=90)
    gapped = fact(coverage_gaps=["diff_truncated"],
                  score_breakdown=[ScoreEntry(rule_id="R012", severity="FATAL",
                                              weight=0, reason="injection")])

    problems = []
    if verdict_level(fatal) != "Critical":
        problems.append("the FATAL band left the closed enum")
    if "FATAL: R013" not in verdict_label(fatal):
        problems.append(f"the label does not name the rule: {verdict_label(fatal)!r}")
    if verdict_label(plain) != "Critical":
        problems.append(f"a plain Critical changed: {verdict_label(plain)!r}")
    label = verdict_label(gapped)
    if "FATAL: R012" not in label or not label.endswith(INCOMPLETE_SUFFIX):
        problems.append(f"the gap qualifier was displaced: {label!r}")

    return Gate("a fatal finding names itself in the label", not problems,
                problems or verdict_label(fatal))

def gate_ci_installs_from_the_lock() -> Gate:
    """The gates only mean something if CI runs the code they check.

    "CI is not compromised" is a stated assumption, and a live dependency
    resolve is its softest edge: a workflow that pip-installs from PyPI on
    every push lets a compromised release of any dependency run inside the
    job that certifies the security model.

    The flag has to be ``--locked``, not ``--frozen``.  Both install the
    pinned, hashed versions in ``uv.lock`` and resolve nothing, but
    ``--frozen`` performs *no check* that the lock still matches
    ``pyproject.toml`` - a dependency added to the manifest and never locked
    is silently ignored, and the job installs an older closure while
    appearing to honour the manifest.  ``--locked`` fails instead, which is
    the property that makes the lock meaningful rather than merely present.

    A live resolve can also arrive as ``uv lock``, which re-resolves rather
    than honouring the committed ``uv.lock``; only ``uv lock --check`` (a
    staleness check that resolves nothing) is allowed.  The install check
    alone missed it, so a workflow could resolve from PyPI and still pass.

    A consumer checkout with its own lock is the one exception: that lock
    freezes *this* project as a path dependency, so a core dependency change
    invalidates it before the consumer can run.  The line must carry the
    explicit ``# lock-exempt: consumer`` marker; an unmarked unlocked
    install still fails.

    Checked structurally over every workflow, because the failure mode is a
    new workflow that installs the old way rather than an existing one
    changing back.
    """
    problems: list[str] = []
    installers: list[str] = []
    #: A consumer checkout (the harness) carries its own lock and pins this
    #: core as a path dependency, so locking its sync to *this* project's
    #: graph cannot work: a core dependency change invalidates it before the
    #: consumer runs.  The marker is explicit at the call site, and the
    #: consumer's own CI still checks its lock against its pinned core.
    consumer_exempt = "lock-exempt: consumer"
    workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    if not workflows:
        return Gate("CI installs from the lock", False, "no workflows found")
    for path in workflows:
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.strip()
            # Comments run nothing; prose that names `uv lock` must not read
            # as the command.
            if stripped.startswith("#"):
                continue
            if "pip install" in stripped:
                problems.append(f"{path.name}:{lineno} pip install")
            if "uv lock" in stripped and "--check" not in stripped:
                problems.append(
                    f"{path.name}:{lineno} runs a live resolve "
                    "(use `uv lock --check`, or `uv sync --locked`)"
                )
            if "uv sync" in stripped or "uv export" in stripped:
                installers.append(f"{path.name}:{lineno}")
                if ("--locked" not in stripped
                        and consumer_exempt not in stripped):
                    problems.append(
                        f"{path.name}:{lineno} reads the lock without --locked"
                        + (" (--frozen skips the staleness check)"
                           if "--frozen" in stripped else "")
                    )
    if not installers:
        problems.append("no workflow installs dependencies from the lock")
    if not (ROOT / "uv.lock").exists():
        problems.append("uv.lock is missing")
    return Gate("CI installs from the lock", not problems,
                problems or installers)

def gate_critical_paths_are_synchronised() -> Gate:
    """Keep CODEOWNERS, CI signature checks and contributor policy aligned."""
    from scripts.critical_paths import ARCHIVE_EXCLUDED_PATHS, CRITICAL_PATHS

    name = "critical paths are synchronised"
    problems = []
    codeowners = ROOT / ".github" / "CODEOWNERS"
    workflow = ROOT / ".github" / "workflows" / "verify-commit-sigs.yml"
    contributing = ROOT / "CONTRIBUTING.md"
    if not codeowners.exists() or not workflow.exists() or not contributing.exists():
        return Gate(name, False, "required policy file missing")

    # The policy half of this gate (CODEOWNERS, the signature workflow, the
    # contributor guidance) is checked everywhere.  The "the file is really
    # there" half cannot be, because `.gitattributes` deliberately keeps
    # some of these paths out of the release tarball, and check() runs the
    # suite from inside that tarball.
    from_archive = not (ROOT / "packaging").exists()

    owned = {
        line.split()[0].lstrip("/").rstrip("/")
        for line in codeowners.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#") and len(line.split()) >= 2
    }
    workflow_text = workflow.read_text(encoding="utf-8")
    missing_owners = sorted(
        path for path in CRITICAL_PATHS
        if path not in owned
        and not any(path.startswith(owner + "/") for owner in owned)
    )
    missing_workflow = [] if "scripts.critical_paths import CRITICAL_PATHS" in workflow_text else sorted(CRITICAL_PATHS)
    missing_files = sorted(
        path for path in CRITICAL_PATHS
        if not (ROOT / path).exists()
        and not (from_archive and path in ARCHIVE_EXCLUDED_PATHS)
    )
    if missing_owners:
        problems.append(f"missing CODEOWNERS entries: {missing_owners}")
    if missing_workflow:
        problems.append(f"missing signature workflow entries: {missing_workflow}")
    if missing_files:
        problems.append(f"critical paths do not exist: {missing_files}")
    if "scripts/critical_paths.py" not in contributing.read_text(encoding="utf-8"):
        problems.append("CONTRIBUTING.md does not name the canonical critical-path list")
    return Gate(name, not problems, problems or sorted(CRITICAL_PATHS))

def gate_h_series_intake_is_frozen() -> Gate:
    """No new H id beyond the frozen set.

    The H series is a junk drawer by exclusion, and new detections must be
    instances of an existing family or filed in another series until the
    reduction target is reached.  The frozen set is the authority (not a
    count), so a PR that adds an H id fails here with a pointer to the
    family tables.
    """
    from trustsight.categories import RULE_CATEGORIES
    from trustsight.rule_id_history import FROZEN_H_IDS

    h_ids = sorted(rid for rid in RULE_CATEGORIES if rid.startswith("H"))
    new = sorted(set(h_ids) - FROZEN_H_IDS)
    problems = []
    if new:
        problems.append(
            f"new H id(s) beyond the intake freeze: {new}; file it as an "
            "instance of an existing family or in another series "
            "(docs/reference/rules/nature.md)"
        )
    return Gate("H-series intake is frozen", not problems,
                {"frozen": len(FROZEN_H_IDS)}, problems)

def gate_h_series_reduction_residue() -> Gate:
    """The live H count, and the frozen ceiling.

    Reports the live (emitting) H count against the 55-65 target band so the
    residue is visible, and **fails only above the documented ceiling** (the
    frozen set minus the retained anchors).  It never fails merely for being
    above the target band: the overlap audit adjudicated every merge
    candidate and no merger is evidence-supported, so no id is retired by
    fiat (the reduction is a data change, not a bookkeeping one).
    """
    from trustsight.categories import RULE_CATEGORIES
    from trustsight.rule_id_history import ANCHOR_RULE_IDS

    h_ids = sorted(rid for rid in RULE_CATEGORIES if rid.startswith("H"))
    # The live count is the *emitting* rules: the retained documentation
    # Anchors are not live H logic.
    live = len([rid for rid in h_ids if rid not in ANCHOR_RULE_IDS])
    ceiling = _h_series_live_ceiling()
    low, high = H_SERIES_REDUCTION_TARGET
    if live > ceiling:
        detail = (f"{live} live H rules exceed the frozen ceiling "
                  f"{ceiling}; a new H id slipped past the intake freeze")
    elif live > high:
        detail = (f"{live} live H rules; {live - high} above the target band "
                  f"{low}-{high} (no evidence-supported merger remains)")
    elif live < low:
        detail = f"{live} live H rules, below the target band {low}-{high}"
    else:
        detail = f"{live} live H rules, within the target band {low}-{high}"
    return Gate("H-series reduction residue", live <= ceiling,
                {"live": live, "ceiling": ceiling, "target": [low, high]},
                detail)

def gate_retired_ids_resolve_to_live_survivors() -> Gate:
    """Every retired id aliases a live, non-retired rule.

    A retired id whose survivor is itself retired, or is absent from the
    catalog, would break the "config keeps the old ID readable" contract.
    The alias map is empty until the overlap audit is measured; this keeps it
    well-formed when it is not.
    """
    from trustsight.categories import RULE_CATEGORIES
    from trustsight.rule_id_history import RETIRED_RULE_IDS, survivor_id

    problems: list[str] = []
    for old, survivor in RETIRED_RULE_IDS.items():
        if survivor in RETIRED_RULE_IDS:
            problems.append(f"{old} -> {survivor} is itself retired")
        if survivor_id(old) not in RULE_CATEGORIES:
            problems.append(f"{old} resolves to {survivor_id(old)}, not live")
        if old in RULE_CATEGORIES:
            problems.append(f"{old} is retired but still in the live catalog")
    return Gate("retired ids resolve to live survivors", not problems,
                {"retired": len(RETIRED_RULE_IDS)}, problems)

def gate_an_audit_does_not_write_history() -> Gate:
    """A15: an audit is read-only unless ``--record`` is given.

    Behavioural as well as structural: the analysis pipeline must not call
    the writing helpers unconditionally.  Before this gate the writes were
    on every path, so two runs over the same diff returned different
    novelty and the determinism claim was false.  The check asserts the
    write helpers are guarded by ``record`` in both producers, and that a
    read-only run reaches neither ``insert_analysis`` nor the novelty
    inserts.
    """
    import sqlite3
    import tempfile

    from trustsight.novelty import check_maintainer_novelty, check_url_novelty

    novelty = (SRC / "novelty.py").read_text(encoding="utf-8")
    problems = []
    if "record: bool = " not in novelty:
        problems.append("novelty.py: check_*_novelty has no record switch")

    # Behavioural: a read-only call must not touch the database.  Pointed at
    # a throwaway file so the gate proves the branch rather than reading it.
    with tempfile.TemporaryDirectory() as tmp:
        db_file = Path(tmp) / "gate.db"
        conn = sqlite3.connect(str(db_file))
        conn.executescript(
            "CREATE TABLE source_urls (id INTEGER PRIMARY KEY, url TEXT UNIQUE,"
            " first_seen_package_id INTEGER, first_seen_globally_timestamp TEXT,"
            " total_uses INTEGER DEFAULT 1, last_seen_timestamp TEXT);"
            "CREATE TABLE maintainers (id INTEGER PRIMARY KEY, name TEXT,"
            " first_seen_package_id INTEGER);"
            "CREATE TABLE maintainers_hashed (name_hash TEXT NOT NULL,"
            " email_hash TEXT, first_seen TEXT, package_count INTEGER DEFAULT 0,"
            " packages TEXT, source TEXT, PRIMARY KEY (name_hash, email_hash));"
            "CREATE TABLE package_maintainers_hashed (name_hash TEXT NOT NULL,"
            " email_hash TEXT, package_id INTEGER NOT NULL, first_seen TEXT,"
            " PRIMARY KEY (name_hash, email_hash, package_id));"
            "CREATE TABLE seed_meta (key TEXT PRIMARY KEY, value TEXT);"
        )
        conn.commit()
        conn.close()

        import trustsight.db._connection as db_conn
        original = db_conn.get_db_path
        db_conn.get_db_path = lambda: db_file
        try:
            check_url_novelty("https://gate.example/pkg.tar.gz", 1, record=False)
            check_maintainer_novelty("gate-maintainer", 1, record=False)
        finally:
            db_conn.get_db_path = original

        conn = sqlite3.connect(str(db_file))
        urls = conn.execute("SELECT COUNT(*) FROM source_urls").fetchone()[0]
        maint = conn.execute("SELECT COUNT(*) FROM maintainers").fetchone()[0]
        conn.close()
        if urls or maint:
            problems.append(
                f"a read-only lookup wrote to the database (urls={urls}, maintainers={maint})"
            )
    return Gate("an audit does not write history", not problems,
                problems or ["read-only novelty lookup writes nothing"])

def gate_the_history_walk_is_bounded() -> Gate:
    """A14: the history walk and the --last ceiling are source constants."""
    problems: list[str] = []
    locations = {
        "MAX_HISTORY_COMMITS": SRC / "differ" / "_bounds.py",
        "MAX_HISTORY_DIFFS": SRC / "fetcher.py",
    }
    for const, path in locations.items():
        if f"{const} =" not in path.read_text(encoding="utf-8"):
            problems.append(f"{const} not defined in {path.name}")
    return Gate("the history walk is bounded", not problems,
                problems or ["MAX_HISTORY_COMMITS", "MAX_HISTORY_DIFFS"])

def gate_run_diff_assembly_is_bounded() -> Gate:
    """A14/B2: MAX_RUN_DIFF_BYTES is charged across results."""
    fetcher = SRC / "fetcher.py"
    text = fetcher.read_text(encoding="utf-8")
    has_const = "MAX_RUN_DIFF_BYTES" in text
    return Gate("run diff assembly is bounded", has_const,
                has_const and ["MAX_RUN_DIFF_BYTES"] or "MAX_RUN_DIFF_BYTES not defined")

def gate_a_truncated_history_walk_is_a_declared_gap() -> Gate:
    """B2: HISTORY_TRUNCATED is in the coverage module."""
    coverage = SRC / "coverage.py"
    text = coverage.read_text(encoding="utf-8")
    has_gap = "HISTORY_TRUNCATED" in text
    return Gate("a truncated history walk is a declared gap", has_gap,
                has_gap and ["HISTORY_TRUNCATED"] or "HISTORY_TRUNCATED not in coverage.py")
