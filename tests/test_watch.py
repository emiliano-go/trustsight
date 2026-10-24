"""``trustsight full-aur --watch``: repeated corpus cycles.

The cycle itself is ``run_baseline_build``, which the other tests cover.
What is asserted here is what --watch adds: it repeats, it honours the
interval floor, it stops when asked, it survives an interrupt, and it
reports a cluster once instead of on every cycle.
"""

import pytest

import trustsight.db as db_module
from trustsight.db import alert_history, init_db, record_alerts
from trustsight.full_aur.pipeline import (
    CycleResult,
    run_watch,
    watch_interval_seconds,
)


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(db_module, "DATA_DIR", tmp_path)
    init_db()
    return tmp_path


# --- the interval ---


def test_interval_defaults_to_the_configured_value(monkeypatch):
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.load_config",
        lambda: {"limits": {"watch_interval": 1800, "watch_min_interval": 60}},
    )
    assert watch_interval_seconds() == 1800


def test_interval_is_clamped_to_the_floor(monkeypatch):
    """A mistyped --interval 1 must not turn into a request loop against
    someone else's mirror."""
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.load_config",
        lambda: {"limits": {"watch_interval": 3600, "watch_min_interval": 60}},
    )
    assert watch_interval_seconds(1) == 60
    assert watch_interval_seconds(900) == 900


# --- the loop ---


def test_watch_runs_the_requested_number_of_cycles(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kwargs: calls.append(kwargs) or CycleResult(added=1),
    )
    slept: list[float] = []
    results = run_watch(interval=60, cycles=3, sleep=slept.append)
    assert len(results) == 3
    assert len(calls) == 3
    # Two sleeps for three cycles: the loop never sleeps after the last one.
    assert slept == [60, 60]


def test_watch_stops_cleanly_on_interrupt(monkeypatch):
    """Ctrl-C ends the loop and returns what already ran; every cycle has
    saved its snapshot and resume file before returning, so nothing is
    lost by stopping between cycles."""
    def _raise_after_one(**kwargs):
        if not calls:
            calls.append(1)
            return CycleResult(added=2)
        raise KeyboardInterrupt

    calls: list[int] = []
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build", _raise_after_one
    )
    results = run_watch(interval=60, cycles=0, sleep=lambda _: None)
    assert len(results) == 1
    assert results[0].added == 2


def test_watch_interrupt_during_the_sleep_also_stops(monkeypatch):
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kwargs: CycleResult(),
    )

    def _interrupted(_seconds):
        raise KeyboardInterrupt

    assert len(run_watch(interval=60, cycles=0, sleep=_interrupted)) == 1


def test_watch_passes_json_output_through(monkeypatch):
    seen = {}
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kwargs: seen.update(kwargs) or CycleResult(),
    )
    run_watch(interval=60, cycles=1, json_output=True, sleep=lambda _: None)
    assert seen == {"json_output": True, "depth": None, "over_threshold": None,
                    "since": None}


# --- alert deduplication ---


def test_a_cluster_is_reported_once_not_every_cycle(data_dir):
    """The second cycle of an unchanged corpus announces nothing: the
    maintainer who adopted forty packages last night is not news twice."""
    pairs = [("pkg-one", "H045"), ("pkg-two", "H045")]
    assert record_alerts(pairs) == pairs
    assert record_alerts(pairs) == []
    assert record_alerts(pairs + [("pkg-three", "H045")]) == [("pkg-three", "H045")]


def test_repeat_alerts_are_counted_not_forgotten(data_dir):
    record_alerts([("pkg", "H044")])
    record_alerts([("pkg", "H044")])
    record_alerts([("pkg", "H044")])
    row = alert_history("pkg")[0]
    assert row["count"] == 3
    assert row["first_seen"] <= row["last_sent"]


def test_alerts_are_per_rule(data_dir):
    """The same package hitting a *different* rule is a new alert."""
    record_alerts([("pkg", "H044")])
    assert record_alerts([("pkg", "H074")]) == [("pkg", "H074")]


def test_record_alerts_with_nothing_to_record(data_dir):
    assert record_alerts([]) == []
    assert alert_history() == []


# --- a real cycle, with the network mocked out ---


@pytest.fixture
def fake_aur(tmp_path, monkeypatch):
    """A two-package AUR whose metadata the test controls."""
    import trustsight.config as config_module
    import trustsight.full_aur.pipeline as pipeline

    monkeypatch.setattr(config_module, "CONFIG_DIR", tmp_path / "config")
    monkeypatch.setattr(db_module, "DATA_DIR", tmp_path / "data")
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    config_module.ensure_default_configs()
    config_module._toml_cache.clear()
    init_db()

    state = {"meta": {}}
    import trustsight.full_aur.metadata as metadata_module

    monkeypatch.setattr(metadata_module, "_current_dump", None)

    def _fetch_meta(*args, **kwargs):
        # The real fetch installs the dump for depth.default_metadata; a
        # fake that only returns it would leave the walk reading the previous
        # snapshot file.
        metadata_module._current_dump = state["meta"]
        return state["meta"]

    monkeypatch.setattr(pipeline, "fetch_metadata", _fetch_meta)
    monkeypatch.setattr(
        pipeline, "fetch_pkgbuild_with_tree",
        lambda base: ("pkgname=%s\npkgver=1.0\n" % base, None, None, False, None, None, None, True),
    )
    monkeypatch.setattr(pipeline, "save_resume_state", lambda *a, **k: None)
    monkeypatch.setattr(pipeline, "clear_resume_state", lambda *a, **k: None)
    monkeypatch.setattr(pipeline, "load_resume_state", lambda *a, **k: None)
    yield state
    config_module._toml_cache.clear()


def _entry(name, maintainer, modified, version="1.0"):
    return {
        "Name": name, "PackageBase": name, "Maintainer": maintainer,
        "Version": version, "LastModified": modified,
    }


def test_a_second_cycle_reports_the_takeover_once(fake_aur, monkeypatch):
    """The first cycle bootstraps (the sweep is silent without a baseline),
    the second sees the takeover, and the third repeats it without
    re-announcing it."""
    from trustsight.full_aur.pipeline import run_baseline_build

    fake_aur["meta"] = {
        "pkg": _entry("pkg", "alice", 1_800_000_000),
        "other": _entry("other", "alice", 1_800_000_000),
    }
    first = run_baseline_build(bootstrap=True)
    assert first.bootstrap
    assert first.cluster_findings == []

    fake_aur["meta"] = {
        "pkg": _entry("pkg", "mallory", 1_800_000_100, version="2.0"),
        "other": _entry("other", "alice", 1_800_000_000),
    }
    second = run_baseline_build()
    fired = {f["rule_id"] for f in second.cluster_findings}
    assert {"H044", "H026"} <= fired
    assert ("pkg", "H026") in second.new_alerts

    third = run_baseline_build()
    assert third.new_alerts == []


def test_a_missing_unchanged_dependency_is_prefilled(fake_aur):
    """A dependency the watcher has never processed is baselined before the
    root walk, so the root does not fail closed on an unread AUR package."""
    import json

    from trustsight.db import (
        forget_package,
        get_last_analysis,
        get_package_id,
        get_package_profile,
        get_pkgbuild_snapshot,
    )
    from trustsight.full_aur.pipeline import run_baseline_build

    fake_aur["meta"] = {
        "pkg": _entry("pkg", "alice", 1_800_000_000),
        "dep": _entry("dep", "bob", 1_800_000_000),
    }
    run_baseline_build(bootstrap=True)
    forget_package("dep")
    assert get_pkgbuild_snapshot("dep") is None

    fake_aur["meta"] = {
        "pkg": {**_entry("pkg", "alice", 1_800_000_010, version="2.0"),
                "Depends": ["dep"]},
        "dep": _entry("dep", "bob", 1_800_000_000),
    }
    result = run_baseline_build()

    assert get_pkgbuild_snapshot("dep") is not None
    assert get_package_profile("dep") is not None
    assert "dep" not in result.detail, "a prefilled dependency is not a root alert"
    fact = json.loads(get_last_analysis(get_package_id("pkg"))["fact_json"])
    assert "deps_not_scanned" not in fact["coverage_gaps"]
    assert [d["name"] for d in fact["dependencies"]] == ["dep"]
    assert fact["dependencies"][0]["failed"] is False


def test_delta_dependencies_are_analysed_before_their_dependents():
    """A changed dependency must be stored before the root that needs it."""
    from trustsight.full_aur.pipeline import _dependencies_first

    meta = {
        "app": {"Depends": ["lib"]},
        "lib": {},
        "other": {},
    }
    assert _dependencies_first(["app", "other", "lib"], meta) == [
        "lib", "app", "other"]


def test_a_dependency_cycle_keeps_every_package():
    from trustsight.full_aur.pipeline import _dependencies_first

    meta = {"a": {"Depends": ["b"]}, "b": {"Depends": ["a"]}}
    assert sorted(_dependencies_first(["a", "b"], meta)) == ["a", "b"]


def test_a_dependency_in_the_delta_is_not_prefilled(fake_aur):
    """A changed dependency must be analysed as a root, or its diff is lost."""
    from trustsight.full_aur.pipeline import _missing_direct_dependencies

    meta = {
        "root": {"Depends": ["dep", "changed"]},
        "dep": {},
        "changed": {},
    }
    missing, capped = _missing_direct_dependencies(
        meta, ["root"], {"root", "changed"}, 10)
    assert missing == ["dep"]
    assert capped is False


def test_dependency_prefill_is_capped(fake_aur):
    from trustsight.full_aur.pipeline import _missing_direct_dependencies

    meta = {
        "root": {"Depends": ["dep-a", "dep-b"]},
        "dep-a": {},
        "dep-b": {},
    }
    missing, capped = _missing_direct_dependencies(meta, ["root"], {"root"}, 1)
    assert missing == ["dep-a"]
    assert capped is True


def test_a_dependency_fetch_failure_still_reports_the_gap(fake_aur, monkeypatch):
    """Prefill is best-effort: a mirror failure must stay visible."""
    import json

    import trustsight.full_aur.pipeline as pipeline
    from trustsight.db import (
        forget_package,
        get_last_analysis,
        get_package_id,
        get_pkgbuild_snapshot,
    )
    from trustsight.full_aur.pipeline import run_baseline_build

    fake_aur["meta"] = {
        "pkg": _entry("pkg", "alice", 1_800_000_000),
        "dep": _entry("dep", "bob", 1_800_000_000),
    }
    run_baseline_build(bootstrap=True)
    forget_package("dep")

    real_fetch = pipeline.fetch_pkgbuild_with_tree

    def _fetch(base):
        if base == "dep":
            return (None, None, None, False, None, None, None, True)
        return real_fetch(base)

    monkeypatch.setattr(pipeline, "fetch_pkgbuild_with_tree", _fetch)
    fake_aur["meta"] = {
        "pkg": {**_entry("pkg", "alice", 1_800_000_010, version="2.0"),
                "Depends": ["dep"]},
        "dep": _entry("dep", "bob", 1_800_000_000),
    }
    run_baseline_build()

    assert get_pkgbuild_snapshot("dep") is None
    fact = json.loads(get_last_analysis(get_package_id("pkg"))["fact_json"])
    assert "deps_not_scanned" in fact["coverage_gaps"]


def test_g004_fires_only_after_a_manifest_baseline(fake_aur, monkeypatch):
    """The first observation of a package is a baseline, not an addition.

    Two packages keep the same (empty) manifest on the bootstrap cycle, so
    neither contributes an addition.  The next cycle both add the same
    remote dependency, and only then does G004 join them.
    """
    import trustsight.full_aur.pipeline as pipeline
    from trustsight.full_aur.pipeline import run_baseline_build

    state = {"deps": "[dependencies]\n"}
    monkeypatch.setattr(
        pipeline, "fetch_pkgbuild_with_tree",
        lambda base: (
            "pkgname=%s\npkgver=1.0\n" % base, [], None, False,
            None, None, [("Cargo.toml", state["deps"])], True,
        ),
    )
    fake_aur["meta"] = {
        "pkg": _entry("pkg", "alice", 1_800_000_000),
        "other": _entry("other", "alice", 1_800_000_000),
    }
    first = run_baseline_build(bootstrap=True)
    assert first.bootstrap
    assert first.cluster_findings == []

    state["deps"] = (
        "[dependencies]\nevil = { git = \"https://evil.example/x.git\" }\n")
    fake_aur["meta"] = {
        "pkg": _entry("pkg", "alice", 1_800_000_100, version="2.0"),
        "other": _entry("other", "alice", 1_800_000_100, version="2.0"),
    }
    second = run_baseline_build()
    g004 = [f for f in second.cluster_findings if f["rule_id"] == "G004"]
    assert len(g004) == 1
    assert g004[0]["params"]["members"] == ["other", "pkg"]
    assert g004[0]["params"]["dependency"] == "evil"
    assert g004[0]["params"]["host"] == "evil.example"


# --- bootstrap guard + per-cycle cap (safe-by-default corpus growth) ---


def test_bootstrap_is_refused_without_the_flag(fake_aur):
    """A from-scratch bootstrap must be asked for, not triggered by a missing
    snapshot; the footgun that scraped the whole AUR by accident is closed."""
    from trustsight.db import get_connection
    from trustsight.full_aur.pipeline import run_baseline_build

    fake_aur["meta"] = {"pkg": _entry("pkg", "alice", 1_800_000_000)}
    result = run_baseline_build()  # no --bootstrap, no snapshot

    assert result.bootstrap is False
    assert result.processed == 0
    with get_connection() as c:
        assert c.execute("SELECT COUNT(*) FROM package_profiles").fetchone()[0] == 0


def test_bootstrap_proceeds_with_the_flag(fake_aur):
    from trustsight.db import get_connection
    from trustsight.full_aur.pipeline import run_baseline_build

    fake_aur["meta"] = {
        "pkg": _entry("pkg", "alice", 1_800_000_000),
        "two": _entry("two", "alice", 1_800_000_000),
    }
    result = run_baseline_build(bootstrap=True)
    assert result.bootstrap is True
    with get_connection() as c:
        assert c.execute("SELECT COUNT(*) FROM package_profiles").fetchone()[0] == 2


def test_a_capped_cycle_processes_a_chunk_and_resumes(fake_aur, monkeypatch):
    """With a cap of 1, a three-package bootstrap advances one per cycle,
    resumes automatically (no --bootstrap needed to continue), and only
    finishes the transition on the last chunk."""
    import trustsight.full_aur.pipeline as pipeline
    from trustsight.db import get_connection
    from trustsight.full_aur.pipeline import run_baseline_build

    store: dict = {}
    monkeypatch.setattr(pipeline, "save_resume_state", lambda s: store.__setitem__("state", s))
    monkeypatch.setattr(pipeline, "load_resume_state", lambda: store.get("state"))
    monkeypatch.setattr(pipeline, "clear_resume_state", lambda: store.pop("state", None))
    monkeypatch.setattr(pipeline, "_max_per_cycle", lambda: 1)

    fake_aur["meta"] = {n: _entry(n, "alice", 1_800_000_000) for n in ("a", "b", "c")}

    def _count():
        with get_connection() as c:
            return c.execute("SELECT COUNT(*) FROM package_profiles").fetchone()[0]

    run_baseline_build(bootstrap=True)      # chunk 1
    assert _count() == 1
    assert "state" in store                 # partial: resume kept, snapshot not advanced

    run_baseline_build()                    # chunk 2, resumes without --bootstrap
    assert _count() == 2
    assert "state" in store

    run_baseline_build()                    # chunk 3 completes the transition
    assert _count() == 3
    assert "state" not in store             # resume cleared on completion


# --- refused cycles ---


def test_a_permanently_refused_cycle_stops_the_watch(monkeypatch):
    """No snapshot and no --bootstrap: every cycle refuses the same way, so
    the loop must stop with guidance instead of fetching metadata forever
    and analysing nothing."""
    from trustsight.full_aur.pipeline import CycleResult, run_watch

    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kwargs: CycleResult(refused=True),
    )
    monkeypatch.setattr(
        "trustsight.full_aur.metadata.load_metadata", lambda *a, **k: None,
    )
    from trustsight.db import init_db
    init_db()
    # cycles=5: without the break this returns five refused cycles.
    results = run_watch(interval=60, cycles=5, sleep=lambda s: None)
    assert len(results) == 1
    assert results[0].refused


def test_a_transient_refusal_does_not_consume_the_cycle_budget(monkeypatch):
    """An empty fetch with a snapshot on disk did no work; it must not eat
    --cycles."""
    from trustsight.full_aur.pipeline import CycleResult, run_watch

    outcomes = iter([
        CycleResult(refused=True),
        CycleResult(refused=True),
        CycleResult(added=1),
        CycleResult(added=1),
    ])
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kwargs: next(outcomes),
    )
    monkeypatch.setattr(
        "trustsight.full_aur.metadata.load_metadata",
        lambda *a, **k: {"pkg": {"Version": "1.0"}},
    )
    results = run_watch(interval=60, cycles=2, sleep=lambda s: None)
    assert len(results) == 2
    assert all(not r.refused for r in results)


def test_the_interval_is_skipped_while_backfilling(monkeypatch):
    """A backfill is a queue, not a schedule: the live interval resumes
    only once the replay catches up."""
    from trustsight.full_aur.pipeline import CycleResult, run_watch

    outcomes = iter([CycleResult(backfilling=True), CycleResult(), CycleResult()])
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kwargs: next(outcomes),
    )
    slept: list[float] = []
    results = run_watch(interval=3600, cycles=3, sleep=slept.append)
    assert len(results) == 3
    # One short pause after the backfill cycle, then the live interval; the
    # loop never sleeps after the last cycle.
    assert slept == [2, 3600]


def test_a_refused_cycle_during_a_backfill_retries(monkeypatch):
    """A --since replay advances no snapshot until it catches up, so a
    refused cycle during one is transient, not 'no snapshot yet'."""
    from trustsight.full_aur.pipeline import CycleResult, run_watch

    outcomes = iter([CycleResult(refused=True), CycleResult(added=1)])
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kwargs: next(outcomes),
    )
    monkeypatch.setattr(
        "trustsight.full_aur.metadata.load_metadata", lambda *a, **k: None,
    )
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline._since_cursor", lambda: 1777593600,
    )
    results = run_watch(interval=60, cycles=1, sleep=lambda s: None)
    assert len(results) == 1
    assert not results[0].refused


# --- the ruleset is synced once at startup ---


def _drifted_rules(tmp_path, monkeypatch):
    """A CONFIG_DIR whose rules.toml holds the classic R001 drift (shipped
    pattern intact, non-pattern field stale)."""
    import trustsight.config as config_module
    from trustsight.config import ensure_default_configs, shipped_rules

    cfg = tmp_path / ".config"
    monkeypatch.setattr(config_module, "CONFIG_DIR", cfg)
    monkeypatch.setattr(config_module, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config_module, "CACHE_DIR", tmp_path / ".cache")
    ensure_default_configs()
    path = cfg / "rules.toml"
    r001 = {r["id"]: r for r in shipped_rules()}["R001"]
    old = r001.get("match_target", "raw_line")
    # R001's shipped match_target is "resolved"; a file still holding
    # "raw_line" is drift the safe sync repairs (pattern untouched).
    path.write_text(
        path.read_text().replace(
            f'match_target = "{old}"', 'match_target = "raw_line"', 1))
    return cfg


def test_watch_syncs_the_shipped_ruleset_at_startup(tmp_path, monkeypatch):
    """A watcher must not analyze with a stale rules.toml.  rules.toml is
    written once and only gains rules, so a rule whose fields moved in a later
    build keeps its old behaviour until synced; the watch syncs the safe way
    at startup."""
    from trustsight.config import drifted_shipped_rules, missing_shipped_rules

    _drifted_rules(tmp_path, monkeypatch)
    monkeypatch.delenv("TRUSTSIGHT_NO_SYNC_RULES", raising=False)
    assert any(r[0] == "R001" for r in drifted_shipped_rules())
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kw: CycleResult(added=1),
    )

    run_watch(interval=60, cycles=1, sleep=lambda _: None)

    assert drifted_shipped_rules() == []
    assert missing_shipped_rules() == []


def test_watch_sync_can_be_disabled(tmp_path, monkeypatch):
    from trustsight.config import drifted_shipped_rules

    _drifted_rules(tmp_path, monkeypatch)
    monkeypatch.setenv("TRUSTSIGHT_NO_SYNC_RULES", "1")
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kw: CycleResult(added=1),
    )

    run_watch(interval=60, cycles=1, sleep=lambda _: None)

    assert any(r[0] == "R001" for r in drifted_shipped_rules())


# --- the alive beat ---


def _isolated_config(tmp_path, monkeypatch):
    import trustsight.config as config_module

    monkeypatch.setattr(config_module, "CONFIG_DIR", tmp_path / ".config")
    monkeypatch.setattr(config_module, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config_module, "CACHE_DIR", tmp_path / ".cache")


def test_a_cycle_that_raises_no_alert_beats(tmp_path, monkeypatch):
    """Silence between alerts must mean the watcher is dead, not quiet, so a
    no-alert analysis still sends the low-priority alive beat."""
    _isolated_config(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kw: CycleResult(added=1),
    )
    beats: list[int] = []
    monkeypatch.setattr("trustsight.notify.maybe_notify", lambda *a, **k: False)
    monkeypatch.setattr("trustsight.notify.maybe_heartbeat",
                        lambda c, u=None: beats.append(1) or True)

    run_watch(interval=60, cycles=1, sleep=lambda _: None)

    assert beats == [1]


def test_a_cycle_that_alerts_does_not_beat(tmp_path, monkeypatch):
    _isolated_config(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "trustsight.full_aur.pipeline.run_baseline_build",
        lambda **kw: CycleResult(added=1),
    )
    beats: list[int] = []
    monkeypatch.setattr("trustsight.notify.maybe_notify", lambda *a, **k: True)
    monkeypatch.setattr("trustsight.notify.maybe_heartbeat",
                        lambda c, u=None: beats.append(1) or True)

    run_watch(interval=60, cycles=1, sleep=lambda _: None)

    assert beats == []
