"""``trustsight full-aur --watch``: repeated corpus cycles (plan §6.4).

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
    assert seen == {"json_output": True}


# --- alert deduplication ---


def test_a_cluster_is_reported_once_not_every_cycle(data_dir):
    """The second cycle of an unchanged corpus announces nothing: the
    maintainer who adopted forty packages last night is not news twice."""
    pairs = [("pkg-one", "R092"), ("pkg-two", "R092")]
    assert record_alerts(pairs) == pairs
    assert record_alerts(pairs) == []
    assert record_alerts(pairs + [("pkg-three", "R092")]) == [("pkg-three", "R092")]


def test_repeat_alerts_are_counted_not_forgotten(data_dir):
    record_alerts([("pkg", "R090")])
    record_alerts([("pkg", "R090")])
    record_alerts([("pkg", "R090")])
    row = alert_history("pkg")[0]
    assert row["count"] == 3
    assert row["first_seen"] <= row["last_sent"]


def test_alerts_are_per_rule(data_dir):
    """The same package hitting a *different* rule is a new alert."""
    record_alerts([("pkg", "R090")])
    assert record_alerts([("pkg", "R126")]) == [("pkg", "R126")]


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
    monkeypatch.setattr(pipeline, "fetch_metadata", lambda *a, **k: state["meta"])
    monkeypatch.setattr(
        pipeline, "fetch_pkgbuild_with_tree",
        lambda base: ("pkgname=%s\npkgver=1.0\n" % base, None),
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
    first = run_baseline_build()
    assert first.bootstrap
    assert first.cluster_findings == []

    fake_aur["meta"] = {
        "pkg": _entry("pkg", "mallory", 1_800_000_100, version="2.0"),
        "other": _entry("other", "alice", 1_800_000_000),
    }
    second = run_baseline_build()
    fired = {f["rule_id"] for f in second.cluster_findings}
    assert {"R090", "R071"} <= fired
    assert ("pkg", "R071") in second.new_alerts

    third = run_baseline_build()
    assert third.new_alerts == []
