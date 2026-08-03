"""Tests for Phase 5 — Class C longitudinal rules (plan §7).

Covers the STABILITY_FLOOR gating in ``stability_weight`` / the property
update step, and the ``longitudinal_findings`` consumer (R094-R098/R102/R083).
The cold-start gate is structural: the first observation only INSERTs, so a
cold database can never produce a PropertyBreak and never fires any of these.
"""

import sqlite3

from trustsight.analysis.longitudinal import longitudinal_findings
from trustsight.full_aur.properties import (
    STABILITY_FLOOR_DEFAULT,
    canonical,
    stability_weight,
    update_properties,
)

TABLE = """CREATE TABLE IF NOT EXISTS package_properties (
    package_name TEXT NOT NULL,
    property_key TEXT NOT NULL,
    value_hash TEXT NOT NULL,
    value TEXT,
    stable_for_n INTEGER DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_changed TEXT NOT NULL,
    PRIMARY KEY (package_name, property_key)
)"""


def conn():
    c = sqlite3.connect(":memory:")
    c.execute(TABLE)
    return c


def _breaks(c, pkg, observed_at, floor=STABILITY_FLOOR_DEFAULT, **props):
    return update_properties(c, pkg, props, observed_at, floor=floor)


# --- STABILITY_FLOOR gating ---


def test_stability_weight_below_floor_is_zero():
    assert stability_weight(0) == 0.0
    assert stability_weight(5, floor=10) == 0.0
    assert stability_weight(9, floor=10) == 0.0


def test_stability_weight_ramps_after_floor():
    assert stability_weight(10, floor=10) > 0.0
    assert stability_weight(40, floor=10) >= 0.9
    assert stability_weight(100, floor=10) >= 0.9  # logistic asymptote ~1.0


def test_update_properties_cold_start_emits_no_breaks():
    c = conn()
    breaks = _breaks(c, "pkg", "t0", configure_flags={"--prefix=/usr"})
    assert breaks == []
    row = c.execute(
        "SELECT stable_for_n FROM package_properties WHERE package_name='pkg'"
    ).fetchone()
    assert row[0] == 0


def test_update_properties_accumulates_then_breaks_above_floor():
    c = conn()
    obs = []
    for i in range(1, 13):
        obs = _breaks(c, "pkg", f"t{i}", configure_flags={"--prefix=/usr"})
        assert obs == []
    # 12 unchanged observations -> stable_for_n reaches floor, change now.
    breaks = _breaks(c, "pkg", "t13", configure_flags={"--prefix=/usr", "-fno-pie"})
    assert len(breaks) == 1
    assert breaks[0].key == "configure_flags"
    assert breaks[0].stable_for_n >= STABILITY_FLOOR_DEFAULT
    assert breaks[0].weight > 0.0


def test_update_properties_short_stability_never_emits():
    c = conn()
    _breaks(c, "pkg", "t1", configure_flags={"--prefix=/usr"})
    # breaks after only one held observation: below floor, weight 0, absent.
    breaks = _breaks(c, "pkg", "t2", configure_flags={})
    assert breaks == []
    # the value still reset, so a later floor-crossing needs a fresh stable run
    row = c.execute(
        "SELECT stable_for_n FROM package_properties WHERE package_name='pkg'"
    ).fetchone()
    assert row[0] == 0


def test_update_properties_is_idempotent():
    c = conn()
    _breaks(c, "pkg", "t1", pkgdesc_tokens={"a", "b"})
    _breaks(c, "pkg", "t2", pkgdesc_tokens={"a", "b"})
    row = c.execute(
        "SELECT stable_for_n FROM package_properties WHERE package_name='pkg'"
    ).fetchone()
    assert row[0] == 1
    _breaks(c, "pkg", "t3", pkgdesc_tokens={"b", "a"})  # same set, reordered
    row = c.execute(
        "SELECT stable_for_n FROM package_properties WHERE package_name='pkg'"
    ).fetchone()
    assert row[0] == 2


# --- longitudinal_findings consumer ---


def _pb(key, old, new, n=12, w=0.8):
    from types import SimpleNamespace
    return SimpleNamespace(
        key=key, old_value=canonical(old), new_value=canonical(new),
        stable_for_n=n, weight=w,
    )


def _ids(diff, breaks):
    return {f["rule_id"] for f in longitudinal_findings(diff, "pkg", breaks, {})}


def test_r094_fires_on_security_flag_change():
    b = _pb("configure_flags", {"--prefix=/usr", "-fno-pie"}, {"--prefix=/usr"})
    r = longitudinal_findings("", "pkg", [b], {})
    assert [f["rule_id"] for f in r] == ["R094"]
    assert r[0]["severity"] == "HIGH"  # hardening flag removed


def test_r094_quiet_for_non_security_flag_churn():
    b = _pb("configure_flags", {"--prefix=/usr"}, {"--prefix=/opt"})
    assert _ids("", [b]) == set()


def test_r095_vendors_matching_source():
    b = _pb("depends", {"openssl", "zlib"}, {"zlib"})
    diff = "+source=('https://x/openssl-3.1.0.tar.gz')\n"
    assert "R095" in _ids(diff, [b])


def test_r095_quiet_when_source_name_does_not_match():
    b = _pb("depends", {"openssl", "zlib"}, {"zlib"})
    diff = "+source=('https://x/libre-ssl-wrapper-2.0.tar.gz')\n"
    assert _ids(diff, [b]) == set()


def test_r095_quiet_without_diff_source():
    b = _pb("depends", {"openssl"}, set())
    assert _ids("+pkgrel=2\n", [b]) == set()


def test_r096_source_host_change():
    b = _pb("source_hosts", {"github.com"}, {"evil.example"})
    assert "R096" in _ids("", [b])


def test_r097_version_scheme_is_context():
    b = _pb("version_scheme", "semver", "hash")
    r = longitudinal_findings("", "pkg", [b], {})
    assert [f["rule_id"] for f in r] == ["R097"]
    assert r[0]["severity"] == "INFO"


def test_r098_pkgdesc_change():
    b = _pb("pkgdesc_tokens", {"nice", "tool"}, {"malicious", "tool"})
    assert "R098" in _ids("", [b])


def test_r102_build_system_change():
    b = _pb("build_system_markers", {"make"}, {"cmake"})
    assert "R102" in _ids("", [b])


def test_r083_residue_property_change():
    b = _pb("license", {"MIT"}, {"custom"})
    assert "R083" in _ids("", [b])
    b2 = _pb("install_hook_present", False, True)
    assert "R083" in _ids("", [b2])


def test_subfloor_break_is_never_consumed():
    b = _pb("pkgdesc_tokens", {"a"}, {"b"}, n=5, w=0.0)
    assert _ids("", [b]) == set()


def test_unknown_property_key_is_quiet():
    b = _pb("mystery_prop", {"x"}, {"y"})
    assert _ids("", [b]) == set()
