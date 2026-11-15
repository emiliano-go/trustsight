"""The containment status reflects the files the process actually has."""

from __future__ import annotations

from trustsight.containment import status


def _files(tmp_path, *, seccomp="2", apparmor="trustsight-watcher (enforce)",
           default_route=True, root="ro"):
    status = tmp_path / "status"
    status.write_text(f"Name:\tpython\nSeccomp:\t{seccomp}\n")
    attr = tmp_path / "attr"
    attr.write_text(apparmor + "\n")
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
        + ("eth0\t00000000\t0100007F\t0003\t0\t0\t0\t00000000\n"
           if default_route else ""))
    route6 = tmp_path / "route6"
    route6.write_text("")
    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        f"1 0 0:1 / / {root},relatime - overlay overlay rw\n")
    return {
        "status_path": str(status),
        "attr_path": str(attr),
        "route_path": str(route),
        "route6_path": str(route6),
        "mountinfo_path": str(mountinfo),
        "euid": 1000,
    }


def test_all_controls_are_reported(tmp_path):
    value = status(**_files(tmp_path))
    assert value == {
        "uid": 1000,
        "root_readonly": True,
        "seccomp_filter": True,
        "apparmor_profile": "trustsight-watcher",
        "default_route": True,
    }


def test_missing_controls_are_false(tmp_path):
    value = status(**_files(
        tmp_path, seccomp="0", apparmor="unconfined",
        default_route=False, root="rw"))
    assert value["seccomp_filter"] is False
    assert value["apparmor_profile"] == "unconfined"
    assert value["default_route"] is False
    assert value["root_readonly"] is False


def test_a_loopback_default_route_is_not_a_default_route(tmp_path):
    files = _files(tmp_path, default_route=False)
    files["route6_path"] = str(tmp_path / "route6")
    (tmp_path / "route6").write_text(
        "0" * 32 + " 00 " + "0" * 32 + " 00 " + "0" * 32
        + " ffffffff 00000001 00000000 00200200       lo\n")
    assert status(**files)["default_route"] is False
