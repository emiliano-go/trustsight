"""The dependency-walk summary the all-scan feed documents carry."""

from dataclasses import dataclass

from trustsight.full_aur._baseline_build import (
    _dependency_analysis,
    _scan_records,
)


@dataclass
class _Report:
    name: str
    depth: int
    score: int = 0
    risk: str = ""
    finding_count: int = 0
    via: str = ""
    parent: str = ""
    failed: bool = False

    @property
    def flagged(self) -> bool:
        return self.score > 20


@dataclass
class _Fact:
    depth: int = -1
    dependencies: tuple = ()
    depth_truncated: bool = False
    depth_note: str = ""


def test_summary_names_what_was_examined_and_what_flagged():
    fact = _Fact(
        dependencies=(
            _Report("direct", 1, score=55, risk="High", finding_count=2,
                    via="depends", parent="root"),
            _Report("deep", 2, via="depends", parent="direct"),
        ),
    )
    summary = _dependency_analysis(fact)
    assert summary["requested_depth"] == -1
    assert summary["examined"] == 2
    assert summary["maximum_depth_reached"] == 2
    assert summary["flagged_count"] == 1
    assert summary["flagged"][0]["name"] == "direct"
    assert summary["failed_count"] == 0


def test_summary_is_absent_when_the_walk_was_off():
    assert _dependency_analysis(_Fact(depth=0)) is None


def test_a_failed_dependency_is_named_separately_from_a_flagged_one():
    fact = _Fact(dependencies=(
        _Report("broken", 1, failed=True),
    ))
    summary = _dependency_analysis(fact)
    assert summary["flagged"] == []
    assert [row["name"] for row in summary["failed"]] == ["broken"]
    assert summary["failed_count"] == 1


def test_scan_record_carries_the_summary():
    summary = _dependency_analysis(_Fact(
        dependencies=(_Report("direct", 1, score=45, risk="High"),),
    ))
    records = _scan_records(
        {"pkg": {"score": 0, "dependency_analysis": summary}},
        {"pkg": "ok"},
    )
    assert records[0]["dependency_analysis"]["flagged"][0]["name"] == "direct"
