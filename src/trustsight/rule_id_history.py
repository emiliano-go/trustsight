"""Rule ids this build has renamed, and what they were called before.

The ``R`` prefix used to mean "a detection rule" and nothing more: some
``R`` ids were regex rules read from ``rules.toml`` and some were emitted
from code, with no way to tell which from the id.  The split makes the
prefix carry the mechanism - ``R`` is a regex rule, ``H`` is a heuristic
emitted by an analysis module - so every ``R`` id is now something an
operator can find, read and edit in ``rules.toml``.

The mapping is frozen.  It was derived once, before the rename, as the
catalog minus the shipped rule set (``scripts/rule_id_mapping.py``), and it
is committed rather than re-derived because after the rename the derivation
returns nothing: the catalog holds the new ids.  Databases, baselines and
fixture expectations name the old ids, so a second, different mapping would
silently renumber rules that existing artifacts already refer to.
"""

from __future__ import annotations

__all__ = ["RENAMED_RULE_IDS", "current_id"]

#: Old id -> new id, for the 95 heuristic rules renamed in this release.
RENAMED_RULE_IDS: dict[str, str] = {
    "R004": "H001",  "R005": "H002",  "R006": "H003",  "R009": "H004",
    "R014": "H005",  "R016": "H006",  "R018": "H007",  "R019": "H008",
    "R020": "H009",  "R021": "H010",  "R022": "H011",  "R023": "H012",
    "R024": "H013",  "R025": "H014",  "R060": "H015",  "R061": "H016",
    "R062": "H017",  "R063": "H018",  "R064": "H019",  "R065": "H020",
    "R066": "H021",  "R067": "H022",  "R068": "H023",  "R069": "H024",
    "R070": "H025",  "R071": "H026",  "R072": "H027",  "R073": "H028",
    "R074": "H029",  "R075": "H030",  "R076": "H031",  "R077": "H032",
    "R079": "H033",  "R080": "H034",  "R081": "H035",  "R082": "H036",
    "R083": "H037",  "R084": "H038",  "R085": "H039",  "R086": "H040",
    "R087": "H041",  "R088": "H042",  "R089": "H043",  "R090": "H044",
    "R092": "H045",  "R093": "H046",  "R094": "H047",  "R095": "H048",
    "R096": "H049",  "R097": "H050",  "R098": "H051",  "R100": "H052",
    "R101": "H053",  "R102": "H054",  "R105": "H055",  "R106": "H056",
    "R107": "H057",  "R108": "H058",  "R110": "H059",  "R111": "H060",
    "R112": "H061",  "R114": "H062",  "R115": "H063",  "R116": "H064",
    "R117": "H065",  "R118": "H066",  "R119": "H067",  "R120": "H068",
    "R121": "H069",  "R122": "H070",  "R123": "H071",  "R124": "H072",
    "R125": "H073",  "R126": "H074",  "R127": "H075",  "R128": "H076",
    "R129": "H077",  "R130": "H078",  "R131": "H079",  "R132": "H080",
    "R136": "H081",  "R137": "H082",  "R138": "H083",  "R139": "H084",
    "R140": "H085",  "R141": "H086",  "R142": "H087",  "R143": "H088",
    "R145": "H089",  "R146": "H090",  "R147": "H091",  "R148": "H092",
    "R149": "H093",  "R150": "H094",  "R151": "H095",
}


def current_id(rule_id: str) -> str:
    """*rule_id* under the current naming, unchanged if it was never renamed.

    Reading path only.  Stored rows are rewritten once by the database
    migration; this exists for artifacts that are read but never rewritten,
    such as a baseline published before the rename.
    """
    return RENAMED_RULE_IDS.get(rule_id, rule_id)
