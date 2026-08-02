from ..db import effective_observation_count, is_maintainer_globally_novel
from ..findings import stamp


def _check_untrusted_maintainer_takeover(
    maintainer_changed: bool,
    new_maintainer: str,
) -> dict | None:
    if not (maintainer_changed and new_maintainer):
        return None
    if effective_observation_count() <= 0:
        return None
    if not is_maintainer_globally_novel(new_maintainer):
        return None
    return stamp({
        "rule_id": "R071",
        "name": "Untrusted Maintainer Takeover",
        "severity": "HIGH", "category": "maintainer",
        "match": f"maintainer changed to '{new_maintainer}', "
                f"who has never been seen in the AUR",
        "params": {"new": new_maintainer},
    })
