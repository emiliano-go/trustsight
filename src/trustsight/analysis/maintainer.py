import re

from ..db import effective_observation_count, is_maintainer_globally_novel
from ..findings import stamp


_EMAIL_RE = re.compile(r"<([^<>]+)>")


def maintainer_identity(value: str) -> str:
    """The account behind a maintainer string.

    AUR maintainer fields are display name plus optional email.  The same
    account can change its display name (`Aleksandar` -> `Aleksandar Zarić`)
    without any takeover; the email is the identity when present.  With no
    email, a whitespace-folded lower-case name is the best available key.
    """
    text = str(value or "").strip()
    match = _EMAIL_RE.search(text)
    if match:
        email = match.group(1).strip().lower()
        if email:
            return f"email:{email}"
    return "name:" + " ".join(text.split()).lower()


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
        "rule_id": "H026",
        "name": "New Maintainer Without Prior History",
        "severity": "HIGH", "category": "maintainer",
        "match": f"maintainer changed to '{new_maintainer}', "
                f"who has never been seen in the AUR",
        "params": {"new": new_maintainer},
    })
