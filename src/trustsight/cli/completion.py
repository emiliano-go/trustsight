"""Shell completion for package-name arguments."""

from .. import db, discovery


def _matching(names, incomplete: str) -> list[str]:
    return sorted({name for name in names if name.startswith(incomplete)})


def tracked_packages(incomplete: str) -> list[str]:
    try:
        return _matching((row["name"] for row in db.get_all_packages()), incomplete)
    except Exception:  # noqa: BLE001 - completion must never break the shell
        return []


def installed_packages(incomplete: str) -> list[str]:
    try:
        installed = [name for name, _version in discovery.get_installed_foreign()]
    except Exception:  # noqa: BLE001 - completion must never break the shell
        installed = []
    return _matching(installed + tracked_packages(incomplete), incomplete)
