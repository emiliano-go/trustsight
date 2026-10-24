"""Input validation, bounds and public exceptions for :mod:`trustsight.api`."""

from __future__ import annotations
from typing import Sequence

__all__ = ['FLAG_THRESHOLD', 'MAX_API_HISTORY', 'MAX_API_NAME_BYTES', 'MAX_API_PACKAGES', 'MAX_API_REPOS', 'MAX_API_TEXT_BYTES', 'PackageNotFound', 'RISK_LEVELS', 'TrustSightError', '_validate_limit', '_validate_name', '_validate_names', '_validate_nonnegative', '_validate_text']

RISK_LEVELS = ("Low", "Medium", "High", "Critical")

FLAG_THRESHOLD = 20

MAX_API_PACKAGES = 10_000

MAX_API_HISTORY = 10_000

MAX_API_REPOS = 256

MAX_API_TEXT_BYTES = 5 * 1024 * 1024

MAX_API_NAME_BYTES = 256

class TrustSightError(Exception):
    """Base class for every error this module raises deliberately."""

def _validate_limit(value: int, *, name: str, maximum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if value < 0 or value > maximum:
        raise ValueError(f"{name} must be between 0 and {maximum}")

def _validate_nonnegative(value: int, *, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")

def _validate_text(value: str, *, name: str, maximum: int = MAX_API_TEXT_BYTES) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    if len(value.encode("utf-8")) > maximum:
        raise ValueError(f"{name} must be at most {maximum} UTF-8 bytes")

def _validate_name(value: str, *, name: str = "package") -> None:
    _validate_text(value, name=name, maximum=MAX_API_NAME_BYTES)
    if not value:
        raise ValueError(f"{name} must not be empty")

def _validate_names(value: Sequence[str], *, name: str, maximum: int) -> None:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{name} must be a sequence of strings")
    if len(value) > maximum:
        raise ValueError(f"{name} must contain at most {maximum} names")
    item_name = name[:-1] if name.endswith("s") else name
    for item in value:
        _validate_name(item, name=f"{item_name} name")

class PackageNotFound(TrustSightError):
    """The package is neither in the AUR nor in the local database."""

    def __init__(self, package: str):
        super().__init__(f"Package {package!r} not found in the AUR.")
        self.package = package
