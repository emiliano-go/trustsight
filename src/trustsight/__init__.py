"""TrustSight: AUR package update vetting.

The supported programmatic surface is :mod:`trustsight.api`, re-exported
here for convenience::

    from trustsight import TrustSight

    report = TrustSight().inspect("some-package")

Everything else under ``trustsight.`` is internal and changes shape between
releases without notice.
"""

# Names resolved on first access rather than at import time.  importlib.
# metadata costs ~46ms and is only needed by `--version`; `api` pulls in the
# analysis stack, which a caller that only wanted `__version__` should not
# pay for.  PEP 562 module __getattr__ keeps every spelling below working
# unchanged for callers.

_API_NAMES = frozenset({
    "TrustSight",
    "Report",
    "Finding",
    "FileChange",
    "SuppressedRule",
    "ReviewResult",
    "FailedPackage",
    "HistoryEntry",
    "TrackedPackage",
    "Status",
    "CycleReport",
    "ClusterFinding",
    "PivotResult",
    "PivotMatch",
    "Progress",
    "TrustSightError",
    "PackageNotFound",
    "FLAG_THRESHOLD",
    "RISK_LEVELS",
    "COVERAGE_GAP_REASONS",
})

__all__ = ["__version__", "api", *sorted(_API_NAMES)]


def __getattr__(name: str):
    if name == "__version__":
        import importlib.metadata

        try:
            version = importlib.metadata.version("trustsight")
        except importlib.metadata.PackageNotFoundError:
            version = "0.0.0"
        globals()["__version__"] = version
        return version
    if name == "api" or name in _API_NAMES:
        # importlib rather than `from . import api`: the fromlist machinery
        # probes the package with getattr first, which lands back here and
        # recurses until the stack runs out.
        import importlib

        api = importlib.import_module(".api", __name__)
        globals()["api"] = api
        if name == "api":
            return api
        value = getattr(api, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(__all__)
