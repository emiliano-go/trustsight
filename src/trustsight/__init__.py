"""TrustSight: CLI-based AUR package update vetting tool."""

# importlib.metadata costs ~46ms to import and its answer is only needed by
# `--version`, so it is resolved on first access instead of at import time.
# PEP 562 module __getattr__ keeps `from trustsight import __version__`
# working unchanged for callers.


def __getattr__(name: str) -> str:
    if name == "__version__":
        import importlib.metadata

        try:
            version = importlib.metadata.version("trustsight")
        except importlib.metadata.PackageNotFoundError:
            version = "0.0.0"
        globals()["__version__"] = version
        return version
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
