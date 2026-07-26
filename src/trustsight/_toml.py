try:
    import tomllib  # Python >=3.11
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]  # noqa: F401  # Python 3.10
