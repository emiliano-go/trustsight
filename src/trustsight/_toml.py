try:
    import tomllib  # Python >=3.11
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]  # Python 3.10
