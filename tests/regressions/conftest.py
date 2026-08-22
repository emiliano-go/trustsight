import pytest


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Config and database in a scratch directory."""
    import trustsight.config as config
    import trustsight.db as db

    monkeypatch.setattr(config, "CONFIG_DIR", tmp_path / "config")
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(config, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(db, "DATA_DIR", tmp_path / "data")
    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    db.init_db()
    return tmp_path
