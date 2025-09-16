from __future__ import annotations

import importlib
import os
import tempfile
from typing import Generator

import pytest
from fastapi.testclient import TestClient

import app.db as db_module
import app.main as main_module
import app.models as models_module


@pytest.fixture(autouse=True)
def _isolate_db(tmp_path, monkeypatch):
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    url = f"sqlite:///{db_path}"
    monkeypatch.setenv("DATABASE_URL", url)
    # Reload DB and app modules so the engine picks up the new env var
    importlib.reload(db_module)
    importlib.reload(models_module)
    importlib.reload(main_module)
    yield
    try:
        os.remove(db_path)
    except FileNotFoundError:
        pass


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    app = main_module.create_app()
    with TestClient(app) as c:
        yield c
