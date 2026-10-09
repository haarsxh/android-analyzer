"""Shared fixtures. Every test run uses a throwaway SQLite database — the
environment variable is set before any app module is imported, since
models.DB_PATH is read at import time."""
from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

import pytest

_TMP = tempfile.mkdtemp(prefix="analyzer-tests-")
os.environ["ANALYZER_DB_PATH"] = str(Path(_TMP) / "test.db")

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def db(tmp_path, monkeypatch):
    """A fresh, empty database per test."""
    from app.storage import models
    monkeypatch.setattr(models, "DB_PATH", tmp_path / "analyzer.db")
    models.init_db()
    return models


@pytest.fixture()
def app(db):
    from app.interface.security import login_throttle
    login_throttle._failures.clear()
    from app.main import create_app
    flask_app = create_app()
    flask_app.config.update(TESTING=True)
    return flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf(client, page="/login") -> str:
    """The CSRF token for this client's session, read the way a browser would
    (from the hidden form field on a page)."""
    html = client.get(page).get_data(as_text=True)
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, f"no CSRF token on {page}"
    return m.group(1)


def post(client, path, data=None, **kw):
    """Form POST with a valid CSRF token."""
    return client.post(path, data={**(data or {}), "csrf_token": csrf(client)}, **kw)


def post_json(client, path, body):
    return client.post(path, json=body, headers={"X-CSRF-Token": csrf(client)})


def signup(client, username="alice", password="correct-horse-1"):
    return post(client, "/signup", {"username": username, "password": password, "confirm": password})


def logout(client):
    return post(client, "/logout")


def login(client, username="alice", password="correct-horse-1", **extra):
    return post(client, "/login", {"username": username, "password": password, **extra})


@pytest.fixture()
def logged_in(client):
    signup(client)
    return client
