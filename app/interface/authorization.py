"""Authorization: simple API-key check shared by the Web Entry and API Entry."""
from __future__ import annotations

import os
import secrets
from functools import wraps

from flask import request, jsonify, session, redirect, url_for, flash

API_KEY = os.environ.get("ANALYZER_API_KEY", "")


def is_authorized_request() -> bool:
    """Web sessions (logged in via the login page) and API requests with a
    matching X-API-Key / Bearer token are both authorized.

    If ANALYZER_API_KEY is unset, the app runs open (local/dev mode) so the
    tool works out of the box without extra setup.
    """
    if not API_KEY:
        return True

    if session.get("authorized"):
        return True

    header_key = request.headers.get("X-API-Key", "")
    auth_header = request.headers.get("Authorization", "")
    bearer_key = auth_header[7:] if auth_header.startswith("Bearer ") else ""

    return secrets.compare_digest(header_key, API_KEY) or secrets.compare_digest(bearer_key, API_KEY)


def require_auth(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not is_authorized_request():
            return jsonify({"error": "unauthorized"}), 401
        return view(*args, **kwargs)
    return wrapped


def login_required(view):
    """Gate a browser page behind a real logged-in user (session['user_id']).

    Separate from require_auth: the REST API stays reachable with just an
    API key for CI clients, while the web UI itself now requires an account.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.")
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)
    return wrapped
