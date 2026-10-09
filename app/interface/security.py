"""Web hardening: CSRF tokens, upload size limit, and login throttling.

Kept dependency-free (no Flask-WTF/Flask-Limiter) so the tool stays a plain
`pip install -r requirements.txt` away from running.
"""
from __future__ import annotations

import os
import secrets
import threading
import time
from collections import defaultdict, deque

from flask import Flask, abort, flash, jsonify, redirect, request, session, url_for

CSRF_SESSION_KEY = "_csrf_token"
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"

# The REST API authenticates with an API key header, not a browser cookie, so
# it can't be driven cross-site and is exempt from CSRF.
CSRF_EXEMPT_BLUEPRINTS = {"api"}

DEFAULT_MAX_UPLOAD_MB = 200


def csrf_token() -> str:
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def _check_csrf() -> None:
    if request.method in ("GET", "HEAD", "OPTIONS") or request.blueprint in CSRF_EXEMPT_BLUEPRINTS:
        return
    expected = session.get(CSRF_SESSION_KEY, "")
    sent = request.form.get(CSRF_FORM_FIELD) or request.headers.get(CSRF_HEADER, "")
    if not expected or not secrets.compare_digest(expected, sent):
        abort(400, description="Missing or invalid CSRF token — reload the page and try again.")


class LoginThrottle:
    """Blocks a client after too many failed logins in a sliding window.

    Tracked per (client IP, username) so one attacker can't lock a user out
    from everywhere, plus per IP so they can't sweep many usernames.
    In-memory: resets on restart, which is fine for a single-process tool.
    """

    def __init__(self, max_per_user: int = 5, max_per_ip: int = 20, window_seconds: int = 15 * 60):
        self.max_per_user = max_per_user
        self.max_per_ip = max_per_ip
        self.window = window_seconds
        self._failures: dict[tuple, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _recent(self, key: tuple, now: float) -> deque:
        q = self._failures[key]
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def retry_after(self, ip: str, username: str) -> int:
        """Seconds until this client may try again (0 = allowed now)."""
        now = time.time()
        with self._lock:
            waits = []
            for key, limit in (((ip, username.lower()), self.max_per_user), ((ip,), self.max_per_ip)):
                q = self._recent(key, now)
                if len(q) >= limit:
                    waits.append(int(self.window - (now - q[0])) + 1)
            return max(waits, default=0)

    def record_failure(self, ip: str, username: str) -> None:
        now = time.time()
        with self._lock:
            self._failures[(ip, username.lower())].append(now)
            self._failures[(ip,)].append(now)

    def record_success(self, ip: str, username: str) -> None:
        with self._lock:
            self._failures.pop((ip, username.lower()), None)


login_throttle = LoginThrottle()


def init_security(app: Flask) -> None:
    max_mb = int(os.environ.get("ANALYZER_MAX_UPLOAD_MB", DEFAULT_MAX_UPLOAD_MB))
    app.config.update(
        MAX_CONTENT_LENGTH=max_mb * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    app.before_request(_check_csrf)
    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.errorhandler(413)
    def too_large(_err):
        message = f"File too large — the upload limit is {max_mb} MB (set ANALYZER_MAX_UPLOAD_MB to change it)."
        if request.blueprint == "api":
            return jsonify({"error": message}), 413
        flash(message)
        return redirect(url_for("scanning.index"))
