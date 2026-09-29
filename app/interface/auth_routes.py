"""Auth: signup/login/logout for the web UI (session-based, separate from the API key)."""
from __future__ import annotations

import sqlite3

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

from app.storage import models

bp = Blueprint("auth", __name__)

MIN_PASSWORD_LENGTH = 8


def _safe_next(path: str) -> str:
    """Only allow same-site relative redirects (never an absolute/external URL)."""
    if path and path.startswith("/") and not path.startswith("//"):
        return path
    return url_for("scanning.index")


@bp.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm", "")

    if not username or not password:
        flash("Username and password are required.")
        return render_template("signup.html", username=username)
    if len(password) < MIN_PASSWORD_LENGTH:
        flash(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        return render_template("signup.html", username=username)
    if password != confirm:
        flash("Passwords do not match.")
        return render_template("signup.html", username=username)

    try:
        user_id = models.create_user(username, generate_password_hash(password))
    except sqlite3.IntegrityError:
        flash("That username is already taken.")
        return render_template("signup.html", username=username)

    session["user_id"] = user_id
    session["username"] = username
    flash("Account created.")
    return redirect(url_for("scanning.index"))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", next=request.args.get("next", ""))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    next_path = _safe_next(request.form.get("next", ""))

    user = models.get_user_by_username(username)
    if not user or not check_password_hash(user["password_hash"], password):
        flash("Invalid username or password.")
        return render_template("login.html", username=username, next=next_path)

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return redirect(next_path)


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("auth.login"))
