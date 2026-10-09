"""Web UI: auth gating, private scans, CSRF, upload limit, login throttling."""
from __future__ import annotations

import io
import json

from app.storage import models
from app.storage.report import build_report, save_report
from tests.conftest import FIXTURES

APP_INFO = json.loads((FIXTURES / "app_info.json").read_text())  # parsed manifest info from a real AndroGoat scan
from tests.conftest import csrf, login, logout, post, post_json, signup


def make_scan(owner: str, package="com.example.app") -> str:
    scan_id = models.new_scan_id()
    models.create_sample(scan_id, "app.apk", "/tmp/app.apk", uploaded_by=owner)
    models.update_sample(scan_id, package_name=package, status="completed")
    models.add_finding(scan_id, "android_checks", "High", "Application is debuggable")
    save_report(scan_id, build_report(scan_id, parsed=APP_INFO))
    return scan_id


# --- auth ----------------------------------------------------------------------

def test_pages_require_login(client):
    for path in ["/", "/dynamic", "/compare", "/trends"]:
        resp = client.get(path)
        assert resp.status_code == 302 and "/login" in resp.headers["Location"], path


def test_signup_then_index(client):
    assert signup(client).status_code == 302
    assert client.get("/").status_code == 200


def test_login_rejects_bad_password(client):
    signup(client)
    logout(client)
    assert b"Invalid username or password" in login(client, password="wrong-password").data


def test_login_next_is_not_open_redirect(client):
    signup(client)
    logout(client)
    resp = login(client, next="//evil.example.com")
    assert resp.headers["Location"] in ("/", "http://localhost/")


def test_upload_rejects_non_apk(logged_in):
    resp = post(logged_in, "/upload", {"apk": (io.BytesIO(b"x"), "notes.txt")}, follow_redirects=True)
    assert b"Only .apk files are accepted" in resp.data


def test_dynamic_controls_need_an_active_session(logged_in):
    scan_id = make_scan("alice")
    assert logged_in.get(f"/dynamic/live/{scan_id}").status_code == 404
    assert post_json(logged_in, f"/dynamic/tap/{scan_id}", {"x": 1, "y": 1}).status_code == 404


# --- private scans -------------------------------------------------------------

def test_scans_are_private_to_their_uploader(client):
    signup(client, "alice")
    mine = make_scan("alice", package="com.alice.app")
    theirs = make_scan("bob", package="com.bob.app")
    finding_id = models.get_findings(theirs)[0]["id"]

    home = client.get("/").get_data(as_text=True)
    assert "com.alice.app" in home and "com.bob.app" not in home
    assert client.get(f"/report/{mine}").status_code == 200

    for path in [f"/report/{theirs}", f"/report/{theirs}/pdf", f"/reports/{theirs}.html",
                 f"/dynamic/session/{theirs}", f"/dynamic/poll/{theirs}", f"/dynamic/live/{theirs}",
                 f"/compare/result?scan_a={mine}&scan_b={theirs}",
                 f"/compare/matrix/result?scan_ids={mine}&scan_ids={theirs}"]:
        assert client.get(path).status_code == 404, path

    assert post(client, f"/finding/{finding_id}/triage", {"status": "dismissed"}).status_code == 404
    assert models.get_finding(finding_id)["triage_status"] == "open"
    assert post_json(client, f"/dynamic/tap/{theirs}", {"x": 1, "y": 1}).status_code == 404
    assert post(client, "/dynamic/start", {"scan_id": theirs, "serial": "emulator-5554"}).status_code == 404

    assert "com.bob.app" not in client.get("/trends").get_data(as_text=True)
    assert "com.bob.app" not in client.get("/compare").get_data(as_text=True)


# --- CSRF ------------------------------------------------------------------------

def test_post_without_csrf_token_is_rejected(client):
    signup(client)
    scan_id = make_scan("alice")
    finding_id = models.get_findings(scan_id)[0]["id"]
    assert client.post(f"/finding/{finding_id}/triage", data={"status": "dismissed"}).status_code == 400
    assert client.post(f"/finding/{finding_id}/triage",
                       data={"status": "dismissed", "csrf_token": "forged"}).status_code == 400
    assert client.post(f"/dynamic/tap/{scan_id}", json={"x": 1, "y": 1}).status_code == 400
    assert client.post("/logout").status_code == 400
    assert models.get_finding(finding_id)["triage_status"] == "open"


def test_post_with_csrf_token_is_accepted(client):
    signup(client)
    scan_id = make_scan("alice")
    finding_id = models.get_findings(scan_id)[0]["id"]
    assert post(client, f"/finding/{finding_id}/triage", {"status": "reviewed"}).status_code == 302
    assert models.get_finding(finding_id)["triage_status"] == "reviewed"


def test_api_is_exempt_from_csrf(client):
    # API clients authenticate with an API key header, not a cookie, so the
    # API's own validation (missing file) answers — not the CSRF check.
    resp = client.post("/api/scan")
    assert b"CSRF" not in resp.data


# --- upload limit -------------------------------------------------------------------

def test_oversized_upload_is_rejected(app, client):
    signup(client)
    app.config["MAX_CONTENT_LENGTH"] = 1024
    resp = post(client, "/upload", {"apk": (io.BytesIO(b"x" * 4096), "big.apk")}, follow_redirects=True)
    assert b"File too large" in resp.data


# --- login throttling ----------------------------------------------------------------

def test_login_is_throttled_after_repeated_failures(client):
    signup(client)
    logout(client)
    for _ in range(5):
        assert login(client, password="wrong-password").status_code == 200
    blocked = login(client)  # even the right password is refused while blocked
    assert blocked.status_code == 429 and b"Too many failed login attempts" in blocked.data


def test_successful_login_resets_failures(client):
    signup(client)
    logout(client)
    for _ in range(4):
        login(client, password="wrong-password")
    assert login(client).status_code == 302
    logout(client)
    for _ in range(4):
        login(client, password="wrong-password")
    assert login(client).status_code == 302
