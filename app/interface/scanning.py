"""Web Entry: browser upload/scan/report routes for the Security Researcher persona."""
from __future__ import annotations

from pathlib import Path

from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, send_file, abort, session
from werkzeug.utils import secure_filename

from app.interface.authorization import login_required
from app.static_analysis.static_analyzer import run_static_analysis
from app.static_analysis.permission_info import describe_permissions
from app.dynamic_analysis import android_runtime
from app.storage import models
from app.storage import jobs
from app.storage.report import build_report, save_report, save_report_pdf, diff_reports, build_trend, build_matrix


def _on_scan_error(scan_id: str, exc: Exception) -> None:
    models.update_sample(scan_id, status="error", error_message=str(exc))


def _current_user() -> str:
    return session.get("username", "anonymous")


bp = Blueprint("scanning", __name__)

UPLOAD_ROOT = Path(__file__).resolve().parent.parent.parent / "uploads"
ALLOWED_EXTENSIONS = {".apk"}


@bp.route("/", methods=["GET"])
@login_required
def index():
    mine_only = request.args.get("mine") == "1"
    samples = models.list_samples_by_user(_current_user()) if mine_only else models.list_samples()
    return render_template("index.html", samples=samples, mine_only=mine_only, current_user=_current_user())


@bp.route("/upload", methods=["POST"])
@login_required
def upload():
    file = request.files.get("apk")
    if not file or file.filename == "":
        flash("No file selected.")
        return redirect(url_for("scanning.index"))

    filename = secure_filename(file.filename)
    if Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        flash("Only .apk files are accepted.")
        return redirect(url_for("scanning.index"))

    UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    scan_id = models.new_scan_id()
    dest = UPLOAD_ROOT / f"{scan_id}_{filename}"
    file.save(dest)

    models.create_sample(scan_id, filename, str(dest), uploaded_by=_current_user())
    jobs.submit_scan(scan_id, str(dest), run_static_analysis, build_report, save_report, _on_scan_error)

    return redirect(url_for("scanning.view_report", scan_id=scan_id))


@bp.route("/report/<scan_id>", methods=["GET"])
@login_required
def view_report(scan_id: str):
    sample = models.get_sample(scan_id)
    if not sample:
        flash("Scan not found.")
        return redirect(url_for("scanning.index"))

    stored = models.get_report(scan_id)
    findings = models.get_findings(scan_id)

    app_info = None
    summary = None
    if stored:
        import json
        stored_report = json.loads(stored["report_json"])
        app_info = stored_report.get("app")
        summary = stored_report.get("summary")

    geo_locations = [
        f["metadata"] for f in findings
        if f["source"] == "geolocation" and f.get("metadata", {}).get("country_code")
    ]

    permission_details = []
    if app_info:
        permission_details = describe_permissions(
            app_info.get("permissions", []), app_info.get("dangerous_permissions", [])
        )

    return render_template(
        "report.html", sample=sample, findings=findings, stored=stored, scan_id=scan_id,
        app=app_info, summary=summary, geo_locations=geo_locations, permission_details=permission_details,
    )


@bp.route("/reports/<scan_id>.html", methods=["GET"])
@login_required
def standalone_report(scan_id: str):
    sample = models.get_sample(scan_id)
    if not sample:
        abort(404)
    from app.storage.report import REPORTS_ROOT
    path = REPORTS_ROOT / f"{scan_id}.html"
    if not path.exists():
        abort(404)
    return send_file(path)


@bp.route("/trends", methods=["GET"])
@login_required
def trends_page():
    packages = models.list_distinct_packages()
    return render_template("trends.html", packages=packages)


@bp.route("/trend/<package_name>", methods=["GET"])
@login_required
def trend_view(package_name: str):
    trend = build_trend(package_name)
    return render_template("trend.html", trend=trend)


@bp.route("/finding/<int:finding_id>/triage", methods=["POST"])
@login_required
def triage_finding(finding_id: int):
    finding = models.get_finding(finding_id)
    if not finding:
        abort(404)

    status = request.form.get("status", "open")
    if status not in ("open", "reviewed", "dismissed"):
        flash("Invalid triage status.")
        return redirect(url_for("scanning.view_report", scan_id=finding["scan_id"]))

    models.set_finding_triage(finding_id, status, request.form.get("note", ""))

    # Keep the persisted report (and its risk score) in sync with the new triage state.
    stored = models.get_report(finding["scan_id"])
    parsed_app = None
    if stored:
        import json
        parsed_app = json.loads(stored["report_json"]).get("app")
    report = build_report(finding["scan_id"], parsed=parsed_app)
    save_report(finding["scan_id"], report)

    return redirect(url_for("scanning.view_report", scan_id=finding["scan_id"]))


@bp.route("/report/<scan_id>/pdf", methods=["GET"])
@login_required
def download_pdf(scan_id: str):
    sample = models.get_sample(scan_id)
    if not sample:
        abort(404)

    from app.storage.report import REPORTS_ROOT
    pdf_path = REPORTS_ROOT / f"{scan_id}.pdf"
    if not pdf_path.exists():
        report = build_report(scan_id)
        pdf_path = save_report_pdf(scan_id, report)

    return send_file(pdf_path, as_attachment=True, download_name=f"{sample['filename']}_report.pdf")


@bp.route("/compare", methods=["GET"])
@login_required
def compare_page():
    samples = models.list_samples()
    return render_template("compare.html", samples=samples)


@bp.route("/compare/result", methods=["GET"])
@login_required
def compare_result():
    scan_a = request.args.get("scan_a")
    scan_b = request.args.get("scan_b")
    if not scan_a or not scan_b:
        flash("Select two scans to compare.")
        return redirect(url_for("scanning.compare_page"))

    diff = diff_reports(scan_a, scan_b)
    return render_template("compare_result.html", diff=diff)


@bp.route("/compare/matrix", methods=["GET"])
@login_required
def compare_matrix_page():
    samples = models.list_samples()
    return render_template("compare_matrix.html", samples=samples)


@bp.route("/compare/matrix/result", methods=["GET"])
@login_required
def compare_matrix_result():
    scan_ids = request.args.getlist("scan_ids")
    if len(scan_ids) < 2:
        flash("Select at least two scans to compare.")
        return redirect(url_for("scanning.compare_matrix_page"))

    matrix = build_matrix(scan_ids)
    return render_template("compare_matrix_result.html", matrix=matrix)


@bp.route("/dynamic", methods=["GET"])
@login_required
def dynamic_page():
    samples = models.list_samples()
    devices = android_runtime.list_devices()
    return render_template("dynamic.html", samples=samples, devices=devices)


@bp.route("/dynamic/start", methods=["POST"])
@login_required
def dynamic_start():
    scan_id = request.form["scan_id"]
    serial = request.form["serial"]
    sample = models.get_sample(scan_id)
    if not sample:
        flash("Scan not found.")
        return redirect(url_for("scanning.dynamic_page"))

    capture_traffic = request.form.get("capture_traffic") == "on"
    bypass_ssl_pinning = request.form.get("bypass_ssl_pinning") == "on"
    bypass_root_detection = request.form.get("bypass_root_detection") == "on"
    result = android_runtime.start_session(
        scan_id, serial, sample["package_name"], capture_traffic=capture_traffic,
        bypass_ssl_pinning=bypass_ssl_pinning, bypass_root_detection=bypass_root_detection,
    )
    if not result["success"]:
        flash(f"Failed to start dynamic session: {result.get('error')}")
    return redirect(url_for("scanning.dynamic_session", scan_id=scan_id))


@bp.route("/dynamic/session/<scan_id>", methods=["GET"])
@login_required
def dynamic_session(scan_id: str):
    sample = models.get_sample(scan_id)
    return render_template("dynamic_session.html", sample=sample, scan_id=scan_id)


@bp.route("/dynamic/poll/<scan_id>", methods=["GET"])
@login_required
def dynamic_poll(scan_id: str):
    from flask import jsonify
    state = android_runtime.poll_session(scan_id)
    if state is None:
        return jsonify({"status": "not_found"}), 404
    return jsonify(state)


@bp.route("/dynamic/stop/<scan_id>", methods=["POST"])
@login_required
def dynamic_stop(scan_id: str):
    android_runtime.stop_session(scan_id)
    return redirect(url_for("scanning.view_report", scan_id=scan_id))


@bp.route("/dynamic/screenshot/<scan_id>", methods=["POST"])
@login_required
def dynamic_screenshot(scan_id: str):
    from flask import jsonify
    result = android_runtime.capture_screenshot(scan_id)
    if result is None:
        return jsonify({"error": "no active session"}), 404
    return jsonify(result)


@bp.route("/dynamic/screenshots/<scan_id>/<filename>", methods=["GET"])
@login_required
def dynamic_screenshot_file(scan_id: str, filename: str):
    path = android_runtime.SCREENSHOTS_ROOT / scan_id / secure_filename(filename)
    if not path.exists():
        abort(404)
    return send_file(path)


@bp.route("/dynamic/live/<scan_id>", methods=["GET"])
@login_required
def dynamic_live(scan_id: str):
    """Near-live device screen: captures the current frame on each request
    (adb screencap takes ~1-2s, so this isn't real-time video — the frontend
    polls it on an interval to approximate a live view)."""
    from flask import Response
    from app.dynamic_analysis import device as device_mod

    serial = android_runtime.get_session_serial(scan_id)
    if not serial:
        abort(404)

    png_bytes = device_mod.screencap_bytes(serial)
    if png_bytes is None:
        abort(503)

    response = Response(png_bytes, mimetype="image/png")
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.route("/dynamic/tap/<scan_id>", methods=["POST"])
@login_required
def dynamic_tap(scan_id: str):
    from flask import jsonify
    from app.dynamic_analysis import device as device_mod

    serial = android_runtime.get_session_serial(scan_id)
    if not serial:
        return jsonify({"error": "no active session"}), 404

    body = request.get_json(silent=True) or {}
    try:
        x, y = int(body["x"]), int(body["y"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "expected integer 'x' and 'y'"}), 400

    return jsonify(device_mod.tap(serial, x, y))


@bp.route("/dynamic/swipe/<scan_id>", methods=["POST"])
@login_required
def dynamic_swipe(scan_id: str):
    from flask import jsonify
    from app.dynamic_analysis import device as device_mod

    serial = android_runtime.get_session_serial(scan_id)
    if not serial:
        return jsonify({"error": "no active session"}), 404

    body = request.get_json(silent=True) or {}
    try:
        x1, y1 = int(body["x1"]), int(body["y1"])
        x2, y2 = int(body["x2"]), int(body["y2"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "expected integer 'x1','y1','x2','y2'"}), 400

    return jsonify(device_mod.swipe(serial, x1, y1, x2, y2))


@bp.route("/dynamic/key/<scan_id>", methods=["POST"])
@login_required
def dynamic_key(scan_id: str):
    from flask import jsonify
    from app.dynamic_analysis import device as device_mod

    serial = android_runtime.get_session_serial(scan_id)
    if not serial:
        return jsonify({"error": "no active session"}), 404

    key = (request.get_json(silent=True) or {}).get("key", "")
    return jsonify(device_mod.press_key(serial, key))


@bp.route("/dynamic/text/<scan_id>", methods=["POST"])
@login_required
def dynamic_text(scan_id: str):
    from flask import jsonify
    from app.dynamic_analysis import device as device_mod

    serial = android_runtime.get_session_serial(scan_id)
    if not serial:
        return jsonify({"error": "no active session"}), 404

    text = (request.get_json(silent=True) or {}).get("text", "")
    return jsonify(device_mod.input_text(serial, text))
