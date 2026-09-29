"""API Entry: REST endpoints for CI/automated clients."""
from __future__ import annotations

from pathlib import Path

from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename

from app.interface.authorization import require_auth
from app.static_analysis.static_analyzer import run_static_analysis
from app.dynamic_analysis import android_runtime
from app.storage import models
from app.storage import jobs
from app.storage.report import build_report, save_report, save_report_pdf, diff_reports, build_trend, build_matrix


def _on_scan_error(scan_id: str, exc: Exception) -> None:
    models.update_sample(scan_id, status="error", error_message=str(exc))

bp = Blueprint("api", __name__, url_prefix="/api")

UPLOAD_ROOT = Path(__file__).resolve().parent.parent.parent / "uploads"
ALLOWED_EXTENSIONS = {".apk"}


@bp.route("/scan", methods=["POST"])
@require_auth
def scan():
    file = request.files.get("apk")
    if not file or file.filename == "":
        return jsonify({"error": "missing 'apk' file field"}), 400

    filename = secure_filename(file.filename)
    if Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "only .apk files are accepted"}), 400

    UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)
    scan_id = models.new_scan_id()
    dest = UPLOAD_ROOT / f"{scan_id}_{filename}"
    file.save(dest)

    webhook_url = request.form.get("webhook_url")
    if webhook_url and not webhook_url.startswith(("http://", "https://")):
        return jsonify({"error": "webhook_url must be http(s)"}), 400

    uploaded_by = request.form.get("uploaded_by", "api")
    models.create_sample(scan_id, filename, str(dest), uploaded_by=uploaded_by)
    jobs.submit_scan(
        scan_id, str(dest), run_static_analysis, build_report, save_report, _on_scan_error,
        webhook_url=webhook_url,
    )

    return jsonify({"scan_id": scan_id, "status": "queued"}), 202


@bp.route("/scans", methods=["GET"])
@require_auth
def list_scans():
    return jsonify(models.list_samples())


@bp.route("/report/<scan_id>", methods=["GET"])
@require_auth
def get_report(scan_id: str):
    import json as _json

    sample = models.get_sample(scan_id)
    if not sample:
        return jsonify({"error": "scan not found"}), 404

    stored = models.get_report(scan_id)
    if stored:
        return jsonify(_json.loads(stored["report_json"]))

    # Fallback: no saved report yet (e.g. dynamic-only findings added after
    # the static pass) — rebuild from live findings, without app metadata.
    return jsonify(build_report(scan_id))


@bp.route("/trend/<package_name>", methods=["GET"])
@require_auth
def trend(package_name: str):
    return jsonify(build_trend(package_name))


@bp.route("/finding/<int:finding_id>/triage", methods=["POST"])
@require_auth
def triage_finding(finding_id: int):
    finding = models.get_finding(finding_id)
    if not finding:
        return jsonify({"error": "finding not found"}), 404

    body = request.get_json(silent=True) or {}
    status = body.get("status", "open")
    if status not in ("open", "reviewed", "dismissed"):
        return jsonify({"error": "status must be one of: open, reviewed, dismissed"}), 400

    models.set_finding_triage(finding_id, status, body.get("note", ""))

    import json as _json
    stored = models.get_report(finding["scan_id"])
    parsed_app = _json.loads(stored["report_json"]).get("app") if stored else None
    report = build_report(finding["scan_id"], parsed=parsed_app)
    save_report(finding["scan_id"], report)

    return jsonify({"success": True, "finding_id": finding_id, "status": status})


@bp.route("/report/<scan_id>/pdf", methods=["GET"])
@require_auth
def report_pdf(scan_id: str):
    from flask import send_file
    from app.storage.report import REPORTS_ROOT

    sample = models.get_sample(scan_id)
    if not sample:
        return jsonify({"error": "scan not found"}), 404

    pdf_path = REPORTS_ROOT / f"{scan_id}.pdf"
    if not pdf_path.exists():
        report = build_report(scan_id)
        pdf_path = save_report_pdf(scan_id, report)

    return send_file(pdf_path, as_attachment=True, download_name=f"{sample['filename']}_report.pdf")


@bp.route("/compare", methods=["GET"])
@require_auth
def compare():
    scan_a = request.args.get("scan_a")
    scan_b = request.args.get("scan_b")
    if not scan_a or not scan_b:
        return jsonify({"error": "missing 'scan_a' and/or 'scan_b' query params"}), 400
    if not models.get_sample(scan_a) or not models.get_sample(scan_b):
        return jsonify({"error": "one or both scans not found"}), 404
    return jsonify(diff_reports(scan_a, scan_b))


@bp.route("/compare/matrix", methods=["GET"])
@require_auth
def compare_matrix():
    scan_ids = request.args.getlist("scan_ids") or request.args.get("scan_ids", "").split(",")
    scan_ids = [s for s in scan_ids if s]
    if len(scan_ids) < 2:
        return jsonify({"error": "provide at least two 'scan_ids' (repeated query param or comma-separated)"}), 400
    return jsonify(build_matrix(scan_ids))


@bp.route("/dynamic/devices", methods=["GET"])
@require_auth
def dynamic_devices():
    return jsonify(android_runtime.list_devices())


@bp.route("/dynamic/<scan_id>/start", methods=["POST"])
@require_auth
def dynamic_start(scan_id: str):
    sample = models.get_sample(scan_id)
    if not sample:
        return jsonify({"error": "scan not found"}), 404

    body = request.get_json(silent=True) or {}
    serial = body.get("serial")
    if not serial:
        return jsonify({"error": "missing 'serial'"}), 400

    result = android_runtime.start_session(
        scan_id, serial, sample["package_name"],
        capture_traffic=bool(body.get("capture_traffic", False)),
        bypass_ssl_pinning=bool(body.get("bypass_ssl_pinning", False)),
        bypass_root_detection=bool(body.get("bypass_root_detection", False)),
    )
    status_code = 200 if result["success"] else 400
    return jsonify(result), status_code


@bp.route("/dynamic/<scan_id>/poll", methods=["GET"])
@require_auth
def dynamic_poll(scan_id: str):
    state = android_runtime.poll_session(scan_id)
    if state is None:
        return jsonify({"error": "no active session"}), 404
    return jsonify(state)


@bp.route("/dynamic/<scan_id>/stop", methods=["POST"])
@require_auth
def dynamic_stop(scan_id: str):
    result = android_runtime.stop_session(scan_id)
    if result is None:
        return jsonify({"error": "no active session"}), 404
    return jsonify(result)
