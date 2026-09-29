"""Static Orchestrator: coordinates Android parsing, manifest checks, and SAST scanning."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from app.static_analysis import app as android_parser
from app.static_analysis import android_checks
from app.static_analysis import sast_engine
from app.security_intel import malware_checks
from app.security_intel import geolocation
from app.security_intel import firebase_checker
from app.storage import models

WORKDIR_ROOT = Path(__file__).resolve().parent.parent.parent / "workdir"


def run_static_analysis(scan_id: str, apk_path: str) -> dict[str, Any]:
    """Run the full static pipeline for a scan and persist findings to storage.

    Returns the parsed APK metadata plus all findings collected.
    """
    models.update_sample(scan_id, status="running")

    parsed = android_parser.parse_apk(apk_path)
    models.update_sample(
        scan_id,
        package_name=parsed.get("package_name"),
        sha256=parsed.get("sha256"),
    )

    all_findings: list[dict[str, Any]] = []

    manifest_findings = android_checks.run_checks(parsed)
    for f in manifest_findings:
        f["source"] = "android_checks"
    all_findings += manifest_findings

    work_dir = WORKDIR_ROOT / scan_id
    sast_result = sast_engine.run(apk_path, work_dir)
    for f in sast_result["findings"]:
        f["source"] = "sast_engine"
    all_findings += sast_result["findings"]

    for err in sast_result["errors"]:
        all_findings.append({
            "source": "sast_engine",
            "severity": "Info",
            "title": "SAST tooling notice",
            "description": err,
            "metadata": {},
        })

    malware_findings = malware_checks.run_checks(parsed)
    for f in malware_findings:
        f["source"] = "malware_checks"
    all_findings += malware_findings

    geo_findings = geolocation.geolocate_domains(sast_result.get("domains", set()))
    for f in geo_findings:
        f["source"] = "geolocation"
    all_findings += geo_findings

    firebase_roots = [d for d in (sast_result.get("jadx_dir"), sast_result.get("apktool_dir")) if d]
    firebase_findings = firebase_checker.check_firebase(firebase_roots)
    for f in firebase_findings:
        f["source"] = "firebase_checker"
    all_findings += firebase_findings

    for f in all_findings:
        models.add_finding(
            scan_id=scan_id,
            source=f["source"],
            severity=f["severity"],
            title=f["title"],
            description=f.get("description", ""),
            metadata=f.get("metadata", {}),
        )

    models.update_sample(scan_id, status="completed")

    return {"parsed": parsed, "findings": all_findings}
