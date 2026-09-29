"""Background job runner for static-analysis scans.

Uses a stdlib ThreadPoolExecutor rather than Celery/RQ so the tool keeps
running with zero extra infrastructure (no Redis/broker required) — a scan
just needs to not block the HTTP request thread while it decompiles/scans a
potentially large APK.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scan-worker")


def _notify_webhook(webhook_url: str, payload: dict[str, Any]) -> None:
    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
    except (urllib.error.URLError, TimeoutError, ValueError):
        pass  # best-effort — a failed webhook shouldn't affect the scan result


def submit_scan(scan_id: str, apk_path: str, run_static_analysis: Callable, build_report: Callable,
                 save_report: Callable, on_error: Callable[[str, Exception], None],
                 webhook_url: str | None = None) -> None:
    """Run the static-analysis pipeline for one scan on a background thread.

    If `webhook_url` is given, POSTs a JSON summary to it once the scan
    finishes (success or failure) — useful for CI clients that don't want to
    poll /api/report/<scan_id>.
    """

    def _job():
        try:
            result = run_static_analysis(scan_id, apk_path)
            report = build_report(scan_id, parsed=result["parsed"])
            save_report(scan_id, report)
            if webhook_url:
                _notify_webhook(webhook_url, {
                    "scan_id": scan_id, "status": "completed",
                    "summary": report["summary"],
                })
        except Exception as e:
            on_error(scan_id, e)
            if webhook_url:
                _notify_webhook(webhook_url, {"scan_id": scan_id, "status": "error", "error": str(e)})

    _EXECUTOR.submit(_job)
