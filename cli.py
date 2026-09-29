#!/usr/bin/env python3
"""CLI entrypoint: run the static analysis pipeline without the web UI.

Usage:
    python cli.py scan path/to/app.apk
    python cli.py devices
"""
from __future__ import annotations

import argparse
import json
import sys

from app.storage.models import init_db, new_scan_id, create_sample
from app.static_analysis.static_analyzer import run_static_analysis
from app.storage.report import build_report, save_report
from app.dynamic_analysis.android_runtime import list_devices


SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]


def cmd_scan(args: argparse.Namespace) -> int:
    init_db()
    scan_id = new_scan_id()
    create_sample(scan_id, args.apk_path.split("/")[-1], args.apk_path)

    print(f"[+] Scanning {args.apk_path} (scan_id={scan_id})...")
    result = run_static_analysis(scan_id, args.apk_path)
    report = build_report(scan_id, parsed=result["parsed"])
    html_path = save_report(scan_id, report)

    print(f"[+] Findings: {report['summary']['total_findings']} "
          f"(risk score {report['summary']['risk_score']})")
    print(f"[+] By severity: {report['summary']['by_severity']}")
    print(f"[+] HTML report: {html_path}")
    print(f"[+] JSON report: reports/{scan_id}.json")

    if args.json:
        print(json.dumps(report, indent=2, default=str))

    if args.fail_on:
        threshold_index = SEVERITY_ORDER.index(args.fail_on)
        blocking = [
            f for f in report["findings"]
            if f.get("triage_status") != "dismissed"
            and SEVERITY_ORDER.index(f["severity"]) >= threshold_index
        ]
        if blocking:
            print(f"\n[!] FAIL: {len(blocking)} finding(s) at or above severity "
                  f"'{args.fail_on}' (--fail-on={args.fail_on}):")
            for f in blocking:
                print(f"    [{f['severity']}] {f['title']}")
            return 1
        print(f"\n[+] PASS: no findings at or above severity '{args.fail_on}'.")

    return 0


def cmd_devices(args: argparse.Namespace) -> None:
    devices = list_devices()
    if not devices:
        print("No devices found. Is adb on PATH and a device/emulator connected?")
        return
    for d in devices:
        print(f"{d['serial']}\t{d['state']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Android APK static/dynamic analyzer CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="run static analysis on an APK")
    scan_parser.add_argument("apk_path")
    scan_parser.add_argument("--json", action="store_true", help="print the full JSON report")
    scan_parser.add_argument(
        "--fail-on", choices=SEVERITY_ORDER, default=None,
        help="exit with status 1 if any finding at or above this severity is present "
             "(for use as a CI/CD gate)",
    )
    scan_parser.set_defaults(func=cmd_scan)

    devices_parser = sub.add_parser("devices", help="list connected adb devices/emulators")
    devices_parser.set_defaults(func=lambda args: (cmd_devices(args), 0)[1])

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
