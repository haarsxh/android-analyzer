"""Android Runtime: orchestrates a dynamic-analysis session end-to-end."""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from app.dynamic_analysis import device
from app.dynamic_analysis.views import FridaBridge
from app.dynamic_analysis.webproxy import TrafficProxy
from app.storage import models
from app.storage.report import build_report, save_report

SCREENSHOTS_ROOT = Path(__file__).resolve().parent.parent.parent / "workdir" / "screenshots"

# In-memory registry of active sessions, keyed by scan_id. Dynamic sessions are
# inherently tied to a live device/process, so they aren't persisted to SQLite
# the way static findings are — only their final summary is.
_SESSIONS: dict[str, "DynamicSession"] = {}
_SESSIONS_LOCK = threading.Lock()


class DynamicSession:
    def __init__(self, scan_id: str, serial: str, package_name: str, main_activity: str | None):
        self.scan_id = scan_id
        self.serial = serial
        self.package_name = package_name
        self.main_activity = main_activity
        self.status = "created"
        self.log: list[str] = []
        self.bridge: FridaBridge | None = None
        self.proxy: TrafficProxy | None = None
        self.screenshots: list[str] = []

    def _note(self, msg: str) -> None:
        self.log.append(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def capture_screenshot(self, label: str) -> dict[str, Any]:
        session_dir = SCREENSHOTS_ROOT / self.scan_id
        filename = f"{int(time.time())}_{label}.png"
        result = device.screenshot(self.serial, session_dir / filename)
        if result["success"]:
            self.screenshots.append(filename)
            self._note(f"screenshot captured: {filename}")
        else:
            self._note(f"screenshot failed: {result.get('error')}")
        return result

    def start(self, capture_traffic: bool = False,
              bypass_ssl_pinning: bool = False, bypass_root_detection: bool = False) -> dict[str, Any]:
        if not device.adb_available():
            self.status = "error"
            self._note("adb not found on PATH")
            return {"success": False, "error": "adb not found on PATH"}

        devices = {d["serial"]: d["state"] for d in device.list_devices()}
        if self.serial not in devices:
            self.status = "error"
            self._note(f"device {self.serial} not found among connected devices")
            return {"success": False, "error": f"device {self.serial} not connected"}

        self._note(f"launching {self.package_name} on {self.serial}")
        launch_result = device.launch_app(self.serial, self.package_name, self.main_activity)
        if not launch_result["success"]:
            self.status = "error"
            self._note(f"launch failed: {launch_result['stderr']}")
            return {"success": False, "error": launch_result["stderr"]}

        time.sleep(2)  # let the process come up before attaching

        self.bridge = FridaBridge(self.serial, self.package_name)
        attach_result = self.bridge.attach(
            bypass_ssl_pinning=bypass_ssl_pinning, bypass_root_detection=bypass_root_detection
        )
        if attach_result["success"]:
            self._note(f"frida attached, loaded scripts: {attach_result['loaded_scripts']}")
        else:
            self._note(f"frida attach failed: {attach_result['error']}")

        if capture_traffic:
            self.proxy = TrafficProxy(self.scan_id)
            proxy_result = self.proxy.start()
            if proxy_result["success"]:
                self._note(f"traffic proxy started on port {proxy_result['port']}")
            else:
                self._note(f"traffic proxy not started: {proxy_result['error']}")

        self.capture_screenshot("launch")

        self.status = "running"
        return {"success": True, "frida": attach_result}

    def poll(self) -> dict[str, Any]:
        events = self.bridge.get_events() if self.bridge else []
        logcat = device.read_logcat(self.serial, self.package_name, max_lines=100)
        return {
            "status": self.status, "log": self.log, "frida_events": events,
            "logcat": logcat, "screenshots": self.screenshots,
        }

    def stop(self) -> dict[str, Any]:
        self.capture_screenshot("final")
        self._note("stopping session")
        if self.bridge:
            self.bridge.detach()
        traffic_summary = []
        if self.proxy:
            self.proxy.stop()
            traffic_summary = self.proxy.summarize_flows()

        device.force_stop(self.serial, self.package_name)
        self.status = "stopped"

        for event in (self.bridge.get_events() if self.bridge else []):
            models.add_finding(
                scan_id=self.scan_id,
                source="dynamic_frida",
                severity="Info",
                title=f"Runtime event: {event.get('hook', 'unknown')}.{event.get('api', '')}",
                description=str(event),
                metadata=event,
            )

        stored = models.get_report(self.scan_id)
        parsed_app = None
        if stored:
            import json
            parsed_app = json.loads(stored["report_json"]).get("app")
        report = build_report(self.scan_id, parsed=parsed_app)
        save_report(self.scan_id, report)

        return {"success": True, "log": self.log, "traffic_flows": len(traffic_summary),
                "screenshots": self.screenshots}


def start_session(scan_id: str, serial: str, package_name: str,
                   main_activity: str | None = None, capture_traffic: bool = False,
                   bypass_ssl_pinning: bool = False, bypass_root_detection: bool = False) -> dict[str, Any]:
    session = DynamicSession(scan_id, serial, package_name, main_activity)
    with _SESSIONS_LOCK:
        _SESSIONS[scan_id] = session
    return session.start(
        capture_traffic=capture_traffic,
        bypass_ssl_pinning=bypass_ssl_pinning,
        bypass_root_detection=bypass_root_detection,
    )


def poll_session(scan_id: str) -> dict[str, Any] | None:
    session = _SESSIONS.get(scan_id)
    return session.poll() if session else None


def capture_screenshot(scan_id: str) -> dict[str, Any] | None:
    session = _SESSIONS.get(scan_id)
    return session.capture_screenshot("manual") if session else None


def get_session_serial(scan_id: str) -> str | None:
    """The device serial for an active session, for the live-screen view."""
    session = _SESSIONS.get(scan_id)
    return session.serial if session else None


def stop_session(scan_id: str) -> dict[str, Any] | None:
    session = _SESSIONS.get(scan_id)
    if not session:
        return None
    result = session.stop()
    with _SESSIONS_LOCK:
        _SESSIONS.pop(scan_id, None)
    return result


def list_devices() -> list[dict[str, str]]:
    return device.list_devices()
