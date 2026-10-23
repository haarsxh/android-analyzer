"""Traffic Proxy: mitmproxy integration for capturing HTTPS traffic from the device."""
from __future__ import annotations

import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

CAPTURE_ROOT = Path(__file__).resolve().parent.parent.parent / "workdir" / "traffic"


def mitmdump_path() -> str | None:
    """mitmdump from this app's own virtualenv (installed with requirements.txt),
    falling back to PATH — the server is often started as `.venv/bin/python`
    without activating the venv, so .venv/bin isn't on PATH."""
    local = Path(sys.executable).parent / "mitmdump"
    if local.exists():
        return str(local)
    return shutil.which("mitmdump")


def mitmdump_available() -> bool:
    return mitmdump_path() is not None


SETUP_INSTRUCTIONS = (
    "Traffic capture requires mitmproxy's CA certificate to be installed on the "
    "target device/emulator, and the device's Wi-Fi/proxy settings pointed at "
    "this machine's IP on the mitmproxy port (default 8080). Steps: "
    "1) run this proxy, 2) on the device set HTTP proxy to <host-ip>:8080, "
    "3) visit http://mitm.it on the device and install the CA for Android, "
    "4) (Android 7+) the target app must also trust user-installed CAs via a "
    "network security config, or use Frida to bypass certificate pinning."
)


class TrafficProxy:
    """Wraps a mitmdump subprocess writing a flow file for one dynamic-analysis run."""

    def __init__(self, scan_id: str, port: int = 8080):
        self.scan_id = scan_id
        self.port = port
        self.flow_path = CAPTURE_ROOT / f"{scan_id}.flow"
        self._proc: subprocess.Popen | None = None

    def start(self) -> dict[str, Any]:
        if not mitmdump_available():
            return {"success": False, "error": "mitmdump not found (pip install -r requirements.txt)",
                    "instructions": SETUP_INSTRUCTIONS}

        CAPTURE_ROOT.mkdir(parents=True, exist_ok=True)
        # mitmdump prints a line per request; an unread PIPE would fill up and
        # freeze the proxy (and the device's traffic with it), so log to a file.
        self.log_path = CAPTURE_ROOT / f"{self.scan_id}.mitmdump.log"
        self._log = open(self.log_path, "w")
        self._proc = subprocess.Popen(
            [mitmdump_path(), "-p", str(self.port), "-w", str(self.flow_path)],
            stdout=self._log, stderr=subprocess.STDOUT,
        )
        time.sleep(1)
        if self._proc.poll() is not None:
            self._log.close()
            tail = self.log_path.read_text(errors="replace")[-300:].strip()
            return {"success": False, "error": f"mitmdump exited immediately: {tail}", "instructions": SETUP_INSTRUCTIONS}

        return {"success": True, "port": self.port, "flow_path": str(self.flow_path), "instructions": SETUP_INSTRUCTIONS}

    def stop(self) -> dict[str, Any]:
        if self._proc is None:
            return {"success": False, "error": "not running"}
        self._proc.terminate()
        try:
            self._proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        self._log.close()
        return {"success": True, "flow_path": str(self.flow_path)}

    def summarize_flows(self) -> list[dict[str, Any]]:
        """Parse the captured flow file into per-request dicts (method, URL,
        headers, truncated body, status) for runtime_rules.analyze_traffic."""
        return read_flow_file(self.flow_path)


MAX_BODY_CHARS = 4000


def read_flow_file(flow_path: Path) -> list[dict[str, Any]]:
    if not flow_path.exists():
        return []
    try:
        from mitmproxy import http
        from mitmproxy.io import FlowReader
    except ImportError:
        return []

    flows = []
    try:
        with open(flow_path, "rb") as fh:
            for flow in FlowReader(fh).stream():
                if not isinstance(flow, http.HTTPFlow):
                    continue
                req, resp = flow.request, flow.response
                flows.append({
                    "method": req.method,
                    "scheme": req.scheme,
                    "host": req.pretty_host,
                    "url": req.pretty_url,
                    "request_headers": dict(req.headers),
                    "request_body": (req.get_text(strict=False) or "")[:MAX_BODY_CHARS],
                    "status": resp.status_code if resp else None,
                    "response_headers": dict(resp.headers) if resp else {},
                })
    except Exception:
        # A truncated flow file (proxy killed mid-write) still yields
        # whatever flows were read before the bad record.
        pass
    return flows
