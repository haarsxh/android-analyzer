"""Frida Bridge: attaches Frida to a running process and dispatches hook scripts."""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Callable

ATTACH_RETRY_ATTEMPTS = 6
ATTACH_RETRY_DELAY_SECONDS = 1.5

SCRIPTS_DIR = Path(__file__).resolve().parent / "frida_scripts"

# Passive observation hooks: always loaded, never alter app behavior.
DEFAULT_SCRIPTS = ["crypto_hooks.js", "shared_prefs_hooks.js", "webview_hooks.js", "http_hooks.js"]

# Active bypass hooks: alter app behavior (defeat pinning/root checks), so
# they're opt-in per session rather than always-on.
OPTIONAL_SCRIPTS = {
    "ssl_pinning_bypass": "ssl_pinning_bypass.js",
    "root_emulator_bypass": "root_emulator_bypass.js",
}


class FridaBridge:
    """Owns a Frida session for one dynamic-analysis run and collects hook events."""

    def __init__(self, device_serial: str, package_name: str):
        self.device_serial = device_serial
        self.package_name = package_name
        self.events: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._session = None
        self._scripts: list[Any] = []

    def _on_message(self, message: dict, data) -> None:
        with self._lock:
            if message.get("type") == "send":
                self.events.append(message.get("payload", {}))
            elif message.get("type") == "error":
                self.events.append({"hook": "frida", "error": message.get("description", str(message))})

    def attach(self, script_names: list[str] | None = None,
               bypass_ssl_pinning: bool = False, bypass_root_detection: bool = False) -> dict[str, Any]:
        """Attach to the target process and load the given hook scripts (or all defaults).

        `bypass_ssl_pinning` / `bypass_root_detection` additionally load the
        matching OPTIONAL_SCRIPTS entry — these actively alter app behavior,
        so they're off unless explicitly requested.
        """
        try:
            import frida
        except ImportError:
            return {"success": False, "error": "frida Python module not installed"}

        try:
            device = frida.get_device(self.device_serial)
        except Exception as e:
            return {"success": False, "error": f"failed to get device {self.device_serial}: {e}"}

        # frida's string-based attach() matches a process by its display
        # label (e.g. "InsecureBankv2"), not its package/bundle identifier
        # (e.g. "com.android.insecurebankv2") — those are usually different
        # strings, so attaching by package_name directly fails even when the
        # app is running. Resolve the real PID via enumerate_applications()
        # (keyed by identifier) and attach by PID instead.
        #
        # Retried with a short backoff: right after launch the process may
        # not have spawned yet (slow-starting app, or — as with some legacy
        # targetSdk apps on modern Android — a blocking permission-consent
        # screen the user has to dismiss before the app process starts).
        pid = None
        last_error = f"{self.package_name} is not installed on this device"
        for attempt in range(ATTACH_RETRY_ATTEMPTS):
            try:
                apps = device.enumerate_applications()
            except Exception as e:
                last_error = f"failed to list applications: {e}"
                break
            match = next((a for a in apps if a.identifier == self.package_name), None)
            if match is None:
                break  # not installed at all — retrying won't help
            if match.pid:
                pid = match.pid
                break
            last_error = (
                f"{self.package_name} is installed but not running yet — if the app is "
                "waiting on a permission dialog or similar on-screen prompt, dismiss it "
                "on the device to let it start"
            )
            if attempt < ATTACH_RETRY_ATTEMPTS - 1:
                time.sleep(ATTACH_RETRY_DELAY_SECONDS)

        if pid is None:
            return {"success": False, "error": last_error}

        try:
            session = device.attach(pid)
        except Exception as e:
            return {"success": False, "error": f"failed to attach to {self.package_name} (pid {pid}): {e}"}

        self._session = session
        names = list(script_names or DEFAULT_SCRIPTS)
        if bypass_ssl_pinning:
            names.append(OPTIONAL_SCRIPTS["ssl_pinning_bypass"])
        if bypass_root_detection:
            names.append(OPTIONAL_SCRIPTS["root_emulator_bypass"])
        loaded = []
        for name in names:
            path = SCRIPTS_DIR / name
            if not path.exists():
                continue
            try:
                script = session.create_script(path.read_text())
                script.on("message", self._on_message)
                script.load()
                self._scripts.append(script)
                loaded.append(name)
            except Exception as e:
                self.events.append({"hook": "frida", "error": f"failed to load {name}: {e}"})

        return {"success": True, "loaded_scripts": loaded}

    def get_events(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.events)

    def detach(self) -> None:
        for script in self._scripts:
            try:
                script.unload()
            except Exception:
                pass
        if self._session is not None:
            try:
                self._session.detach()
            except Exception:
                pass
