"""Device Control: thin adb wrapper for listing devices and installing/launching APKs."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any


def adb_available() -> bool:
    return shutil.which("adb") is not None


def _run(args: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["adb", *args], capture_output=True, text=True, timeout=timeout)


def list_devices() -> list[dict[str, str]]:
    """Return connected devices/emulators as [{serial, state}]."""
    if not adb_available():
        return []
    result = _run(["devices"])
    devices = []
    for line in result.stdout.splitlines()[1:]:
        line = line.strip()
        if not line or "\t" not in line:
            continue
        serial, state = line.split("\t", 1)
        devices.append({"serial": serial, "state": state})
    return devices


def install_apk(serial: str, apk_path: str) -> dict[str, Any]:
    result = _run(["-s", serial, "install", "-r", apk_path], timeout=180)
    return {"success": result.returncode == 0, "stdout": result.stdout, "stderr": result.stderr}


def launch_app(serial: str, package_name: str, main_activity: str | None) -> dict[str, Any]:
    if main_activity:
        component = main_activity if "/" in main_activity else f"{package_name}/{main_activity}"
        args = ["-s", serial, "shell", "am", "start", "-n", component]
    else:
        args = ["-s", serial, "shell", "monkey", "-p", package_name,
                 "-c", "android.intent.category.LAUNCHER", "1"]
    result = _run(args)
    return {"success": result.returncode == 0, "stdout": result.stdout, "stderr": result.stderr}


def force_stop(serial: str, package_name: str) -> dict[str, Any]:
    result = _run(["-s", serial, "shell", "am", "force-stop", package_name])
    return {"success": result.returncode == 0}


def uninstall_apk(serial: str, package_name: str) -> dict[str, Any]:
    result = _run(["-s", serial, "uninstall", package_name])
    return {"success": result.returncode == 0, "stdout": result.stdout, "stderr": result.stderr}


def get_pid(serial: str, package_name: str) -> str | None:
    result = _run(["-s", serial, "shell", "pidof", package_name])
    pid = result.stdout.strip()
    return pid or None


def screenshot(serial: str, dest_path: Path) -> dict[str, Any]:
    """Capture the device's current screen to dest_path (PNG)."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    device_tmp = "/data/local/tmp/analyzer_screencap.png"
    cap = _run(["-s", serial, "shell", "screencap", "-p", device_tmp], timeout=20)
    if cap.returncode != 0:
        return {"success": False, "error": cap.stderr}
    pull = _run(["-s", serial, "pull", device_tmp, str(dest_path)], timeout=20)
    _run(["-s", serial, "shell", "rm", device_tmp], timeout=10)
    if pull.returncode != 0:
        return {"success": False, "error": pull.stderr}
    return {"success": True, "path": str(dest_path)}


def screencap_bytes(serial: str, timeout: int = 8) -> bytes | None:
    """Capture the device's current screen and return raw PNG bytes directly
    (via `adb exec-out`, no on-device file/pull round trip) — fast enough to
    poll repeatedly for a near-live view of the screen."""
    try:
        result = subprocess.run(
            ["adb", "-s", serial, "exec-out", "screencap", "-p"],
            capture_output=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    if result.returncode != 0 or not result.stdout:
        return None
    return result.stdout


# Named keys the UI exposes, mapped to Android keyevent codes.
KEY_CODES = {
    "back": 4,
    "home": 3,
    "recents": 187,
    "enter": 66,
    "delete": 67,
    "power": 26,
}


def tap(serial: str, x: int, y: int) -> dict[str, Any]:
    """Send a tap at device-pixel coordinates (matching the live screencap's resolution)."""
    result = _run(["-s", serial, "shell", "input", "tap", str(int(x)), str(int(y))], timeout=10)
    return {"success": result.returncode == 0, "stderr": result.stderr}


def swipe(serial: str, x1: int, y1: int, x2: int, y2: int, duration_ms: int = 300) -> dict[str, Any]:
    """Send a swipe/drag gesture between two device-pixel points."""
    result = _run(
        ["-s", serial, "shell", "input", "swipe",
         str(int(x1)), str(int(y1)), str(int(x2)), str(int(y2)), str(int(duration_ms))],
        timeout=10,
    )
    return {"success": result.returncode == 0, "stderr": result.stderr}


def press_key(serial: str, key: str) -> dict[str, Any]:
    """Send a named key event (see KEY_CODES) — Back, Home, Recents, etc."""
    code = KEY_CODES.get(key.lower())
    if code is None:
        return {"success": False, "error": f"unknown key '{key}'"}
    result = _run(["-s", serial, "shell", "input", "keyevent", str(code)], timeout=10)
    return {"success": result.returncode == 0, "stderr": result.stderr}


def input_text(serial: str, text: str) -> dict[str, Any]:
    """Type text into the currently focused field.

    `adb shell input text` treats spaces specially and has no real escaping
    for shell metacharacters, so this only allows a conservative character
    set — safe for typical login/search fields without shell-injection risk.
    """
    import re
    if not re.fullmatch(r"[\w\s@.\-+!#$%^&*(),:;'\"?/]*", text):
        return {"success": False, "error": "text contains unsupported characters"}
    android_text = text.replace(" ", "%s")
    result = _run(["-s", serial, "shell", "input", "text", android_text], timeout=10)
    return {"success": result.returncode == 0, "stderr": result.stderr}


def read_logcat(serial: str, package_name: str, max_lines: int = 200) -> list[str]:
    """Snapshot the current logcat buffer filtered to the given package's PID."""
    pid = get_pid(serial, package_name)
    _run(["-s", serial, "logcat", "-c"], timeout=10)
    args = ["-s", serial, "logcat", "-d"]
    if pid:
        args += ["--pid", pid]
    result = _run(args, timeout=15)
    lines = result.stdout.splitlines()
    return lines[-max_lines:]
