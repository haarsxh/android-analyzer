"""Starting a dynamic session must end any session still running for the same
scan or device — otherwise two sets of Frida hooks load into one app and crash it."""
from __future__ import annotations

from app.dynamic_analysis import android_runtime


def test_new_session_stops_previous_ones(monkeypatch):
    stopped = []
    monkeypatch.setattr(android_runtime.DynamicSession, "start", lambda self, **kw: {"success": True})
    monkeypatch.setattr(android_runtime.DynamicSession, "stop", lambda self: stopped.append(self.scan_id))
    monkeypatch.setattr(android_runtime, "_SESSIONS", {})

    android_runtime.start_session("scanA", "emulator-5554", "owasp.sat.agoat")
    android_runtime.start_session("scanB", "emulator-5556", "com.example.other")   # other device: untouched
    android_runtime.start_session("scanA", "emulator-5554", "owasp.sat.agoat")    # restart same scan
    assert stopped == ["scanA"]

    android_runtime.start_session("scanC", "emulator-5554", "com.insecureshop")   # same device, other app
    assert stopped == ["scanA", "scanA"]
    assert set(android_runtime._SESSIONS) == {"scanB", "scanC"}
