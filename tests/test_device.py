"""adb input: text typed into the device must never be able to run commands.

`adb shell` joins its arguments and runs them through the device's /bin/sh,
so the command string is replayed here through a local sh (with `echo` in
place of `input`) to check the shell sees the text as one literal argument.
"""
from __future__ import annotations

import subprocess

import pytest

from app.dynamic_analysis import device


def _captured_command(monkeypatch, text):
    seen = {}

    def fake_run(args, timeout=60):
        seen["args"] = args
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(device, "_run", fake_run)
    result = device.input_text("emulator-5554", text)
    return result, seen.get("args")


@pytest.mark.parametrize("text", [
    "abc;touch /tmp/analyzer_pwned",
    "a$(id)b",
    "it's `whoami` & \"q\" | cat",
    "Dinesh@123$",
])
def test_shell_metacharacters_are_literal(monkeypatch, tmp_path, text):
    result, args = _captured_command(monkeypatch, text)
    assert result["success"]
    command = args[-1].replace("input text", "echo", 1)
    out = subprocess.run(["sh", "-c", command], capture_output=True, text=True, cwd=tmp_path).stdout.strip()
    assert out == text.replace(" ", "%s")
    assert not list(tmp_path.iterdir())


def test_non_ascii_is_rejected(monkeypatch):
    result, args = _captured_command(monkeypatch, "naïve")
    assert not result["success"] and args is None


def test_unknown_key_is_rejected(monkeypatch):
    monkeypatch.setattr(device, "_run", lambda *a, **k: pytest.fail("adb should not run"))
    assert not device.press_key("emulator-5554", "reboot")["success"]
