"""Native Library Scanner: checks bundled .so files for missing binary hardening
(NX stack, RELRO, stack canary) via readelf/nm — the same checks a manual binary
security review would run, applied to every native library the APK ships."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any


def tools_available() -> bool:
    return shutil.which("readelf") is not None and shutil.which("nm") is not None


def _run(args: list[str]) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=20)
        return result.stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return ""


def check_nx(so_path: Path) -> bool:
    """True if the stack is non-executable (GNU_STACK segment without 'E' flag).

    `readelf -lW` prints "GNU_STACK  <off> <vaddr> <paddr> <filesz> <memsz> <flags> <align>",
    so the flags column is the second-to-last field, not the last (that's alignment).
    """
    output = _run(["readelf", "-lW", str(so_path)])
    for line in output.splitlines():
        if "GNU_STACK" in line:
            fields = line.split()
            flags = fields[-2] if len(fields) >= 2 else ""
            return "E" not in flags
    # No GNU_STACK segment at all is itself a (older-toolchain) red flag, but
    # treat as NX-enabled by default rather than false-flagging modern libs.
    return True


def check_relro(so_path: Path) -> str:
    """Returns 'full', 'partial', or 'none' based on GNU_RELRO segment + BIND_NOW."""
    output = _run(["readelf", "-lW", str(so_path)])
    has_relro = "GNU_RELRO" in output
    if not has_relro:
        return "none"
    dynamic_output = _run(["readelf", "-dW", str(so_path)])
    if "BIND_NOW" in dynamic_output or "FLAGS_1" in dynamic_output and "NOW" in dynamic_output:
        return "full"
    return "partial"


def check_stack_canary(so_path: Path) -> bool:
    """True if the stack-protector symbol is present."""
    output = _run(["nm", "-D", str(so_path)])
    return "__stack_chk_fail" in output


def check_pie(so_path: Path) -> bool:
    """True if built as a position-independent (DYN) object — expected for .so files."""
    output = _run(["readelf", "-hW", str(so_path)])
    return "DYN" in output


def scan_libs(root_dir: Path) -> list[dict[str, Any]]:
    """Scan every .so under root_dir (typically apktool's lib/ output) for
    missing hardening flags. Returns one finding per weakness per unique lib
    name (deduped across ABIs, since the same source usually produces the
    same flags for every architecture)."""
    if not tools_available():
        return [{
            "severity": "Info",
            "title": "Native library analysis skipped",
            "description": "readelf/nm not found on PATH; install binutils to enable "
                            "native .so hardening checks (NX, RELRO, stack canary).",
            "metadata": {},
        }]

    if not root_dir.exists():
        return []

    so_files = list(root_dir.rglob("*.so"))
    if not so_files:
        return []

    # Dedupe by filename — the same library built for arm64-v8a/armeabi-v7a/x86
    # etc. is almost always compiled with identical hardening flags.
    seen_names: set[str] = set()
    findings: list[dict[str, Any]] = []

    for so_path in so_files:
        if so_path.name in seen_names:
            continue
        seen_names.add(so_path.name)

        if not check_nx(so_path):
            findings.append({
                "severity": "Medium",
                "title": f"Executable stack in native library: {so_path.name}",
                "description": "This native library was compiled without NX (non-executable "
                                "stack) protection, making stack-based buffer overflows easier "
                                "to exploit. Rebuild with a modern NDK/toolchain default.",
                "metadata": {"library": so_path.name, "check": "nx"},
            })

        relro = check_relro(so_path)
        if relro == "none":
            findings.append({
                "severity": "Medium",
                "title": f"No RELRO protection in native library: {so_path.name}",
                "description": "This library has no RELRO (Relocation Read-Only) hardening, "
                                "leaving the GOT writable and easier to target for GOT-overwrite "
                                "exploits. Rebuild with -Wl,-z,relro,-z,now.",
                "metadata": {"library": so_path.name, "check": "relro"},
            })
        elif relro == "partial":
            findings.append({
                "severity": "Low",
                "title": f"Only partial RELRO in native library: {so_path.name}",
                "description": "This library has partial RELRO only. Full RELRO "
                                "(-Wl,-z,relro,-z,now) provides stronger protection against "
                                "GOT-overwrite exploits.",
                "metadata": {"library": so_path.name, "check": "relro"},
            })

        if not check_stack_canary(so_path):
            findings.append({
                "severity": "Low",
                "title": f"No stack canary in native library: {so_path.name}",
                "description": "This library was compiled without stack-protector support "
                                "(-fstack-protector), making stack-buffer overflows harder to "
                                "detect at runtime.",
                "metadata": {"library": so_path.name, "check": "stack_canary"},
            })

    return findings
