"""SAST Engine: decompiles the APK (apktool + jadx) and scans source for vulnerable patterns."""
from __future__ import annotations

import math
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

RULES: list[dict[str, Any]] = [
    {
        "id": "hardcoded-secret",
        "severity": "High",
        "title": "Possible hardcoded secret or API key",
        "pattern": re.compile(
            r"""(?i)(api[_-]?key|secret|token|password|passwd|pwd)\s*=\s*["'][A-Za-z0-9_\-/+=]{8,}["']"""
        ),
    },
    {
        "id": "insecure-trustmanager",
        "severity": "Critical",
        "title": "Insecure TrustManager (accepts all certificates)",
        "pattern": re.compile(r"checkServerTrusted\s*\([^)]*\)\s*\{\s*\}"),
    },
    {
        "id": "insecure-hostname-verifier",
        "severity": "High",
        "title": "Insecure HostnameVerifier (always returns true)",
        "pattern": re.compile(r"return\s+true\s*;\s*\}\s*//?\s*verify|ALLOW_ALL_HOSTNAME_VERIFIER"),
    },
    {
        "id": "cleartext-url",
        "severity": "Medium",
        "title": "Hardcoded cleartext HTTP URL",
        "pattern": re.compile(r"""["']http://(?!localhost|127\.0\.0\.1)[^"']+["']"""),
    },
    {
        "id": "weak-crypto-des",
        "severity": "High",
        "title": "Weak cryptographic algorithm (DES)",
        "pattern": re.compile(r"""["']DES(/|["'])"""),
    },
    {
        "id": "weak-crypto-md5",
        "severity": "Medium",
        "title": "Weak hash algorithm (MD5) used, possibly for security purposes",
        "pattern": re.compile(r"""MessageDigest\.getInstance\(\s*["']MD5["']\s*\)"""),
    },
    {
        "id": "weak-crypto-ecb",
        "severity": "High",
        "title": "Weak cipher mode (ECB)",
        "pattern": re.compile(r"""["'][A-Za-z0-9]+/ECB/"""),
    },
    {
        "id": "world-readable-mode",
        "severity": "High",
        "title": "World-readable/writable file mode",
        "pattern": re.compile(r"MODE_WORLD_(READABLE|WRITEABLE)"),
    },
    {
        "id": "webview-js-interface",
        "severity": "Medium",
        "title": "WebView JavaScript interface exposed with JS enabled",
        "pattern": re.compile(r"addJavascriptInterface\s*\("),
    },
    {
        "id": "webview-js-enabled",
        "severity": "Low",
        "title": "WebView JavaScript execution enabled",
        "pattern": re.compile(r"setJavaScriptEnabled\s*\(\s*true\s*\)"),
    },
    {
        "id": "sql-raw-query",
        "severity": "Medium",
        "title": "Raw SQL query construction (possible SQL injection)",
        "pattern": re.compile(r"""rawQuery\s*\(\s*["'][^"']*\+|execSQL\s*\(\s*["'][^"']*\+"""),
    },
    {
        "id": "log-sensitive",
        "severity": "Low",
        "title": "Logging call with potentially sensitive keyword",
        "pattern": re.compile(r"""Log\.[a-z]\s*\(\s*["'][^"']*(password|token|secret)[^"']*["']""", re.IGNORECASE),
    },
]


def tools_available() -> dict[str, bool]:
    return {
        "apktool": shutil.which("apktool") is not None,
        "jadx": shutil.which("jadx") is not None,
    }


def decompile(apk_path: str, out_dir: Path) -> dict[str, Any]:
    """Run apktool (smali+resources) and jadx (java source) into out_dir.

    Returns paths and a list of tool errors (missing tools are non-fatal —
    scanning falls back to whatever output is available).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    apktool_dir = out_dir / "apktool"
    jadx_dir = out_dir / "jadx"
    errors = []
    tools = tools_available()

    if tools["apktool"]:
        try:
            subprocess.run(
                ["apktool", "d", "-f", "-o", str(apktool_dir), apk_path],
                check=True, capture_output=True, timeout=300,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            errors.append(f"apktool failed: {e}")
    else:
        errors.append("apktool not found on PATH; smali/resource decompilation skipped")

    if tools["jadx"]:
        try:
            subprocess.run(
                ["jadx", "-d", str(jadx_dir), apk_path],
                check=True, capture_output=True, timeout=300,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            errors.append(f"jadx failed: {e}")
    else:
        errors.append("jadx not found on PATH; Java source decompilation skipped")

    return {"apktool_dir": apktool_dir, "jadx_dir": jadx_dir, "errors": errors}


MAX_OCCURRENCES_LISTED = 5


def scan_source(root_dir: Path, extensions: tuple[str, ...] = (".java", ".smali", ".xml")) -> list[dict[str, Any]]:
    """Run RULES against every source file under root_dir.

    Matches are deduplicated by (rule_id, matched snippet) so the same
    hardcoded string or pattern repeated across many files/lines (common with
    bundled third-party SDK code) produces one finding with an occurrence
    count, instead of one row per line.
    """
    if not root_dir.exists():
        return []

    groups: dict[tuple[str, str], dict[str, Any]] = {}

    for path in root_dir.rglob("*"):
        if not path.is_file() or path.suffix not in extensions:
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue

        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule in RULES:
                if rule["pattern"].search(line):
                    snippet = line.strip()[:200]
                    key = (rule["id"], snippet)
                    if key not in groups:
                        groups[key] = {
                            "rule": rule,
                            "snippet": snippet,
                            "occurrences": [],
                        }
                    groups[key]["occurrences"].append({
                        "file": str(path.relative_to(root_dir)),
                        "line": lineno,
                    })

    findings = []
    for (rule_id, snippet), group in groups.items():
        rule = group["rule"]
        occurrences = group["occurrences"]
        count = len(occurrences)
        title = rule["title"]
        if count > 1:
            title += f" ({count} occurrences)"
        findings.append({
            "severity": rule["severity"],
            "title": title,
            "description": f"Rule '{rule_id}' matched {count} time(s), e.g. in "
                            f"{occurrences[0]['file']} at line {occurrences[0]['line']}.",
            "metadata": {
                "rule_id": rule_id,
                "snippet": snippet,
                "occurrence_count": count,
                "occurrences": occurrences[:MAX_OCCURRENCES_LISTED],
            },
        })
    return findings


URL_RE = re.compile(r'https?://([A-Za-z0-9.\-]+\.[A-Za-z]{2,})')
KNOWN_PLATFORM_DOMAINS = {
    "schemas.android.com", "www.w3.org", "xmlpull.org", "www.apache.org",
    "developer.android.com", "goo.gl", "g.co",
}


def extract_domains(root_dir: Path, extensions: tuple[str, ...] = (".java", ".smali", ".xml")) -> set[str]:
    """Collect distinct hostnames referenced anywhere in the decompiled source,
    for server-geolocation lookups (separate from the security cleartext-URL rule)."""
    domains: set[str] = set()
    if not root_dir.exists():
        return domains

    for path in root_dir.rglob("*"):
        if not path.is_file() or path.suffix not in extensions:
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for match in URL_RE.finditer(text):
            domain = match.group(1).lower()
            if domain not in KNOWN_PLATFORM_DOMAINS:
                domains.add(domain)
    return domains


STRING_LITERAL_RE = re.compile(r'"([A-Za-z0-9+/=_\-]{20,100})"')
ENTROPY_THRESHOLD = 4.3  # bits/char; random base64/hex-like data lands well above typical English/identifiers
EXCLUDE_SUBSTRINGS = ("http://", "https://", "android.", "androidx.", "com.google.", "com.android.")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _looks_like_secret(candidate: str) -> bool:
    if any(sub in candidate for sub in EXCLUDE_SUBSTRINGS):
        return False
    if candidate.count(".") > 3:  # long dotted identifiers (class/package names)
        return False
    has_letter = any(c.isalpha() for c in candidate)
    has_digit = any(c.isdigit() for c in candidate)
    if not (has_letter and has_digit):
        return False
    return shannon_entropy(candidate) >= ENTROPY_THRESHOLD


def scan_entropy_secrets(root_dir: Path, extensions: tuple[str, ...] = (".java", ".smali")) -> list[dict[str, Any]]:
    """Flag high-entropy string literals that look like embedded keys/tokens/credentials,
    even when they don't sit next to a keyword like 'key=' or 'secret='."""
    if not root_dir.exists():
        return []

    groups: dict[str, list[dict[str, Any]]] = {}
    for path in root_dir.rglob("*"):
        if not path.is_file() or path.suffix not in extensions:
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue

        for lineno, line in enumerate(text.splitlines(), start=1):
            for match in STRING_LITERAL_RE.finditer(line):
                candidate = match.group(1)
                if _looks_like_secret(candidate):
                    groups.setdefault(candidate, []).append({
                        "file": str(path.relative_to(root_dir)),
                        "line": lineno,
                    })

    findings = []
    for candidate, occurrences in groups.items():
        count = len(occurrences)
        title = "High-entropy string literal (possible embedded secret/key)"
        if count > 1:
            title += f" ({count} occurrences)"
        findings.append({
            "severity": "High",
            "title": title,
            "description": f"A {len(candidate)}-character string with high randomness "
                            f"(entropy {shannon_entropy(candidate):.2f} bits/char) was found, "
                            f"e.g. in {occurrences[0]['file']} at line {occurrences[0]['line']}. "
                            "This pattern commonly indicates a hardcoded API key, token, or "
                            "credential embedded directly in the app.",
            "metadata": {
                "rule_id": "entropy-secret",
                "snippet": candidate[:20] + "..." if len(candidate) > 20 else candidate,
                "occurrence_count": count,
                "occurrences": occurrences[:MAX_OCCURRENCES_LISTED],
            },
        })
    return findings


def run(apk_path: str, work_dir: Path) -> dict[str, Any]:
    """Full SAST pipeline: decompile then scan. Returns {findings, errors, domains}."""
    from app.static_analysis import library_detector, native_lib_scanner

    decomp = decompile(apk_path, work_dir)
    findings = []
    findings += scan_source(decomp["jadx_dir"], (".java",))
    findings += scan_source(decomp["apktool_dir"], (".smali", ".xml"))
    findings += scan_entropy_secrets(decomp["jadx_dir"], (".java",))
    findings += library_detector.detect(decomp["jadx_dir"] / "sources")
    findings += native_lib_scanner.scan_libs(decomp["apktool_dir"] / "lib")

    domains = extract_domains(decomp["jadx_dir"], (".java",))
    domains |= extract_domains(decomp["apktool_dir"], (".smali", ".xml"))

    return {
        "findings": findings, "errors": decomp["errors"], "domains": domains,
        "jadx_dir": decomp["jadx_dir"], "apktool_dir": decomp["apktool_dir"],
    }
