"""App data at rest: copy the app's private data folder (and its external
storage folder) off the device when a session ends, then look at what's
actually stored there.

Hooks see data *being written*; this sees what's *on disk*, which catches
writes the hooks missed (native code, unhooked APIs, data from earlier runs)
and shows the real file contents — e.g. a temp file whose name says nothing
but whose content is "password is Temp@Secret88".

Needs root (emulators: `adb root`) or a debuggable app (`run-as`).
"""
from __future__ import annotations

import base64
import binascii
import io
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from app.dynamic_analysis.runtime_rules import (
    JWT_RE, LOG_KV_RE, SENSITIVE_NAME_RE, _Collector, _looks_like_secret, mask,
)
from app.static_analysis.sast_engine import provider_matches

APPDATA_ROOT = Path(__file__).resolve().parent.parent.parent / "workdir" / "appdata"
PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")

# Folders that hold the app's own code/runtime caches, never its data.
SKIPPED_DIRS = ("code_cache", "app_webview", "lib", "no_backup/com.google.android.gms")
MAX_TOTAL_BYTES = 200 * 1024 * 1024
MAX_TEXT_FILE_BYTES = 1024 * 1024

# "password is Temp@Secret88", "Password -Sd@Secret55", "pin: 4821"
CREDENTIAL_PHRASE_RE = re.compile(
    r"(?i)\b(?P<key>pass(?:word|wd)?|pwd|pin|token|secret|api[_ -]?key)\b\s*(?:is\b|[:=\-])\s*(?P<value>\S{4,})"
)


HASH_LENGTHS = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}


def _looks_like_credential_value(value: str) -> bool:
    """Filters out prose ("password is required"): real values usually carry a
    digit or symbol."""
    return any(c.isdigit() for c in value) or any(not c.isalnum() for c in value.strip(".,;"))


# --- collection -----------------------------------------------------------------

def _adb(serial: str, *args: str, timeout: int = 120, binary: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(["adb", "-s", serial, *args], capture_output=True, timeout=timeout, text=not binary)


def _access_mode(serial: str, package: str) -> str | None:
    """'root', 'run-as' or None."""
    if _adb(serial, "shell", "id", "-u", timeout=10).stdout.strip() == "0":
        return "root"
    if _adb(serial, "shell", "run-as", package, "id", "-u", timeout=10).returncode == 0:
        return "run-as"
    return None


def _pull_tar(serial: str, command: str, dest: Path) -> dict[str, Any]:
    """Run a tar-to-stdout command on the device and extract its output."""
    proc = _adb(serial, "exec-out", command, timeout=300, binary=True)
    return extract_tar(proc.stdout or b"", dest)


def extract_tar(data: bytes, dest: Path) -> dict[str, Any]:
    """Safely extract a tar archive produced on the device.

    Its content is attacker-controlled (it's the app's files), so extraction
    uses tarfile's "data" filter — no absolute paths, no "..", no links
    pointing outside dest, no device files — and members the filter rejects
    are skipped rather than aborting the whole copy.
    """
    if not data:
        return {"files": 0, "modes": {}, "rejected": []}
    modes, rejected, total = {}, [], 0
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
        for m in tar.getmembers():
            if any(f"/{d}/" in f"/{m.name}/" for d in SKIPPED_DIRS):
                continue
            total += m.size
            if total > MAX_TOTAL_BYTES:
                break
            try:
                tar.extract(m, dest, filter="data")
            except (tarfile.FilterError, OSError):
                rejected.append(m.name)
                continue
            if m.isfile():
                modes[m.name] = m.mode
    return {"files": len(modes), "modes": modes, "rejected": rejected}


def collect(serial: str, package: str, scan_id: str) -> dict[str, Any]:
    """Copy /data/data/<package> and its external-storage folder into
    workdir/appdata/<scan_id>/{internal,external}."""
    if not PACKAGE_RE.match(package or ""):
        return {"success": False, "error": f"refusing to use unexpected package name {package!r}"}
    mode = _access_mode(serial, package)
    if mode is None:
        return {"success": False, "error": "can't read the app's private data: the device isn't rooted (run "
                                           "`adb root` on an emulator) and the app isn't debuggable"}

    out = APPDATA_ROOT / scan_id
    shutil.rmtree(out, ignore_errors=True)
    if mode == "root":
        internal_cmd = f"tar -cf - -C /data/data {package}"
    else:
        internal_cmd = f"run-as {package} tar -cf - ."
    internal = _pull_tar(serial, internal_cmd, out / "internal")
    # The external folder is readable by the shell user, no root needed.
    external = _pull_tar(serial, f"tar -cf - -C /storage/emulated/0/Android/data {package} 2>/dev/null",
                         out / "external")
    return {"success": True, "mode": mode, "path": out, "internal_modes": internal["modes"],
            "files": internal["files"] + external["files"]}


# --- analysis -------------------------------------------------------------------

def _decoded_base64(value: str) -> str | None:
    """Readable text hidden behind base64 (encoding, not encryption)."""
    if len(value) < 8 or len(value) % 4 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value):
        return None
    try:
        text = base64.b64decode(value, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    return text if len(text) >= 4 and text.isprintable() else None


def _scan_prefs(c: _Collector, path: Path, rel: str, skip_keys: set[str]) -> None:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return
    for el in root:
        key, value = el.get("name", ""), (el.text if el.tag == "string" else el.get("value")) or ""
        if not value or key in skip_keys:
            continue
        meta = {"file": rel, "key": key, "value_preview": mask(value)}
        decoded = _decoded_base64(value)
        hash_name = HASH_LENGTHS.get(len(value)) if re.fullmatch(r"[0-9a-fA-F]+", value) else None
        if SENSITIVE_NAME_RE.search(key) and hash_name:
            c.add(("prefs_hash", rel, key), "High", f"Sensitive value stored as unsalted {hash_name} hash: {key}",
                  f"{rel} stores '{key}' as a bare {hash_name} digest ('{mask(value)}'). Short secrets like PINs "
                  "are recovered from an unsalted hash in seconds by trying every value; use a slow salted hash "
                  "(bcrypt/Argon2/PBKDF2) or the Android Keystore.", {**meta, "hash": hash_name})
        elif SENSITIVE_NAME_RE.search(key) and value.lower() not in ("null", "true", "false"):
            c.add(("prefs", rel, key), "High", f"Sensitive value in plaintext SharedPreferences file: {key}",
                  f"{rel} stores '{key}' = '{mask(value)}' unencrypted on disk. Use EncryptedSharedPreferences "
                  "or the Android Keystore.", meta)
        elif decoded:
            c.add(("prefs_b64", rel, key), "Medium", f"Base64-encoded (not encrypted) value in SharedPreferences: {key}",
                  f"{rel} stores '{key}' as base64, which anyone can decode (to '{mask(decoded)}'). Encoding "
                  "isn't encryption.", {**meta, "decoded_preview": mask(decoded)})
        elif _looks_like_secret(value):
            c.add(("prefs_secret", rel, key), "Medium", f"Secret-like value in SharedPreferences file: {key}",
                  f"{rel} stores a high-entropy value ('{mask(value)}') under '{key}' unencrypted.", meta)


def _scan_database(c: _Collector, path: Path, rel: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        # Copy (with any WAL/journal) so the original evidence is never modified.
        for sibling in path.parent.glob(path.name + "*"):
            shutil.copy2(sibling, Path(tmp) / sibling.name)
        try:
            conn = sqlite3.connect(Path(tmp) / path.name)
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        except sqlite3.DatabaseError:
            c.add(("db_encrypted", rel), "Info", f"Database not readable as plain SQLite: {rel}",
                  "Likely encrypted (e.g. SQLCipher) — good practice for sensitive data.", {"file": rel})
            return
        tables = [t for t in tables if t not in ("android_metadata", "sqlite_sequence")]
        c.add(("db", rel), "Info", f"Unencrypted SQLite database: {rel}",
              f"Tables: {', '.join(tables) or 'none'}. Readable by anyone with root or a device backup.",
              {"file": rel, "tables": tables})
        for table in tables:
            try:
                cols = [r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')]
                for col in cols:
                    if not SENSITIVE_NAME_RE.search(col):
                        continue
                    rows = conn.execute(f'SELECT "{col}" FROM "{table}" WHERE "{col}" IS NOT NULL AND "{col}" != \'\'').fetchall()
                    if rows:
                        sample = str(rows[0][0])
                        c.add(("db_sensitive", rel, table, col), "High",
                              f"Plaintext sensitive data in database: {path.name} → {table}.{col} ({len(rows)} row(s))",
                              f"Column '{col}' holds values like '{mask(sample)}' in plain text. Hash passwords "
                              "(bcrypt/Argon2) and encrypt other secrets.",
                              {"file": rel, "table": table, "column": col, "rows": len(rows), "value_preview": mask(sample)})
            except sqlite3.DatabaseError:
                continue
        conn.close()


def _scan_text_file(c: _Collector, path: Path, rel: str, external: bool) -> None:
    data = path.read_bytes()[:MAX_TEXT_FILE_BYTES]
    if b"\x00" in data[:4096]:
        return  # binary
    text = data.decode("utf-8", errors="ignore")
    where = "shared external storage" if external else "the app's private storage"
    severity = "High"
    for line in text.splitlines():
        hits = []
        for rule, secret in provider_matches(line):
            hits.append((rule["title"], secret))
        hits += [("JWT", m.group(0)) for m in JWT_RE.finditer(line)]
        for regex in (LOG_KV_RE, CREDENTIAL_PHRASE_RE):
            for m in regex.finditer(line):
                if SENSITIVE_NAME_RE.search(m.group("key")) and _looks_like_credential_value(m.group("value")):
                    hits.append((m.group("key").strip().lower(), m.group("value")))
        for label, value in hits:
            c.add(("file_secret", rel, label), severity, f"Credential stored in plaintext file: {rel} ({label})",
                  f"{rel} in {where} contains a {label} ('{mask(value)}') in clear text."
                  + (" Files here can be read by other apps (older Android) and over USB." if external else ""),
                  {"file": rel, "kind": label, "value_preview": mask(value), "external": external})


def analyze(collected: dict[str, Any], skip_pref_keys: set[str] | None = None) -> list[dict[str, Any]]:
    """Findings (source 'dynamic_storage') for a collect() result."""
    c = _Collector("dynamic_storage")
    root: Path = collected["path"]
    for area in ("internal", "external"):
        base = root / area
        if not base.exists():
            continue
        for path in sorted(p for p in base.rglob("*") if p.is_file()):
            rel = str(path.relative_to(base))
            parts = path.relative_to(base).parts
            if "shared_prefs" in parts and path.suffix == ".xml":
                _scan_prefs(c, path, rel, skip_pref_keys or set())
            elif path.read_bytes()[:16].startswith(b"SQLite format 3"):
                _scan_database(c, path, rel)
            elif "databases" in parts and not path.name.endswith(("-journal", "-wal", "-shm")):
                _scan_database(c, path, rel)  # not plain SQLite: reported as possibly encrypted
            elif not path.name.endswith(("-journal", "-wal", "-shm")):
                _scan_text_file(c, path, rel, external=(area == "external"))

    for name, mode in collected.get("internal_modes", {}).items():
        if mode & 0o004:
            c.add(("world_readable", name), "Medium", f"World-readable file in private storage: {name}",
                  "Created with world-readable permissions (MODE_WORLD_READABLE or chmod), so other apps can "
                  "read it despite being in the app's private folder.", {"file": name, "mode": oct(mode)})
    return c.results()
