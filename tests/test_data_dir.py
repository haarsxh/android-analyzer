"""App data-at-rest analysis, and safe extraction of the app's (untrusted) files."""
from __future__ import annotations

import io
import sqlite3
import tarfile

from app.dynamic_analysis import data_dir


def _tar(entries) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, content, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == "symlink":
                info.type, info.linkname = tarfile.SYMTYPE, content
                tar.addfile(info)
            else:
                data = content.encode()
                info.size, info.mode = len(data), (0o644 if kind == "world" else 0o600)
                tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_extraction_cannot_escape_destination(tmp_path):
    dest = tmp_path / "out"
    result = data_dir.extract_tar(_tar([
        ("pkg/files/ok.txt", "fine", "file"),
        ("../escaped.txt", "pwned", "file"),
        ("/tmp/abs_escaped.txt", "pwned", "file"),
        ("pkg/files/link", "/etc", "symlink"),
        ("pkg/files/link/passwd", "pwned", "file"),
    ]), dest)
    assert (dest / "pkg/files/ok.txt").read_text() == "fine"
    assert not (tmp_path / "escaped.txt").exists()
    assert not any(tmp_path.parent.glob("abs_escaped.txt"))
    assert "../escaped.txt" in result["rejected"]


def _layout(tmp_path, files: dict[str, str]) -> dict:
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return {"path": tmp_path, "internal_modes": {}}


PREFS = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="password">Goat@Pass99</string>
    <string name="EncryptedUsername">ZGluZXNoMTIz</string>
    <string name="pin">d41d8cd98f00b204e9800998ecf8427e</string>
    <string name="theme">dark</string>
</map>"""


def titles(findings):
    return {f["title"]: f["severity"] for f in findings}


def test_shared_prefs_file(tmp_path):
    found = titles(data_dir.analyze(_layout(tmp_path, {"internal/pkg/shared_prefs/users.xml": PREFS})))
    assert found["Sensitive value in plaintext SharedPreferences file: password"] == "High"
    assert found["Base64-encoded (not encrypted) value in SharedPreferences: EncryptedUsername"] == "Medium"
    assert found["Sensitive value stored as unsalted MD5 hash: pin"] == "High"
    assert not any("theme" in t for t in found)


def test_runtime_reported_pref_keys_are_not_repeated(tmp_path):
    found = data_dir.analyze(_layout(tmp_path, {"internal/pkg/shared_prefs/users.xml": PREFS}),
                             skip_pref_keys={"password"})
    assert not any(f["metadata"].get("key") == "password" for f in found)


def test_plaintext_credentials_in_files(tmp_path):
    found = data_dir.analyze(_layout(tmp_path, {
        "internal/pkg/users123tmp": "username is tempuser\npassword is Temp@Secret88\n",
        "external/pkg/files/notes_tmp": "Username - sduser Password -Sd@Secret55",
        "internal/pkg/files/help.txt": "Your password is required to continue.",
    }))
    by_file = {f["metadata"]["file"]: f for f in found}
    assert by_file["pkg/users123tmp"]["severity"] == "High"
    assert by_file["pkg/files/notes_tmp"]["metadata"]["external"] is True
    assert "pkg/files/help.txt" not in by_file  # prose, not a credential
    for f in found:
        assert "Temp@Secret88" not in str(f) and "Sd@Secret55" not in str(f)


def test_database_with_password_column(tmp_path):
    db = tmp_path / "internal/pkg/databases/aGoat"
    db.parent.mkdir(parents=True)
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    conn.execute("INSERT INTO users (username, password) VALUES ('sqluser', 'Sql@Secret77')")
    conn.commit(); conn.close()
    before = db.read_bytes()
    found = titles(data_dir.analyze({"path": tmp_path, "internal_modes": {}}))
    assert found["Plaintext sensitive data in database: aGoat → users.password (1 row(s))"] == "High"
    assert db.read_bytes() == before  # evidence untouched


def test_non_sqlite_database_is_reported_as_possibly_encrypted(tmp_path):
    found = titles(data_dir.analyze(_layout(tmp_path, {"internal/pkg/databases/secure.db": "\x00" * 64 + "x"})))
    assert found["Database not readable as plain SQLite: pkg/databases/secure.db"] == "Info"


def test_world_readable_file(tmp_path):
    found = titles(data_dir.analyze({"path": tmp_path, "internal_modes": {"pkg/files/shared.txt": 0o644,
                                                                           "pkg/files/private.txt": 0o600}}))
    assert "World-readable file in private storage: pkg/files/shared.txt" in found
    assert not any("private.txt" in t for t in found)


def test_unexpected_package_name_is_refused():
    assert not data_dir.collect("emulator-5554", "x; rm -rf /", "scan")["success"]
