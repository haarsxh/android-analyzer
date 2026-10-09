"""App code vs. bundled library code."""
from __future__ import annotations

import pytest

from app.static_analysis import libraries
from app.static_analysis import sast_engine as se


@pytest.mark.parametrize("path,expected", [
    ("sources/kotlin/UNumbersKt.java", True),
    ("sources/okhttp3/OkHttpClient.java", True),
    ("smali_classes2/com/google/android/gms/internal/zzat.smali", True),
    ("sources/owasp/sat/agoat/CloudServicesActivity.java", False),
    ("sources/com/android/insecurebankv2/DoLogin.java", False),
    ("sources/a/b/c.java", False),               # obfuscated: assume app
    ("res/layout/activity_main.xml", False),     # resources: can't attribute, assume app
    ("sources/com/googlex/App.java", False),     # prefix must match a whole package segment
])
def test_is_library_path(path, expected):
    assert libraries.is_library_path(path) is expected


@pytest.mark.parametrize("cls,expected", [
    ("okhttp3.internal.connection.RealConnection.connectTls", True),
    ("owasp.sat.agoat.AccessControlIssue1Activity.hashPIN", False),
    (None, False),
])
def test_is_library_class(cls, expected):
    assert libraries.is_library_class(cls) is expected


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


DES_LINE = 'Cipher c = Cipher.getInstance("DES");'


def _des_finding(tmp_path):
    [f] = [f for f in se.scan_source(tmp_path, (".java",)) if f["metadata"]["rule_id"] == "weak-crypto-des"]
    return f


def test_library_only_finding_is_downgraded_and_labelled(tmp_path):
    _write(tmp_path, "sources/org/apache/commons/Crypto.java", DES_LINE)
    f = _des_finding(tmp_path)
    assert f["metadata"]["origin"] == "library"
    assert f["severity"] == se.downgrade(f["metadata"]["original_severity"])
    assert f["title"].endswith(se.LIBRARY_SUFFIX)
    assert "org.apache" in f["description"]


def test_app_occurrence_keeps_full_severity(tmp_path):
    _write(tmp_path, "sources/org/apache/commons/Crypto.java", DES_LINE)
    _write(tmp_path, "sources/com/example/app/Login.java", DES_LINE)
    f = _des_finding(tmp_path)
    assert f["metadata"]["origin"] == "app"
    assert f["severity"] == f["metadata"]["original_severity"]
    assert se.LIBRARY_SUFFIX not in f["title"]


def test_library_findings_collapse_to_one_per_rule(tmp_path):
    for i in range(5):
        _write(tmp_path, f"sources/com/google/android/gms/internal/zz{i}.java", f'String u = "http://example{i}.com";')
    _write(tmp_path, "sources/com/example/app/Api.java", 'String u = "http://api.example.com";')
    found = se.collapse_library_findings(se.scan_source(tmp_path, (".java",)))
    urls = [f for f in found if f["metadata"]["rule_id"] == "cleartext-url"]
    lib = [f for f in urls if f["metadata"]["origin"] == "library"]
    app = [f for f in urls if f["metadata"]["origin"] == "app"]
    assert len(app) == 1
    assert len(lib) == 1 and lib[0]["metadata"]["occurrence_count"] == 5
    assert "com.google" in lib[0]["description"]


def test_collapsed_title_keeps_full_rule_title(tmp_path):
    for i in range(2):
        _write(tmp_path, f"sources/com/google/zz{i}.java", 'MessageDigest.getInstance("MD5");')
    [f] = [f for f in se.collapse_library_findings(se.scan_source(tmp_path, (".java",)))
           if f["metadata"]["rule_id"] == "weak-crypto-md5"]
    assert f["title"].startswith(f["metadata"]["rule_title"] + " (2 occurrences)")
