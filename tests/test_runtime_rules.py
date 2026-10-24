"""Runtime rules: severities for Frida events, traffic and logcat — and, just
as important, the false positives found on real devices that must stay gone."""
from __future__ import annotations

import pytest

from app.dynamic_analysis import runtime_rules as rr
from tests.conftest import FIXTURES


def titles(findings):
    return {f["title"]: f["severity"] for f in findings}


# --- Frida events -----------------------------------------------------------

@pytest.mark.parametrize("algorithm,severity", [
    ("DES/CBC/PKCS5Padding", "High"),
    ("DESede/CBC/NoPadding", "High"),
    ("AES/ECB/PKCS5Padding", "High"),
    ("AES", "High"),  # bare "AES" defaults to ECB on Android
    ("AES/GCM/NoPadding", "Info"),
])
def test_cipher_severity(algorithm, severity):
    [f] = rr.analyze_frida_events([{"hook": "crypto", "api": "Cipher.doFinal", "algorithm": algorithm}])
    assert f["severity"] == severity


def test_short_aes_key_is_high():
    [f] = rr.analyze_frida_events([{"hook": "crypto", "api": "SecretKeySpec", "algorithm": "AES", "key_len": 8}])
    assert f["severity"] == "High"


def test_weak_hash_from_app_code_is_flagged():
    [f] = rr.analyze_frida_events([{
        "hook": "crypto", "api": "MessageDigest.getInstance", "algorithm": "MD5",
        "caller": "owasp.sat.agoat.AccessControlIssue1Activity.hashPIN",
    }])
    assert f["severity"] == "Medium"
    assert f["metadata"]["caller"].endswith("hashPIN")


@pytest.mark.parametrize("caller", [
    "okhttp3.internal.connection.RealConnection.connectTls",  # seen live on AndroGoat
    "okio.ByteString.digest$okio",
    None,  # every frame was platform code (e.g. the system TLS stack)
])
def test_weak_hash_from_library_or_platform_is_info(caller):
    [f] = rr.analyze_frida_events([{
        "hook": "crypto", "api": "MessageDigest.getInstance", "algorithm": "MD5", "caller": caller,
    }])
    assert f["severity"] == "Info"
    assert "not app code" in f["title"]


def test_repeated_events_are_collapsed():
    events = [{"hook": "crypto", "api": "Cipher.doFinal", "algorithm": "AES"}] * 300
    [f] = rr.analyze_frida_events(events)
    assert f["metadata"]["occurrences"] == 300
    assert "300 times" in f["description"]


def test_sensitive_shared_prefs_value_is_high_and_masked():
    [f] = rr.analyze_frida_events([
        {"hook": "shared_prefs", "api": "putString", "key": "password", "value": "Goat@Pass99"},
    ])
    assert f["severity"] == "High"
    assert "Goat@Pass99" not in f["description"]
    assert "Goat@Pass99" not in str(f["metadata"])


def test_apache_post_body_over_cleartext_is_high():
    found = titles(rr.analyze_frida_events([{
        "hook": "http", "api": "Apache HttpClient.execute", "method": "POST",
        "url": "http://10.0.2.2:8888/login", "body": "username=dinesh&password=Dinesh123",
    }]))
    assert found["Sensitive field 'password' sent over cleartext HTTP to 10.0.2.2:8888"] == "High"
    assert found["Cleartext HTTP request at runtime: 10.0.2.2:8888"] == "Medium"


def test_secret_in_url_query_is_high():
    found = titles(rr.analyze_frida_events([
        {"hook": "http", "api": "URL.openConnection", "url": "https://api.example.com/v1?api_key=abc123"},
    ]))
    assert found["Sensitive parameter 'api_key' sent in URL to api.example.com"] == "High"


def test_hook_errors_become_one_coverage_note():
    found = rr.analyze_frida_events([
        {"hook": "webview", "error": "loadUrl hook failed"},
        {"hook": "http", "error": "x"},
    ])
    assert len(found) == 1 and found[0]["severity"] == "Info"


# --- Traffic ----------------------------------------------------------------

def test_traffic_rules():
    flows = [
        {"method": "POST", "scheme": "http", "host": "10.0.2.2", "url": "http://10.0.2.2:8888/dologin",
         "request_headers": {"Cookie": "sid=abc"}, "request_body": "username=a&password=b",
         "status": 200, "response_headers": {}},
        {"method": "GET", "scheme": "https", "host": "api.example.com",
         "url": "https://api.example.com/me?token=xyz", "request_headers": {"Authorization": "Basic Zm9vOmJhcg=="},
         "request_body": "", "status": 200, "response_headers": {}},
    ]
    found = titles(rr.analyze_traffic(flows))
    assert found["Credentials/session sent over cleartext HTTP to 10.0.2.2"] == "High"
    assert found["Sensitive field 'password' sent over cleartext HTTP to 10.0.2.2"] == "High"
    assert found["Sensitive parameter 'token' sent in URL to api.example.com"] == "High"
    assert found["HTTP Basic authentication used with api.example.com"] == "Medium"
    assert found["No HSTS header from api.example.com"] == "Low"


# --- Logcat -----------------------------------------------------------------

# Assembled at runtime so the repo never contains a string in Stripe's live-key format.
STRIPE_LIKE = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc"

LEAKS = [
    "10-01 12:00:02.456  4321  4321 D Auth    : password=Dinesh@123$ user=dinesh",
    "10-01 12:00:03.000  4321  4321 I Api     : token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "10-01 12:00:04.500  4321  4321 D Net     : got key a8F3kL9qZ2xP7vB4nM6tR1wY from server",
    "10-01 12:00:04.600  4321  4321 D Pay     : using " + STRIPE_LIKE,
    "10-01 12:00:04.700  4321  4321 D Net     : sig dGhpc2lzYXNlY3JldGtleTEyMzQ1Ng==",
    "10-01 12:00:04.800  4321  4321 D User    : user_ssn=123-45-6789 className=LoginActivity",
    "10-01 12:00:04.900  4321  4321 I System.out: <html><body>session_token=Q9x7LmP2vR8kT4wZ1nB6cY3s</body></html>",
]


@pytest.mark.parametrize("line", LEAKS)
def test_logcat_leak_is_detected(line):
    assert rr.analyze_logcat([line]), line


def test_logcat_leaks_are_masked_in_report():
    for f in rr.analyze_logcat(LEAKS):
        line = f["metadata"].get("line", "")
        for secret in ("Dinesh@123$", "a8F3kL9qZ2xP7vB4nM6tR1wY", "Q9x7LmP2vR8kT4wZ1nB6cY3s"):
            assert secret not in line


def test_class_name_is_not_ssn():
    found = rr.analyze_logcat(["10-01 12:00:04.800  4321  4321 D Ui      : className=LoginActivity"])
    assert found == []


def test_real_device_logcat_has_no_false_positives():
    """1,189 real lines from an Android 13 emulator (system + InsecureBankv2 +
    AndroGoat sessions): native-loader paths, emulator capability names,
    frame stats, binder tokens, a logged web page. None are secrets."""
    lines = (FIXTURES / "logcat_noise.txt").read_text(errors="replace").splitlines()
    assert len(lines) > 1000
    found = rr.analyze_logcat(lines)
    assert found == [], [f["metadata"].get("line") for f in found]


# --- Storage hooks ----------------------------------------------------------------

APP = "owasp.sat.agoat.InsecureStorageSQLiteActivity.onClick"


def storage(api, **fields):
    return {"hook": "storage", "api": api, "caller": APP, **fields}


def test_sqlite_insert_with_password_column_is_high_and_masked():
    [f] = rr.analyze_frida_events([storage("SQLiteDatabase.insert", table="users", db="/data/user/0/x/databases/aGoat",
                                           values={"username": "goat", "password": "Goat@Pass99"})])
    assert f["severity"] == "High" and "users.password" in f["title"]
    assert "Goat@Pass99" not in str(f)


def test_raw_sql_with_inline_values_and_sensitive_column():
    found = titles(rr.analyze_frida_events([storage(
        "SQLiteDatabase.execSQL", db="/data/user/0/x/databases/aGoat", bind_args=[],
        sql="INSERT INTO users(username, password) VALUES('goat', 'Goat@Pass99')")]))
    assert found["Raw SQL with inline values in aGoat (SQL injection risk)"] == "Medium"
    assert found["Sensitive data written with raw SQL into aGoat"] == "High"
    assert "Goat@Pass99" not in str(found)


def test_create_table_is_info():
    [f] = rr.analyze_frida_events([storage("SQLiteDatabase.execSQL", db="/d/aGoat", sql="CREATE TABLE users(id INT)")])
    assert f["severity"] == "Info"


@pytest.mark.parametrize("path,severity", [
    ("/storage/emulated/0/Download/users.txt", "Medium"),
    ("/storage/emulated/0/Android/data/owasp.sat.agoat/files/x.txt", "Low"),
    ("/data/user/0/owasp.sat.agoat/files/x.txt", "Info"),
])
def test_file_writes_by_location(path, severity):
    [f] = rr.analyze_frida_events([storage("FileOutputStream", path=path)])
    assert f["severity"] == severity


def test_clipboard():
    assert rr.analyze_frida_events([storage("ClipboardManager.setPrimaryClip", text="hello world")])[0]["severity"] == "Medium"
    [f] = rr.analyze_frida_events([storage("ClipboardManager.setPrimaryClip", text="a8F3kL9qZ2xP7vB4nM6tR1wY")])
    assert f["severity"] == "High" and "a8F3kL9qZ2xP7vB4nM6tR1wY" not in str(f)


def test_library_storage_is_info():
    [f] = rr.analyze_frida_events([{"hook": "storage", "api": "SQLiteDatabase.insert", "table": "events",
                                    "values": {"token": "abc"}, "db": "/d/analytics",
                                    "caller": "com.google.android.gms.measurement.internal.zzx.a"}])
    assert f["severity"] == "Info" and "library" in f["title"]


# --- Android's own connectivity probes must not be blamed on the app ----------------

def probe(host, path):
    return {"method": "GET", "scheme": "http", "host": host, "url": f"http://{host}{path}",
            "request_headers": {}, "request_body": "", "status": 204, "response_headers": {}}


def test_android_connectivity_probes_are_summarised_not_flagged():
    flows = [probe("connectivitycheck.gstatic.com", "/generate_204")] * 20 + [
        probe("www.google.com", "/gen_204"), probe("play.googleapis.com", "/generate_204")]
    found = rr.analyze_traffic(flows)
    assert [f["severity"] for f in found] == ["Info"]
    assert "22 requests" in found[0]["title"]
    assert not any("Cleartext" in f["title"] for f in found)


def test_real_app_cleartext_traffic_is_still_flagged_next_to_probes():
    app = {**probe("demo.testfire.net", "/"), "url": "http://demo.testfire.net/"}
    found = titles(rr.analyze_traffic([app, probe("connectivitycheck.gstatic.com", "/generate_204")]))
    assert found["Cleartext HTTP traffic to demo.testfire.net"] == "Medium"
    assert not any("gstatic" in t for t in found if t.startswith("Cleartext"))


def test_only_the_probe_path_is_treated_as_system_traffic():
    # An app that really calls a Google host with a different path is still analyzed.
    flow = {**probe("www.google.com", "/search?q=x"), "url": "http://www.google.com/search?q=x"}
    assert "Cleartext HTTP traffic to www.google.com" in titles(rr.analyze_traffic([flow]))


def test_probe_host_the_app_itself_contacted_is_still_analyzed():
    flows = [probe("www.google.com", "/gen_204")]
    events = [{"hook": "http", "api": "OkHttp Request.Builder.url", "url": "http://www.google.com/gen_204"}]
    found = rr.analyze_traffic(flows, app_hosts=rr.app_hosts_from_events(events))
    assert "Cleartext HTTP traffic to www.google.com" in titles(found)
