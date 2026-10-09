"""Static secret / URL rules, including the false positives AndroGoat exposed."""
from __future__ import annotations

import pytest

from app.static_analysis import sast_engine as se


@pytest.mark.parametrize("candidate", [
    "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc",  # assembled: no live-format key in the repo
    "OviCwsFNWeoCSDKl3ZoD8j4BPnc1kCsfV+lOABCw",                           # AndroGoat's AWS-style key
    "ByD3U8Y1/AgbpCyfyeSVz8sgQxwJtj0KeOq39mxS8/W2V8R59wcMIr3KMkSY7Pjq",   # base64 containing '/'
    "a8F3kL9qZ2xP7vB4nM6tR1wY",
])
def test_real_secrets_are_kept(candidate):
    assert se._looks_like_secret(candidate)


@pytest.mark.parametrize("candidate", [
    "countLeadingZeroBits-7apg3OU",          # Kotlin mangled name
    "reduceRightOrNull-ELGow60",
    "kotlin/io/encoding/StreamEncodingKt",   # class path
    "sha256/5gsjyidrmWjcLRClfCk+Dd6O0nx1CyFrVUW5wVkwEx0=",  # public certificate pin
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
])
def test_non_secrets_are_dropped(candidate):
    assert not se._looks_like_secret(candidate)


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_entropy_scan_skips_library_packages(tmp_path):
    _write(tmp_path, "sources/kotlin/Foo.java", 'String s = "a8F3kL9qZ2xP7vB4nM6tR1wY";')
    _write(tmp_path, "sources/com/example/app/Keys.java", 'String s = "a8F3kL9qZ2xP7vB4nM6tR1wY";')
    found = se.scan_entropy_secrets(tmp_path, (".java",))
    assert [o["file"] for f in found for o in f["metadata"]["occurrences"]] == ["sources/com/example/app/Keys.java"]


def rule_ids(findings):
    return sorted(f["metadata"]["rule_id"] for f in findings)


def test_xml_namespaces_are_not_cleartext_urls(tmp_path):
    _write(tmp_path, "res/layout/main.xml",
           '<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android" />')
    assert "cleartext-url" not in rule_ids(se.scan_source(tmp_path))


def test_real_cleartext_url_is_flagged(tmp_path):
    _write(tmp_path, "sources/a/B.java", 'private String httpurl = "http://demo.testfire.net";')
    assert "cleartext-url" in rule_ids(se.scan_source(tmp_path))


def test_certificate_pin_is_info_not_secret(tmp_path):
    _write(tmp_path, "sources/a/B.java", 'add("owasp.org", "sha256/5gsjyidrmWjcLRClfCk+Dd6O0nx1CyFrVUW5wVkwEx0=");')
    [pin] = [f for f in se.scan_source(tmp_path) if f["metadata"]["rule_id"] == "certificate-pin"]
    assert pin["severity"] == "Info"
    assert se.scan_entropy_secrets(tmp_path, (".java",)) == []


CRYPTO_FILE = '''
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
public class CryptoClass {
    String key = "This is the super secret key 123";
    byte[] ivBytes = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    AlgorithmParameterSpec ivSpec = new IvParameterSpec(new byte[16]);
}
'''


def test_insecurebank_crypto_weaknesses(tmp_path):
    """InsecureBankv2's CryptoClass: hardcoded key (with spaces) and an all-zero IV."""
    _write(tmp_path, "sources/com/android/insecurebankv2/CryptoClass.java", CRYPTO_FILE)
    ids = rule_ids(se.scan_source(tmp_path))
    assert "hardcoded-crypto-key" in ids
    assert ids.count("static-iv") == 2


def test_key_strings_outside_crypto_files_are_ignored(tmp_path):
    _write(tmp_path, "sources/com/example/Prefs.java", 'String prefKey = "remember_me_checkbox";')
    assert "hardcoded-crypto-key" not in rule_ids(se.scan_source(tmp_path))
