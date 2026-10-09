"""Provider-specific credential rules.

Sample keys are assembled at runtime so this file never contains a string
that looks like a live credential (which secret scanners / push protection
would rightly flag).
"""
from __future__ import annotations

import pytest

from app.static_analysis import sast_engine as se

X = "x7Kp2mQ9"  # filler with letters + digits

SAMPLES = {
    "private-key": "-----BEGIN RSA " + "PRIVATE KEY-----",
    "stripe-secret-key": "sk_" + "live_" + X * 3,
    "aws-access-key-id": "AKIA" + "X56QKKOLPQ7G7ABC",
    "google-oauth-client-secret": "GOCSPX-" + (X * 4)[:28],
    "openai-api-key": "sk-proj-" + X * 6,
    "anthropic-api-key": "sk-ant-api03-" + X * 11,
    "github-token": "ghp_" + (X * 5)[:36],
    "slack-token": "xoxb-" + "1234567890-" + X,
    "sendgrid-api-key": "SG." + (X * 3)[:22] + "." + (X * 6)[:43],
    "twilio-api-key": "SK" + "0123456789abcdef" * 2,
    "google-api-key": "AIza" + (X * 5)[:35],
    "stripe-test-key": "sk_" + "test_" + X * 3,
}


@pytest.mark.parametrize("rule_id,value", SAMPLES.items())
def test_provider_formats_are_recognized(rule_id, value):
    assert rule_id in [rule["id"] for rule, _ in se.provider_matches(f'String k = "{value}";')]


def test_aws_secret_needs_aws_context():
    secret = "OviCwsFNWeoCSDKl3ZoD8j4BPnc1kCsfV+lOABCw"  # AndroGoat's (deliberately leaked) sample key
    assert [r["id"] for r, _ in se.provider_matches(f'aws_secret_access_key = "{secret}";')] == ["aws-secret-access-key"]
    assert se.provider_matches(f'String unrelated = "{secret}";') == []


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def test_secret_is_masked_and_replaces_generic_rule(tmp_path):
    key = SAMPLES["stripe-secret-key"]
    _write(tmp_path, "sources/com/example/Pay.java", f'String api_key = "{key}";')
    found = se.scan_source(tmp_path, (".java",))
    assert [f["metadata"]["rule_id"] for f in found] == ["stripe-secret-key"]  # not also hardcoded-secret
    [f] = found
    assert f["severity"] == "Critical"
    assert key not in f["description"] and key not in str(f["metadata"])


def test_same_key_in_java_and_smali_is_one_finding(tmp_path):
    key = SAMPLES["aws-access-key-id"]
    _write(tmp_path / "jadx", "sources/com/example/Cloud.java", f'String id = "{key}";')
    _write(tmp_path / "apktool", "smali/com/example/Cloud.smali", f'const-string v0, "{key}"')
    found = se.merge_secret_findings(
        se.scan_source(tmp_path / "jadx", (".java",)) + se.scan_source(tmp_path / "apktool", (".smali",))
    )
    [f] = [f for f in found if f["metadata"]["rule_id"] == "aws-access-key-id"]
    assert f["metadata"]["occurrence_count"] == 2


def test_entropy_finding_dropped_when_provider_rule_names_the_value(tmp_path):
    secret = "OviCwsFNWeoCSDKl3ZoD8j4BPnc1kCsfV+lOABCw"
    _write(tmp_path, "sources/com/example/Cloud.java", f'private final String aws_secret_access_key = "{secret}";')
    found = se.merge_secret_findings(
        se.scan_source(tmp_path, (".java",)) + se.scan_entropy_secrets(tmp_path, (".java",))
    )
    assert [f["metadata"]["rule_id"] for f in found] == ["aws-secret-access-key"]
