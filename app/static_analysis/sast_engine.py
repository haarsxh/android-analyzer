"""SAST Engine: decompiles the APK (apktool + jadx) and scans source for vulnerable patterns."""
from __future__ import annotations

import hashlib
import math
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from app.static_analysis.libraries import is_library_path, package_path

# Exact formats of well-known credentials. More precise than the keyword and
# entropy heuristics (an AWS access key ID, all caps + digits, has too little
# entropy for the entropy scan to notice), and each one names the provider
# so the finding says what the key unlocks. Severity reflects what a leaked
# key of that type typically allows.
PROVIDER_RULES: list[dict[str, Any]] = [
    {"id": "private-key", "severity": "Critical", "title": "Private key embedded in app",
     "pattern": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
     "impact": "Anyone with the APK can extract it and impersonate the key's owner (sign data, decrypt traffic, log in)."},
    {"id": "stripe-secret-key", "severity": "Critical", "title": "Stripe live secret key",
     "pattern": re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"),
     "impact": "Grants full API access to the Stripe account: charges, refunds, customer and payout data."},
    {"id": "aws-access-key-id", "severity": "High", "title": "AWS access key ID",
     "pattern": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
     "impact": "Paired with its secret key (often stored nearby) it grants the IAM user's AWS permissions."},
    {"id": "aws-secret-access-key", "severity": "Critical", "title": "AWS secret access key",
     "pattern": re.compile(r"""(?i)aws.{0,30}?(?:secret|sk).{0,20}?["'=:\s]([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"""),
     "group": 1,
     "impact": "With the access key ID, grants the IAM user's AWS permissions (S3 data, compute, billing)."},
    {"id": "google-oauth-client-secret", "severity": "High", "title": "Google OAuth client secret",
     "pattern": re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{28}\b"),
     "impact": "Lets an attacker impersonate the app in Google OAuth flows."},
    {"id": "firebase-server-key", "severity": "High", "title": "Firebase Cloud Messaging server key",
     "pattern": re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b"),
     "impact": "Allows sending push notifications to every user of the app."},
    {"id": "openai-api-key", "severity": "High", "title": "OpenAI API key",
     "pattern": re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b"
                           r"|\bsk-proj-[A-Za-z0-9_-]{40,}\b"),
     "impact": "Usage is billed to the key owner's account and exposes their API data."},
    {"id": "anthropic-api-key", "severity": "High", "title": "Anthropic API key",
     "pattern": re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b"),
     "impact": "Usage is billed to the key owner's account."},
    {"id": "github-token", "severity": "High", "title": "GitHub access token",
     "pattern": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"),
     "impact": "Grants the token's repository/organization access (source code, possibly write access)."},
    {"id": "slack-token", "severity": "High", "title": "Slack token",
     "pattern": re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
     "impact": "Can read and post messages in the Slack workspace."},
    {"id": "slack-webhook", "severity": "Medium", "title": "Slack incoming webhook URL",
     "pattern": re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
     "impact": "Anyone can post messages into the linked Slack channel (phishing, spam)."},
    {"id": "sendgrid-api-key", "severity": "High", "title": "SendGrid API key",
     "pattern": re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
     "impact": "Allows sending email as the app's domain (phishing that passes SPF/DKIM)."},
    {"id": "twilio-api-key", "severity": "High", "title": "Twilio API key",
     "pattern": re.compile(r"\bSK[0-9a-f]{32}\b"),
     "impact": "Allows sending SMS/calls billed to the account."},
    {"id": "google-api-key", "severity": "Medium", "title": "Google API key",
     "pattern": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
     "impact": "Often intentionally shipped (Maps, Firebase) — check it's restricted to this app's package and "
               "signature in Google Cloud Console, otherwise others can use it on your quota."},
    {"id": "stripe-test-key", "severity": "Low", "title": "Stripe test secret key",
     "pattern": re.compile(r"\bsk_test_[0-9A-Za-z]{24,}\b"),
     "impact": "Test-mode only (no real money), but indicates secret keys are being embedded in builds."},
]


def mask_secret(value: str) -> str:
    keep = 6 if len(value) > 12 else 2
    return value[:keep] + "*" * min(len(value) - keep, 16)


# Cheap first pass: every provider format starts with one of these markers,
# so most of the millions of decompiled lines skip all PROVIDER_RULES.
PROVIDER_PREFILTER = re.compile(
    r"PRIVATE KEY|_live_|_test_|AKIA|ASIA|(?i:aws)|GOCSPX-|AAAA|sk-|gh[pousr]_|github_pat_|xox[abprs]-"
    r"|hooks\.slack\.com|SG\.|SK[0-9a-f]{32}|AIza"
)


def provider_matches(text: str) -> list[tuple[dict[str, Any], str]]:
    """(rule, secret value) for every known-format credential in text."""
    if not PROVIDER_PREFILTER.search(text):
        return []
    out = []
    for rule in PROVIDER_RULES:
        for m in rule["pattern"].finditer(text):
            out.append((rule, m.group(rule.get("group", 0))))
    return out


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
        # Values may contain spaces ("This is the super secret key 123"), so
        # only applied in files that actually do encryption — elsewhere a
        # `key = "..."` string is usually a preference name or label.
        "id": "hardcoded-crypto-key",
        "severity": "High",
        "title": "Hardcoded encryption key",
        "pattern": re.compile(r"""\b\w*(?:key|Key|KEY)\w*\s*=\s*"[^"]{8,}\""""),
        "requires_in_file": re.compile(r"SecretKeySpec|Cipher\.getInstance"),
    },
    {
        "id": "static-iv",
        "severity": "High",
        "title": "Static (all-zero) initialization vector",
        "pattern": re.compile(
            r"""(?i)byte\[\]\s*\w*iv\w*\s*=\s*\{\s*(?:0x0*|0)(?:\s*,\s*(?:0x0*|0))+\s*\}"""
            r"""|new\s+IvParameterSpec\(\s*new\s+byte\[\s*\d+\s*\]\s*\)"""
        ),
        "requires_in_file": re.compile(r"IvParameterSpec"),
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
        "id": "certificate-pin",
        "severity": "Info",
        "title": "Certificate pin hash (certificate pinning in use)",
        "pattern": re.compile(r"""["']sha(?:256|1)/[A-Za-z0-9+/]{20,}={0,2}["']"""),
    },
    {
        "id": "cleartext-url",
        "severity": "Medium",
        "title": "Hardcoded cleartext HTTP URL",
        # Excludes loopback and XML namespace URIs (xmlns:android="http://schemas.android.com/...")
        # — identifiers that appear in nearly every resource file, never fetched over the network.
        "pattern": re.compile(
            r"""["']http://(?!localhost|127\.0\.0\.1|schemas\.android\.com|www\.w3\.org|xmlpull\.org"""
            r"""|ns\.adobe\.com|purl\.org|schemas\.microsoft\.com|schemas\.openxmlformats\.org)[^"']+["']"""
        ),
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
            result = subprocess.run(
                ["jadx", "-d", str(jadx_dir), apk_path],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == JADX_FINISHED_WITH_ERRORS and (jadx_dir / "sources").is_dir():
                # Normal for real apps (obfuscated or unusual bytecode): the
                # rest of the source is written and scanned as usual.
                m = re.search(r"ERROR - finished with errors, count: (\d+)", result.stdout + result.stderr)
                count = f"{m.group(1)} " if m else ""
                errors.append(f"jadx could not decompile {count}method(s); those are missing from code analysis "
                              "(the rest of the app was decompiled and scanned normally)")
            elif result.returncode != 0:
                errors.append(f"jadx failed (exit {result.returncode}): {(result.stderr or result.stdout)[-300:]}")
        except subprocess.TimeoutExpired:
            errors.append("jadx timed out after 300s; Java source analysis is incomplete")
    else:
        errors.append("jadx not found on PATH; Java source decompilation skipped")

    return {"apktool_dir": apktool_dir, "jadx_dir": jadx_dir, "errors": errors}


MAX_OCCURRENCES_LISTED = 5

# jadx exit code meaning "done, but some methods failed to decompile".
JADX_FINISHED_WITH_ERRORS = 3


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

        # File-level preconditions, checked once per file (not per line).
        skipped_for_file = {r["id"] for r in RULES if "requires_in_file" in r and not r["requires_in_file"].search(text)}

        rel_file = str(path.relative_to(root_dir))

        for lineno, line in enumerate(text.splitlines(), start=1):
            location = {"file": rel_file, "line": lineno}
            provider_hits = provider_matches(line)
            for rule, secret in provider_hits:
                # Grouped by the secret itself, not the line, so the same key
                # found in many files (or in both Java and smali) is one finding.
                key = (rule["id"], secret)
                if key not in groups:
                    groups[key] = {"rule": rule, "snippet": line.strip()[:200].replace(secret, mask_secret(secret)),
                                   "secret": secret, "occurrences": []}
                groups[key]["occurrences"].append(location)

            for rule in RULES:
                if provider_hits and rule["id"] in ("hardcoded-secret", "hardcoded-crypto-key"):
                    continue  # already reported precisely by the provider rule
                if rule["id"] in skipped_for_file:
                    continue
                if rule["pattern"].search(line):
                    snippet = line.strip()[:200]
                    key = (rule["id"], snippet)
                    if key not in groups:
                        groups[key] = {
                            "rule": rule,
                            "snippet": snippet,
                            "occurrences": [],
                        }
                    groups[key]["occurrences"].append(location)

    return [_group_to_finding(rule_id, group) for (rule_id, _), group in groups.items()]


SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]
LIBRARY_SUFFIX = " — library code only"


def downgrade(severity: str) -> str:
    return SEVERITY_ORDER[max(0, SEVERITY_ORDER.index(severity) - 1)]


def _title(base: str, count: int, origin: str) -> str:
    return base + (f" ({count} occurrences)" if count > 1 else "") + (LIBRARY_SUFFIX if origin == "library" else "")


def _library_note_end(original_severity: str) -> str:
    return f"severity lowered from {original_severity}. "


def _origin(occurrences: list[dict[str, Any]]) -> str:
    """'library' only if every occurrence is in a bundled library package."""
    return "library" if occurrences and all(is_library_path(o["file"]) for o in occurrences) else "app"


def _library_names(occurrences: list[dict[str, Any]]) -> list[str]:
    names = set()
    for o in occurrences:
        pkg = package_path(o["file"]) or ""
        names.add(".".join(pkg.split("/")[:2]))
    return sorted(names)[:5]


def _group_to_finding(rule_id: str, group: dict[str, Any]) -> dict[str, Any]:
    rule = group["rule"]
    occurrences = group["occurrences"]
    count = len(occurrences)
    origin = _origin(occurrences)
    title = _title(rule["title"], count, origin)
    where = f"{occurrences[0]['file']} at line {occurrences[0]['line']}"
    metadata = {
        "rule_id": rule_id,
        "snippet": group["snippet"],
        "occurrence_count": count,
        "occurrences": occurrences[:MAX_OCCURRENCES_LISTED],
        "origin": origin,
        "original_severity": rule["severity"],
        "rule_title": rule["title"],
    }
    if "secret" in group:
        description = (f"Found '{mask_secret(group['secret'])}' in {where}. {rule['impact']} "
                       "Rotate the key, then move it server-side — anything in an APK is public.")
        metadata["secret_preview"] = mask_secret(group["secret"])
        metadata["secret_sha256"] = hashlib.sha256(group["secret"].encode()).hexdigest()
    else:
        description = f"Rule '{rule_id}' matched {count} time(s), e.g. in {where}."
    severity = rule["severity"]
    if origin == "library":
        severity = downgrade(severity)
        description = (f"Only found in bundled library code ({', '.join(_library_names(occurrences))}), not the "
                       f"app's own code — {_library_note_end(rule['severity'])}" + description)
    return {"severity": severity, "title": title, "description": description, "metadata": metadata}


def collapse_library_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One finding per rule for library-only matches.

    App-code findings stay one-per-distinct-match (each is something the
    developer should look at); library matches are background context, and
    listing every URL string inside Google Play Services as its own row buried
    the app's real issues (InsecureBankv2: 48 library rows vs 2 app rows).
    """
    out, by_rule = [], {}
    for f in findings:
        m = f.get("metadata", {})
        if m.get("origin") != "library":
            out.append(f)
            continue
        group = by_rule.setdefault(m["rule_id"], {"first": f, "count": 0, "occurrences": [], "snippets": []})
        group["count"] += m.get("occurrence_count", 1)
        group["occurrences"].extend(m.get("occurrences", []))
        if len(group["snippets"]) < 3 and m.get("snippet"):
            group["snippets"].append(m["snippet"])
    for rule_id, g in by_rule.items():
        first = g["first"]
        libs = _library_names(g["occurrences"])
        out.append({
            "severity": first["severity"],
            "title": _title(first["metadata"]["rule_title"], g["count"], "library"),
            "description": (f"Matched {g['count']} time(s), only in bundled library code ({', '.join(libs)}), "
                            f"not the app's own code — {_library_note_end(first['metadata']['original_severity'])}"
                            "Usually not fixable by the app developer beyond updating the library."),
            "metadata": {
                **first["metadata"],
                "snippet": " | ".join(g["snippets"]),
                "occurrence_count": g["count"],
                "occurrences": g["occurrences"][:MAX_OCCURRENCES_LISTED],
                "libraries": libs,
            },
        })
    return out


def merge_secret_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge provider-key findings for the same secret found by separate
    scans (decompiled Java and smali), summing their occurrences — and drop
    entropy findings for a value a provider rule already identified."""
    named = {f["metadata"]["secret_sha256"] for f in findings if f.get("metadata", {}).get("secret_sha256")}
    findings = [f for f in findings if f.get("metadata", {}).get("value_sha256") not in named]
    merged: dict[tuple, dict[str, Any]] = {}
    out = []
    for f in findings:
        digest = f.get("metadata", {}).get("secret_sha256")
        if not digest:
            out.append(f)
            continue
        key = (f["metadata"]["rule_id"], digest)
        if key not in merged:
            merged[key] = f
            out.append(f)
            continue
        base = merged[key]["metadata"]
        base["occurrence_count"] += f["metadata"]["occurrence_count"]
        base["occurrences"] = (base["occurrences"] + f["metadata"]["occurrences"])[:MAX_OCCURRENCES_LISTED]
        if f["metadata"]["origin"] == "app" and base["origin"] == "library":
            # Also present in app code: restore full severity and drop the library note.
            base["origin"] = "app"
            merged[key]["severity"] = base["original_severity"]
            merged[key]["description"] = merged[key]["description"].split(_library_note_end(base["original_severity"]), 1)[-1]
    for f in merged.values():
        m = f["metadata"]
        f["title"] = _title(m["rule_title"], m["occurrence_count"], m["origin"])
    return out


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
# Public certificate-pin hashes (reported separately by the certificate-pin rule).
EXCLUDE_PREFIXES = ("sha256/", "sha1/")
# Runs of a character set (base64/hex alphabets, test vectors) score high entropy but aren't secrets.
ALPHABET_RUNS = ("ABCDEFGHIJ", "abcdefghij", "0123456789", "QRSTUVWXYZ", "qrstuvwxyz")
# Kotlin mangles functions taking inline/unsigned types: "countLeadingZeroBits-7apg3OU".
KOTLIN_MANGLED_RE = re.compile(r"[a-z][A-Za-z0-9]*-[A-Za-z0-9_]{5,8}")
# Slash-separated class/resource paths: "kotlin/io/encoding/StreamEncodingKt".
# Package segments are lowercase — mixed-case segments ("ByD3U8Y1/AgbpCyfy...")
# are base64, which legitimately contains '/', and must still be scanned.
CLASS_PATH_RE = re.compile(r"[a-z][a-z0-9_]*(?:/[a-z][a-z0-9_]*)+(?:/[A-Za-z_$][\w$]*)?/?")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _looks_like_secret(candidate: str) -> bool:
    if any(sub in candidate for sub in EXCLUDE_SUBSTRINGS):
        return False
    if candidate.startswith(EXCLUDE_PREFIXES) or any(run in candidate for run in ALPHABET_RUNS):
        return False
    if KOTLIN_MANGLED_RE.fullmatch(candidate) or CLASS_PATH_RE.fullmatch(candidate):
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
        if is_library_path(path.relative_to(root_dir)):
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue

        for lineno, line in enumerate(text.splitlines(), start=1):
            for match in STRING_LITERAL_RE.finditer(line):
                candidate = match.group(1)
                if _looks_like_secret(candidate) and not provider_matches(candidate):
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
                "value_sha256": hashlib.sha256(candidate.encode()).hexdigest(),
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
    findings = collapse_library_findings(merge_secret_findings(findings))
    findings += library_detector.detect(decomp["jadx_dir"] / "sources")
    findings += native_lib_scanner.scan_libs(decomp["apktool_dir"] / "lib")

    domains = extract_domains(decomp["jadx_dir"], (".java",))
    domains |= extract_domains(decomp["apktool_dir"], (".smali", ".xml"))

    return {
        "findings": findings, "errors": decomp["errors"], "domains": domains,
        "jadx_dir": decomp["jadx_dir"], "apktool_dir": decomp["apktool_dir"],
    }
