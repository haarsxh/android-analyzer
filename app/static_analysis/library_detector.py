"""Library Detection: identifies bundled third-party SDKs by decompiled package tree
and flags packages with a history of known CVEs for manual version verification.

This works from the jadx-decompiled source tree's package layout rather than a live
CVE feed, since exact library *versions* aren't reliably recoverable from decompiled
code alone — findings here are identification + "check this" flags, not confirmed CVEs.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

# package prefix -> (human name, informational note)
KNOWN_LIBRARIES: dict[str, tuple[str, str]] = {
    "com/google/android/gms": ("Google Play Services", "Google's core mobile services SDK."),
    "com/google/firebase": ("Firebase", "Google's app development platform (analytics, auth, database, etc)."),
    "com/facebook": ("Facebook SDK", "Meta's SDK for Facebook Login/Graph API/Ads integration."),
    "com/squareup/okhttp": ("OkHttp (legacy package)", "HTTP client library."),
    "okhttp3": ("OkHttp3", "HTTP client library."),
    "retrofit2": ("Retrofit", "Type-safe HTTP client for Android/Java."),
    "com/squareup/picasso": ("Picasso", "Image loading/caching library."),
    "com/bumptech/glide": ("Glide", "Image loading/caching library."),
    "com/google/gson": ("Gson", "JSON serialization library."),
    "org/apache/commons": ("Apache Commons", "Java utility libraries (check specific commons-* module)."),
    "com/google/ads": ("Google Mobile Ads (legacy)", "Ad-serving SDK."),
    "com/mopub": ("MoPub SDK", "Ad-mediation SDK (end-of-life; historically many disclosed vulnerabilities)."),
    "com/unity3d/ads": ("Unity Ads", "Ad-serving SDK bundled with Unity-based apps."),
    "com/crashlytics": ("Crashlytics", "Crash reporting SDK."),
    "io/fabric": ("Fabric", "Crash/analytics SDK (deprecated, folded into Firebase)."),
    "com/adjust/sdk": ("Adjust SDK", "Mobile attribution/analytics SDK."),
    "com/appsflyer": ("AppsFlyer SDK", "Mobile attribution/analytics SDK."),
    "com/braintreepayments": ("Braintree", "Payment processing SDK."),
    "com/stripe": ("Stripe SDK", "Payment processing SDK."),
}

# Package prefixes with a notable history of disclosed CVEs where the bundled
# version can't be determined from decompiled code — flagged for manual review.
CVE_WATCH: dict[str, str] = {
    "org/apache/commons/collections": (
        "Apache Commons Collections has a well-known unsafe-deserialization RCE "
        "history (CVE-2015-7501 and related). Verify the bundled version is patched."
    ),
    "com/mopub": (
        "MoPub SDK reached end-of-life in 2023 with several historically disclosed "
        "vulnerabilities (ad-fraud, insecure data handling). Verify this dependency "
        "is still necessary and update/replace it."
    ),
    "com/facebook": (
        "Older Facebook SDK versions had disclosed vulnerabilities including "
        "insecure local broadcast handling (e.g. CVE-2014-4948 access-token exposure). "
        "Verify the bundled SDK version is current."
    ),
}


def detect(jadx_sources_dir: Path) -> list[dict[str, Any]]:
    """Walk the decompiled source tree and identify bundled third-party libraries."""
    if not jadx_sources_dir.exists():
        return []

    present_prefixes: set[str] = set()
    for prefix in list(KNOWN_LIBRARIES.keys()) + list(CVE_WATCH.keys()):
        if (jadx_sources_dir / prefix).exists():
            present_prefixes.add(prefix)

    findings: list[dict[str, Any]] = []

    for prefix, (name, note) in KNOWN_LIBRARIES.items():
        if prefix in present_prefixes:
            findings.append({
                "severity": "Info",
                "title": f"Bundled library detected: {name}",
                "description": note,
                "metadata": {"package_prefix": prefix},
            })

    for prefix, note in CVE_WATCH.items():
        if prefix in present_prefixes:
            findings.append({
                "severity": "Medium",
                "title": f"Bundled library with known CVE history: {prefix.replace('/', '.')}",
                "description": note,
                "metadata": {"package_prefix": prefix},
            })

    return findings
