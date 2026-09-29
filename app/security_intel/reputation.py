"""Reputation Service client: optional hash-reputation lookup (e.g. VirusTotal).

No-ops (returns None) unless REPUTATION_API_KEY is configured, so the tool
works fully offline with local heuristics only by default.
"""
from __future__ import annotations

import os
from typing import Any

import urllib.request
import urllib.error
import json

VT_API_KEY = os.environ.get("REPUTATION_API_KEY", "")
VT_HASH_URL = "https://www.virustotal.com/api/v3/files/{sha256}"


def lookup_hash(sha256: str) -> dict[str, Any] | None:
    """Query a public hash-reputation API if an API key is configured.

    Returns a finding dict, or None if no key is set / the lookup fails /
    there's nothing noteworthy.
    """
    if not VT_API_KEY:
        return None

    req = urllib.request.Request(
        VT_HASH_URL.format(sha256=sha256),
        headers={"x-apikey": VT_API_KEY},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        return {
            "severity": "Info",
            "title": "Reputation lookup failed",
            "description": f"HTTP {e.code} from reputation service",
            "metadata": {},
        }
    except (urllib.error.URLError, TimeoutError, ValueError):
        return None

    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious == 0 and suspicious == 0:
        return None

    severity = "Critical" if malicious > 0 else "Medium"
    return {
        "severity": severity,
        "title": f"Reputation service flagged this sample ({malicious} malicious, {suspicious} suspicious)",
        "description": "The uploaded APK's hash was flagged by one or more engines in the "
                        "configured reputation service.",
        "metadata": {"stats": stats},
    }
