"""Firebase Misconfiguration Check: finds hardcoded Firebase Realtime Database
URLs in the app and probes whether the database is publicly readable —
one of the most common real-world Android app misconfigurations.

Offline-safe like reputation.py/geolocation.py: the probe is time-boxed and
any network failure just means no finding, never a failed scan.
"""
from __future__ import annotations

import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

FIREBASE_URL_RE = re.compile(r'https?://([a-z0-9\-]+)\.(firebaseio\.com|firebasedatabase\.app)')
HTTP_TIMEOUT_SECONDS = 5
MAX_DATABASES = 5


def extract_firebase_urls(root_dir: Path, extensions: tuple[str, ...] = (".java", ".smali", ".xml")) -> set[str]:
    """Find distinct Firebase Realtime Database base URLs referenced in the decompiled source."""
    urls: set[str] = set()
    if not root_dir.exists():
        return urls

    for path in root_dir.rglob("*"):
        if not path.is_file() or path.suffix not in extensions:
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for match in FIREBASE_URL_RE.finditer(text):
            urls.add(f"https://{match.group(1)}.{match.group(2)}")
    return urls


def probe_database(base_url: str) -> dict[str, Any] | None:
    """GET <base_url>/.json?shallow=true — Firebase returns actual data (or `null`)
    when read rules are open, and a permission-denied error when they're locked down."""
    probe_url = f"{base_url}/.json?shallow=true"
    try:
        req = urllib.request.Request(probe_url, headers={"User-Agent": "android-analyzer"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            body = resp.read(2048).decode(errors="ignore")
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
        body = e.read(2048).decode(errors="ignore") if e.fp else ""
    except (urllib.error.URLError, TimeoutError, OSError):
        return None

    is_denied = status in (401, 403) or "permission_denied" in body.lower() or "unauthorized" in body.lower()
    return {"url": base_url, "status": status, "publicly_readable": status == 200 and not is_denied, "sample": body[:200]}


def check_firebase(root_dirs: list[Path]) -> list[dict[str, Any]]:
    """Extract Firebase DB URLs from the given source roots and probe up to
    MAX_DATABASES of them for public read access."""
    urls: set[str] = set()
    for root in root_dirs:
        urls |= extract_firebase_urls(root)

    findings: list[dict[str, Any]] = []
    for base_url in sorted(urls)[:MAX_DATABASES]:
        result = probe_database(base_url)
        if result is None:
            continue
        if result["publicly_readable"]:
            findings.append({
                "severity": "Critical",
                "title": f"Publicly readable Firebase database: {base_url}",
                "description": f"The Firebase Realtime Database at {base_url} responded with "
                                "HTTP 200 to an unauthenticated read request — its security "
                                "rules appear to allow public read access. Anyone can download "
                                "the entire database. Review the database's rules "
                                "(`.read`/`.write`) immediately.",
                "metadata": result,
            })
        else:
            findings.append({
                "severity": "Info",
                "title": f"Firebase database found, access properly restricted: {base_url}",
                "description": f"The Firebase Realtime Database at {base_url} was referenced "
                                "in the app but an unauthenticated read request was denied "
                                f"(HTTP {result['status']}), suggesting read rules are locked down.",
                "metadata": result,
            })
    return findings
