"""Server Geolocation: resolves domains found in the app to IPs and looks up
their country/city/ISP via a free public API (ip-api.com, no key required).

Best-effort and offline-safe: DNS resolution and the geolocation lookup are
both time-boxed, and any failure (no internet, rate-limited, domain doesn't
resolve) just means fewer/no location findings — it never fails the scan.
"""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from typing import Any

DNS_TIMEOUT_SECONDS = 3
HTTP_TIMEOUT_SECONDS = 5
MAX_DOMAINS = 15
IP_API_BATCH_URL = "http://ip-api.com/batch?fields=status,country,countryCode,city,isp,org,query"

# Domains that resolve but aren't meaningful "app server" locations.
SKIP_DOMAINS = {"localhost", "schemas.android.com", "www.w3.org", "xmlpull.org"}


def resolve_domain(domain: str) -> str | None:
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT_SECONDS)
        return socket.gethostbyname(domain)
    except (socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(None)


def locate_ips(domain_to_ip: dict[str, str]) -> list[dict[str, Any]]:
    """Batch-query ip-api.com for country/city/ISP of each resolved IP."""
    if not domain_to_ip:
        return []

    ips = list(domain_to_ip.values())
    body = json.dumps(ips).encode()
    req = urllib.request.Request(
        IP_API_BATCH_URL, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            results = json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return []

    ip_to_domain = {ip: dom for dom, ip in domain_to_ip.items()}
    located = []
    for r in results:
        if r.get("status") != "success":
            continue
        ip = r.get("query")
        located.append({
            "domain": ip_to_domain.get(ip, ip),
            "ip": ip,
            "country": r.get("country"),
            "country_code": r.get("countryCode"),
            "city": r.get("city"),
            "isp": r.get("isp"),
            "org": r.get("org"),
        })
    return located


def geolocate_domains(domains: set[str]) -> list[dict[str, Any]]:
    """Resolve up to MAX_DOMAINS domains and return geolocation findings."""
    candidates = sorted(d for d in domains if d and d not in SKIP_DOMAINS)[:MAX_DOMAINS]

    domain_to_ip = {}
    for domain in candidates:
        ip = resolve_domain(domain)
        if ip:
            domain_to_ip[domain] = ip

    located = locate_ips(domain_to_ip)

    findings = []
    for entry in located:
        location = ", ".join(filter(None, [entry.get("city"), entry.get("country")]))
        findings.append({
            "severity": "Info",
            "title": f"Server location: {entry['domain']} → {location or 'unknown'}",
            "description": f"{entry['domain']} resolves to {entry['ip']}, hosted by "
                            f"{entry.get('isp') or entry.get('org') or 'an unknown provider'} "
                            f"in {location or 'an unresolved location'}.",
            "metadata": entry,
        })
    return findings
