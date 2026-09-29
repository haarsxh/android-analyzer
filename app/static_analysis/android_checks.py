"""Android Checks: manifest/config-level security rules over parsed APK data."""
from __future__ import annotations

from typing import Any


def run_checks(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    """Run manifest/config security rules against the parsed APK data.

    Returns a list of findings: {severity, title, description, metadata}.
    """
    findings: list[dict[str, Any]] = []

    if parsed.get("is_debuggable"):
        findings.append({
            "severity": "High",
            "title": "Application is debuggable",
            "description": "android:debuggable=\"true\" allows any user to attach a debugger "
                            "and inspect/modify the app's runtime, including reading memory "
                            "and calling arbitrary methods.",
            "metadata": {},
        })

    if parsed.get("allow_backup"):
        findings.append({
            "severity": "Medium",
            "title": "Application allows full backup",
            "description": "android:allowBackup=\"true\" lets app data be extracted via "
                            "'adb backup' on devices without a lock screen or with USB "
                            "debugging enabled.",
            "metadata": {},
        })

    if parsed.get("uses_cleartext_traffic"):
        findings.append({
            "severity": "Medium",
            "title": "Cleartext traffic permitted",
            "description": "android:usesCleartextTraffic=\"true\" (or unset on API < 28) "
                            "allows unencrypted HTTP traffic, exposing data to network "
                            "interception.",
            "metadata": {},
        })

    for comp_type, comps in (
        ("activity", parsed.get("activities", [])),
        ("service", parsed.get("services", [])),
        ("receiver", parsed.get("receivers", [])),
        ("provider", parsed.get("providers", [])),
    ):
        for comp in comps:
            if comp.get("exported") == "true" and not comp.get("permission"):
                findings.append({
                    "severity": "Medium",
                    "title": f"Exported {comp_type} without permission: {comp['name']}",
                    "description": f"This {comp_type} is exported (accessible to other apps) "
                                    "and does not require a permission to invoke it, which can "
                                    "allow unauthorized access or intent injection.",
                    "metadata": {"component": comp["name"], "type": comp_type},
                })

    findings += check_deep_links(parsed.get("activities", []))

    dangerous = parsed.get("dangerous_permissions", [])
    if dangerous:
        findings.append({
            "severity": "Low",
            "title": f"{len(dangerous)} dangerous permission(s) requested",
            "description": "The app requests permissions considered sensitive by the "
                            "Android permission model: " + ", ".join(dangerous),
            "metadata": {"permissions": dangerous},
        })

    min_sdk = parsed.get("min_sdk")
    try:
        if min_sdk is not None and int(min_sdk) < 23:
            findings.append({
                "severity": "Low",
                "title": f"Low minimum SDK version ({min_sdk})",
                "description": "A minSdkVersion below 23 (Android 6.0) allows installation "
                                "on devices lacking the runtime permission model and modern "
                                "platform security mitigations.",
                "metadata": {"min_sdk": min_sdk},
            })
    except (TypeError, ValueError):
        pass

    if not parsed.get("certificates"):
        findings.append({
            "severity": "Info",
            "title": "No signing certificate information found",
            "description": "Could not extract a signing certificate from the APK.",
            "metadata": {},
        })

    return findings


WEB_SCHEMES = {"http", "https"}


def check_deep_links(activities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flag deep links (custom URI schemes and App Links) on exported activities.

    Custom schemes are a classic hijack vector: any other app can register the
    same scheme and race to handle it, enabling phishing or intent-based
    account takeover. http(s) App Links without autoVerify skip Android's
    domain-ownership verification, so another app can register the same host.
    """
    findings: list[dict[str, Any]] = []

    for activity in activities:
        if activity.get("exported") != "true":
            continue
        for link in activity.get("deep_links", []):
            scheme = link.get("scheme", "")
            uri = f"{scheme}://{link.get('host') or ''}{link.get('path') or ''}"

            if scheme not in WEB_SCHEMES:
                findings.append({
                    "severity": "Medium",
                    "title": f"Custom URL scheme deep link: {scheme}://",
                    "description": f"Exported activity {activity['name']} handles the custom "
                                    f"URI scheme '{scheme}://' ({uri}). Any other installed app "
                                    "can register the same scheme and intercept these links, or "
                                    "a malicious app can craft intents to this activity directly "
                                    "— validate all deep-link parameters as untrusted input.",
                    "metadata": {"component": activity["name"], "scheme": scheme, "uri": uri},
                })
            elif not link.get("auto_verify"):
                findings.append({
                    "severity": "Low",
                    "title": f"App Link without autoVerify: {uri}",
                    "description": f"Exported activity {activity['name']} declares an http(s) "
                                    f"App Link ({uri}) without android:autoVerify=\"true\", so "
                                    "Android skips domain-ownership verification — another app "
                                    "can register the same host and intercept these links.",
                    "metadata": {"component": activity["name"], "scheme": scheme, "uri": uri},
                })

    return findings
