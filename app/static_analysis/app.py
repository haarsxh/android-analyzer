"""Android Parsing: manifest, permissions, components, cert info via androguard."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from androguard.core.apk import APK

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _android_attr(element, attr: str) -> str | None:
    return element.get(f"{{{ANDROID_NS}}}{attr}")


DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
}


def file_hashes(path: str) -> dict[str, str]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def parse_apk(apk_path: str) -> dict[str, Any]:
    """Parse manifest, permissions, components, and certs from an APK."""
    apk = APK(apk_path)
    manifest_root = apk.get_android_manifest_xml()

    permissions = apk.get_permissions()
    dangerous = sorted(set(permissions) & DANGEROUS_PERMISSIONS)

    activities = _components(manifest_root, apk.get_activities(), "activity")
    services = _components(manifest_root, apk.get_services(), "service")
    receivers = _components(manifest_root, apk.get_receivers(), "receiver")
    providers = _components(manifest_root, apk.get_providers(), "provider")

    certs = []
    try:
        for cert in apk.get_certificates():
            certs.append({
                "subject": getattr(cert.subject, "human_friendly", str(cert.subject)),
                "issuer": getattr(cert.issuer, "human_friendly", str(cert.issuer)),
                "serial_number": str(cert.serial_number),
                "not_before": str(cert.not_valid_before) if hasattr(cert, "not_valid_before") else None,
                "not_after": str(cert.not_valid_after) if hasattr(cert, "not_valid_after") else None,
                "sha256": cert.sha256.hex() if hasattr(cert, "sha256") else None,
            })
    except Exception:
        pass

    return {
        "package_name": apk.get_package(),
        "app_name": apk.get_app_name(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "max_sdk": apk.get_max_sdk_version(),
        "is_debuggable": _manifest_flag(manifest_root, "debuggable"),
        "allow_backup": _manifest_flag(manifest_root, "allowBackup"),
        "uses_cleartext_traffic": _manifest_flag(manifest_root, "usesCleartextTraffic"),
        "permissions": sorted(permissions),
        "dangerous_permissions": dangerous,
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "providers": providers,
        "main_activity": apk.get_main_activity(),
        "certificates": certs,
        **file_hashes(apk_path),
        "file_size": Path(apk_path).stat().st_size,
    }


def _components(manifest_root, names: list[str], tag: str) -> list[dict[str, Any]]:
    out = []
    elements_by_name = {}
    for el in manifest_root.findall(f"application/{tag}"):
        name = _android_attr(el, "name")
        if name:
            elements_by_name[name] = el

    for name in names:
        el = elements_by_name.get(name)
        exported_attr = _android_attr(el, "exported") if el is not None else None
        permission = _android_attr(el, "permission") if el is not None else None
        has_intent_filter = el is not None and el.find("intent-filter") is not None

        if exported_attr is not None:
            exported = exported_attr.lower() == "true"
        else:
            # Android's implicit-export rule: a component with an
            # intent-filter and no explicit android:exported is exported.
            exported = has_intent_filter

        deep_links = _extract_deep_links(el) if el is not None else []

        out.append({
            "name": name,
            "exported": "true" if exported else "false",
            "permission": permission,
            "deep_links": deep_links,
        })
    return out


def _extract_deep_links(el) -> list[dict[str, Any]]:
    """Collect <data> scheme/host/path entries from every intent-filter on this component."""
    links = []
    for intent_filter in el.findall("intent-filter"):
        has_browsable = any(
            _android_attr(cat, "name") == "android.intent.category.BROWSABLE"
            for cat in intent_filter.findall("category")
        )
        for data in intent_filter.findall("data"):
            scheme = _android_attr(data, "scheme")
            host = _android_attr(data, "host")
            path = _android_attr(data, "path") or _android_attr(data, "pathPrefix") or _android_attr(data, "pathPattern")
            if scheme:
                links.append({
                    "scheme": scheme,
                    "host": host,
                    "path": path,
                    "browsable": has_browsable,
                    "auto_verify": _android_attr(intent_filter, "autoVerify") == "true",
                })
    return links


def _manifest_flag(manifest_root, attr: str) -> bool | None:
    app_element = manifest_root.find("application")
    if app_element is None:
        return None
    value = _android_attr(app_element, attr)
    if value is None:
        return None
    return value.lower() == "true"
