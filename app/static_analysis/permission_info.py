"""Permission risk descriptions: what each Android permission actually lets an app do,
so the report can explain *why* a requested permission is risky, not just that it's dangerous."""
from __future__ import annotations

from typing import Any

# permission -> (risk, short description)
# risk: "Critical" | "High" | "Medium" | "Low"
PERMISSION_INFO: dict[str, tuple[str, str]] = {
    "android.permission.READ_SMS": ("Critical", "Can read all SMS messages, including one-time passcodes and 2FA codes sent by banks and other services."),
    "android.permission.RECEIVE_SMS": ("Critical", "Can intercept incoming SMS messages in real time, including one-time passcodes."),
    "android.permission.SEND_SMS": ("Critical", "Can send SMS messages without user confirmation — abused for premium-rate SMS fraud."),
    "android.permission.RECEIVE_MMS": ("High", "Can intercept incoming MMS messages."),
    "android.permission.READ_CALL_LOG": ("High", "Can read the full call history, including numbers dialed and received."),
    "android.permission.WRITE_CALL_LOG": ("Medium", "Can modify or delete call history."),
    "android.permission.CALL_PHONE": ("Medium", "Can place phone calls without going through the dialer UI."),
    "android.permission.ANSWER_PHONE_CALLS": ("Medium", "Can answer incoming calls programmatically."),
    "android.permission.PROCESS_OUTGOING_CALLS": ("High", "Can see and redirect the number being dialed on outgoing calls."),
    "android.permission.READ_PHONE_STATE": ("Medium", "Can read the device's phone number, IMEI, and call state — commonly used for device fingerprinting."),
    "android.permission.ACCESS_FINE_LOCATION": ("High", "Can determine precise GPS location."),
    "android.permission.ACCESS_COARSE_LOCATION": ("Medium", "Can determine approximate (network-based) location."),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("Critical", "Can track location even when the app is not in use."),
    "android.permission.READ_CONTACTS": ("High", "Can read the entire contact list."),
    "android.permission.WRITE_CONTACTS": ("Medium", "Can add, modify, or delete contacts."),
    "android.permission.GET_ACCOUNTS": ("Medium", "Can list accounts registered on the device (e.g. Google accounts)."),
    "android.permission.CAMERA": ("High", "Can capture photos and video via the camera."),
    "android.permission.RECORD_AUDIO": ("Critical", "Can record audio from the microphone."),
    "android.permission.BODY_SENSORS": ("Medium", "Can access body sensor data (heart rate, etc)."),
    "android.permission.ACTIVITY_RECOGNITION": ("Low", "Can detect physical activity (walking, driving, etc)."),
    "android.permission.READ_EXTERNAL_STORAGE": ("Medium", "Can read files on shared/external storage, including other apps' downloaded files and media."),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("Medium", "Can write/delete files on shared/external storage."),
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("Critical", "Can read and write essentially all files on the device, bypassing scoped storage."),
    "android.permission.SYSTEM_ALERT_WINDOW": ("Critical", "Can draw over other apps — used in overlay/phishing and tapjacking attacks."),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("Critical", "Can prompt the user to install other APKs — a path for unwanted/malicious app installs."),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("Critical", "Can read screen content and perform actions on behalf of the user — the most powerful and most abused Android permission for banking trojans."),
    "android.permission.BIND_DEVICE_ADMIN": ("Critical", "Can enforce device-admin policies (wipe device, lock screen, disable camera) and strongly resist uninstallation."),
    "android.permission.WRITE_SETTINGS": ("Medium", "Can modify system settings."),
    "android.permission.BLUETOOTH_CONNECT": ("Low", "Can connect to already-paired Bluetooth devices."),
    "android.permission.BLUETOOTH_SCAN": ("Medium", "Can scan for nearby Bluetooth devices — can be used for proximity tracking."),
    "android.permission.NFC": ("Low", "Can communicate via NFC (e.g. contactless payment cards)."),
}

DEFAULT_DANGEROUS_RISK = ("Medium", "Classified as a dangerous permission by the Android permission model.")
DEFAULT_NORMAL_RISK = ("Low", "Standard permission with limited security impact.")


def describe_permissions(permissions: list[str], dangerous_permissions: list[str]) -> list[dict[str, Any]]:
    """Return risk/description info for every requested permission, dangerous ones first."""
    dangerous_set = set(dangerous_permissions)
    out = []
    for perm in permissions:
        if perm in PERMISSION_INFO:
            risk, description = PERMISSION_INFO[perm]
        elif perm in dangerous_set:
            risk, description = DEFAULT_DANGEROUS_RISK
        else:
            risk, description = DEFAULT_NORMAL_RISK
        out.append({
            "permission": perm,
            "short_name": perm.rsplit(".", 1)[-1],
            "risk": risk,
            "description": description,
        })

    risk_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    out.sort(key=lambda p: risk_order.get(p["risk"], 4))
    return out
