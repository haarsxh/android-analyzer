"""Which code belongs to the app vs. a bundled third-party library.

One list, shared by the static scanner (decompiled file paths) and the runtime
rules (Java class names in stack traces), so both agree on what "the app's own
code" means. A finding only in library code is still worth knowing about, but
it's usually not something the app's developer wrote or can fix directly.

Anything not matched here counts as app code — including obfuscated packages
(a/b/c), so the scanner errs towards reporting.
"""
from __future__ import annotations

from pathlib import PurePath

LIBRARY_PACKAGES = (
    # Language runtimes / platform support
    "kotlin", "kotlinx", "java", "javax", "j$", "org.jetbrains", "org.intellij",
    "androidx", "android.support", "com.android.support",
    # Google / Firebase SDKs
    "com.google",
    # Networking / serialization
    "okhttp3", "okio", "retrofit2", "com.squareup", "com.fasterxml", "io.grpc",
    "org.apache", "org.bouncycastle", "org.spongycastle",
    # Rx, DI, images, animation
    "io.reactivex", "rx", "dagger", "com.bumptech.glide", "com.airbnb.lottie",
    # Analytics / crash / ads / attribution
    "com.facebook", "com.crashlytics", "io.fabric", "io.sentry", "com.adjust.sdk",
    "com.appsflyer", "com.unity3d", "com.mopub", "com.amplitude", "com.mixpanel",
    "com.onesignal", "com.braintreepayments", "com.stripe", "org.chromium", "org.json",
)

_DOTTED = tuple(p + "." for p in LIBRARY_PACKAGES)
_SLASHED = tuple(p.replace(".", "/") + "/" for p in LIBRARY_PACKAGES)

# Top-level folders that decompilers put Java/smali sources under.
_SOURCE_ROOTS = ("sources",)
_SMALI_ROOT_PREFIX = "smali"  # smali, smali_classes2, ...


def is_library_class(class_name: str | None) -> bool:
    """For a dotted Java class/method name, e.g. 'okhttp3.internal.connection.RealConnection'."""
    return bool(class_name) and class_name.startswith(_DOTTED)


def package_path(rel_path: str | PurePath) -> str | None:
    """The package-path part of a decompiled file's path, or None for
    non-code files (resources, manifest)."""
    parts = PurePath(rel_path).parts
    if parts and (parts[0] in _SOURCE_ROOTS or parts[0].startswith(_SMALI_ROOT_PREFIX)):
        return "/".join(parts[1:])
    return None


def is_library_path(rel_path: str | PurePath) -> bool:
    """For a decompiled file path, e.g. 'sources/kotlin/UNumbersKt.java' or
    'smali_classes2/okhttp3/OkHttpClient.smali'. Resources count as app."""
    pkg = package_path(rel_path)
    return pkg is not None and pkg.startswith(_SLASHED)
