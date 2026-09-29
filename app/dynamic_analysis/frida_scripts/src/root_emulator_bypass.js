import Java from 'frida-java-bridge';

/*
 * Bypasses common root/emulator detection checks so apps that refuse to run
 * on a rooted device or emulator (common in banking/finance apps) can still
 * be dynamically analyzed.
 */
Java.perform(function () {
    // 1. Runtime.exec-based root checks (su, which su, busybox, etc).
    try {
        var Runtime = Java.use("java.lang.Runtime");
        var ROOT_INDICATORS = ["su", "which su", "busybox", "magisk"];
        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
            if (ROOT_INDICATORS.some(function (i) { return cmd.indexOf(i) !== -1; })) {
                send({ hook: "root_bypass", api: "Runtime.exec", cmd: cmd, action: "blocked" });
                throw Java.use("java.io.IOException").$new("blocked by analyzer");
            }
            return this.exec(cmd);
        };
    } catch (e) {
        send({ hook: "root_bypass", error: "Runtime.exec hook failed: " + e });
    }

    // 2. File.exists() checks for common su/magisk/busybox paths.
    try {
        var File = Java.use("java.io.File");
        var ROOT_PATHS = [
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
            "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su",
            "/system/xbin/busybox", "/data/adb/magisk",
        ];
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            if (ROOT_PATHS.indexOf(path) !== -1) {
                send({ hook: "root_bypass", api: "File.exists", path: path, action: "forced false" });
                return false;
            }
            return this.exists();
        };
    } catch (e) {
        send({ hook: "root_bypass", error: "File.exists hook failed: " + e });
    }

    // 3. Build fingerprint / model checks used for emulator detection.
    try {
        var Build = Java.use("android.os.Build");
        var EMULATOR_FINGERPRINTS = ["generic", "unknown", "emulator", "sdk_gphone"];
        var origFingerprint = Build.FINGERPRINT.value;
        if (EMULATOR_FINGERPRINTS.some(function (f) { return origFingerprint && origFingerprint.indexOf(f) !== -1; })) {
            send({ hook: "root_bypass", api: "Build.FINGERPRINT", detail: "device reports as emulator-like; not overridden (would require a stable spoof value)" });
        }
    } catch (e) {
        send({ hook: "root_bypass", error: "Build fingerprint check failed: " + e });
    }

    // 4. Debug.isDebuggerConnected — used by some anti-tamper checks.
    try {
        var Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function () {
            send({ hook: "root_bypass", api: "Debug.isDebuggerConnected", action: "forced false" });
            return false;
        };
    } catch (e) {
        send({ hook: "root_bypass", error: "Debug.isDebuggerConnected hook failed: " + e });
    }
});
