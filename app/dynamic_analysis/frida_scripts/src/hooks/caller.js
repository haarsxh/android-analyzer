import Java from 'frida-java-bridge';

/*
 * The first stack frame outside the Java/Android platform itself, as
 * "class.method" — or null when every frame is platform code (e.g. the system
 * TLS stack, or SharedPreferences writing its own XML file). runtime_rules.py
 * uses it to only blame the app for what its own code (or a library it
 * bundles) did.
 */
var PLATFORM_PREFIXES = [
    "java.", "javax.", "sun.", "libcore.", "dalvik.", "android.", "com.android.",
    "org.apache.harmony.", "jdk.",
];

export function findCaller() {
    try {
        var frames = Java.use("java.lang.Thread").currentThread().getStackTrace();
        for (var i = 0; i < frames.length; i++) {
            var cls = String(frames[i].getClassName());
            var platform = PLATFORM_PREFIXES.some(function (p) { return cls.indexOf(p) === 0; });
            if (!platform) {
                return cls + "." + frames[i].getMethodName();
            }
        }
    } catch (e) {
        // Stack unavailable; caller stays unknown.
    }
    return null;
}
