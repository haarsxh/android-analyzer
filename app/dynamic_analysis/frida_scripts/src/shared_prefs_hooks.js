import Java from 'frida-java-bridge';

/*
 * Hooks SharedPreferences reads/writes to reveal what keys/values an app
 * persists locally, which is useful for spotting plaintext secrets.
 */
Java.perform(function () {
    try {
        var Editor = Java.use("android.content.SharedPreferences$Editor");
        ["putString", "putInt", "putBoolean", "putLong", "putFloat"].forEach(function (method) {
            try {
                Editor[method].overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        var args = Array.prototype.slice.call(arguments);
                        send({ hook: "shared_prefs", api: method, key: args[0], value: String(args[1]) });
                        return overload.apply(this, arguments);
                    };
                });
            } catch (e) {
                // method/overload not present on this target, skip
            }
        });
    } catch (e) {
        send({ hook: "shared_prefs", error: "Editor hook failed: " + e });
    }
});
