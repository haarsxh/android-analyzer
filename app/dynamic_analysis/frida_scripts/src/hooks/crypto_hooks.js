import Java from 'frida-java-bridge';
import { findCaller } from './caller.js';

/*
 * Hooks common javax.crypto / java.security APIs to log key material,
 * algorithms, and I/O so weak or hardcoded crypto usage is visible at runtime.
 *
 * Each event carries `caller` (see caller.js). The TLS stack hashes
 * certificates with MD5/SHA-1 on every HTTPS connection, so without this,
 * every app making HTTPS calls would look like it uses weak hashes — runtime_rules.py uses `caller` to only blame the
 * app for crypto its own code invoked.
 */
export function install() {
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload("[B").implementation = function (input) {
            send({ hook: "crypto", api: "Cipher.doFinal", algorithm: this.getAlgorithm(), caller: findCaller() });
            return this.doFinal(input);
        };
    } catch (e) {
        send({ hook: "crypto", error: "Cipher hook failed: " + e });
    }

    try {
        var MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.getInstance.overload("java.lang.String").implementation = function (algo) {
            send({ hook: "crypto", api: "MessageDigest.getInstance", algorithm: algo, caller: findCaller() });
            return this.getInstance(algo);
        };
    } catch (e) {
        send({ hook: "crypto", error: "MessageDigest hook failed: " + e });
    }

    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algo) {
            send({ hook: "crypto", api: "SecretKeySpec", algorithm: algo, key_len: key.length, caller: findCaller() });
            return this.$init(key, algo);
        };
    } catch (e) {
        send({ hook: "crypto", error: "SecretKeySpec hook failed: " + e });
    }
}
