import Java from 'frida-java-bridge';

/*
 * Universal SSL pinning bypass: neutralizes the most common Android
 * certificate-pinning implementations so mitmproxy (webproxy.py) can see
 * decrypted HTTPS traffic. Covers standard TrustManager/HostnameVerifier,
 * OkHttp's CertificatePinner, and TrustManagerImpl (Android 7+ network
 * security config pinning).
 */
Java.perform(function () {
    // 1. Custom X509TrustManager implementations: neutralize checkServerTrusted.
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");

        var TrustManager = Java.registerClass({
            name: "com.androidanalyzer.TrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; },
            },
        });

        var TrustManagers = [TrustManager.$new()];
        var SSLContext_init = SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom"
        );
        SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {
            send({ hook: "ssl_bypass", api: "SSLContext.init", detail: "trust managers replaced" });
            SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
        };
    } catch (e) {
        send({ hook: "ssl_bypass", error: "SSLContext/TrustManager hook failed: " + e });
    }

    // 2. HostnameVerifier: always accept.
    try {
        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        var SSLSession = Java.use("javax.net.ssl.SSLSession");
        var AllowAllVerifier = Java.registerClass({
            name: "com.androidanalyzer.AllowAllHostnameVerifier",
            implements: [HostnameVerifier],
            methods: { verify: function () { return true; } },
        });
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier) {
            send({ hook: "ssl_bypass", api: "HttpsURLConnection.setDefaultHostnameVerifier", detail: "replaced with allow-all" });
            this.setDefaultHostnameVerifier(AllowAllVerifier.$new());
        };
        HttpsURLConnection.setHostnameVerifier.implementation = function (verifier) {
            this.setHostnameVerifier(AllowAllVerifier.$new());
        };
    } catch (e) {
        send({ hook: "ssl_bypass", error: "HostnameVerifier hook failed: " + e });
    }

    // 3. OkHttp3 CertificatePinner.check — the most common pinning path in
    //    modern apps. Make it a no-op.
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, certs) {
            send({ hook: "ssl_bypass", api: "OkHttp3 CertificatePinner.check", hostname: hostname });
        };
    } catch (e) {
        // OkHttp3 not present in this app; not an error.
    }

    // 4. Android's own TrustManagerImpl (used by network security config
    //    pinning on API 24+). Neutralize checkTrustedRecursive.
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.checkTrustedRecursive.implementation = function () {
            send({ hook: "ssl_bypass", api: "TrustManagerImpl.checkTrustedRecursive" });
            return Java.use("java.util.ArrayList").$new();
        };
    } catch (e) {
        // Not present on this API level/ROM; not an error.
    }
});
