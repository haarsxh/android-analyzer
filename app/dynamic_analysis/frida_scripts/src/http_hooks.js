import Java from 'frida-java-bridge';

/*
 * Hooks common HTTP client entry points (OkHttp, HttpURLConnection) to log
 * outgoing request URLs at runtime.
 */
Java.perform(function () {
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            send({ hook: "http", api: "URL.openConnection", url: this.toString() });
            return this.openConnection();
        };
    } catch (e) {
        send({ hook: "http", error: "URL.openConnection hook failed: " + e });
    }

    try {
        var OkHttpClient = Java.use("okhttp3.Request$Builder");
        OkHttpClient.url.overload("java.lang.String").implementation = function (url) {
            send({ hook: "http", api: "OkHttp Request.Builder.url", url: url });
            return this.url(url);
        };
    } catch (e) {
        // OkHttp not present in this app; not an error
    }
});
