import Java from 'frida-java-bridge';

/*
 * Hooks common HTTP client entry points (HttpURLConnection, OkHttp, legacy
 * Apache HttpClient) to log outgoing request URLs at runtime.
 *
 * Deliberately no java.net.Socket.connect hook: it was tried as a
 * library-agnostic fallback, but intermittently crashed the target
 * (SIGSEGV on the network thread) when combined with the other hooks.
 */
var MAX_BODY_CHARS = 2000;

export function install() {
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

    // Legacy Apache HttpClient (DefaultHttpClient), still common in older
    // apps. Every execute(...) overload funnels into this one.
    try {
        var AbstractHttpClient = Java.use("org.apache.http.impl.client.AbstractHttpClient");
        var EntityUtils = Java.use("org.apache.http.util.EntityUtils");
        var EnclosingRequest = Java.use("org.apache.http.HttpEntityEnclosingRequest");
        var execute = AbstractHttpClient.execute.overload(
            "org.apache.http.HttpHost", "org.apache.http.HttpRequest", "org.apache.http.protocol.HttpContext"
        );
        execute.implementation = function (target, request, context) {
            var line = request.getRequestLine();
            var uri = line.getUri();
            var url = uri.indexOf("://") !== -1 || target === null ? uri : target.toURI() + uri;
            var event = { hook: "http", api: "Apache HttpClient.execute", method: line.getMethod(), url: url };
            try {
                // Only read repeatable entities (form/string/byte bodies) —
                // reading a streaming body here would consume it before the
                // app sends it.
                var entity = Java.cast(request, EnclosingRequest).getEntity();
                if (entity !== null && entity.isRepeatable()) {
                    event.body = String(EntityUtils.toString(entity)).substring(0, MAX_BODY_CHARS);
                }
            } catch (e) {
                // Not an entity-enclosing request (GET/DELETE); no body.
            }
            send(event);
            return execute.call(this, target, request, context);
        };
    } catch (e) {
        // Apache HttpClient not available to this app; not an error
    }
}
