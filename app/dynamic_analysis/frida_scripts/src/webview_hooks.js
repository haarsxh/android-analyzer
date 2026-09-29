import Java from 'frida-java-bridge';

/*
 * Hooks WebView.loadUrl / addJavascriptInterface to surface loaded URLs and
 * any JS bridge objects exposed to web content.
 */
Java.perform(function () {
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function (url) {
            send({ hook: "webview", api: "loadUrl", url: url });
            return this.loadUrl(url);
        };
    } catch (e) {
        send({ hook: "webview", error: "loadUrl hook failed: " + e });
    }

    try {
        var WebView2 = Java.use("android.webkit.WebView");
        WebView2.addJavascriptInterface.implementation = function (obj, name) {
            send({ hook: "webview", api: "addJavascriptInterface", interface_name: name });
            return this.addJavascriptInterface(obj, name);
        };
    } catch (e) {
        send({ hook: "webview", error: "addJavascriptInterface hook failed: " + e });
    }
});
