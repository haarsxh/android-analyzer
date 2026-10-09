import Java from 'frida-java-bridge';

import { install as installCrypto } from './hooks/crypto_hooks.js';
import { install as installSharedPrefs } from './hooks/shared_prefs_hooks.js';
import { install as installWebView } from './hooks/webview_hooks.js';
import { install as installHttp } from './hooks/http_hooks.js';
import { install as installStorage } from './hooks/storage_hooks.js';
import { install as installSslPinningBypass } from './hooks/ssl_pinning_bypass.js';
import { install as installRootEmulatorBypass } from './hooks/root_emulator_bypass.js';

/*
 * Single entry point for every hook, compiled into ONE bundle (hooks.js).
 *
 * All hooks must share one frida-java-bridge instance: loading each hook as
 * its own bundled script puts several independent Java bridges into the
 * target process, each patching ART on its own — which made hooks silently
 * stop firing and intermittently crashed the app (SIGSEGV).
 *
 * views.py loads this bundle, then calls rpc start({...}) with which hook
 * groups to install; the bypass hooks alter app behavior, so they're opt-in.
 */
const HOOKS = {
    crypto: installCrypto,
    shared_prefs: installSharedPrefs,
    webview: installWebView,
    http: installHttp,
    storage: installStorage,
    ssl_pinning_bypass: installSslPinningBypass,
    root_emulator_bypass: installRootEmulatorBypass,
};

rpc.exports = {
    start(names) {
        const installed = [];
        Java.perform(function () {
            names.forEach(function (name) {
                const install = HOOKS[name];
                if (!install) {
                    send({ hook: "frida", error: "unknown hook group: " + name });
                    return;
                }
                try {
                    install();
                    installed.push(name);
                } catch (e) {
                    send({ hook: name, error: "install failed: " + e });
                }
            });
        });
        return installed;
    },
};
