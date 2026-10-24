"""Runtime Rules: turn raw dynamic-analysis output into scored, deduplicated findings.

Three inputs, one shape of output. Each analyze_* function returns a list of
finding dicts ({source, severity, title, description, metadata}) ready for
models.add_finding:

- analyze_frida_events: hook events from frida_scripts/ (crypto, shared
  prefs, WebView, HTTP, bypass hooks).
- analyze_traffic: HTTP flows captured by webproxy.py's mitmproxy.
- analyze_logcat: the app's logcat output for the session.

Events that repeat (the same weak cipher called 300 times) collapse into one
finding with an occurrence count, so the report stays readable.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from app.static_analysis.libraries import is_library_class
from app.static_analysis.sast_engine import _looks_like_secret

SENSITIVE_NAME_RE = re.compile(
    r"pass(word|wd)?|pwd|secret|token|api[_-]?key|auth|session|cookie|credential|"
    r"credit|card[_-]?(no|num)|cvv|(?<![a-z])ssn(?![a-z])|\bpin\b|otp|private[_-]?key",
    re.IGNORECASE,
)
WEAK_CIPHERS = ("DES", "DESEDE", "3DES", "TRIPLEDES", "RC4", "ARCFOUR", "RC2", "BLOWFISH")
WEAK_DIGESTS = ("MD2", "MD4", "MD5", "SHA1", "SHA-1", "SHA")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
LOG_KV_RE = re.compile(
    r"(?P<key>[A-Za-z_][\w\-]{0,40})\s*[=:]\s*[\"']?(?P<value>[^\s\"',;&]{3,})"
)
# '=' only as trailing base64 padding, so "Vsync=1098628" isn't read as one token.
TOKEN_RE = re.compile(r"[A-Za-z0-9+/_\-]{20,100}={0,2}")
# Words joined by underscores (ANDROID_EMU_CHECKSUM_HELPER_v1) — identifiers,
# not secrets; a real key like sk_live_<24 mixed chars> has a long
# mixed letter+digit segment so doesn't match.
IDENTIFIER_RE = re.compile(r"(?:[A-Za-z]+|[A-Za-z0-9]{1,4})(?:_(?:[A-Za-z]+|[A-Za-z0-9]{1,4}))+")
HTML_TAG_RE = re.compile(r"<(?:!DOCTYPE|html|head|body|meta|link|script|div|span|style)\b", re.IGNORECASE)
# Java object toString()s like android.os.BinderProxy@17ab06d — a window or
# binder handle that happens to be named "token", not a secret.
OBJECT_REF_RE = re.compile(r"[\w.$]+@[0-9a-f]{4,}")
# Android framework components that log from inside the app's process (and
# so pass the --pid filter) but never log the app's own data.
FRAMEWORK_LOG_TAGS = {
    "nativeloader", "libEGL", "HostConnection", "OpenGLRenderer", "EGL_emulation", "Choreographer",
    "CompatibilityChangeReporter", "AssistStructure", "ziparchive", "Gralloc4", "AdrenoGLES",
    "ActivityThread", "ApplicationLoaders", "DynamiteModule", "GraphicsEnvironment", "Perf",
    "TextInputLayout", "ProfileInstaller", "InputMethodManager", "ImeTracker", "InsetsController",
    "RenderThread", "SurfaceView", "ViewRootImpl", "WindowOnBackDispatcher", "AutofillManager",
    "VRI", "WindowManager", "BLASTBufferQueue", "FrameEvents", "IInputConnectionWrapper", "re.frida.helper",
}
# threadtime ("10-01 12:00:01.123  1234  1234 D Tag : msg") and brief ("D/Tag( 1234): msg") formats.
LOGCAT_TAG_RE = re.compile(
    r"^(?:\S+\s+\S+\s+\d+\s+\d+\s+[VDIWEFA]\s+(?P<tag>[^:]*?)\s*:"
    r"|(?:\S+\s+\S+\s+)?[VDIWEFA]/(?P<tag2>[^:(]*))"
)
LOGCAT_PREFIX_RE = re.compile(
    r"^(?:\S+\s+\S+\s+\d+\s+\d+\s+[VDIWEFA]\s+[^:]*?\s*:\s?"
    r"|(?:\S+\s+\S+\s+)?[VDIWEFA]/[^:(]*(?:\(\s*\d+\))?:\s?)"
)

MAX_LOGCAT_FINDINGS = 25


def mask(value: Any, keep: int = 3) -> str:
    """Show just enough of a secret to recognize it, never the whole thing."""
    s = str(value)
    if len(s) <= keep:
        return "*" * len(s)
    return s[:keep] + "*" * min(len(s) - keep, 12)


class _Collector:
    """Dedupes findings by a key and counts how many times each one fired."""

    def __init__(self, source: str):
        self.source = source
        self._findings: dict[tuple, dict[str, Any]] = {}

    def add(self, key: tuple, severity: str, title: str, description: str,
            metadata: dict[str, Any] | None = None) -> None:
        existing = self._findings.get(key)
        if existing:
            existing["metadata"]["occurrences"] += 1
            return
        self._findings[key] = {
            "source": self.source, "severity": severity, "title": title,
            "description": description,
            "metadata": {**(metadata or {}), "occurrences": 1},
        }

    def results(self) -> list[dict[str, Any]]:
        out = []
        for f in self._findings.values():
            n = f["metadata"]["occurrences"]
            if n > 1:
                f = {**f, "description": f"{f['description']} (observed {n} times)"}
            out.append(f)
        return out


# ---------------------------------------------------------------------------
# Frida hook events
# ---------------------------------------------------------------------------

def _cipher_parts(transformation: str) -> tuple[str, str]:
    """'AES/CBC/PKCS5Padding' -> ('AES', 'CBC'); bare 'AES' -> ('AES', '')."""
    parts = (transformation or "").upper().split("/")
    return parts[0], (parts[1] if len(parts) > 1 else "")




def _crypto_event(c: _Collector, e: dict[str, Any]) -> None:
    api = e.get("api", "")
    algo = str(e.get("algorithm") or "")
    caller = e.get("caller")

    # The hook only reports `caller` on builds that capture it. When present
    # but not the app's own code, the platform (TLS/certificate handling) or a
    # bundled library made the call — record it, but don't blame the app.
    if "caller" in e and (caller is None or is_library_class(caller)):
        who = caller.rsplit(".", 1)[0] if caller else "the Android platform (e.g. TLS certificate handling)"
        c.add(("crypto_external", api, algo.upper(), who), "Info",
              f"{algo} used by {'library ' + who if caller else 'Android platform internals'} (not app code)",
              f"{api}({algo}) was called by {who}, not by the app's own code, so it isn't counted "
              "against the app.", {"hook": "crypto", "api": api, "algorithm": algo, "caller": caller})
        return

    if api == "Cipher.doFinal":
        base, mode = _cipher_parts(algo)
        if base in WEAK_CIPHERS:
            c.add(("weak_cipher", base), "High", f"Weak cipher used at runtime: {algo}",
                  f"The app encrypted/decrypted data with {algo}. {base} is broken or "
                  "deprecated and should be replaced with AES-GCM.",
                  {"hook": "crypto", "api": api, "algorithm": algo, "caller": caller})
        elif mode == "ECB" or (base == "AES" and not mode):
            c.add(("ecb_mode", algo), "High", f"ECB mode encryption used at runtime: {algo}",
                  f"The app used {algo}. " + ("Bare 'AES' defaults to ECB on Android. " if not mode else "")
                  + "ECB leaks patterns in the plaintext; use AES/GCM/NoPadding.",
                  {"hook": "crypto", "api": api, "algorithm": algo, "caller": caller})
        else:
            c.add(("cipher_ok", algo), "Info", f"Cipher used at runtime: {algo}",
                  f"The app used {algo} for encryption/decryption.",
                  {"hook": "crypto", "api": api, "algorithm": algo, "caller": caller})

    elif api == "MessageDigest.getInstance":
        if algo.upper() in WEAK_DIGESTS:
            c.add(("weak_digest", algo.upper()), "Medium", f"Weak hash algorithm used at runtime: {algo}",
                  f"The app computed {algo} hashes. {algo} is collision-prone; if this protects "
                  "passwords or integrity checks, switch to SHA-256+ (or bcrypt/Argon2 for passwords).",
                  {"hook": "crypto", "api": api, "algorithm": algo, "caller": caller})
        else:
            c.add(("digest_ok", algo.upper()), "Info", f"Hash algorithm used at runtime: {algo}",
                  f"The app computed {algo} hashes.", {"hook": "crypto", "api": api, "algorithm": algo, "caller": caller})

    elif api == "SecretKeySpec":
        key_len = e.get("key_len")
        base, _ = _cipher_parts(algo)
        if base in WEAK_CIPHERS:
            c.add(("weak_key_algo", base), "High", f"Encryption key created for weak algorithm: {algo}",
                  f"A {key_len}-byte key was created for {algo}, a broken/deprecated algorithm.",
                  {"hook": "crypto", "api": api, "algorithm": algo, "key_len": key_len, "caller": caller})
        elif base == "AES" and isinstance(key_len, int) and key_len < 16:
            c.add(("short_key", algo, key_len), "High", f"AES key shorter than 128 bits ({key_len} bytes)",
                  f"A {key_len}-byte AES key was created. AES requires 16/24/32-byte keys; a short "
                  "key usually means a hardcoded or password-derived key padded insecurely.",
                  {"hook": "crypto", "api": api, "algorithm": algo, "key_len": key_len, "caller": caller})
        else:
            c.add(("key_spec", algo, key_len), "Info", f"Encryption key created: {algo} ({key_len} bytes)",
                  "Check whether this key is hardcoded in the app (see static Code Analysis findings) "
                  "or derived/stored in the Android Keystore.",
                  {"hook": "crypto", "api": api, "algorithm": algo, "key_len": key_len, "caller": caller})


def _shared_prefs_event(c: _Collector, e: dict[str, Any]) -> None:
    key = str(e.get("key", ""))
    value = str(e.get("value", ""))
    meta = {"hook": "shared_prefs", "api": e.get("api"), "key": key, "value_preview": mask(value)}

    if SENSITIVE_NAME_RE.search(key) and value not in ("", "null", "false", "true", "0"):
        c.add(("prefs_sensitive", key), "High", f"Sensitive value stored in plaintext SharedPreferences: '{key}'",
              f"The app wrote '{key}' = '{mask(value)}' to SharedPreferences, which is an unencrypted XML "
              "file in the app's data directory (readable on rooted devices and via backups). Use "
              "EncryptedSharedPreferences or the Android Keystore.", meta)
    elif _looks_like_secret(value):
        c.add(("prefs_secretlike", key), "Medium", f"Secret-like value stored in SharedPreferences: '{key}'",
              f"The app wrote a high-entropy value ('{mask(value)}') under '{key}' to unencrypted "
              "SharedPreferences — likely a token or key.", meta)
    else:
        c.add(("prefs_write", key), "Info", f"SharedPreferences write: '{key}'",
              f"The app stored '{key}' in SharedPreferences.", meta)


def _webview_event(c: _Collector, e: dict[str, Any]) -> None:
    api = e.get("api")
    if api == "addJavascriptInterface":
        name = e.get("interface_name", "")
        c.add(("js_interface", name), "Medium", f"JavaScript bridge exposed to WebView: '{name}'",
              f"The app exposed a native object to web content as window.{name}. Any page loaded "
              "into this WebView (including over cleartext HTTP or via injected content) can call its "
              "@JavascriptInterface methods.",
              {"hook": "webview", "api": api, "interface_name": name})
    elif api == "loadUrl":
        url = str(e.get("url", ""))
        scheme = urlsplit(url).scheme.lower()
        meta = {"hook": "webview", "api": api, "url": url}
        if scheme == "http":
            c.add(("webview_http", urlsplit(url).netloc), "Medium", f"WebView loads cleartext HTTP page: {url}",
                  "Content loaded over HTTP can be modified by anyone on the network, including "
                  "injecting scripts into the WebView.", meta)
        elif scheme == "file":
            c.add(("webview_file", url), "Low", f"WebView loads local file: {url}",
                  "Loading file:// URLs is risky if file access from file URLs is enabled.", meta)
        elif scheme in ("https", ""):
            c.add(("webview_url", urlsplit(url).netloc), "Info", f"WebView loaded: {urlsplit(url).netloc or url}",
                  f"The app loaded {url} in a WebView.", meta)


def _http_event(c: _Collector, e: dict[str, Any]) -> None:
    if e.get("api") == "Socket.connect":
        endpoint = f"{e.get('host')}:{e.get('port')}"
        c.add(("socket", endpoint), "Info", f"Network connection opened: {endpoint}",
              "Raw TCP connection observed at runtime (any HTTP library or protocol).",
              {"hook": "http", "api": "Socket.connect", "host": e.get("host"), "port": e.get("port")})
        return

    url = str(e.get("url", ""))
    parts = urlsplit(url)
    meta = {"hook": "http", "api": e.get("api"), "url": url, "method": e.get("method")}
    if parts.scheme.lower() == "http":
        c.add(("http_cleartext", parts.netloc), "Medium", f"Cleartext HTTP request at runtime: {parts.netloc}",
              f"The app opened an unencrypted connection to {url}.", meta)
        for name in _sensitive_body_fields(e.get("body") or ""):
            c.add(("http_cleartext_body", parts.netloc, name), "High",
                  f"Sensitive field '{name}' sent over cleartext HTTP to {parts.netloc}",
                  f"The {e.get('method') or 'request'} body sent to {url} contained '{name}' without TLS — "
                  "anyone on the same network can read it.", meta)
    for name, value in parse_qsl(parts.query):
        if SENSITIVE_NAME_RE.search(name):
            c.add(("http_url_param", parts.netloc, name), "High",
                  f"Sensitive parameter '{name}' sent in URL to {parts.netloc}",
                  f"'{name}' = '{mask(value)}' was placed in a request URL. URLs end up in server, "
                  "proxy and analytics logs.", meta)
    if parts.netloc:
        c.add(("http_endpoint", parts.scheme, parts.netloc), "Info",
              f"Network endpoint contacted: {parts.scheme}://{parts.netloc}",
              "Observed at runtime (not just referenced in code).", meta)


def _bypass_event(c: _Collector, e: dict[str, Any]) -> None:
    hook, api = e.get("hook"), e.get("api", "")
    what = "certificate pinning" if hook == "ssl_bypass" else "root/emulator/debugger detection"
    c.add((hook, api), "Info", f"App {what} check triggered and bypassed: {api}",
          f"The analyzer's {hook} hook intercepted {api}. This shows the app has {what}, and that it "
          "was defeated by a standard Frida hook.", {"hook": hook, "api": api, "detail": e})


EXTERNAL_STORAGE_PREFIXES = ("/storage/", "/sdcard/", "/mnt/sdcard/", "/mnt/media_rw/")
SQL_WRITE_RE = re.compile(r"^\s*(INSERT|UPDATE|REPLACE)\b", re.IGNORECASE)
SQL_CREATE_RE = re.compile(r"^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"'`]?(\w+)", re.IGNORECASE)


def _db_name(path: str) -> str:
    return path.rsplit("/", 1)[-1] or path


def _storage_event(c: _Collector, e: dict[str, Any]) -> None:
    api = e.get("api", "")
    caller = e.get("caller")
    meta = {"hook": "storage", "api": api, "caller": caller}

    if is_library_class(caller):
        lib = ".".join(caller.split(".")[:2])
        c.add(("storage_library", api, lib), "Info", f"{api} used by library {lib} (not app code)",
              "Data written by a bundled library, not the app's own code.", meta)
        return

    if api in ("SQLiteDatabase.insert", "SQLiteDatabase.update"):
        table, db = e.get("table", ""), _db_name(e.get("db", ""))
        values = e.get("values") or {}
        sensitive = [k for k, v in values.items() if SENSITIVE_NAME_RE.search(k) and v not in ("", "null")]
        for col in sensitive:
            c.add(("sqlite_sensitive", db, table, col), "High",
                  f"Sensitive value stored in plaintext SQLite database: {table}.{col}",
                  f"The app wrote '{col}' = '{mask(values[col])}' into table '{table}' of {db}. Android's SQLite "
                  "databases are unencrypted files in the app's data directory (readable on rooted devices and "
                  "via backups). Hash passwords, or use SQLCipher / the Android Keystore for secrets.",
                  {**meta, "db": e.get("db"), "table": table, "column": col, "value_preview": mask(values[col])})
        if not sensitive:
            c.add(("sqlite_write", db, table), "Info", f"SQLite write: {db} → {table}",
                  f"The app wrote to table '{table}' (columns: {', '.join(sorted(values)) or 'none'}).",
                  {**meta, "db": e.get("db"), "table": table})

    elif api == "SQLiteDatabase.execSQL":
        sql, db = e.get("sql", ""), _db_name(e.get("db", ""))
        create = SQL_CREATE_RE.match(sql)
        if create:
            c.add(("sqlite_table", db, create.group(1)), "Info", f"SQLite table created: {db} → {create.group(1)}",
                  f"Schema: {sql[:200]}", {**meta, "db": e.get("db"), "sql": sql[:300]})
        elif SQL_WRITE_RE.match(sql):
            if not e.get("bind_args") and "'" in sql:
                c.add(("sql_literals", db), "Medium", f"Raw SQL with inline values in {db} (SQL injection risk)",
                      "The app ran an INSERT/UPDATE with values written directly into the SQL text instead of "
                      "bound '?' parameters. If any value comes from user input this is SQL injection; use "
                      "ContentValues or bind arguments.", {**meta, "db": e.get("db"), "sql": _mask_sql(sql)})
            if SENSITIVE_NAME_RE.search(sql):
                c.add(("sql_sensitive", db), "High", f"Sensitive data written with raw SQL into {db}",
                      f"An INSERT/UPDATE touching sensitive-looking columns ran against the unencrypted database "
                      f"{db}: {_mask_sql(sql)[:200]}", {**meta, "db": e.get("db"), "sql": _mask_sql(sql)})

    elif api == "FileOutputStream":
        path = e.get("path", "")
        directory = path.rsplit("/", 1)[0]
        if path.startswith(EXTERNAL_STORAGE_PREFIXES) and "/Android/data/" not in path:
            c.add(("file_shared_external", directory), "Medium", f"File written to shared external storage: {path}",
                  "Shared external storage is readable by other apps with storage permission (and by anyone "
                  "via USB). Don't store personal or sensitive data there.", {**meta, "path": path})
        elif path.startswith(EXTERNAL_STORAGE_PREFIXES):
            c.add(("file_app_external", directory), "Low", f"File written to app-specific external storage: {path}",
                  "Not encrypted, and readable by other apps on older Android versions / via USB.", {**meta, "path": path})
        else:
            c.add(("file_internal", directory), "Info", f"File written to internal storage: {directory}/",
                  f"e.g. {path}", {**meta, "path": path})

    elif api == "File.createTempFile":
        path = e.get("path", "")
        c.add(("temp_file", path.rsplit("/", 1)[0]), "Low", f"Temporary file created: {path}",
              "Temp files are often forgotten and left on disk; make sure they're deleted and hold nothing "
              "sensitive.", {**meta, "path": path})

    elif api == "ClipboardManager.setPrimaryClip":
        text = e.get("text", "")
        if not text:
            return
        secret_like = _looks_like_secret(text) or any(
            SENSITIVE_NAME_RE.search(m.group("key")) for m in LOG_KV_RE.finditer(text))
        c.add(("clipboard", "secret" if secret_like else "text"), "High" if secret_like else "Medium",
              "Secret-like value copied to the clipboard" if secret_like else "App copies data to the clipboard",
              f"The app put '{mask(text, 4)}' on the clipboard. Before Android 10 any app could read it, and "
              "keyboards / clipboard managers still can. Avoid copying passwords, tokens or personal data.",
              {**meta, "text_preview": mask(text, 4)})

    elif api == "KeyStore.getInstance":
        ks_type = e.get("type", "")
        if ks_type == "AndroidKeyStore":
            c.add(("keystore", ks_type), "Info", "Uses the Android Keystore",
                  "Good practice: keys in the Android Keystore stay in secure hardware and can't be extracted "
                  "from the app's files.", {**meta, "type": ks_type})
        else:
            c.add(("keystore", ks_type), "Info", f"Uses a file-based {ks_type} key store",
                  "Keys in a file-based key store are only as safe as the file and its password — check where "
                  "the password comes from.", {**meta, "type": ks_type})


SQL_VALUE_RE = re.compile(r"'([^']*)'")


def _mask_sql(sql: str) -> str:
    """SQL with quoted literal values masked (they may be credentials)."""
    return SQL_VALUE_RE.sub(lambda m: "'" + mask(m.group(1)) + "'", sql)[:300]


EVENT_HANDLERS = {
    "crypto": _crypto_event,
    "shared_prefs": _shared_prefs_event,
    "webview": _webview_event,
    "http": _http_event,
    "storage": _storage_event,
    "ssl_bypass": _bypass_event,
    "root_bypass": _bypass_event,
}


def analyze_frida_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    c = _Collector("dynamic_frida")
    hook_errors = []
    for e in events:
        if not isinstance(e, dict):
            continue
        if "error" in e:
            hook_errors.append(f"{e.get('hook', 'frida')}: {e['error']}")
            continue
        handler = EVENT_HANDLERS.get(e.get("hook"))
        if handler:
            handler(c, e)
        else:
            c.add(("other", e.get("hook"), e.get("api")), "Info",
                  f"Runtime event: {e.get('hook', 'unknown')}.{e.get('api', '')}", str(e), e)

    results = c.results()
    if hook_errors:
        results.append({
            "source": "dynamic_frida", "severity": "Info",
            "title": f"{len(hook_errors)} Frida hook(s) reported errors",
            "description": "Coverage gap — these hooks didn't run, so their checks are missing from "
                           "this session: " + "; ".join(sorted(set(hook_errors))[:10]),
            "metadata": {"errors": hook_errors[:50]},
        })
    return results


# ---------------------------------------------------------------------------
# Captured traffic (mitmproxy flows, as summarized by webproxy.py)
# ---------------------------------------------------------------------------

# The proxy sits in front of the whole emulator, so it records Android's own
# background traffic too. The clearest case is the connectivity probe the OS
# sends every few seconds ("is the internet working?") — a GET to /generate_204
# or /gen_204 on a Google host. It has nothing to do with the app under test,
# so it must not be reported as the app using cleartext HTTP.
SYSTEM_PROBE_PATHS = {"/generate_204", "/gen_204"}
GOOGLE_SYSTEM_DOMAINS = ("google.com", "googleapis.com", "gstatic.com", "android.com")


def _is_system_probe(host: str, url: str) -> bool:
    host = (host or "").lower()
    on_google = any(host == d or host.endswith("." + d) for d in GOOGLE_SYSTEM_DOMAINS)
    return on_google and urlsplit(url).path in SYSTEM_PROBE_PATHS


def app_hosts_from_events(events: list[dict[str, Any]]) -> set[str]:
    """Hosts the app itself contacted, according to its own Frida HTTP hooks."""
    hosts = set()
    for e in events:
        if isinstance(e, dict) and e.get("hook") == "http" and e.get("url"):
            host = urlsplit(str(e["url"])).hostname
            if host:
                hosts.add(host.lower())
    return hosts


def analyze_traffic(flows: list[dict[str, Any]], app_hosts: set[str] | frozenset = frozenset()) -> list[dict[str, Any]]:
    """Findings for captured HTTP(S) flows.

    `app_hosts` are hosts the app itself is known to have contacted; a flow to
    one of those is always analyzed, even if it looks like an OS probe.
    """
    c = _Collector("dynamic_traffic")
    background: dict[str, int] = {}
    for f in flows:
        scheme = (f.get("scheme") or "").lower()
        host = f.get("host", "")
        url = f.get("url", "")
        if _is_system_probe(host, url) and host.lower() not in app_hosts:
            background[host] = background.get(host, 0) + 1
            continue
        headers = {k.lower(): v for k, v in (f.get("request_headers") or {}).items()}
        body = f.get("request_body") or ""
        meta = {"method": f.get("method"), "url": url, "status": f.get("status")}

        c.add(("endpoint", scheme, host), "Info", f"Traffic to {scheme}://{host}",
              f"Captured {f.get('method')} {url}", meta)

        if scheme == "http":
            c.add(("cleartext", host), "Medium", f"Cleartext HTTP traffic to {host}",
                  f"{f.get('method')} {url} was sent unencrypted — anyone on the same network can read "
                  "and modify it.", meta)
            if "authorization" in headers or "cookie" in headers:
                c.add(("cleartext_auth", host), "High", f"Credentials/session sent over cleartext HTTP to {host}",
                      "An Authorization header or session cookie was sent without TLS and can be stolen "
                      "by a network attacker.", meta)
            for name in _sensitive_body_fields(body):
                c.add(("cleartext_body", host, name), "High",
                      f"Sensitive field '{name}' sent over cleartext HTTP to {host}",
                      f"The request body to {url} contained '{name}' without TLS.", meta)

        for name, value in parse_qsl(urlsplit(url).query):
            if SENSITIVE_NAME_RE.search(name):
                c.add(("url_param", host, name), "High", f"Sensitive parameter '{name}' sent in URL to {host}",
                      f"'{name}' = '{mask(value)}' appeared in the request URL. URLs are logged by "
                      "servers, proxies and analytics — send secrets in the body or headers instead.", meta)

        auth = headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            c.add(("basic_auth", host), "Medium", f"HTTP Basic authentication used with {host}",
                  "Basic auth sends a reversible base64 username:password on every request.", meta)

        resp_headers = {k.lower() for k in (f.get("response_headers") or {})}
        if scheme == "https" and f.get("status") and "strict-transport-security" not in resp_headers:
            c.add(("no_hsts", host), "Low", f"No HSTS header from {host}",
                  "The server doesn't send Strict-Transport-Security, so clients aren't told to refuse "
                  "downgraded HTTP connections.", meta)
    results = c.results()
    if background:
        total = sum(background.values())
        results.append({
            "source": "dynamic_traffic", "severity": "Info",
            "title": f"Android background connectivity checks ignored ({total} requests)",
            "description": "The emulator's own internet checks (GET /generate_204 or /gen_204 to "
                           + ", ".join(sorted(background)) + ") passed through the proxy. They come from "
                           "Android itself, not the app, so they weren't checked for cleartext or sensitive data.",
            "metadata": {"hosts": background, "occurrences": total},
        })
    return results


def _sensitive_body_fields(body: str) -> list[str]:
    names = set()
    for name, _ in parse_qsl(body):
        if SENSITIVE_NAME_RE.search(name):
            names.add(name)
    for m in re.finditer(r'"([\w\-]{2,40})"\s*:', body):
        if SENSITIVE_NAME_RE.search(m.group(1)):
            names.add(m.group(1))
    return sorted(names)


# ---------------------------------------------------------------------------
# Logcat
# ---------------------------------------------------------------------------

def _log_tag(line: str) -> str:
    m = LOGCAT_TAG_RE.match(line)
    return (m.group("tag") or m.group("tag2") or "").strip() if m else ""


def _is_secret_token(message: str, m: re.Match) -> bool:
    token = m.group(0)
    before = message[m.start() - 1] if m.start() > 0 else ""
    after = message[m.end()] if m.end() < len(message) else ""
    if before in ("/", ".") or after in ("/", "."):  # path segment / file name / dotted name
        return False
    if token.startswith("/") or IDENTIFIER_RE.fullmatch(token.rstrip("=")):
        return False
    return _looks_like_secret(token)


def _log_message(line: str) -> str:
    """Drop logcat's date/pid/level/tag prefix so the tag ('D/Auth:') isn't
    mistaken for a key name; lines in an unknown format are scanned whole."""
    m = LOGCAT_PREFIX_RE.match(line)
    return line[m.end():] if m else line


def analyze_logcat(lines: list[str]) -> list[dict[str, Any]]:
    c = _Collector("dynamic_logcat")
    for line in lines:
        if len(c._findings) >= MAX_LOGCAT_FINDINGS:
            break
        if _log_tag(line) in FRAMEWORK_LOG_TAGS:
            continue  # Android framework component, never the app's own data
        message = _log_message(line)
        jwt_spans = []
        for m in JWT_RE.finditer(message):
            jwt_spans.append(m.span())
            c.add(("jwt", m.group(0)[:40]), "High", "JWT/session token written to logcat",
                  f"A JSON Web Token ('{mask(m.group(0), 10)}') appeared in the app's logs. Other apps "
                  "with READ_LOGS, bug-report tools and crash reporters can read it.",
                  {"line": _mask_line(line)})

        reported_spans = list(jwt_spans)

        def inside_jwt(m: re.Match) -> bool:
            return any(s <= m.start() < e for s, e in jwt_spans)

        for m in LOG_KV_RE.finditer(message):
            key, value = m.group("key"), m.group("value")
            if inside_jwt(m) or JWT_RE.match(value):
                continue
            if SENSITIVE_NAME_RE.search(key) and value.lower() not in ("null", "true", "false") \
                    and not OBJECT_REF_RE.fullmatch(value):
                reported_spans.append(m.span("value"))
                c.add(("kv", key.lower()), "High", f"Sensitive value '{key}' written to logcat",
                      f"The app logged '{key}' = '{mask(value)}'. Logs are readable via adb, bug "
                      "reports and crash reporters; strip this logging from release builds.",
                      {"key": key, "line": _mask_line(line)})
        if HTML_TAG_RE.search(message):
            # A logged web page (deployment IDs, hashed CSS class names) —
            # random-looking but not secrets. kv/JWT checks above still ran.
            continue
        for m in TOKEN_RE.finditer(message):
            token = m.group(0)
            already = any(m.start() < e and s < m.end() for s, e in reported_spans)
            if not already and _is_secret_token(message, m):
                c.add(("token", token[:24]), "Medium", "Secret-like token written to logcat",
                      f"A high-entropy string ('{mask(token, 6)}') was logged — likely a key, token or "
                      "session ID.", {"line": _mask_line(line)})
    return c.results()


def _mask_line(line: str) -> str:
    """Logcat line for the report with obvious secret values masked."""
    message = _log_message(line)
    prefix = line[:len(line) - len(message)]
    message = JWT_RE.sub(lambda m: mask(m.group(0), 10), message)
    message = LOG_KV_RE.sub(
        lambda m: f"{m.group('key')}={mask(m.group('value'))}"
        if SENSITIVE_NAME_RE.search(m.group("key")) else m.group(0),
        message,
    )
    message = TOKEN_RE.sub(lambda m: mask(m.group(0), 6) if _is_secret_token(message, m) else m.group(0), message)
    return (prefix + message)[:300]
