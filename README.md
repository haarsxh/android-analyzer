# Android Analyzer

A MobSF-style static + dynamic analysis tool for Android APKs, Android-only
(no iOS/Windows support), built in Python/Flask.

## Architecture

Mirrors MobSF's real design, scoped to Android:

- **Interface and Access** (`app/interface/`): `scanning.py` (Web Entry),
  `api.py` (API Entry for CI clients), `authorization.py` (shared auth check).
- **Static Analysis** (`app/static_analysis/`): `static_analyzer.py`
  (orchestrator), `app.py` (androguard-based manifest/permission/component
  parsing), `sast_engine.py` (apktool/jadx decompile + rule-based source
  scanning), `android_checks.py` (manifest/config security rules).
- **Dynamic Analysis** (`app/dynamic_analysis/`): `android_runtime.py`
  (session orchestrator), `device.py` (adb control, incl. screenshots),
  `views.py` (Frida Bridge), `frida_scripts/` (hooks — crypto,
  SharedPreferences, WebView, HTTP incl. legacy Apache HttpClient, plus opt-in SSL-pinning and
  root/emulator-detection bypass), `webproxy.py` (mitmproxy traffic capture).
- **Security Intelligence** (`app/security_intel/`): `malware_checks.py`
  (local heuristics), `reputation.py` (optional hash-reputation lookup),
  `geolocation.py` (resolves domains found in the app to IPs and looks up
  country/city/ISP).
- **Results and Storage** (`app/storage/`): `models.py` (SQLite, incl. finding
  triage), `report.py` (scored JSON/HTML/PDF report generation, scan diff,
  risk trend), `jobs.py` (background scan execution + webhook notification).

## Setup

### 1. Python dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. External tools (required for full functionality)

Static analysis works without these, but decompilation-based scanning
(`sast_engine.py`) needs:

- **Java JDK** (for apktool/jadx)
- **apktool** — `brew install apktool`
- **jadx** — `brew install jadx`
- **binutils** (`readelf`/`nm`, for native `.so` hardening checks) — `brew install binutils`
  (Homebrew installs these under `/opt/homebrew/opt/binutils/bin`; make sure that's on `PATH`)

Dynamic analysis needs:

- **Android SDK platform-tools** (`adb`) — `brew install android-platform-tools`
- An Android emulator (Android Studio AVD) or physical device with USB
  debugging enabled
- **Frida-server** running on the device/emulator, matching your installed
  `frida` Python package version (download from
  https://github.com/frida/frida/releases, push to `/data/local/tmp`, `chmod
  755`, run as root)
- **mitmproxy** (`pip install mitmproxy`, included in requirements.txt) if you
  want HTTPS traffic capture — see in-app instructions for installing the CA
  on the device
- **Node.js/npm** — only needed if you're editing a Frida hook script (the
  compiled bundles are committed, so a fresh clone works without this); see
  "Frida hook scripts must be compiled" below.

### 3. Run

Web UI:

```bash
python -m app.main
# open http://127.0.0.1:5000
```

Server settings (environment variables):

| Variable | Default | Notes |
|---|---|---|
| `ANALYZER_HOST` | `127.0.0.1` | Listening on anything else requires `FLASK_SECRET_KEY` to be set. |
| `ANALYZER_PORT` | `5000` | macOS AirPlay Receiver also uses 5000 on all interfaces; change this if it conflicts. |
| `ANALYZER_DEBUG` | off | Enables Werkzeug's debugger — an interactive Python console in the browser. Local only: the server refuses to start with it on a non-loopback host. |
| `ANALYZER_MAX_UPLOAD_MB` | `200` | Larger uploads are rejected with a message. |
| `ANALYZER_DB_PATH` | `reports/analyzer.db` | SQLite database location (the test suite points this at a temp file). |

Tests:

```bash
pip install -r requirements-dev.txt
python -m pytest
```

The suite covers the static and runtime rules (including real-device logcat noise and decompiled
library code that must *not* be flagged), the adb text-input quoting, and the web app's access
control, CSRF and login throttling.

CLI (static analysis only, no web server):

```bash
python cli.py scan /path/to/app.apk
python cli.py devices
```

### 4. Authentication

The web UI now requires a real account: visit `/signup` to create one, then
`/login`. Every page is gated behind `login_required` (session-based). **Scans
are private to the user who uploaded them**: reports, PDFs, triage, compare,
trends and dynamic sessions for anyone else's scan return 404, and lists only
show your own scans. (Scans uploaded before accounts existed have no owner and
are only reachable via the API.) Every form and in-page request carries a CSRF
token, and logins are locked for 15 minutes after 5 failures for one username
(or 20 from one IP). Passwords are hashed with
Werkzeug's `generate_password_hash`/`check_password_hash` (salted PBKDF2) and
never stored in plaintext.

The REST API (`/api/...`) is separate and unaffected by accounts — it's
open by default for local use. To require an API key for it, set:

```bash
export ANALYZER_API_KEY="some-long-random-string"
```

Then pass it as `X-API-Key: <key>` or `Authorization: Bearer <key>` on API
calls. Also set a real `FLASK_SECRET_KEY` in any non-local deployment —
the default in `app/main.py` is a dev placeholder and signs session
cookies, so a fixed/default value would let anyone forge a login session.

### 5. Reputation lookups (optional)

To enable hash-reputation checks (e.g. VirusTotal) during static analysis,
set:

```bash
export REPUTATION_API_KEY="your-virustotal-api-key"
```

Without this set, malware detection falls back to local heuristics only.

## REST API

- `POST /api/scan` — multipart upload, field `apk`, optional `webhook_url`. Scans run in the
  background; returns `{scan_id, status: "queued"}` (HTTP 202) immediately.
- `GET /api/scans` — list past scans.
- `GET /api/report/<scan_id>` — full JSON report (poll `status` on `/api/scans` until `completed`).
- `GET /api/report/<scan_id>/pdf` — download the PDF report.
- `GET /api/compare?scan_a=<id>&scan_b=<id>` — diff findings between two scans.
- `GET /api/compare/matrix?scan_ids=<id>&scan_ids=<id>&...` — compare 3+ scans at once (repeated
  param or comma-separated); every unique finding as a row, presence per scan as columns.
- `GET /api/trend/<package_name>` — risk-score/finding-count trend across all scans of a package.
- `POST /api/finding/<id>/triage` — body `{"status": "open"|"reviewed"|"dismissed", "note": "..."}`.
- `GET /api/dynamic/devices` — list connected adb devices.
- `POST /api/dynamic/<scan_id>/start` — body `{"serial", "capture_traffic", "bypass_ssl_pinning", "bypass_root_detection"}`.
- `GET /api/dynamic/<scan_id>/poll` — session log, Frida events, logcat tail, screenshots.
- `POST /api/dynamic/<scan_id>/stop` — stop the session, persist findings.

## Feature notes

- **Server geolocation**: `security_intel/geolocation.py` extracts every hostname referenced in
  the decompiled code (`sast_engine.extract_domains`), resolves up to 15 of them via DNS, and
  batch-queries the free `ip-api.com` API (no key required) for country/city/ISP — surfaced as
  `Info`-severity "Server location: ..." findings. Fully offline-safe: DNS/HTTP lookups are
  time-boxed and any failure (no internet, rate limit) just means fewer location findings, never
  a failed scan. This reports where third-party SDK traffic *could* go (from static strings), not
  confirmed runtime connections — pair with a dynamic session + traffic capture for that.
- **Provider-specific secret rules** (`sast_engine.PROVIDER_RULES`): exact formats for AWS access
  key IDs and secret keys, Stripe, Google API/OAuth, Firebase server keys, OpenAI, Anthropic,
  GitHub, Slack, SendGrid, Twilio and embedded private keys, each with a severity and a note on
  what a leaked key of that type allows. Values are masked in reports, the same key found in Java
  and smali is one finding, and they replace the generic keyword/entropy findings for that value.
  Also: hardcoded encryption keys and static all-zero IVs in files that do encryption.
- **App code vs. library code** (`static_analysis/libraries.py`): code findings that only occur in
  bundled libraries (Google Play Services, Kotlin, OkHttp, …) are lowered one severity level and
  collapsed into one finding per rule, labelled "library code only" — on InsecureBankv2 this turned
  48 Play Services rows into 4 and put the app's own hardcoded key and zero IV at the top. The
  runtime crypto attribution uses the same package list.
- **Static analysis**: entropy-based secret detection (`sast_engine.scan_entropy_secrets`)
  catches high-randomness embedded strings that don't match a `key=`/`secret=` keyword pattern.
  To keep it from drowning real secrets in noise, it skips well-known open-source library packages
  (`kotlin/`, `okio/`, `androidx/`, …), Kotlin's mangled function names (`countLeadingZeroBits-7apg3OU`),
  alphabet strings and lowercase class paths. Certificate-pin hashes (`"sha256/…"`) are reported as
  an Info "certificate pinning in use" finding rather than a secret, and XML namespace URIs
  (`http://schemas.android.com/…`) are not counted as cleartext HTTP URLs. Tested on AndroGoat:
  62 findings → 30, with every removed one a false positive.
  `library_detector.py` identifies bundled third-party SDKs from the decompiled package tree and
  flags a small curated list with known CVE history for manual version verification.
- **Dynamic analysis**: the `ssl_pinning_bypass` and `root_emulator_bypass` hook groups are
  opt-in (they actively alter app behavior) — enable them per session via the checkboxes on the
  Dynamic page, or `bypass_ssl_pinning`/`bypass_root_detection` in the API. SSL pinning bypass is
  usually required before `webproxy.py`'s mitmproxy capture will see any traffic from apps that
  pin certificates. Screenshots are captured automatically on launch/stop and can be triggered
  manually during a session. The session page also has a "Live Screen" toggle (`GET
  /dynamic/live/<scan_id>`) that polls `adb screencap` every ~2 seconds for a near-live view of
  the device — not smooth video (screencap itself takes 1-2s), but enough to see what state the
  app is in without a manual screenshot each time. **The live view is also interactive**: once
  it's on, click the screen to tap, click-and-drag to swipe (`POST /dynamic/tap|swipe/<scan_id>`,
  coordinates computed client-side from the image's natural size, which matches the device's real
  resolution 1:1), Back/Home/Recents buttons send key events (`POST /dynamic/key/<scan_id>`), and
  the text field types into whatever's focused on the device (`POST /dynamic/text/<scan_id>`;
  printable ASCII only, and shell-quoted because `adb shell` runs the command through the device's
  `/bin/sh` — unquoted, input like `abc;reboot` would execute `reboot`). This lets
  you drive the app under test (navigate past onboarding, log in, trigger a specific screen)
  entirely from the browser, without needing separate access to the emulator/device.
- **Runtime findings are scored, not just logged** (`dynamic_analysis/runtime_rules.py`): when a
  session stops, three inputs are turned into deduplicated findings with real severities (repeats
  collapse into one finding with an occurrence count; secret values are masked in the report):
  - *Frida events* (`dynamic_frida`): crypto events carry the calling class, so weak algorithms are
    only blamed on the app when its own code called them — MD5/SHA-1 used by Android's TLS stack or a
    library like OkHttp (on every HTTPS connection) is reported as Info, "not app code". Then:
    DES/3DES/RC4 or ECB-mode ciphers actually used (High; bare
    `"AES"` counts as ECB since that's Android's default), AES keys under 128 bits (High), MD5/SHA-1
    (Medium), sensitive keys like `password`/`token` written to SharedPreferences (High) or
    high-entropy values written there (Medium), `addJavascriptInterface` (Medium), WebView loading
    `http://` (Medium), cleartext HTTP connections (Medium), secrets in URL query params (High),
    root/pinning checks that the bypass hooks defeated (Info), and hooks that failed to load (Info,
    flagged as a coverage gap).
  - *Captured traffic* (`dynamic_traffic`, needs "capture traffic"): the mitmproxy flow file is
    parsed with mitmproxy's own `FlowReader` — cleartext HTTP per host (Medium), credentials/cookies
    or sensitive body fields over HTTP (High), secrets in URLs (High), HTTP Basic auth (Medium),
    missing HSTS (Low).
  - *Logcat* (`dynamic_logcat`): sensitive `key=value` pairs, JWTs (High) and high-entropy tokens
    (Medium) in the app's own log output. Logcat is cleared once at session start and read
    non-destructively after that, so the final read covers the whole session; the full log is saved
    to `workdir/logcat/<scan_id>.txt`.
- **Findings triage**: each finding can be marked Open/Reviewed/Dismissed via the report page or
  API; dismissed findings are excluded from the risk score but stay visible (dimmed) in the UI.
- **Compare & Trends**: the "Compare" page diffs findings between any two scans (e.g. two versions
  of the same APK); "Trends" charts risk score over time for all scans of a given package.
- **Background jobs**: scans run on a small in-process thread pool (`app/storage/jobs.py`) rather
  than blocking the request — no Redis/Celery/RQ dependency required. This means job state doesn't
  survive a process restart; a production deployment with heavier scan volume would want a real
  broker-backed queue instead.
- **Deep-link scanner** (`android_checks.check_deep_links`): flags exported activities with custom
  URL scheme intent-filters (Medium — classic hijack/phishing vector, since any app can register
  the same scheme) and http(s) App Links missing `android:autoVerify="true"` (Low — skips Android's
  domain-ownership check).
- **Firebase misconfiguration check** (`security_intel/firebase_checker.py`): extracts hardcoded
  `*.firebaseio.com` / `*.firebasedatabase.app` URLs from the decompiled source and sends an
  unauthenticated read probe to up to 5 of them; a `200` response with readable data is flagged
  Critical ("publicly readable database"), a denied response is Info. Offline-safe like the
  geolocation/reputation checks.
- **Native library hardening scan** (`static_analysis/native_lib_scanner.py`): runs `readelf`/`nm`
  against every bundled `.so` (deduped across ABIs) for missing NX stack protection, RELRO, and
  stack-canary symbols — the same manual checks a binary security review would run. Requires
  `binutils` (`brew install binutils`) on PATH; degrades to a single Info notice if unavailable.
- **Score breakdown by category**: the report's App Score is broken down per analysis category
  (Manifest & Config, Code Analysis, Malware Heuristics, Network/Server, Cloud/Firebase,
  Dynamic/Runtime), each scored 0-100 the same way as the overall score, so it's clear *which*
  category is dragging the grade down.
- **CI/CD gate**: `python cli.py scan <apk> --fail-on High` exits with status 1 (and prints the
  blocking findings) if any non-dismissed finding is at or above the given severity — drop straight
  into a CI pipeline step.
- **Multi-scan comparison matrix**: "Compare → multi-scan matrix" (or `/api/compare/matrix`) diffs
  3+ scans at once — every unique finding across all of them as a row, presence per scan as a
  column — useful for tracking finding creep across an entire release train, not just two builds.

## Notes

- This is a from-scratch, Android-only reimplementation inspired by MobSF's
  architecture — it does not reuse MobSF's code.
- Dynamic analysis is only as capable as the Frida hooks shipped in
  `app/dynamic_analysis/frida_scripts/src/hooks/`. To add one: write
  `src/hooks/<name>.js` exporting an `install()` function, register it in
  `src/index.js`'s `HOOKS` map, add its name to `views.py`'s `DEFAULT_HOOKS`
  (or `OPTIONAL_HOOKS` for opt-in behavior-altering hooks), and rebuild.
- **All hooks are compiled into one bundle (`frida_scripts/hooks.js`) on
  purpose.** Each bundle carries its own copy of `frida-java-bridge`; loading
  every hook as a separate script put several independent Java bridges into
  the target process, which made hooks silently stop firing and
  intermittently crashed the app (SIGSEGV). `views.py` loads `hooks.js` once
  and calls its `start([...hook names])` RPC export to install the chosen
  groups.
- Hook only concrete classes, never interfaces — e.g. SharedPreferences
  writes are hooked on `android.app.SharedPreferencesImpl$EditorImpl`, since
  hooking the `SharedPreferences$Editor` interface never fires. A
  `java.net.Socket.connect` hook was also tried and removed: it crashed the
  target on its network thread.
- **Frida hook scripts must be compiled, not edited in place.** Frida 16+
  dropped the auto-injected `Java`/`ObjC` globals for raw scripts — they now
  live in the separate `frida-java-bridge` npm package, which has to be
  bundled into the script at build time (`session.create_script()` doesn't
  support `require()` at runtime). Sources live in
  `app/dynamic_analysis/frida_scripts/src/` (`index.js` plus one module per
  hook group under `src/hooks/`); the file `views.py` actually loads is the
  compiled `hooks.js` next to `src/`. To edit a hook:
  ```bash
  cd app/dynamic_analysis/frida_scripts
  npm install   # first time only
  # edit the file under src/hooks/
  npm run build # recompiles src/index.js (and every hook) into hooks.js
  ```
  A raw (uncompiled) hook script will silently fail with
  `ReferenceError: 'Java' is not defined` the moment it runs — that error in
  a dynamic session's Frida events means a hook was edited without rebuilding.
