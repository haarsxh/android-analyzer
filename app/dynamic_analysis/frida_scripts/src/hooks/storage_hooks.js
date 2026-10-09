import Java from 'frida-java-bridge';
import { findCaller } from './caller.js';

/*
 * Where the app puts data at rest, beyond SharedPreferences: SQLite writes,
 * files on shared external storage and temp files, the clipboard — plus
 * whether it uses the Android Keystore (the right place for keys).
 *
 * Every event carries `caller`; writes made purely by the platform (e.g.
 * SharedPreferences saving its own XML file) have caller null and are skipped
 * here to keep the event stream about what the app did.
 */
var MAX_VALUE_CHARS = 300;

function clip(value) {
    var s = String(value);
    return s.length > MAX_VALUE_CHARS ? s.substring(0, MAX_VALUE_CHARS) + "…" : s;
}

function contentValuesToObject(values) {
    var out = {};
    if (values === null) {
        return out;
    }
    var it = values.keySet().iterator();
    while (it.hasNext()) {
        var key = String(it.next());
        out[key] = clip(values.get(key));
    }
    return out;
}

export function install() {
    // --- SQLite ------------------------------------------------------------
    try {
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

        SQLiteDatabase.execSQL.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var args = Array.prototype.slice.call(arguments);
                var bind = args.length > 1 && args[1] !== null
                    ? Array.prototype.map.call(args[1], function (v) { return clip(v); }) : [];
                send({ hook: "storage", api: "SQLiteDatabase.execSQL", sql: clip(args[0]), bind_args: bind,
                       db: String(this.getPath()), caller: findCaller() });
                return overload.apply(this, arguments);
            };
        });

        // insert()/replace() funnel into insertWithOnConflict; update() into updateWithOnConflict.
        SQLiteDatabase.insertWithOnConflict.implementation = function (table, nullHack, values, conflict) {
            send({ hook: "storage", api: "SQLiteDatabase.insert", table: String(table),
                   values: contentValuesToObject(values), db: String(this.getPath()), caller: findCaller() });
            return this.insertWithOnConflict(table, nullHack, values, conflict);
        };
        SQLiteDatabase.updateWithOnConflict.implementation = function (table, values, where, whereArgs, conflict) {
            send({ hook: "storage", api: "SQLiteDatabase.update", table: String(table),
                   values: contentValuesToObject(values), db: String(this.getPath()), caller: findCaller() });
            return this.updateWithOnConflict(table, values, where, whereArgs, conflict);
        };
    } catch (e) {
        send({ hook: "storage", error: "SQLite hooks failed: " + e });
    }

    // --- Files ---------------------------------------------------------------
    try {
        // Every FileOutputStream constructor funnels into (File, boolean).
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        var ctor = FileOutputStream.$init.overload("java.io.File", "boolean");
        ctor.implementation = function (file, append) {
            var caller = findCaller();
            if (caller !== null && file !== null) {
                send({ hook: "storage", api: "FileOutputStream", path: String(file.getAbsolutePath()),
                       append: append, caller: caller });
            }
            return ctor.call(this, file, append);
        };
    } catch (e) {
        send({ hook: "storage", error: "FileOutputStream hook failed: " + e });
    }

    try {
        var File = Java.use("java.io.File");
        var createTemp = File.createTempFile.overload("java.lang.String", "java.lang.String", "java.io.File");
        createTemp.implementation = function (prefix, suffix, dir) {
            var result = createTemp.call(this, prefix, suffix, dir);
            send({ hook: "storage", api: "File.createTempFile", path: String(result.getAbsolutePath()),
                   caller: findCaller() });
            return result;
        };
    } catch (e) {
        send({ hook: "storage", error: "createTempFile hook failed: " + e });
    }

    // --- Clipboard -------------------------------------------------------------
    try {
        var ClipboardManager = Java.use("android.content.ClipboardManager");
        ClipboardManager.setPrimaryClip.implementation = function (clipData) {
            var text = "";
            try {
                text = String(clipData.getItemAt(0).coerceToText(Java.use("android.app.ActivityThread")
                    .currentApplication().getApplicationContext()));
            } catch (err) {
                // Non-text clip (URI/intent); nothing to inspect.
            }
            send({ hook: "storage", api: "ClipboardManager.setPrimaryClip", text: clip(text), caller: findCaller() });
            return this.setPrimaryClip(clipData);
        };
    } catch (e) {
        send({ hook: "storage", error: "Clipboard hook failed: " + e });
    }

    // --- Android Keystore (good practice; reported so its absence is visible) --
    try {
        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.getInstance.overload("java.lang.String").implementation = function (type) {
            send({ hook: "storage", api: "KeyStore.getInstance", type: String(type), caller: findCaller() });
            return this.getInstance(type);
        };
    } catch (e) {
        send({ hook: "storage", error: "KeyStore hook failed: " + e });
    }
}
