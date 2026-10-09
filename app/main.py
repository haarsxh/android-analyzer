"""Flask app factory / entrypoint."""
from __future__ import annotations

import os

from flask import Flask

from app.storage.models import init_db


def create_app() -> Flask:
    app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

    init_db()

    from app.interface.security import init_security
    init_security(app)

    from app.interface.scanning import bp as scanning_bp
    from app.interface.api import bp as api_bp
    from app.interface.auth_routes import bp as auth_bp

    app.register_blueprint(scanning_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(auth_bp)

    return app


app = create_app()


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


if __name__ == "__main__":
    # Debug mode enables Werkzeug's interactive debugger, which lets anyone who
    # can reach the server run arbitrary Python — so it's opt-in, never default.
    debug = _env_flag("ANALYZER_DEBUG")
    host = os.environ.get("ANALYZER_HOST", "127.0.0.1")
    port = int(os.environ.get("ANALYZER_PORT", "5000"))

    if host not in ("127.0.0.1", "localhost", "::1"):
        if debug:
            raise SystemExit("Refusing to start: ANALYZER_DEBUG exposes a code-execution console and "
                             f"ANALYZER_HOST={host} makes it reachable from the network.")
        if app.secret_key == "dev-secret-change-me":
            raise SystemExit("Refusing to start: set FLASK_SECRET_KEY before listening on "
                             f"{host} — the default key lets anyone forge a login session.")

    app.run(host=host, port=port, debug=debug)
