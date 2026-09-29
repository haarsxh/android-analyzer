"""Flask app factory / entrypoint."""
from __future__ import annotations

import os

from flask import Flask

from app.storage.models import init_db


def create_app() -> Flask:
    app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

    init_db()

    from app.interface.scanning import bp as scanning_bp
    from app.interface.api import bp as api_bp
    from app.interface.auth_routes import bp as auth_bp

    app.register_blueprint(scanning_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(auth_bp)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
