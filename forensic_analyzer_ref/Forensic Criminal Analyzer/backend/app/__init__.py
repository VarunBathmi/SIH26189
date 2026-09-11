import os
from flask import Flask
from flask_cors import CORS


def create_app():
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    # CORS: allow the configured frontend origin(s) in production, allow all in dev.
    allowed_origins = os.environ.get("ALLOWED_ORIGINS", "*")
    origins = [o.strip() for o in allowed_origins.split(",")] if allowed_origins != "*" else "*"
    CORS(app, resources={r"/api/*": {"origins": origins}})

    from app.routes.api import api_bp
    app.register_blueprint(api_bp, url_prefix="/api")

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    return app
