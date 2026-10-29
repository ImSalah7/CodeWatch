"""Production launcher for the CodeWatch API server.

Environment variables:
    MYSCAN_HOST          Bind address (default 0.0.0.0)
    MYSCAN_PORT          Bind port (default 8443)
    MYSCAN_API_KEY       API key; when set, all /api/* routes require it
    MYSCAN_RATE_LIMIT    Max requests per client per minute (default 300)
    MYSCAN_RATE_LIMIT_BURST  Max requests per client per second (default 60)
    MYSCAN_CORS_ORIGINS  Comma-separated allowed origins
    MYSCAN_ALLOWED_PATHS Semicolon-separated allowed local scan paths
    MYSCAN_DB            SQLite database path (default src/myscan.db)
    MYSCAN_TRUST_PROXY   Set "1" to trust X-Forwarded-For

Uses waitress (production WSGI) when installed, falling back to the Flask
dev server otherwise. For TLS, terminate HTTPS in a reverse proxy (nginx/caddy)
in front of this service.
"""
import os

from src.api import app, create_app

create_app()

HOST = os.environ.get("MYSCAN_HOST", "0.0.0.0")
PORT = int(os.environ.get("MYSCAN_PORT", "8443"))
DEBUG = os.environ.get("MYSCAN_DEBUG", "").strip().lower() in ("1", "true", "yes")


def main() -> None:
    try:
        from waitress import serve

        print(f"CodeWatch API listening on http://{HOST}:{PORT} (waitress)")
        serve(app, host=HOST, port=PORT, threads=16, channel_timeout=600)
    except ImportError:
        print(f"CodeWatch API listening on http://{HOST}:{PORT} (Flask dev server)")
        app.run(host=HOST, port=PORT, debug=DEBUG)


if __name__ == "__main__":
    main()
