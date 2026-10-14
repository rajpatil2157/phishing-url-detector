
import os

from waitress import serve
from app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))

    print("Starting Phishing URL Detector...", flush=True)
    print(f"Dashboard: http://127.0.0.1:{port}", flush=True)
    print("Server: Waitress (production WSGI)", flush=True)

    serve(app, host="0.0.0.0", port=port)
