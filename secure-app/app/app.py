import os
import re
import json
import sqlite3
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

# ── Allowed base directory for /file endpoint ─────────────────────────────────
FILES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "files"))

# ── Security headers injected on every response ───────────────────────────────
@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# ── Database helper ───────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)"
    )
    conn.execute("INSERT INTO users (name, email) VALUES ('alice', 'alice@example.com')")
    conn.execute("INSERT INTO users (name, email) VALUES ('bob',   'bob@example.com')")
    conn.commit()
    return conn


@app.route("/")
def index():
    return jsonify({"app": "Secure Flask Demo", "status": "ok"})


# ── /ping — FIX for Command Injection ────────────────────────────────────────
# Vulnerable version used: subprocess.run(f"ping {host}", shell=True)
# Fix: shell=False with a list argv, plus strict input whitelist.
# Only hostnames / IPs matching the allowlist pattern are accepted.
_HOST_RE = re.compile(r"^[a-zA-Z0-9.\-]{1,253}$")

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not _HOST_RE.match(host):
        return jsonify({"error": "Invalid host parameter"}), 400

    result = subprocess.run(
        ["ping", "-c", "1", host],   # shell=False — no shell interpolation possible
        capture_output=True,
        text=True,
        timeout=5,
    )
    return jsonify({"output": result.stdout})


# ── /load — FIX for Insecure Deserialization ──────────────────────────────────
# Vulnerable version used: pickle.loads(request.data)
# Fix: json.loads() only. JSON cannot execute arbitrary code on deserialization.
@app.route("/load", methods=["POST"])
def load():
    try:
        data = json.loads(request.data)
    except (json.JSONDecodeError, ValueError):
        return jsonify({"error": "Invalid JSON body"}), 400
    return jsonify({"loaded": data})


# ── /user — FIX for SQL Injection ────────────────────────────────────────────
# Vulnerable version used: f"SELECT * FROM users WHERE name='{name}'"
# Fix: parameterized query — the DB driver escapes the value, never interpolates it.
@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    if not name:
        return jsonify({"error": "name parameter required"}), 400

    conn = get_db()
    cursor = conn.execute(
        "SELECT id, name, email FROM users WHERE name = ?",  # parameterized
        (name,),
    )
    rows = [{"id": r[0], "name": r[1], "email": r[2]} for r in cursor.fetchall()]
    conn.close()
    return jsonify({"users": rows})


# ── /secret — FIX for Hardcoded Credentials ──────────────────────────────────
# Vulnerable version used: SECRET_KEY = "supersecret123" at module level
# Fix: read from environment at request time; never log or return the value.
@app.route("/secret")
def secret():
    key = os.environ.get("SECRET_KEY")
    if not key:
        return jsonify({"error": "Server configuration error"}), 500
    # Confirm the key is configured without exposing it
    return jsonify({"status": "secret is configured", "length": len(key)})


# ── /file — FIX for Path Traversal ───────────────────────────────────────────
# Vulnerable version used: open(filename) with raw user input
# Fix: basename strips directory components; abspath resolves symlinks and ..;
#      final check ensures the resolved path is inside FILES_DIR.
_FILENAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]+$")

@app.route("/file")
def read_file():
    filename = request.args.get("name", "")
    if not _FILENAME_RE.match(filename):
        return jsonify({"error": "Invalid filename"}), 400

    safe_name = os.path.basename(filename)
    full_path = os.path.abspath(os.path.join(FILES_DIR, safe_name))

    # Confirm the resolved path is still inside the allowed directory
    if not full_path.startswith(FILES_DIR + os.sep):
        return jsonify({"error": "Access denied"}), 403

    if not os.path.isfile(full_path):
        return jsonify({"error": "File not found"}), 404

    with open(full_path, "r") as f:
        content = f.read()
    return jsonify({"content": content})


if __name__ == "__main__":
    # debug=False — never expose the Werkzeug interactive debugger.
    # In production the Dockerfile uses gunicorn instead of this entrypoint.
    app.run(host="127.0.0.1", port=8000, debug=False)
