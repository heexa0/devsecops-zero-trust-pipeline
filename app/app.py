"""
================================================================================
  DELIBERATELY VULNERABLE FLASK APPLICATION
  FOR SECURITY TESTING AND DEVSECOPS PIPELINE DEMONSTRATION ONLY
================================================================================

  WARNING: This application contains INTENTIONAL security vulnerabilities.
  It is designed to be scanned by tools like Semgrep, Trivy, and Bandit as
  part of a DevSecOps Zero Trust pipeline demonstration.

  DO NOT deploy this application in any real or production environment.
  DO NOT use this code as a template for real applications.

  Vulnerability index:
    VULN-1  OS Command Injection     (/ping endpoint)
    VULN-2  Insecure Deserialization (/load endpoint)
    VULN-3  SQL Injection            (/user endpoint)
    VULN-4  Hardcoded Secrets        (module-level constants)
    VULN-5  Debug Mode Enabled       (app.run)
    VULN-6  Path Traversal           (/file endpoint)
================================================================================
"""

import os
import sqlite3
import subprocess
import pickle

from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# VULN-4: Hardcoded Secrets
# Hardcoding credentials in source code exposes them to anyone with repository
# access, leaks them into logs/stack traces, and makes rotation difficult.
# CWE-798: Use of Hard-coded Credentials
# ---------------------------------------------------------------------------
SECRET_KEY = "supersecret123"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


# ---------------------------------------------------------------------------
# Database helper — creates an in-memory SQLite DB with a users table so the
# SQL injection endpoint has something real to query against.
# ---------------------------------------------------------------------------
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
    return jsonify(
        {
            "app": "Deliberately Vulnerable Demo",
            "endpoints": ["/ping", "/load", "/user", "/file"],
            "warning": "For security testing only.",
        }
    )


# ---------------------------------------------------------------------------
# VULN-1: OS Command Injection
# The 'host' parameter is passed directly into a shell command without any
# sanitisation.  An attacker can append arbitrary shell commands with
# characters such as ; | && etc.
# Example exploit: GET /ping?host=127.0.0.1;cat+/etc/passwd
# CWE-78: Improper Neutralization of Special Elements used in an OS Command
# ---------------------------------------------------------------------------
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULN-1: Command Injection — user-controlled input fed directly to shell
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
    return jsonify({"output": result})


# ---------------------------------------------------------------------------
# VULN-2: Insecure Deserialization
# pickle.loads() executed on raw, untrusted request bytes allows an attacker
# to craft a payload that executes arbitrary Python code upon deserialization.
# Example exploit: send a pickle payload that calls os.system("id")
# CWE-502: Deserialization of Untrusted Data
# ---------------------------------------------------------------------------
@app.route("/load", methods=["POST"])
def load():
    # VULN-2: Insecure Deserialization — raw request body passed to pickle.loads
    data = pickle.loads(request.data)
    return jsonify({"loaded": str(data)})


# ---------------------------------------------------------------------------
# VULN-3: SQL Injection
# The 'id' query parameter is interpolated directly into a SQL query string.
# An attacker can break out of the query and extract, modify, or delete data.
# Example exploit: GET /user?id=1 OR 1=1--
# CWE-89: Improper Neutralization of Special Elements used in an SQL Command
# ---------------------------------------------------------------------------
@app.route("/user")
def get_user():
    user_id = request.args.get("id", "1")
    conn = get_db()
    # VULN-3: SQL Injection — f-string concatenation builds the query directly
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor = conn.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return jsonify({"users": rows})


# ---------------------------------------------------------------------------
# VULN-6: Path Traversal
# The 'name' parameter is used to open a file on disk with no path
# sanitisation.  An attacker can supply ../../etc/passwd to read arbitrary
# files that the process has access to.
# Example exploit: GET /file?name=../../etc/passwd
# CWE-22: Improper Limitation of a Pathname to a Restricted Directory
# ---------------------------------------------------------------------------
@app.route("/file")
def read_file():
    filename = request.args.get("name", "readme.txt")
    # VULN-6: Path Traversal — filename used directly without sanitisation
    with open(filename, "r") as f:
        content = f.read()
    return jsonify({"content": content})


if __name__ == "__main__":
    # VULN-5: Debug Mode Enabled
    # Running Flask with debug=True exposes an interactive debugger in the
    # browser, enables auto-reloading, and prints full stack traces to clients,
    # leaking internal implementation details and allowing remote code execution
    # via the Werkzeug debugger PIN bypass.
    # CWE-94 / Flask security misconfiguration
    app.run(host="0.0.0.0", port=5000, debug=True)  # VULN-5: Debug Mode
