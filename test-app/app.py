from flask import Flask, request, jsonify
import sqlite3
import os
import requests

app = Flask(__name__)
DB_PATH = '/tmp/taskmanager.db'


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        done INTEGER DEFAULT 0
    )''')
    conn.execute("INSERT OR IGNORE INTO tasks (id, title, done) VALUES (1, 'Setup projet', 1)")
    conn.execute("INSERT OR IGNORE INTO tasks (id, title, done) VALUES (2, 'Ecrire les tests', 0)")
    conn.commit()
    conn.close()


init_db()


@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Server'] = 'zerotrust'
    return response


@app.route('/')
def index():
    return jsonify({"app": "Task Manager API", "version": "1.0", "status": "running"})


@app.route('/health')
def health():
    return jsonify({"status": "ok"})


@app.route('/tasks', methods=['GET'])
def get_tasks():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, title, done FROM tasks").fetchall()
    conn.close()
    return jsonify({"tasks": [{"id": r[0], "title": r[1], "done": bool(r[2])} for r in rows]})


# FIX : requête paramétrée — plus d'injection SQL
@app.route('/tasks/search', methods=['GET'])
def search_tasks():
    keyword = request.args.get('q', '')
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, title, done FROM tasks WHERE title LIKE ?",
        (f'%{keyword}%',)
    ).fetchall()
    conn.close()
    return jsonify({"results": [{"id": r[0], "title": r[1], "done": bool(r[2])} for r in rows]})


@app.route('/tasks', methods=['POST'])
def create_task():
    data = request.get_json() or {}
    title = data.get('title', '').strip()
    if not title:
        return jsonify({"error": "title requis"}), 400
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO tasks (title) VALUES (?)", (title,))
    conn.commit()
    conn.close()
    return jsonify({"message": "tâche créée"}), 201


@app.route('/tasks/<int:task_id>', methods=['GET'])
def get_task(task_id):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, title, done FROM tasks WHERE id = ?", (task_id,)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "tâche introuvable"}), 404
    return jsonify({"id": row[0], "title": row[1], "done": bool(row[2])})


# FIX : whitelist de domaines autorisés — plus de SSRF
ALLOWED_HOSTS = {'httpbin.org', 'api.github.com', 'jsonplaceholder.typicode.com'}

@app.route('/fetch', methods=['GET'])
def fetch_url():
    url = request.args.get('url', '')
    if not url:
        return jsonify({"error": "url requise"}), 400
    from urllib.parse import urlparse
    host = urlparse(url).hostname or ''
    if host not in ALLOWED_HOSTS:
        return jsonify({"error": f"hôte non autorisé : {host}"}), 403
    resp = requests.get(url, timeout=5)
    return jsonify({"status": resp.status_code, "content": resp.text[:500]})


if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)
