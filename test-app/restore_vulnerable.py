"""Restaure l'application vulnérable (pour démonstration Security Gate) dans test-app/."""
import os

BASE = os.path.dirname(os.path.abspath(__file__))

APP_VULNERABLE = '''\
from flask import Flask, request, jsonify
import sqlite3
import requests

app = Flask(__name__)
DB_PATH = '/tmp/taskmanager.db'


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(\'\'\'CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        done INTEGER DEFAULT 0
    )\'\'\')
    conn.execute("INSERT OR IGNORE INTO tasks (id, title, done) VALUES (1, \'Setup projet\', 1)")
    conn.execute("INSERT OR IGNORE INTO tasks (id, title, done) VALUES (2, \'Ecrire les tests\', 0)")
    conn.commit()
    conn.close()


init_db()


@app.route(\'/\')
def index():
    return jsonify({"app": "Task Manager API", "version": "1.0", "status": "running"})


@app.route(\'/health\')
def health():
    return jsonify({"status": "ok"})


@app.route(\'/tasks\', methods=[\'GET\'])
def get_tasks():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT id, title, done FROM tasks").fetchall()
    conn.close()
    return jsonify({"tasks": [{"id": r[0], "title": r[1], "done": bool(r[2])} for r in rows]})


# VULNERABLE : injection SQL — concaténation directe du paramètre utilisateur
@app.route(\'/tasks/search\', methods=[\'GET\'])
def search_tasks():
    keyword = request.args.get(\'q\', \'\')
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, title, done FROM tasks WHERE title LIKE \'%" + keyword + "%\'"
    ).fetchall()
    conn.close()
    return jsonify({"results": [{"id": r[0], "title": r[1], "done": bool(r[2])} for r in rows]})


@app.route(\'/tasks\', methods=[\'POST\'])
def create_task():
    data = request.get_json() or {}
    title = data.get(\'title\', \'\').strip()
    if not title:
        return jsonify({"error": "title requis"}), 400
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO tasks (title) VALUES (?)", (title,))
    conn.commit()
    conn.close()
    return jsonify({"message": "tâche créée"}), 201


@app.route(\'/tasks/<int:task_id>\', methods=[\'GET\'])
def get_task(task_id):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, title, done FROM tasks WHERE id = ?", (task_id,)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "tâche introuvable"}), 404
    return jsonify({"id": row[0], "title": row[1], "done": bool(row[2])})


# VULNERABLE : SSRF — aucune validation de l\'hôte
@app.route(\'/fetch\', methods=[\'GET\'])
def fetch_url():
    url = request.args.get(\'url\', \'\')
    if not url:
        return jsonify({"error": "url requise"}), 400
    resp = requests.get(url, timeout=5)
    return jsonify({"status": resp.status_code, "content": resp.text[:500]})


if __name__ == \'__main__\':
    # VULNERABLE : debug=True expose le debugger interactif Werkzeug
    app.run(host=\'0.0.0.0\', port=5000, debug=True)
'''

REQUIREMENTS_VULNERABLE = '''\
flask==2.2.2
Werkzeug==2.2.2
requests==2.28.0
Pillow==9.3.0
cryptography==38.0.4
urllib3==1.26.12
'''

def write(filename, content):
    path = os.path.join(BASE, filename)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f'[OK] {filename} restauré')

write('app.py', APP_VULNERABLE)
write('requirements.txt', REQUIREMENTS_VULNERABLE)
print('\nApplication vulnérable restaurée.')
print('Failles actives :')
print('  - SQLi  : /tasks/search?q= (concaténation directe)')
print('  - SSRF  : /fetch?url= (aucune validation hôte)')
print('  - DEBUG : Flask debug=True exposé')
print('  - CVEs  : Pillow 9.3.0, cryptography 38.0.4, urllib3 1.26.12')
print('\nRelance le pipeline Jenkins pour voir le Security Gate bloquer le déploiement.')
print('Pour restaurer la version sécurisée : python test-app/restore_secure.py')
