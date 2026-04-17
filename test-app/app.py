from flask import Flask, request, jsonify
import sqlite3
import subprocess
import os

app = Flask(__name__)

# --- Route normale ---
@app.route('/')
def index():
    return jsonify({"message": "API Zero Trust Test App", "version": "1.0"})

# --- VULNÉRABILITÉ 1 : Injection SQL ---
# Cette fonction est volontairement vulnérable pour le test
@app.route('/user', methods=['GET'])
def get_user():
    username = request.args.get('username', '')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNÉRABLE : pas de requête paramétrée
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return jsonify({"users": results})

# --- VULNÉRABILITÉ 2 : Exécution de commande OS ---
@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host', 'localhost')
    # VULNÉRABLE : injection de commande possible
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return jsonify({"result": result.stdout})

# --- Route sécurisée (pour comparer) ---
@app.route('/health')
def health():
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)