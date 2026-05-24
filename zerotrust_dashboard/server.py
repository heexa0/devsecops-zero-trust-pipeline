"""
ZeroTrust CI/CD Dashboard — Flask server
Lance avec : python server.py
Ouvre : http://localhost:8888
"""
import json, os, glob, requests, shutil
from datetime import datetime
from flask import Flask, render_template, jsonify, send_from_directory, request
from requests.auth import HTTPBasicAuth

def load_dotenv(path=None):
    candidates = [
        path,
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
        os.path.join(os.getcwd(), ".env"),
    ]
    for p in candidates:
        if p and os.path.isfile(p):
            print(f"[.env] Chargé depuis : {p}")
            with open(p, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    if key and key not in os.environ:
                        os.environ[key] = val
            return True
    print("[.env] Aucun fichier .env trouvé — variables système utilisées")
    return False

load_dotenv()

app = Flask(__name__, template_folder="templates", static_folder="static")

JENKINS_URL   = os.environ.get("JENKINS_URL",   "http://localhost:9090")
JENKINS_USER  = os.environ.get("JENKINS_USER",  "admin")
JENKINS_TOKEN = os.environ.get("JENKINS_TOKEN", "")
JENKINS_JOB   = os.environ.get("JENKINS_JOB",  "zero-trust-pipeline")

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.environ.get("REPORTS_DIR", os.path.join(BASE_DIR, "reports"))
AGENT_DIR   = os.environ.get("AGENT_DIR",   os.path.join(BASE_DIR, "agent"))

HISTORY_DIR = os.environ.get("HISTORY_DIR", os.path.join(BASE_DIR, "history"))

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(AGENT_DIR,   exist_ok=True)
os.makedirs(HISTORY_DIR, exist_ok=True)

if JENKINS_TOKEN:
    JENKINS_AUTH = HTTPBasicAuth(JENKINS_USER, JENKINS_TOKEN)
    print(f"[Auth] Jenkins : {JENKINS_USER}@{JENKINS_URL}/job/{JENKINS_JOB} ✓")
else:
    JENKINS_AUTH = None
    print(f"[Auth] ⚠ JENKINS_TOKEN vide")

# ── Helpers Jenkins ───────────────────────────────────────────────────────────

def jenkins_get(path, timeout=6):
    try:
        url = f"{JENKINS_URL}{path}"
        r = requests.get(url, auth=JENKINS_AUTH, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        print(f"[Jenkins] Connexion refusée : {JENKINS_URL}")
        return None
    except requests.exceptions.Timeout:
        print(f"[Jenkins] Timeout ({timeout}s) : {path}")
        return None
    except requests.exceptions.HTTPError as e:
        print(f"[Jenkins] HTTP {e.response.status_code} : {path}")
        return None
    except Exception as e:
        print(f"[Jenkins] Erreur : {path} → {e}")
        return None

def jenkins_get_text(path, timeout=10):
    try:
        url = f"{JENKINS_URL}{path}"
        r = requests.get(url, auth=JENKINS_AUTH, timeout=timeout)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[Jenkins text] {path} → {e}")
        return None

def jenkins_get_binary(path, timeout=30):
    try:
        url = f"{JENKINS_URL}{path}"
        r = requests.get(url, auth=JENKINS_AUTH, timeout=timeout)
        r.raise_for_status()
        return r.content
    except Exception as e:
        print(f"[Jenkins binary] {path} → {e}")
        return None

def get_last_build():
    return jenkins_get(f"/job/{JENKINS_JOB}/lastBuild/api/json?depth=2")

# ── FIX PRINCIPAL : extraction robuste des stages avec fallback Blue Ocean ────
def get_build_stages(build_number):
    """
    Tente d'abord l'API wfapi/describe (Pipeline plugin).
    Si les noms sont vides ou génériques, bascule sur Blue Ocean REST API.
    """
    data = jenkins_get(f"/job/{JENKINS_JOB}/{build_number}/wfapi/describe")

    if data and data.get("stages"):
        # Vérifie que les noms sont réels (pas tous vides ou "Stage")
        names = [s.get("name", "").strip() for s in data["stages"]]
        real_names = [n for n in names if n and n not in ("Stage", "stage")]
        if real_names:
            print(f"[Stages] wfapi OK — {len(real_names)} noms trouvés : {real_names[:3]}")
            return data
        else:
            print(f"[Stages] wfapi retourne des noms vides — tentative Blue Ocean")

    # Fallback : Blue Ocean REST API (retourne displayName)
    blue = jenkins_get(
        f"/blue/rest/organizations/jenkins/pipelines/{JENKINS_JOB}/runs/{build_number}/nodes/?limit=100"
    )
    if blue and isinstance(blue, list) and len(blue) > 0:
        print(f"[Stages] Blue Ocean OK — {len(blue)} stages trouvés")
        return {"stages": blue, "_source": "blue_ocean"}

    # Fallback 2 : API générique lastBuild
    generic = jenkins_get(f"/job/{JENKINS_JOB}/{build_number}/api/json?depth=1&tree=stages[*]")
    if generic and generic.get("stages"):
        return generic

    return data

def get_console_log(build_number):
    return jenkins_get_text(f"/job/{JENKINS_JOB}/{build_number}/logText/progressiveText?start=0")

def get_crumb():
    data = jenkins_get("/crumbIssuer/api/json", timeout=4)
    if data:
        return data.get("crumb"), data.get("crumbRequestField", "Jenkins-Crumb")
    return None, "Jenkins-Crumb"

def map_stage_status(s):
    return {
        "SUCCESS":              "done",
        "FAILED":               "fail",
        "FAILURE":              "fail",
        "IN_PROGRESS":          "running",
        "NOT_EXECUTED":         "waiting",
        "ABORTED":              "waiting",
        "UNSTABLE":             "done",
        "PAUSED_PENDING_INPUT": "running",
        # Blue Ocean values
        "FINISHED":             "done",
        "RUNNING":              "running",
        "QUEUED":               "waiting",
        "SKIPPED":              "waiting",
        "UNKNOWN":              "waiting",
    }.get(s, "waiting")

def map_build_status(s):
    return {
        "SUCCESS":  "success",
        "FAILURE":  "failure",
        "ABORTED":  "aborted",
        "UNSTABLE": "unstable",
        None:       "running",
    }.get(s, "running")

# ── FIX : extraction du nom de stage multi-format ────────────────────────────
def extract_stage_name(s, idx):
    """
    Extrait le nom d'un stage depuis n'importe quel format Jenkins.
    Cherche dans toutes les clés connues : wfapi, Blue Ocean, Pipeline plugin.
    """
    # Ordre de priorité des clés de nom selon les différentes APIs Jenkins
    name = (
        s.get("displayName") or      # Blue Ocean REST API
        s.get("name") or             # wfapi/describe standard
        s.get("stageName") or        # Certains plugins alternatifs
        s.get("displayDescription") or
        s.get("label") or
        ""
    )
    name = name.strip()

    # Si le nom est générique ou vide, on utilise un fallback lisible
    if not name or name.lower() in ("stage", ""):
        # Essaie de lire depuis les actions imbriquées
        for action in s.get("actions", []):
            if isinstance(action, dict):
                sub = action.get("displayName") or action.get("name") or ""
                if sub.strip() and sub.strip().lower() != "stage":
                    name = sub.strip()
                    break

        # Dernier recours : numéro d'index lisible
        if not name or name.lower() == "stage":
            name = f"Étape {idx + 1}"

    return name

# ── Helpers fichiers rapport ──────────────────────────────────────────────────

def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as e:
        print(f"[JSON] Invalide {path}: {e}")
        return {}

def find_file(*candidates):
    for p in candidates:
        if p and os.path.isfile(p) and os.path.getsize(p) > 10:
            return load_json(p)
    return {}

def load_trivy():
    return find_file(
        os.path.join(REPORTS_DIR, "trivy-report.json"),
        os.path.join(AGENT_DIR,   "trivy-report.json"),
        os.path.join(BASE_DIR,    "trivy-report.json"),
    )

def load_semgrep():
    return find_file(
        os.path.join(REPORTS_DIR, "semgrep-results.json"),
        os.path.join(AGENT_DIR,   "semgrep-results.json"),
        os.path.join(BASE_DIR,    "semgrep-results.json"),
    )

def load_zap():
    return find_file(
        os.path.join(REPORTS_DIR, "zap-report.json"),
        os.path.join(AGENT_DIR,   "zap-report.json"),
        os.path.join(BASE_DIR,    "zap-report.json"),
    )

def load_ai():
    return find_file(
        os.path.join(AGENT_DIR,   "ai-remediation-report.json"),
        os.path.join(REPORTS_DIR, "ai-remediation-report.json"),
        os.path.join(AGENT_DIR,   "remediation-report.json"),
    )

# ── Sync artifacts depuis Jenkins ─────────────────────────────────────────────

def sync_reports_from_jenkins(build_number):
    artifact_map = [
        (f"/job/{JENKINS_JOB}/{build_number}/artifact/reports/trivy-report.json",
         os.path.join(REPORTS_DIR, "trivy-report.json")),
        (f"/job/{JENKINS_JOB}/{build_number}/artifact/reports/semgrep-results.json",
         os.path.join(REPORTS_DIR, "semgrep-results.json")),
        (f"/job/{JENKINS_JOB}/{build_number}/artifact/reports/zap-report.json",
         os.path.join(REPORTS_DIR, "zap-report.json")),
        (f"/job/{JENKINS_JOB}/{build_number}/artifact/reports/zap-report.html",
         os.path.join(REPORTS_DIR, "zap-report.html")),
        (f"/job/{JENKINS_JOB}/{build_number}/artifact/agent/trivy-report.json",
         os.path.join(AGENT_DIR,   "trivy-report.json")),
        (f"/job/{JENKINS_JOB}/{build_number}/artifact/agent/semgrep-results.json",
         os.path.join(AGENT_DIR,   "semgrep-results.json")),
        (f"/job/{JENKINS_JOB}/{build_number}/artifact/agent/zap-report.json",
         os.path.join(AGENT_DIR,   "zap-report.json")),
        (f"/job/{JENKINS_JOB}/{build_number}/artifact/agent/ai-remediation-report.json",
         os.path.join(AGENT_DIR,   "ai-remediation-report.json")),
        (f"/job/{JENKINS_JOB}/{build_number}/artifact/agent/rapport-explicatif.md",
         os.path.join(AGENT_DIR,   "rapport-explicatif.md")),
        (f"/job/{JENKINS_JOB}/{build_number}/artifact/reports/rapport-zerotrust.pdf",
         os.path.join(REPORTS_DIR, "rapport-zerotrust.pdf")),
    ]

    synced = []
    errors = []

    for jenkins_path, local_path in artifact_map:
        content = jenkins_get_binary(jenkins_path, timeout=30)
        if content and len(content) > 10:
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            with open(local_path, "wb") as f:
                f.write(content)
            synced.append(os.path.basename(local_path))
            print(f"[Sync] ✓ {os.path.basename(local_path)} ({len(content)} bytes)")
        else:
            errors.append(os.path.basename(local_path))

    return synced, errors

# ── Build history helpers ──────────────────────────────────────────────────────

HISTORY_FILE = os.path.join(HISTORY_DIR, "builds.json")

def load_history():
    try:
        if os.path.isfile(HISTORY_FILE):
            with open(HISTORY_FILE, encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return []

def save_history(history):
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)

def snapshot_build(build_number, build_result, branch, commit, duration_ms, timestamp_ms):
    """Save a snapshot of the current build metrics into history."""
    history = load_history()
    # avoid duplicates
    if any(h["build_number"] == build_number for h in history):
        return

    trivy   = load_trivy()
    semgrep = load_semgrep()
    zap     = load_zap()
    ai      = load_ai()

    cve_total = cve_crit = cve_high = 0
    for result in trivy.get("Results", []):
        for v in (result.get("Vulnerabilities") or []):
            cve_total += 1
            sev = v.get("Severity", "")
            if sev == "CRITICAL": cve_crit += 1
            elif sev == "HIGH":   cve_high += 1

    sast_findings = len(semgrep.get("results", []))
    zap_alerts    = [a for s in zap.get("site", []) for a in s.get("alerts", [])]
    zap_high      = len([a for a in zap_alerts if a.get("riskdesc", "").startswith("High")])

    entry = {
        "build_number":  build_number,
        "build_result":  build_result or "UNKNOWN",
        "branch":        branch,
        "commit":        commit,
        "duration_ms":   duration_ms,
        "timestamp":     datetime.fromtimestamp(timestamp_ms / 1000).isoformat() if timestamp_ms else datetime.now().isoformat(),
        "cve_total":     cve_total,
        "cve_critical":  cve_crit,
        "cve_high":      cve_high,
        "sast_findings": sast_findings,
        "zap_alerts":    len(zap_alerts),
        "zap_high":      zap_high,
        "ai_provider":   ai.get("provider", "claude"),
        "ai_calls":      ai.get("total_calls", 0),
        "fallback_count":ai.get("fallback_count", 0),
    }

    history.insert(0, entry)
    history = history[:50]  # keep last 50 builds
    save_history(history)

    # archive reports for this build
    archive_dir = os.path.join(HISTORY_DIR, f"build-{build_number}")
    os.makedirs(archive_dir, exist_ok=True)
    for src in [
        os.path.join(REPORTS_DIR, "trivy-report.json"),
        os.path.join(REPORTS_DIR, "semgrep-results.json"),
        os.path.join(REPORTS_DIR, "zap-report.json"),
        os.path.join(REPORTS_DIR, "rapport-zerotrust.pdf"),
    ]:
        if os.path.isfile(src):
            shutil.copy2(src, archive_dir)

    print(f"[History] Build #{build_number} archivé dans {archive_dir}")

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── ROUTE DEBUG : voir la structure brute retournée par Jenkins ───────────────
@app.route("/api/debug/stages")
def api_debug_stages():
    """Affiche la structure brute des stages pour diagnostiquer le problème de noms."""
    build = get_last_build()
    if not build:
        return jsonify({"error": "Jenkins hors ligne"})
    n = build.get("number")
    wfapi = jenkins_get(f"/job/{JENKINS_JOB}/{n}/wfapi/describe")
    blue  = jenkins_get(
        f"/blue/rest/organizations/jenkins/pipelines/{JENKINS_JOB}/runs/{n}/nodes/?limit=10"
    )
    sample_wfapi = None
    sample_blue  = None
    if wfapi and wfapi.get("stages"):
        sample_wfapi = wfapi["stages"][0] if wfapi["stages"] else None
    if blue and isinstance(blue, list) and blue:
        sample_blue = blue[0]
    return jsonify({
        "build": n,
        "wfapi_first_stage_keys": list(sample_wfapi.keys()) if sample_wfapi else None,
        "wfapi_first_stage":      sample_wfapi,
        "blue_first_stage_keys":  list(sample_blue.keys()) if sample_blue else None,
        "blue_first_stage":       sample_blue,
        "wfapi_stages_count": len(wfapi.get("stages", [])) if wfapi else 0,
        "blue_nodes_count":   len(blue) if isinstance(blue, list) else 0,
    })


@app.route("/api/jenkins/status")
def api_jenkins_status():
    build = get_last_build()
    if not build:
        return jsonify({
            "jenkins_available": False,
            "error": f"Jenkins non joignable sur {JENKINS_URL}"
        })

    build_number = build.get("number", "?")
    build_result = build.get("result")
    build_status = map_build_status(build_result)
    duration_ms  = build.get("duration", 0)
    timestamp_ms = build.get("timestamp", 0)

    branch = JENKINS_JOB
    commit = "–"
    for action in build.get("actions", []):
        if not isinstance(action, dict):
            continue
        for branch_data in action.get("buildsByBranchName", {}).values():
            sha = branch_data.get("revision", {}).get("SHA1", "")
            if sha:
                commit = sha[:7]
            marked = branch_data.get("revision", {}).get("branch", [{}])
            if marked:
                branch = marked[0].get("name", branch).split("/")[-1]
        for p in action.get("parameters", []):
            if p.get("name") == "BRANCH":
                branch = p.get("value", branch)

    stages_data = get_build_stages(build_number)
    stages = []
    raw_stages = []

    if stages_data:
        if "stages" in stages_data:
            raw_stages = stages_data["stages"]
        elif isinstance(stages_data, list):
            raw_stages = stages_data

    # ── FIX : boucle avec extraction robuste du nom ───────────────────────────
    for idx, s in enumerate(raw_stages):
        # Durée : wfapi → durationMillis, Blue Ocean → durationInMillis
        dur_ms  = s.get("durationMillis") or s.get("durationInMillis") or 0
        dur_str = f"{dur_ms // 1000}s" if dur_ms > 0 else "–"

        # Statut : wfapi → status, Blue Ocean → result ou state
        status_raw = (
            s.get("status") or
            s.get("result") or
            s.get("state") or
            "NOT_EXECUTED"
        )

        # Nom : utilise la fonction robuste extract_stage_name
        stage_name = extract_stage_name(s, idx)

        stages.append({
            "id":       s.get("id"),
            "name":     stage_name,
            "status":   map_stage_status(status_raw),
            "duration": dur_str,
        })

    done_count  = sum(1 for s in stages if s["status"] == "done")
    elapsed_sec = int((datetime.now().timestamp() * 1000 - timestamp_ms) / 1000) if timestamp_ms else 0

    build_finished = build_result in ("SUCCESS", "FAILURE", "UNSTABLE", "ABORTED")

    # Auto-snapshot finished builds into history
    if build_finished:
        try:
            snapshot_build(
                build_number, build_result, branch, commit,
                duration_ms, timestamp_ms
            )
        except Exception as e:
            print(f"[History] Snapshot error: {e}")

    return jsonify({
        "jenkins_available": True,
        "build_number":      build_number,
        "build_status":      build_status,
        "build_result":      build_result,
        "build_finished":    build_finished,
        "branch":            branch,
        "commit":            commit,
        "duration_ms":       duration_ms,
        "elapsed_sec":       elapsed_sec,
        "timestamp":         datetime.fromtimestamp(timestamp_ms / 1000).isoformat() if timestamp_ms else None,
        "stages":            stages,
        "stages_count":      len(stages),
        "done_count":        done_count,
    })


@app.route("/api/history")
def api_history():
    return jsonify(load_history())


@app.route("/api/history/<int:build_number>/reports/<path:filename>")
def serve_history_report(build_number, filename):
    archive_dir = os.path.join(HISTORY_DIR, f"build-{build_number}")
    return send_from_directory(archive_dir, filename)


@app.route("/api/jenkins/logs")
def api_jenkins_logs():
    build = get_last_build()
    if not build:
        return jsonify({"available": False, "text": "", "error": "Jenkins hors ligne"})
    number = build.get("number", "lastBuild")
    text   = get_console_log(number) or ""
    return jsonify({"available": bool(text), "build": number, "text": text})


@app.route("/api/jenkins/trigger", methods=["POST"])
def api_jenkins_trigger():
    if not JENKINS_TOKEN:
        return jsonify({"success": False, "error": "JENKINS_TOKEN non configuré dans .env"}), 400

    crumb, crumb_field = get_crumb()
    headers = {}
    if crumb:
        headers[crumb_field] = crumb

    try:
        url = f"{JENKINS_URL}/job/{JENKINS_JOB}/build"
        r = requests.post(url, auth=JENKINS_AUTH, headers=headers, timeout=10)
        if r.status_code in (200, 201):
            return jsonify({"success": True, "message": f"Pipeline '{JENKINS_JOB}' lancé ✓"})
        elif r.status_code == 403:
            return jsonify({"success": False, "error": "Accès refusé — vérifier les permissions Jenkins"}), 403
        elif r.status_code == 404:
            return jsonify({"success": False, "error": f"Job '{JENKINS_JOB}' introuvable"}), 404
        else:
            return jsonify({"success": False, "error": f"Jenkins {r.status_code}: {r.text[:200]}"}), r.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({"success": False, "error": f"Impossible de joindre Jenkins à {JENKINS_URL}"}), 503


@app.route("/api/sync-reports", methods=["GET", "POST"])
def api_sync_reports():
    build = get_last_build()
    if not build:
        return jsonify({"success": False, "error": "Jenkins hors ligne"})

    build_number = build.get("number")
    build_result = build.get("result")

    synced, errors = sync_reports_from_jenkins(build_number)

    return jsonify({
        "success":      True,
        "build_number": build_number,
        "build_result": build_result,
        "synced":       synced,
        "errors":       errors,
        "message":      f"✓ {len(synced)} fichier(s) synchronisé(s) depuis build #{build_number}"
    })


@app.route("/api/status")
def api_status():
    trivy   = load_trivy()
    semgrep = load_semgrep()
    zap     = load_zap()
    ai      = load_ai()

    cve_total = cve_crit = cve_high = 0
    for result in trivy.get("Results", []):
        for v in (result.get("Vulnerabilities") or []):
            cve_total += 1
            sev = v.get("Severity", "")
            if sev == "CRITICAL": cve_crit += 1
            elif sev == "HIGH":   cve_high += 1

    sast_findings = len(semgrep.get("results", []))
    zap_alerts    = [a for s in zap.get("site", []) for a in s.get("alerts", [])]
    zap_high      = [a for a in zap_alerts if a.get("riskdesc", "").startswith("High")]

    return jsonify({
        "cve_total":      cve_total,
        "cve_critical":   cve_crit,
        "cve_high":       cve_high,
        "sast_findings":  sast_findings,
        "zap_alerts":     len(zap_alerts),
        "zap_high":       len(zap_high),
        "ai_provider":    ai.get("provider", "claude"),
        "ai_calls":       ai.get("total_calls", 0),
        "fallback_count": ai.get("fallback_count", 0),
        "timestamp":      datetime.now().isoformat(),
        "reports_ready": {
            "trivy":   bool(trivy),
            "semgrep": bool(semgrep),
            "zap":     bool(zap),
            "ai":      bool(ai),
        },
    })


@app.route("/api/findings")
def api_findings():
    findings = []

    for r in load_semgrep().get("results", []):
        sev_raw = r.get("extra", {}).get("severity", "ERROR").upper()
        sev = "critical" if sev_raw in ("ERROR", "CRITICAL") else "high" if sev_raw == "WARNING" else "medium"
        findings.append({
            "source": "SAST", "severity": sev,
            "title":  r.get("check_id", "Unknown rule"),
            "detail": r.get("extra", {}).get("message", ""),
            "file":   f"{r.get('path','?')}:{r.get('start',{}).get('line','?')}",
        })

    for result in load_trivy().get("Results", []):
        for v in (result.get("Vulnerabilities") or []):
            sev = v.get("Severity", "LOW").lower()
            sev_key = "critical" if sev == "critical" else "high" if sev == "high" else "medium"
            findings.append({
                "source": "SCA", "severity": sev_key,
                "title":  f"{v.get('VulnerabilityID','')} — {v.get('PkgName','')} {v.get('InstalledVersion','')}",
                "detail": v.get("Description", v.get("Title", ""))[:150],
                "file":   f"requirements.txt · fix: {v.get('FixedVersion','N/A')}",
            })

    for site in load_zap().get("site", []):
        for alert in site.get("alerts", []):
            rd = alert.get("riskdesc", "")
            sev_key = "high" if rd.startswith("High") else "medium" if rd.startswith("Medium") else "info"
            findings.append({
                "source": "DAST", "severity": sev_key,
                "title":  alert.get("alert", "Unknown"),
                "detail": alert.get("desc", "")[:150],
                "file":   alert.get("solution", "")[:100],
            })

    return jsonify(findings)


@app.route("/api/ai")
def api_ai():
    return jsonify(load_ai())


@app.route("/api/reports")
def api_reports():
    files = []
    for d in [REPORTS_DIR, AGENT_DIR]:
        if not os.path.isdir(d):
            continue
        for ext in ["*.json", "*.html", "*.md", "*.pdf"]:
            for f in glob.glob(os.path.join(d, ext)):
                size = os.path.getsize(f)
                files.append({
                    "name":  os.path.basename(f),
                    "size":  f"{size // 1024} KB" if size > 1024 else f"{size} B",
                    "mtime": datetime.fromtimestamp(os.path.getmtime(f)).strftime("%H:%M:%S"),
                })
    return jsonify(files)


@app.route("/api/debug")
def api_debug():
    report_files = {}
    for name, path in [
        ("trivy",   os.path.join(REPORTS_DIR, "trivy-report.json")),
        ("semgrep", os.path.join(REPORTS_DIR, "semgrep-results.json")),
        ("zap",     os.path.join(REPORTS_DIR, "zap-report.json")),
        ("ai",      os.path.join(AGENT_DIR,   "ai-remediation-report.json")),
    ]:
        report_files[name] = {
            "path":   path,
            "exists": os.path.exists(path),
            "size":   os.path.getsize(path) if os.path.exists(path) else 0,
        }
    jenkins_ok = get_last_build() is not None
    return jsonify({
        "config": {
            "JENKINS_URL":   JENKINS_URL,
            "JENKINS_USER":  JENKINS_USER,
            "JENKINS_TOKEN": f"✓ {JENKINS_TOKEN[:6]}…" if JENKINS_TOKEN else "✗ VIDE",
            "JENKINS_JOB":   JENKINS_JOB,
            "REPORTS_DIR":   REPORTS_DIR,
            "AGENT_DIR":     AGENT_DIR,
        },
        "jenkins_reachable": jenkins_ok,
        "reports":           report_files,
        "cwd":               os.getcwd(),
    })


@app.route("/reports/<path:filename>")
def serve_report(filename):
    return send_from_directory(REPORTS_DIR, filename)


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  ZeroTrust CI Dashboard")
    print(f"  http://localhost:8888")
    print(f"  Jenkins : {JENKINS_URL}/job/{JENKINS_JOB}")
    print(f"  Auth    : {'✓ Token ' + JENKINS_TOKEN[:6] + '…' if JENKINS_TOKEN else '✗ Token manquant'}")
    print(f"  Reports : {REPORTS_DIR}")
    print(f"  Sync    : http://localhost:8888/api/sync-reports")
    print(f"  Debug   : http://localhost:8888/api/debug")
    print(f"  Stages  : http://localhost:8888/api/debug/stages")
    print("=" * 60 + "\n")
    app.run(host="0.0.0.0", port=8888, debug=False)