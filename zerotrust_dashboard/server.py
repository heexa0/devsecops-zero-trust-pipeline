"""
ZeroTrust CI/CD Dashboard — Flask server
Lance avec : python dashboard/server.py
Ouvre : http://localhost:8888
"""
import json
import os
import glob
import time
from datetime import datetime
from flask import Flask, render_template, jsonify, send_from_directory

app = Flask(__name__, template_folder="templates", static_folder="static")

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")
AGENT_DIR   = os.path.join(os.path.dirname(__file__), "..", "agent")

# ─── helpers ────────────────────────────────────────────────────────────────

def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def load_trivy():
    for p in [
        os.path.join(REPORTS_DIR, "trivy-report.json"),
        os.path.join(AGENT_DIR,   "trivy-report.json"),
        os.path.join(os.path.dirname(__file__), "..", "trivy-report.json"),
    ]:
        if os.path.exists(p):
            return load_json(p)
    return {}

def load_semgrep():
    for p in [
        os.path.join(REPORTS_DIR, "semgrep-results.json"),
        os.path.join(AGENT_DIR,   "semgrep-results.json"),
    ]:
        if os.path.exists(p):
            return load_json(p)
    return {}

def load_zap():
    for p in [
        os.path.join(REPORTS_DIR, "zap-report.json"),
        os.path.join(AGENT_DIR,   "zap-report.json"),
    ]:
        if os.path.exists(p):
            return load_json(p)
    return {}

def load_ai():
    for p in [
        os.path.join(AGENT_DIR, "ai-remediation-report.json"),
        os.path.join(REPORTS_DIR, "ai-remediation-report.json"),
    ]:
        if os.path.exists(p):
            return load_json(p)
    return {}

# ─── routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status")
def api_status():
    """Résumé global du dernier build."""
    trivy   = load_trivy()
    semgrep = load_semgrep()
    zap     = load_zap()
    ai      = load_ai()

    # CVEs
    cve_total = cve_crit = cve_high = 0
    for r in trivy.get("Results", []):
        for v in (r.get("Vulnerabilities") or []):
            cve_total += 1
            sev = v.get("Severity", "")
            if sev == "CRITICAL": cve_crit += 1
            elif sev == "HIGH":   cve_high += 1

    # SAST
    sast_findings = len(semgrep.get("results", []))

    # ZAP
    zap_alerts = [a for s in zap.get("site", []) for a in s.get("alerts", [])]
    zap_high   = [a for a in zap_alerts if a.get("riskdesc", "").startswith("High")]

    # AI provider
    ai_provider = ai.get("provider", "claude")
    ai_calls    = ai.get("total_calls", 0)
    fallbacks   = ai.get("fallback_count", 0)

    return jsonify({
        "cve_total":      cve_total,
        "cve_critical":   cve_crit,
        "cve_high":       cve_high,
        "sast_findings":  sast_findings,
        "zap_alerts":     len(zap_alerts),
        "zap_high":       len(zap_high),
        "ai_provider":    ai_provider,
        "ai_calls":       ai_calls,
        "fallback_count": fallbacks,
        "timestamp":      datetime.now().isoformat(),
    })

@app.route("/api/findings")
def api_findings():
    """Toutes les findings consolidées (SAST + SCA + DAST)."""
    findings = []

    # SAST — Semgrep
    semgrep = load_semgrep()
    for r in semgrep.get("results", []):
        findings.append({
            "source": "SAST",
            "severity": "critical",
            "title": r.get("check_id", "Unknown rule"),
            "detail": r.get("extra", {}).get("message", ""),
            "file": f"{r.get('path','?')}:{r.get('start',{}).get('line','?')}",
        })

    # SCA — Trivy
    trivy = load_trivy()
    for result in trivy.get("Results", []):
        for v in (result.get("Vulnerabilities") or []):
            sev = v.get("Severity", "LOW").lower()
            if sev == "critical": sev_key = "critical"
            elif sev == "high":   sev_key = "high"
            else:                 sev_key = "medium"
            findings.append({
                "source": "SCA",
                "severity": sev_key,
                "title": f"{v.get('VulnerabilityID','')} — {v.get('PkgName','')} {v.get('InstalledVersion','')}",
                "detail": v.get("Description", v.get("Title", ""))[:120],
                "file": f"requirements.txt (fix: {v.get('FixedVersion','N/A')})",
            })

    # DAST — ZAP
    zap = load_zap()
    for site in zap.get("site", []):
        for alert in site.get("alerts", []):
            rd = alert.get("riskdesc", "")
            if rd.startswith("High"):   sev_key = "high"
            elif rd.startswith("Medium"): sev_key = "medium"
            else:                         sev_key = "info"
            findings.append({
                "source": "DAST",
                "severity": sev_key,
                "title": alert.get("alert", "Unknown"),
                "detail": alert.get("desc", "")[:120],
                "file": alert.get("solution", "")[:80],
            })

    return jsonify(findings)

@app.route("/api/ai")
def api_ai():
    """Détails de l'agent IA."""
    ai = load_ai()
    return jsonify(ai)

@app.route("/api/reports")
def api_reports():
    """Liste des fichiers de rapport disponibles."""
    files = []
    for d in [REPORTS_DIR, AGENT_DIR]:
        if not os.path.isdir(d):
            continue
        for ext in ["*.json", "*.html", "*.md", "*.pdf"]:
            for f in glob.glob(os.path.join(d, ext)):
                size = os.path.getsize(f)
                files.append({
                    "name": os.path.basename(f),
                    "path": f,
                    "size": f"{size // 1024} KB" if size > 1024 else f"{size} B",
                    "mtime": datetime.fromtimestamp(os.path.getmtime(f)).strftime("%H:%M:%S"),
                })
    return jsonify(files)

@app.route("/reports/<path:filename>")
def serve_report(filename):
    return send_from_directory(REPORTS_DIR, filename)

# ─── main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*50)
    print("  ZeroTrust CI Dashboard")
    print("  http://localhost:8888")
    print("="*50 + "\n")
    app.run(host="0.0.0.0", port=8888, debug=True)