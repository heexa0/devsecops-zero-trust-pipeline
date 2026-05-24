"""Security Gate — calcule un score sur 100 et bloque le déploiement si < 90."""
import sys
import json
import os


def load_json(path):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


reports_dir = os.environ.get('REPORTS_DIR', '../reports')

trivy   = load_json(os.path.join(reports_dir, 'trivy-report.json'))
semgrep = load_json(os.path.join(reports_dir, 'semgrep-results.json'))
zap     = load_json(os.path.join(reports_dir, 'zap-report.json'))

score = 100
penalties = {
    'cve_critical': 0, 'cve_high': 0, 'cve_medium': 0, 'cve_low': 0,
    'sast_critical': 0, 'sast_high': 0,
    'dast_high': 0, 'dast_medium': 0,
}

# ── CVE (Trivy) ────────────────────────────────────────────────────────────────
for r in trivy.get('Results', []):
    for v in (r.get('Vulnerabilities') or []):
        sev = v.get('Severity', '')
        if sev == 'CRITICAL':
            score -= 15; penalties['cve_critical'] += 1
        elif sev == 'HIGH':
            score -= 8;  penalties['cve_high'] += 1
        elif sev == 'MEDIUM':
            score -= 3;  penalties['cve_medium'] += 1
        elif sev == 'LOW':
            score -= 1;  penalties['cve_low'] += 1

# ── SAST (Semgrep) ─────────────────────────────────────────────────────────────
for f in semgrep.get('results', []):
    sev = f.get('extra', {}).get('severity', '').upper()
    if sev in ('ERROR', 'CRITICAL'):
        score -= 10; penalties['sast_critical'] += 1
    elif sev == 'WARNING':
        score -= 5;  penalties['sast_high'] += 1

# ── DAST (ZAP) ────────────────────────────────────────────────────────────────
for site in zap.get('site', []):
    for alert in site.get('alerts', []):
        rd = alert.get('riskdesc', '')
        if rd.startswith('High'):
            score -= 8;  penalties['dast_high'] += 1
        elif rd.startswith('Medium'):
            score -= 4;  penalties['dast_medium'] += 1

score = max(0, score)
gate  = score >= 90
grade = ('A' if score >= 90 else 'B' if score >= 75 else
         'C' if score >= 60 else 'D' if score >= 40 else 'F')

gate_result = {
    'score':       score,
    'grade':       grade,
    'gate_passed': gate,
    'threshold':   90,
    'penalties':   penalties,
}

out_path = os.path.join(reports_dir, 'security-gate.json')
os.makedirs(os.path.dirname(out_path), exist_ok=True)
with open(out_path, 'w', encoding='utf-8') as f:
    json.dump(gate_result, f, indent=2)

sep = '=' * 50
print(sep)
print(f'  SECURITY GATE — Score : {score}/100  (Grade {grade})')
print(f'  Seuil deploiement     : 90/100')
print(f'  CVE  Critical : {penalties["cve_critical"]:>3} x(-15) | High : {penalties["cve_high"]:>3} x(-8) | Medium : {penalties["cve_medium"]:>3} x(-3)')
print(f'  SAST Critical : {penalties["sast_critical"]:>3} x(-10) | High : {penalties["sast_high"]:>3} x(-5)')
print(f'  DAST High     : {penalties["dast_high"]:>3} x( -8) | Medium : {penalties["dast_medium"]:>3} x(-4)')
print(f'  Resultat : {"PASS -- deploiement autorise" if gate else "FAIL -- deploiement BLOQUE"}')
print(sep)

if not gate:
    print(f'Score {score}/100 < 90 — pipeline arrete', file=sys.stderr)
    sys.exit(1)
