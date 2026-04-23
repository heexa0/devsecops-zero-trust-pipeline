"""
run_scans.py
============
Script de scan de sécurité automatique pour le pipeline Zero Trust.
Lance Trivy et Semgrep sur le dossier app/ et génère des rapports JSON.
"""

import subprocess
import os
import json
from datetime import datetime

# ─── Configuration ────────────────────────────────────────────────
APP_DIR = "app"
TRIVY_REPORT = "trivy-report.json"
SEMGREP_REPORT = "semgrep-report.json"
SEMGREP_CONFIG = "auto"  # Utilise les règles automatiques de Semgrep

# ─── Couleurs terminal ─────────────────────────────────────────────
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

def print_step(msg):
    print(f"\n{BLUE}{'─'*50}{RESET}")
    print(f"{BLUE}▶ {msg}{RESET}")
    print(f"{BLUE}{'─'*50}{RESET}")

def print_success(msg):
    print(f"{GREEN}✅ {msg}{RESET}")

def print_error(msg):
    print(f"{RED}❌ {msg}{RESET}")

def print_warning(msg):
    print(f"{YELLOW}⚠️  {msg}{RESET}")


# ─── Étape 1 : Vérifier les outils installés ─────────────────────
def check_tools():
    print_step("Vérification des outils installés")
    tools = {"trivy": False, "semgrep": False}

    for tool in tools:
        result = subprocess.run(
            [tool, "--version"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            version = result.stdout.strip().split("\n")[0]
            print_success(f"{tool} détecté → {version}")
            tools[tool] = True
        else:
            print_error(f"{tool} non trouvé — installe-le avant de continuer")

    return tools


# ─── Étape 2 : Lancer Trivy ───────────────────────────────────────
def run_trivy():
    print_step("Étape 2 — Lancement de Trivy sur app/requirements.txt")

    if not os.path.exists(APP_DIR):
        print_error(f"Dossier '{APP_DIR}' introuvable")
        return False

    cmd = [
        "trivy", "fs",
        "--format", "json",
        "--output", TRIVY_REPORT,
        "--severity", "HIGH,CRITICAL",
        "--quiet",
        APP_DIR
    ]

    print(f"  Commande : {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if os.path.exists(TRIVY_REPORT):
        # Compter les vulnérabilités trouvées
        try:
            with open(TRIVY_REPORT, "r", encoding="utf-8") as f:
                data = json.load(f)
            count = 0
            for result_item in data.get("Results", []):
                count += len(result_item.get("Vulnerabilities") or [])
            print_success(f"Trivy terminé → {TRIVY_REPORT} ({count} vulnérabilités trouvées)")
        except Exception:
            print_success(f"Trivy terminé → {TRIVY_REPORT}")
        return True
    else:
        print_error("Trivy n'a pas généré de rapport")
        print(result.stderr)
        return False


# ─── Étape 3 : Lancer Semgrep ─────────────────────────────────────
def run_semgrep():
    print_step("Étape 3 — Lancement de Semgrep sur app/ (règles auto)")

    if not os.path.exists(APP_DIR):
        print_error(f"Dossier '{APP_DIR}' introuvable")
        return False

    # Forcer UTF-8 pour éviter l'erreur d'encodage Windows (cp1252)
    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONLEGACYWINDOWSSTDIO"] = "0"

    cmd = [
        "semgrep",
        "--config", SEMGREP_CONFIG,          # "auto" = règles officielles Semgrep
        "--json",
        "--output", SEMGREP_REPORT,
        APP_DIR
    ]

    print(f"  Config   : {SEMGREP_CONFIG} (règles officielles Semgrep)")
    print(f"  Cible    : {APP_DIR}/")
    print(f"  Sortie   : {SEMGREP_REPORT}")
    print(f"  ⏳ Chargement des règles depuis le registry... (peut prendre 30s)")

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env
    )

    if os.path.exists(SEMGREP_REPORT):
        try:
            with open(SEMGREP_REPORT, "r", encoding="utf-8") as f:
                data = json.load(f)
            count = len(data.get("results", []))
            print_success(f"Semgrep terminé → {SEMGREP_REPORT} ({count} findings trouvés)")
        except Exception:
            print_success(f"Semgrep terminé → {SEMGREP_REPORT}")
        return True
    else:
        print_error("Semgrep n'a pas généré de rapport JSON")
        if result.stderr:
            print(f"  Erreur : {result.stderr[:300]}")
        return False


# ─── Étape 5 : Résumé final ───────────────────────────────────────
def print_summary(trivy_ok, semgrep_ok):
    print_step("Résumé des scans")

    print(f"  Trivy   : {'✅ OK' if trivy_ok else '❌ Échec'}")
    print(f"  Semgrep : {'✅ OK' if semgrep_ok else '❌ Échec'}")

    if trivy_ok and semgrep_ok:
        print(f"\n{GREEN}🎉 Scans terminés avec succès !{RESET}")
        print(f"  📄 {TRIVY_REPORT}")
        print(f"  📄 {SEMGREP_REPORT}")
        print(f"\n{YELLOW}➡️  Prochaine étape : lancer ai_agent.py{RESET}")
    else:
        print_warning("Certains scans ont échoué — vérifie les erreurs ci-dessus")


# ─── Main ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"\n{'═'*50}")
    print(f"  🔐 Zero Trust Security Scanner")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═'*50}")

    # 1. Vérifier les outils
    tools = check_tools()

    # 2. Lancer Trivy
    trivy_ok = False
    if tools["trivy"]:
        trivy_ok = run_trivy()
    else:
        print_warning("Trivy ignoré (non installé)")

    # 3. Lancer Semgrep
    semgrep_ok = False
    if tools["semgrep"]:
        semgrep_ok = run_semgrep()
    else:
        print_warning("Semgrep ignoré (non installé)")

    # 4. Résumé
    print_summary(trivy_ok, semgrep_ok)