import sys
import json
from pathlib import Path
from rich.console import Console
from rich.markdown import Markdown
 
from ollama_client import verifier_ollama, appeler_ollama
from utils import charger_json, afficher_banniere
 
console = Console()
 
 
def _extraire_alerts_zap(zap: dict) -> list:
    """Extrait toutes les alertes de tous les sites ZAP."""
    alerts = []
    for site in zap.get('site', []):
        alerts.extend(site.get('alerts', []))
    return alerts


def generer_rapport_pedagogique(
    trivy_path='trivy-report.json',
    semgrep_path='semgrep-results.json',
    zap_path='zap-report.json'
) -> str:
    """Génère un rapport d'analyse de sécurité pour l'équipe technique."""
    trivy   = charger_json(trivy_path) or {}
    semgrep = charger_json(semgrep_path) or {}
    zap     = charger_json(zap_path) or {}

    # Résumé SCA
    nb_cve = sum(
        len(r.get('Vulnerabilities', []))
        for r in trivy.get('Results', [])
    )
    nb_sast = len(semgrep.get('results', []))

    # Résumé DAST
    zap_alerts = _extraire_alerts_zap(zap)
    nb_dast_high   = sum(1 for a in zap_alerts if a.get('riskcode') == '3')
    nb_dast_medium = sum(1 for a in zap_alerts if a.get('riskcode') == '2')
    nb_dast_low    = sum(1 for a in zap_alerts if a.get('riskcode') == '1')

    # Extrait des alertes DAST High/Medium pour le prompt
    dast_critical_alerts = [
        {
            'alert': a.get('alert'),
            'riskdesc': a.get('riskdesc'),
            'cweid': a.get('cweid'),
            'solution': a.get('solution', '')[:300],
            'url': a.get('instances', [{}])[0].get('uri', '') if a.get('instances') else ''
        }
        for a in zap_alerts if a.get('riskcode') in ('3', '2')
    ]

    prompt = f"""Tu es un ingénieur DevSecOps senior produisant un rapport d'analyse de sécurité destiné à une équipe technique.

Résultats des scans de sécurité :
- Trivy (SCA) : {nb_cve} CVE détectées dans les dépendances Python
- Semgrep (SAST) : {nb_sast} findings dans le code source
- OWASP ZAP (DAST) : {nb_dast_high} High, {nb_dast_medium} Medium, {nb_dast_low} Low — scan dynamique sur l'application déployée

Données Trivy (extrait) :
{json.dumps(trivy.get('Results', [])[:2], ensure_ascii=False)[:1200]}

Données Semgrep (extrait) :
{json.dumps(semgrep.get('results', [])[:3], ensure_ascii=False)[:800]}

Données ZAP — alertes High/Medium :
{json.dumps(dast_critical_alerts[:5], ensure_ascii=False)[:1000]}

Génère un rapport Markdown technique structuré avec :
1. **Executive Summary** — synthèse en 3 lignes : surface d'attaque, criticité globale, statut de conformité Zero Trust
2. **Findings critiques** — pour chaque finding HIGH/CRITICAL (SCA + SAST + DAST) : identifiant (CVE/CWE/WASC), vecteur d'attaque, composant/endpoint affecté, impact opérationnel, exploitabilité
3. **Plan de remédiation** — actions priorisées par sévérité avec commandes exactes (`pip install`, patches, refactoring HTTP headers), délais recommandés (immédiat / 48h / sprint prochain)
4. **Analyse de la posture de sécurité** — forces identifiées, dette technique résiduelle, couverture des contrôles Zero Trust (SCA + SAST + DAST)
5. **Métriques** — MTTR estimé, score de risque résiduel, recommandations pour le prochain cycle CI/CD

Ton style : direct, factuel. Utilise la terminologie OWASP, CVSSv3, NIST, CWE. Pas d'emojis."""

    return appeler_ollama(prompt)
 
 
if __name__ == '__main__':
    afficher_banniere('Agent Explicatif — Dual AI Engine', 'green')
 
    if not verifier_ollama():
        sys.exit(1)
 
    rapport_md = generer_rapport_pedagogique()
 
    if rapport_md:
        # Afficher dans le terminal
        console.print(Markdown(rapport_md))
 
        # Sauvegarder
        with open('rapport-explicatif.md', 'w', encoding='utf-8') as f:
            f.write(rapport_md)
        console.print('[green]Rapport sauvegardé : rapport-explicatif.md[/green]')
    else:
        console.print('[red]Génération du rapport échouée[/red]')
        sys.exit(1)
 
