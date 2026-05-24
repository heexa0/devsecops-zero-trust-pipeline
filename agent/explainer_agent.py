import sys
import json
from pathlib import Path
from rich.console import Console
from rich.markdown import Markdown
 
from ollama_client import verifier_ollama, appeler_ollama
from utils import charger_json, afficher_banniere
 
console = Console()
 
 
def generer_rapport_pedagogique(
    trivy_path='trivy-report.json',
    semgrep_path='semgrep-results.json'
) -> str:
    """Génère un rapport pédagogique pour les développeurs"""
    trivy   = charger_json(trivy_path) or {}
    semgrep = charger_json(semgrep_path) or {}
 
    # Résumé des résultats pour le prompt
    nb_cve = sum(
        len(r.get('Vulnerabilities', []))
        for r in trivy.get('Results', [])
    )
    nb_sast = len(semgrep.get('results', []))
 
    prompt = f"""Tu es un ingénieur DevSecOps senior produisant un rapport d'analyse de sécurité destiné à une équipe technique.

Résultats des scans de sécurité :
- Trivy (SCA) : {nb_cve} CVE détectées dans les dépendances Python
- Semgrep (SAST) : {nb_sast} findings dans le code source

Données Trivy (extrait) :
{json.dumps(trivy.get('Results', [])[:2], ensure_ascii=False)[:1500]}

Données Semgrep (extrait) :
{json.dumps(semgrep.get('results', [])[:3], ensure_ascii=False)[:1000]}

Génère un rapport Markdown technique structuré avec :
1. **Executive Summary** — synthèse en 3 lignes : surface d'attaque, criticité globale, statut de conformité Zero Trust
2. **Findings critiques** — pour chaque finding HIGH/CRITICAL : CVE ID, vecteur CVSS, composant affecté, impact opérationnel, exploitabilité
3. **Plan de remédiation** — actions priorisées par sévérité avec commandes exactes (`pip install`, patches, refactoring), délais recommandés (immédiat / 48h / sprint prochain)
4. **Analyse de la posture de sécurité** — forces identifiées, dette technique résiduelle, couverture des contrôles Zero Trust
5. **Métriques** — MTTR estimé, score de risque résiduel, recommandations pour le prochain cycle CI/CD

Ton style : direct, factuel, sans formulation pédagogique. Utilise la terminologie OWASP, CVSSv3, NIST. Pas d'emojis."""
 
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
 
