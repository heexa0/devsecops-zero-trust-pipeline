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
 
    prompt = f"""Tu es un mentor bienveillant qui explique la sécurité à des étudiantes.
 
Résultats des scans de sécurité :
- Trivy a trouvé {nb_cve} vulnérabilités dans les dépendances Python
- Semgrep a trouvé {nb_sast} problèmes dans le code source
 
Données Trivy (extrait) :
{json.dumps(trivy.get('Results', [])[:2], ensure_ascii=False)[:1500]}
 
Données Semgrep (extrait) :
{json.dumps(semgrep.get('results', [])[:3], ensure_ascii=False)[:1000]}
 
Génère un rapport Markdown pédagogique avec :
1. Résumé en 3 lignes simples (pour quelqu'un de non-technique)
2. Les 3 problèmes les plus importants, expliqués simplement
3. Les étapes concrètes à faire (commandes exactes)
4. Ce que vous avez bien fait (points positifs)
5. Ce que vous allez apprendre en corrigeant cela
 
Sois encourageant, pédagogique et précis. Utilise des emojis."""
 
    return appeler_ollama(prompt)
 
 
if __name__ == '__main__':
    afficher_banniere('Agent Explicatif — Ollama Zero Trust', 'green')
 
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
 
