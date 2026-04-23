import sys
from pathlib import Path
from rich.console import Console
 
from ollama_client import verifier_ollama, appeler_ollama_json
from utils import afficher_banniere
 
console = Console()
 
PIPELINE_PATH = '.github/workflows/pipeline.yml'
 
# Patterns suspects à détecter (règles fixes, sans IA)
PATTERNS_SUSPECTS = [
    'curl http://',
    'curl https://',
    'wget http://',
    'nc -',
    'netcat',
    '/dev/tcp/',
    'base64 -d',
    'eval(',
    '| bash',
    '| sh',
]
 
 
def detection_rapide(contenu: str) -> list[str]:
    """Détection par règles fixes (rapide, sans IA)"""
    alertes = []
    for i, ligne in enumerate(contenu.split('\n'), 1):
        for pattern in PATTERNS_SUSPECTS:
            if pattern.lower() in ligne.lower():
                alertes.append(f"Ligne {i}: '{pattern}' détecté → {ligne.strip()}")
    return alertes
 
 
def analyse_ia(contenu: str) -> dict:
    """Analyse approfondie par Ollama"""
    prompt = f"""Tu es un expert en sécurité CI/CD. Analyse ce fichier GitHub Actions :
 
```yaml
{contenu[:3000]}
```
 
Détecte les problèmes de sécurité : commandes d'exfiltration, backdoors,
téléchargements suspects, variables d'environnement exposées.
 
Réponds en JSON :
{{
  \"statut\": \"SAFE ou SUSPECT ou DANGEREUX\",
  \"problemes\": [\"description du problème 1\"],
  \"recommandation\": \"Que faire\",
  \"bloquer\": true ou false
}}
 
Réponds UNIQUEMENT en JSON valide."""
    return appeler_ollama_json(prompt)
 
 
if __name__ == '__main__':
    afficher_banniere('Agent Anti-Tampering — Ollama Zero Trust', 'red')
 
    # Vérifier qu'Ollama tourne
    if not verifier_ollama():
        sys.exit(1)
 
    # Lire le pipeline
    path = Path(PIPELINE_PATH)
    if not path.exists():
        console.print(f'[red]{PIPELINE_PATH} introuvable[/red]')
        sys.exit(1)
    contenu = path.read_text(encoding='utf-8')
 
    # Étape 1 : détection rapide par règles fixes
    alertes = detection_rapide(contenu)
    if alertes:
        console.print('[red bold]ALERTES DÉTECTÉES (règles fixes) :[/red bold]')
        for alerte in alertes:
            console.print(f'  [red]✗ {alerte}[/red]')
 
    # Étape 2 : analyse IA approfondie
    console.print('[blue]Analyse IA approfondie en cours...[/blue]')
    resultat = analyse_ia(contenu)
 
    statut = resultat.get('statut', 'INCONNU')
    bloquer = resultat.get('bloquer', False) or len(alertes) > 0
 
    if statut == 'DANGEREUX' or bloquer:
        console.print('[red bold]PIPELINE BLOQUÉ — Modification malveillante détectée ![/red bold]')
        for pb in resultat.get('problemes', []):
            console.print(f'  [red]✗ {pb}[/red]')
        sys.exit(1)  # Code 1 = bloque GitHub Actions
    elif statut == 'SUSPECT':
        console.print('[yellow]AVERTISSEMENT — Éléments suspects détectés[/yellow]')
        for pb in resultat.get('problemes', []):
            console.print(f'  [yellow]⚠ {pb}[/yellow]')
    else:
        console.print('[green bold]Pipeline vérifié — Aucune anomalie détectée[/green bold]')
 
