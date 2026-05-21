import os
import sys
from pathlib import Path
from rich.console import Console

from ollama_client import verifier_ollama, appeler_ollama_json
from utils import afficher_banniere

console = Console()

PIPELINE_PATH = os.environ.get('PIPELINE_PATH', '../Jenkinsfile')

# Patterns suspects à détecter (règles fixes, sans IA)
PATTERNS_SUSPECTS = [
    'curl http://',      # HTTP non sécurisé uniquement
    'wget http://',      # HTTP non sécurisé uniquement
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
    """Analyse approfondie par Ollama — détection de tampering uniquement"""
    prompt = f"""Tu es un expert en sécurité CI/CD. Analyse ce Jenkinsfile pour détecter des MODIFICATIONS MALVEILLANTES (tampering).

```groovy
{contenu[:5000]}
```

Cherche UNIQUEMENT ces signes de tampering réel :
- Exfiltration de données : curl/wget vers des domaines inconnus (hors aquasecurity.github.io, download.docker.com, deb.debian.org, pypi.org, api.anthropic.com)
- Reverse shells ou backdoors : nc, netcat, /dev/tcp/, base64 | bash, base64 | sh
- Injection de code obfusqué : eval(), commandes encodées
- Téléchargement et exécution de scripts non vérifiés depuis des domaines suspects
- Envoi de secrets ou credentials vers l'extérieur

NE PAS signaler comme problèmes :
- La directive "agent any" (standard Jenkins)
- L'installation de packages légitimes (trivy, docker, semgrep, python, pip)
- Les variables OLLAMA_URL, OLLAMA_MODEL, IMAGE_NAME, REPORTS_DIR (non sensibles)
- La connexion à ollama:11434 (service interne du pipeline)
- Les commandes apt-get, wget, pip standard
- Les "|| true" ou "2>/dev/null" (gestion d'erreurs normale)
- withCredentials Jenkins (mécanisme sécurisé)
- L'installation de Docker CLI dans un agent CI/CD (pratique standard)

Réponds en JSON :
{{
  "statut": "SAFE ou SUSPECT ou DANGEREUX",
  "problemes": ["description du problème 1"],
  "recommandation": "Que faire",
  "bloquer": true ou false
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
        console.print(f'[yellow]⚠ {PIPELINE_PATH} introuvable — analyse ignorée[/yellow]')
        sys.exit(0)  # pas de blocage si fichier absent
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
        sys.exit(1)
    elif statut == 'SUSPECT':
        console.print('[yellow]AVERTISSEMENT — Éléments suspects détectés[/yellow]')
        for pb in resultat.get('problemes', []):
            console.print(f'  [yellow]⚠ {pb}[/yellow]')
    else:
        console.print('[green bold]Pipeline vérifié — Aucune anomalie détectée[/green bold]')