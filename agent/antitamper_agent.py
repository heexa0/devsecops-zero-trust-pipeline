import os
import sys
import json
from pathlib import Path
from rich.console import Console

from ollama_client import verifier_ollama, appeler_ollama_json, get_dernier_moteur
from utils import afficher_banniere

console = Console()

PIPELINE_PATH     = os.environ.get('PIPELINE_PATH', '../jenkinsfile')
SIMULATE_FALLBACK = os.environ.get('SIMULATE_FALLBACK', 'false').lower() == 'true'

# Patterns suspects détectés par règles fixes (sans IA)
PATTERNS_SUSPECTS = [
    'curl http://',
    'wget http://',
    'nc -',
    'netcat',
    '/dev/tcp/',
    'base64 -d',
    'eval(',
    '| bash',
    '| sh',
]

# Domaines légitimes connus du pipeline (ne pas alerter sur eux)
DOMAINES_LEGAUX = [
    'aquasecurity.github.io',
    'download.docker.com',
    'deb.debian.org',
    'pypi.org',
    'api.anthropic.com',
    'github.com/sigstore',
    'ghcr.io/zaproxy',
    'mirror.gcr.io',
    'github.com/aquasecurity',
]


def detection_rapide(contenu: str) -> list[str]:
    """Détection par règles fixes — rapide, sans IA."""
    alertes = []
    for i, ligne in enumerate(contenu.split('\n'), 1):
        ligne_lower = ligne.lower()
        for pattern in PATTERNS_SUSPECTS:
            if pattern.lower() in ligne_lower:
                # Exclure les faux positifs connus
                if any(domaine in ligne_lower for domaine in DOMAINES_LEGAUX):
                    continue
                # Exclure les commentaires
                if ligne.strip().startswith('#') or ligne.strip().startswith('//'):
                    continue
                alertes.append(f"Ligne {i}: '{pattern}' détecté → {ligne.strip()[:120]}")
    return alertes


def construire_prompt(contenu: str) -> str:
    return f"""Tu es un expert en sécurité CI/CD. Analyse ce Jenkinsfile pour détecter des MODIFICATIONS MALVEILLANTES (tampering).

```groovy
{contenu[:5000]}
```

Cherche UNIQUEMENT ces signes de tampering réel :
- Exfiltration de données : curl/wget vers des domaines inconnus (hors aquasecurity.github.io, download.docker.com, deb.debian.org, pypi.org, api.anthropic.com, github.com/sigstore, ghcr.io/zaproxy)
- Reverse shells ou backdoors : nc, netcat, /dev/tcp/, base64 | bash, base64 | sh
- Injection de code obfusqué : eval(), commandes encodées en base64 exécutées
- Téléchargement et exécution de scripts depuis des domaines suspects
- Envoi de secrets ou credentials vers l'extérieur

NE PAS signaler comme problèmes :
- La directive "agent any" (standard Jenkins)
- L'installation de packages légitimes (trivy, docker, semgrep, python, pip, cosign)
- Les variables OLLAMA_URL, OLLAMA_MODEL, IMAGE_NAME, REPORTS_DIR (non sensibles)
- La connexion à ollama:11434 (service interne du pipeline)
- Les commandes apt-get, wget https://, pip standard
- Les "|| true" ou "2>/dev/null" (gestion d'erreurs normale)
- withCredentials Jenkins (mécanisme sécurisé)
- L'installation de Docker CLI dans un agent CI/CD (pratique standard)
- curl/wget vers des domaines connus et légitimes

Réponds UNIQUEMENT en JSON valide, sans texte avant ou après :
{{
  "statut": "SAFE",
  "problemes": [],
  "recommandation": "Pipeline conforme — aucune anomalie détectée",
  "bloquer": false
}}

Si tu détectes un vrai problème, utilise "SUSPECT" ou "DANGEREUX" dans statut et mets bloquer à true."""


def analyse_ia(contenu: str) -> dict:
    """Analyse approfondie par IA (Ollama ou Claude selon disponibilité)."""
    prompt = construire_prompt(contenu)
    return appeler_ollama_json(prompt)


if __name__ == '__main__':
    afficher_banniere('Agent Anti-Tampering — Dual AI Engine', 'red')

    if SIMULATE_FALLBACK:
        console.print('[yellow bold]⚠ MODE SIMULATION FALLBACK : Claude API sera utilisé[/yellow bold]')

    # Vérifier qu'au moins un moteur est disponible
    if not verifier_ollama():
        console.print('[yellow]⚠ Aucun moteur IA — analyse par règles fixes uniquement[/yellow]')

    # Lire le pipeline
    path = Path(PIPELINE_PATH)
    if not path.exists():
        console.print(f'[yellow]⚠ {PIPELINE_PATH} introuvable — analyse ignorée[/yellow]')
        sys.exit(0)

    contenu = path.read_text(encoding='utf-8')

    # Étape 1 : détection rapide par règles fixes
    alertes = detection_rapide(contenu)
    if alertes:
        console.print('[red bold]ALERTES DÉTECTÉES (règles fixes) :[/red bold]')
        for alerte in alertes:
            console.print(f'  [red]✗ {alerte}[/red]')
    else:
        console.print('[green]✓ Détection rapide : aucun pattern suspect[/green]')

    # Étape 2 : analyse IA approfondie
    console.print('[blue]Analyse IA approfondie en cours...[/blue]')
    resultat = analyse_ia(contenu)

    moteur = get_dernier_moteur()

    # Gérer le cas où l'IA n'a pas répondu
    if not resultat:
        console.print('[yellow]⚠ Aucune réponse IA — décision basée sur règles fixes uniquement[/yellow]')
        if alertes:
            console.print('[red bold]PIPELINE BLOQUÉ — Patterns suspects détectés (règles fixes)[/red bold]')
            sys.exit(1)
        else:
            console.print('[green bold]Pipeline vérifié — Aucune anomalie détectée (règles fixes)[/green bold]')
            sys.exit(0)

    console.print(f'[blue]Analyse effectuée par : {moteur}[/blue]')

    statut  = resultat.get('statut', 'INCONNU')
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
        console.print(f'[yellow]Recommandation : {resultat.get("recommandation", "")}[/yellow]')
    else:
        console.print('[green bold]Pipeline vérifié — Aucune anomalie détectée[/green bold]')
        console.print(f'[green]Moteur utilisé : {moteur}[/green]')