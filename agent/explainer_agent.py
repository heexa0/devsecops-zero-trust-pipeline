import anthropic
import json
import os
from pathlib import Path
from rich.console import Console
from rich.markdown import Markdown

console = Console()

def generer_rapport_humain(rapport_trivy_path="trivy-report.json",
                            rapport_semgrep_path="semgrep-results.json"):
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    # Charger les deux rapports
    trivy_data = json.load(open(rapport_trivy_path)) if Path(rapport_trivy_path).exists() else {}
    semgrep_data = json.load(open(rapport_semgrep_path)) if Path(rapport_semgrep_path).exists() else {}

    prompt = f"""Tu es un mentor en sécurité qui explique les résultats à des étudiantes en cybersécurité.

Rapport Trivy (dépendances vulnérables) :
{json.dumps(trivy_data, indent=2)[:2000]}

Rapport Semgrep (vulnérabilités de code) :
{json.dumps(semgrep_data, indent=2)[:2000]}

Génère un rapport pédagogique en Markdown avec :
1. Un résumé en 3 lignes (comme si tu expliquais à quelqu'un de non-technique)
2. Les 3 problèmes les plus importants, expliqués simplement
3. Les étapes concrètes à faire (avec les commandes exactes)
4. Ce que vous avez bien fait (points positifs)
5. Ce que vous apprendrez en corrigeant cela

Sois encourageant, pédagogique et précis."""

    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}]
    )

    rapport_md = message.content[0].text

    # Sauvegarder
    with open("rapport-explicatif.md", "w") as f:
        f.write(rapport_md)

    console.print(Markdown(rapport_md))
    console.print("[green]Rapport sauvegardé : rapport-explicatif.md[/green]")

if __name__ == "__main__":
    generer_rapport_humain()