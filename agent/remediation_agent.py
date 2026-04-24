import anthropic
import json
import os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel

console = Console()

# ─── Charger les rapports de scan ───
def charger_rapport_trivy(chemin="trivy-report.json"):
    """Lit le rapport JSON généré par Trivy"""
    if not Path(chemin).exists():
        console.print("[red]trivy-report.json introuvable. Trivy doit tourner avant l'agent.[/red]")
        return None
    with open(chemin) as f:
        return json.load(f)

def extraire_vulnerabilites(rapport):
    """Extrait les CVE importantes du rapport Trivy"""
    vulns = []
    results = rapport.get("Results", [])
    for result in results:
        for vuln in result.get("Vulnerabilities", []):
            if vuln.get("Severity") in ["HIGH", "CRITICAL"]:
                vulns.append({
                    "cve": vuln.get("VulnerabilityID"),
                    "package": vuln.get("PkgName"),
                    "version_actuelle": vuln.get("InstalledVersion"),
                    "version_corrigee": vuln.get("FixedVersion"),
                    "description": vuln.get("Description", "")[:200],
                    "severite": vuln.get("Severity")
                })
    return vulns

# ─── Appel à l'API Claude ───
def analyser_avec_ia(vulnerabilites):
    """Envoie les CVE à Claude et récupère les corrections"""
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    # Construire le prompt avec les vulnérabilités
    vuln_text = json.dumps(vulnerabilites, indent=2, ensure_ascii=False)

    prompt = f"""Tu es un expert en sécurité DevSecOps. Analyse ces vulnérabilités détectées dans une application Python :

{vuln_text}

Pour CHAQUE vulnérabilité, fournis en JSON :
{{
  "vulnerabilites": [
    {{
      "cve": "CVE-XXXX-XXXX",
      "package": "nom-du-package",
      "correction": "pip install package==version_corrigee",
      "explication_simple": "Explication en 1 phrase compréhensible",
      "priorite": "CRITIQUE|HAUTE|MOYENNE",
      "ligne_requirements": "package==version_corrigee"
    }}
  ],
  "resume_global": "Résumé en 2 phrases pour le développeur",
  "action_immediate": "La chose la plus urgente à faire"
}}

Réponds UNIQUEMENT en JSON valide, sans texte avant ou après."""

    console.print("[blue]Envoi à l'agent IA Claude...[/blue]")

    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}]
    )

    return json.loads(message.content[0].text)

# ─── Afficher les résultats ───
def afficher_rapport(analyse):
    """Affiche un rapport lisible dans les logs GitHub Actions"""
    console.print(Panel.fit(
        f"[bold]RAPPORT AGENT IA - REMÉDIATION[/bold]\n\n"
        f"[yellow]{analyse['resume_global']}[/yellow]\n\n"
        f"[red]ACTION URGENTE : {analyse['action_immediate']}[/red]",
        border_style="blue"
    ))

    for vuln in analyse.get("vulnerabilites", []):
        color = "red" if vuln["priorite"] == "CRITIQUE" else "yellow"
        console.print(Panel(
            f"[bold]{vuln['cve']}[/bold] — {vuln['package']}\n"
            f"Explication : {vuln['explication_simple']}\n"
            f"Correction  : [green]{vuln['correction']}[/green]\n"
            f"Dans requirements.txt : [green]{vuln['ligne_requirements']}[/green]",
            border_style=color,
            title=f"[{color}]{vuln['priorite']}[/{color}]"
        ))

# ─── Sauvegarder le rapport ───
def sauvegarder_rapport(analyse):
    """Sauvegarde le rapport pour GitHub Actions Summary"""
    with open("ai-remediation-report.json", "w") as f:
        json.dump(analyse, f, indent=2, ensure_ascii=False)

    # Écrire dans le résumé GitHub Actions
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "summary.md")
    with open(summary_path, "w") as f:
        f.write("## Rapport Agent IA — Remédiation\n\n")
        f.write(f"**Résumé :** {analyse['resume_global']}\n\n")
        f.write(f"**Action urgente :** {analyse['action_immediate']}\n\n")
        f.write("### Corrections proposées\n\n")
        for vuln in analyse.get("vulnerabilites", []):
            f.write(f"- **{vuln['cve']}** ({vuln['package']}) : `{vuln['ligne_requirements']}`\n")

# ─── Point d'entrée ───
if __name__ == "__main__":
    console.print("[bold blue]Agent IA de Remédiation démarré[/bold blue]")

    rapport = charger_rapport_trivy()
    if not rapport:
        exit(1)

    vulns = extraire_vulnerabilites(rapport)
    if not vulns:
        console.print("[green]Aucune vulnérabilité HIGH/CRITICAL détectée. Bien joué ![/green]")
        exit(0)

    console.print(f"[yellow]{len(vulns)} vulnérabilités détectées. Analyse IA en cours...[/yellow]")

    analyse = analyser_avec_ia(vulns)
    afficher_rapport(analyse)
    sauvegarder_rapport(analyse)

    console.print("[green]Rapport sauvegardé : ai-remediation-report.json[/green]")