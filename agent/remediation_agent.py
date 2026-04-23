import sys
import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ollama_client import verifier_ollama, appeler_ollama_json
from utils import charger_json, sauvegarder_rapport, ecrire_github_summary, afficher_banniere

console = Console()


def extraire_vulnerabilites(rapport_trivy: dict) -> list:
    """Extrait les CVE CRITICAL et HIGH du rapport Trivy"""
    vulns = []
    for result in rapport_trivy.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            severite = vuln.get('Severity', '')
            if severite in ['HIGH', 'CRITICAL']:
                vulns.append({
                    'cve':              vuln.get('VulnerabilityID', 'N/A'),
                    'package':          vuln.get('PkgName', 'N/A'),
                    'version_actuelle': vuln.get('InstalledVersion', 'N/A'),
                    'version_corrigee': vuln.get('FixedVersion', 'non disponible'),
                    # CORRECTION 1 : description raccourcie 300 -> 80 chars
                    # Moins de tokens = prompt plus court = réponse plus rapide
                    'description':      vuln.get('Description', '')[:80],
                    'severite':         severite
                })
    return vulns


def construire_prompt(vulns: list) -> str:
    """
    CORRECTION 2 : Prompt simplifié — moins de champs demandés.
    Moins de tokens générés = réponse 3x plus rapide sur CPU.
    """
    vuln_texte = json.dumps(vulns, indent=2, ensure_ascii=False)
    return f"""Analyse ces CVE Python et reponds en JSON uniquement.

{vuln_texte}

JSON attendu (rien d'autre) :
{{"vulnerabilites": [{{"cve": "CVE-...", "package": "nom", "correction_requirements": "package==version", "priorite": "CRITIQUE ou HAUTE"}}]}}

UNIQUEMENT le JSON, sans texte avant ou apres."""


def analyser_par_lots(vulns: list, taille_lot: int = 3) -> dict:
    """
    CORRECTION 3 : Envoyer les CVE par lots de 3 au lieu de tout en une fois.
    Évite le timeout — chaque lot prend 30-60s au lieu de 5+ minutes.
    """
    toutes_analyses = []
    total_lots = (len(vulns) + taille_lot - 1) // taille_lot

    for i in range(0, len(vulns), taille_lot):
        lot = vulns[i:i + taille_lot]
        num_lot = i // taille_lot + 1

        console.print(f"[blue]Lot {num_lot}/{total_lots} — analyse de {len(lot)} CVE...[/blue]")

        prompt = construire_prompt(lot)
        resultat = appeler_ollama_json(prompt)

        if not resultat:
            console.print(f"[yellow]Lot {num_lot} : timeout ou erreur, on continue...[/yellow]")
            continue

        if "vulnerabilites" in resultat:
            toutes_analyses.extend(resultat["vulnerabilites"])
            console.print(f"[green]Lot {num_lot} OK — {len(resultat['vulnerabilites'])} CVE analysées[/green]")
        elif "texte_brut" in resultat:
            console.print(f"[yellow]Lot {num_lot} : réponse non-JSON reçue, ignorée[/yellow]")

    return {
        "vulnerabilites":   toutes_analyses,
        "resume":           f"{len(toutes_analyses)} CVE analysées en {total_lots} lot(s) par l'IA Ollama",
        "action_immediate": "Appliquer les corrections dans requirements.txt et relancer Trivy"
    }


def afficher_resultats(analyse: dict):
    """Affiche les résultats dans un format lisible dans le terminal"""
    console.print(Panel(
        f"[yellow]{analyse.get('resume', 'Analyse terminée')}[/yellow]\n"
        f"[red bold]Action urgente : {analyse.get('action_immediate', 'Voir détails')}[/red bold]",
        title="[blue bold]Rapport Agent IA — Remédiation[/blue bold]",
        border_style="blue"
    ))

    table = Table(title="Corrections proposées par l'IA Ollama")
    table.add_column("CVE",       style="cyan",  no_wrap=True)
    table.add_column("Package",   style="white")
    table.add_column("Priorité",  style="red")
    table.add_column("Correction requirements.txt", style="green")

    for v in analyse.get('vulnerabilites', []):
        table.add_row(
            v.get('cve',                      'N/A'),
            v.get('package',                  'N/A'),
            v.get('priorite',                 'N/A'),
            v.get('correction_requirements',  'N/A')
        )

    console.print(table)


def generer_summary_md(analyse: dict) -> str:
    """Génère le Markdown pour le résumé GitHub Actions"""
    md  = "## Rapport Agent IA — Remédiation (Ollama — Zero Trust)\n\n"
    md += f"**Résumé :** {analyse.get('resume', 'N/A')}\n\n"
    md += f"**Action urgente :** {analyse.get('action_immediate', 'N/A')}\n\n"
    md += "### Corrections à appliquer dans requirements.txt\n\n```\n"
    for v in analyse.get('vulnerabilites', []):
        correction = v.get('correction_requirements', '')
        if correction and correction != 'N/A':
            md += f"{correction}\n"
    md += "```\n"
    return md


# ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    afficher_banniere('Agent IA Remédiation — Ollama Zero Trust', 'blue')

    # 1. Vérifier qu'Ollama tourne
    if not verifier_ollama():
        console.print("[red]Lancer 'ollama serve' dans un autre terminal puis réessayer.[/red]")
        sys.exit(1)

    # 2. Charger le rapport Trivy
    rapport = charger_json('trivy-report.json')
    if not rapport:
        console.print("[red]trivy-report.json introuvable. Lancer d'abord : trivy fs ../test-app --format json --output trivy-report.json[/red]")
        sys.exit(1)

    # 3. Extraire toutes les CVE HIGH + CRITICAL
    toutes_vulns = extraire_vulnerabilites(rapport)

    if not toutes_vulns:
        console.print('[green]Aucune CVE HIGH/CRITICAL détectée — Bravo ![/green]')
        sys.exit(0)

    # CORRECTION 4 : Prioriser CRITICAL, limiter à 9 CVE max pour le PoC
    # En soutenance, analyser 9 CVE suffit largement à démontrer la valeur
    critical = [v for v in toutes_vulns if v['severite'] == 'CRITICAL']
    high     = [v for v in toutes_vulns if v['severite'] == 'HIGH']

    # Prendre toutes les CRITICAL + les 3 premières HIGH (max 9 total)
    vulns = (critical + high[:3])[:9]

    console.print(f"[yellow]{len(toutes_vulns)} CVE trouvées — analyse des {len(vulns)} plus critiques en lots de 3[/yellow]")
    console.print(f"[blue]({len(critical)} CRITICAL + {min(len(high), 3)} HIGH sélectionnées)[/blue]")

    # 4. Analyser par lots de 3 (évite le timeout)
    analyse = analyser_par_lots(vulns, taille_lot=3)

    if not analyse or not analyse.get('vulnerabilites'):
        console.print('[red]Aucune CVE analysée avec succès.[/red]')
        console.print('[yellow]Vérifier que ollama serve tourne et que le modèle répond bien.[/yellow]')
        sys.exit(1)

    # 5. Afficher, sauvegarder, générer le résumé GitHub
    afficher_resultats(analyse)
    sauvegarder_rapport(analyse, 'ai-remediation-report.json')
    ecrire_github_summary(generer_summary_md(analyse))

    console.print(f'[green bold]Agent Remédiation terminé — {len(analyse["vulnerabilites"])} corrections proposées[/green bold]')