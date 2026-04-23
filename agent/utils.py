import json
import sys
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
 
console = Console()
 
 
def charger_json(chemin: str) -> dict | None:
    """Charge un fichier JSON avec messages d'erreur clairs"""
    path = Path(chemin)
    if not path.exists():
        console.print(f"[red]Fichier introuvable : {chemin}[/red]")
        console.print(f"[yellow]Assurez-vous que le scan a été lancé avant l'agent[/yellow]")
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        console.print(f"[red]JSON invalide dans {chemin} : {e}[/red]")
        return None
 
 
def sauvegarder_rapport(contenu: dict, chemin: str):
    """Sauvegarde un rapport JSON"""
    with open(chemin, 'w', encoding='utf-8') as f:
        json.dump(contenu, f, indent=2, ensure_ascii=False)
    console.print(f"[green]Rapport sauvegardé : {chemin}[/green]")
 
 
def ecrire_github_summary(contenu_md: str):
    """Écrit dans le résumé GitHub Actions (visible dans l'UI Actions)"""
    import os
    summary_path = os.environ.get('GITHUB_STEP_SUMMARY', 'summary.md')
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write(contenu_md)
 
 
def afficher_banniere(titre: str, couleur: str = 'blue'):
    console.print(Panel.fit(
        f"[bold {couleur}]{titre}[/bold {couleur}]",
        border_style=couleur
    ))
