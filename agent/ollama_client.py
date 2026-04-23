import requests
import json
from rich.console import Console

console = Console()

OLLAMA_URL    = "http://localhost:11434"
DEFAULT_MODEL = "llama3.2:3b"   # modèle léger recommandé sur CPU Windows


def verifier_ollama() -> bool:
    """Vérifie qu'Ollama tourne et que le modèle est disponible"""
    try:
        resp    = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        modeles = [m['name'] for m in resp.json().get('models', [])]

        # Chercher le modèle même sans le tag exact (ex: llama3.2:3b ou llama3.2)
        modele_trouve = any(DEFAULT_MODEL.split(':')[0] in m for m in modeles)

        if not modele_trouve:
            console.print(f"[red]Modèle '{DEFAULT_MODEL}' non trouvé.[/red]")
            console.print(f"[yellow]Lancer : ollama pull {DEFAULT_MODEL}[/yellow]")
            console.print(f"[blue]Modèles disponibles : {modeles}[/blue]")
            return False

        console.print(f"[green]Ollama OK — modèle {DEFAULT_MODEL} prêt[/green]")
        return True

    except requests.exceptions.ConnectionError:
        console.print("[red]Ollama n'est pas lancé ![/red]")
        console.print("[yellow]Ouvrir un AUTRE terminal et lancer : ollama serve[/yellow]")
        return False
    except Exception as e:
        console.print(f"[red]Erreur vérification Ollama : {e}[/red]")
        return False


def appeler_ollama(prompt: str, model: str = DEFAULT_MODEL) -> str:
    """
    Envoie un prompt à Ollama et retourne la réponse texte.
    Zero Trust : aucune donnée ne quitte la machine locale.
    CORRECTION : timeout augmenté à 300s (5 min) pour CPU sans GPU.
    """
    payload = {
        "model":  model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature":  0.1,    # Faible = réponses plus cohérentes
            "num_predict":  512,    # CORRECTION : réduit de 2048 à 512 — assez pour du JSON court
            "num_ctx":      2048,   # Fenêtre de contexte
        }
    }

    try:
        console.print(f"[blue]Appel Ollama ({model}) — attendre jusqu'à 5 min sur CPU...[/blue]")

        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json=payload,
            # CORRECTION PRINCIPALE : 300s au lieu de 120s
            timeout=300
        )
        resp.raise_for_status()
        return resp.json().get("response", "")

    except requests.exceptions.Timeout:
        console.print("[red]Timeout (300s dépassé). Votre CPU est très lent ou le prompt est trop grand.[/red]")
        console.print("[yellow]Solution : réduire taille_lot=2 dans analyser_par_lots()[/yellow]")
        return ""
    except requests.exceptions.ConnectionError:
        console.print("[red]Connexion Ollama perdue. Vérifier que 'ollama serve' tourne toujours.[/red]")
        return ""
    except Exception as e:
        console.print(f"[red]Erreur Ollama : {e}[/red]")
        return ""


def appeler_ollama_json(prompt: str, model: str = DEFAULT_MODEL) -> dict:
    """
    Appelle Ollama et parse la réponse en JSON.
    Gère les cas où le modèle ajoute du texte avant/après le JSON.
    """
    reponse = appeler_ollama(prompt, model)
    if not reponse:
        return {}

    # Nettoyer la réponse — le modèle ajoute souvent des backticks
    texte = reponse.strip()

    # Retirer les blocs ```json ... ``` ou ``` ... ```
    if "```json" in texte:
        texte = texte.split("```json")[1].split("```")[0]
    elif "```" in texte:
        texte = texte.split("```")[1].split("```")[0]

    # Trouver le premier { et le dernier } pour extraire le JSON
    debut = texte.find('{')
    fin   = texte.rfind('}')
    if debut != -1 and fin != -1:
        texte = texte[debut:fin + 1]

    try:
        return json.loads(texte.strip())
    except json.JSONDecodeError as e:
        console.print(f"[yellow]Réponse IA non-JSON ({e}) — retour texte brut[/yellow]")
        return {"texte_brut": reponse}