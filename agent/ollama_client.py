import os
import json
import requests
from rich.console import Console

console = Console()

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
OLLAMA_URL        = "http://localhost:11434"
DEFAULT_MODEL     = "llama3.2:3b"
CLOUD_MODEL       = "claude-haiku-4-5-20251001"

# Detecte automatiquement le mode :
#   ANTHROPIC_API_KEY defini -> cloud (GitHub Actions)
#   pas de cle              -> local (Ollama)
MODE = "cloud" if ANTHROPIC_API_KEY else "local"


def verifier_ollama() -> bool:
    """
    Mode cloud : retourne True immediatement, Ollama n'est pas installe
                 sur les runners GitHub Actions.
    Mode local : verifie qu'Ollama tourne sur localhost.
    """
    if MODE == "cloud":
        console.print(f"[blue]Mode CI/CD — API Anthropic ({CLOUD_MODEL})[/blue]")
        return True

    try:
        resp    = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        modeles = [m["name"] for m in resp.json().get("models", [])]
        trouve  = any(DEFAULT_MODEL.split(":")[0] in m for m in modeles)
        if not trouve:
            console.print(f"[red]Modele {DEFAULT_MODEL} non trouve[/red]")
            console.print(f"[yellow]Lancer : ollama pull {DEFAULT_MODEL}[/yellow]")
            return False
        console.print(f"[green]Ollama OK — {DEFAULT_MODEL} pret (Zero Trust local)[/green]")
        return True
    except requests.exceptions.ConnectionError:
        console.print("[red]Ollama non lance — lancer : ollama serve[/red]")
        return False
    except Exception as e:
        console.print(f"[red]Erreur verification Ollama : {e}[/red]")
        return False


def _appeler_anthropic(prompt: str) -> str:
    """Appelle l'API Anthropic — utilise en CI/CD GitHub Actions."""
    headers = {
        "x-api-key":         ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type":      "application/json",
    }
    payload = {
        "model":      CLOUD_MODEL,
        "max_tokens": 1024,
        "messages":   [{"role": "user", "content": prompt}],
    }
    try:
        console.print(f"[blue]API Anthropic ({CLOUD_MODEL})...[/blue]")
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers=headers,
            json=payload,
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["content"][0]["text"]
    except requests.exceptions.Timeout:
        console.print("[red]Timeout API Anthropic (60s)[/red]")
        return ""
    except Exception as e:
        console.print(f"[red]Erreur Anthropic : {e}[/red]")
        return ""


def _appeler_ollama_local(prompt: str) -> str:
    """Appelle Ollama en local — Zero Trust, aucune donnee vers internet."""
    payload = {
        "model":   DEFAULT_MODEL,
        "prompt":  prompt,
        "stream":  False,
        "options": {
            "temperature": 0.1,
            "num_predict": 512,
            "num_ctx":     2048,
        },
    }
    try:
        console.print(f"[blue]Ollama ({DEFAULT_MODEL}) — jusqu'a 5 min sur CPU...[/blue]")
        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json=payload,
            timeout=300,
        )
        resp.raise_for_status()
        return resp.json().get("response", "")
    except requests.exceptions.Timeout:
        console.print("[red]Timeout Ollama (300s) — reduire taille_lot[/red]")
        return ""
    except Exception as e:
        console.print(f"[red]Erreur Ollama : {e}[/red]")
        return ""


def appeler_ollama(prompt: str, model: str = None) -> str:
    """Point d'entree unique — choisit Anthropic ou Ollama automatiquement."""
    if MODE == "cloud":
        return _appeler_anthropic(prompt)
    return _appeler_ollama_local(prompt)


def appeler_ollama_json(prompt: str, model: str = None) -> dict:
    """Appelle le backend IA et retourne la reponse parsee en JSON."""
    reponse = appeler_ollama(prompt, model)
    if not reponse:
        return {}

    texte = reponse.strip()

    if "```json" in texte:
        texte = texte.split("```json")[1].split("```")[0]
    elif "```" in texte:
        texte = texte.split("```")[1].split("```")[0]

    debut = texte.find("{")
    fin   = texte.rfind("}")
    if debut != -1 and fin != -1:
        texte = texte[debut:fin + 1]

    try:
        return json.loads(texte.strip())
    except json.JSONDecodeError as e:
        console.print(f"[yellow]Reponse non-JSON ({e})[/yellow]")
        return {"texte_brut": reponse}