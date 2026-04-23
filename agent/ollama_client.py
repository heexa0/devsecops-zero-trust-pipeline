import os
import json
import time
import requests
from rich.console import Console

console = Console()

# ─── CONFIG ───────────────────────────────────────────────

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()

# ✅ FIX IMPORTANT (Windows local)
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")

OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
CLOUD_MODEL = "claude-haiku-4-5-20251001"

TIMEOUT_CLOUD = 60
TIMEOUT_LOCAL = 120   # ⬅️ réduit pour CI/CD

# ─── CHECKERS ─────────────────────────────────────────────

def _claude_disponible() -> bool:
    return ANTHROPIC_API_KEY.startswith("sk-ant-") and len(ANTHROPIC_API_KEY) > 20


def _ollama_disponible() -> bool:
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=3)
        models = r.json().get("models", [])

        model_names = [m.get("name", "") for m in models]

        if not any(OLLAMA_MODEL.split(":")[0] in m for m in model_names):
            console.print(f"[yellow]Modèle Ollama manquant : {OLLAMA_MODEL}[/yellow]")
            return False

        return True

    except Exception:
        return False


def verifier_ollama():
    claude = _claude_disponible()
    ollama = _ollama_disponible()

    console.print("\n=== IA STATUS ===")

    if claude:
        console.print("[blue]Claude API : OK[/blue]")
    else:
        console.print("[yellow]Claude API : OFF[/yellow]")

    if ollama:
        console.print("[green]Ollama local : OK[/green]")
    else:
        console.print("[red]Ollama local : OFF[/red]")

    return claude or ollama

# ─── CLAUDE ───────────────────────────────────────────────

def _call_claude(prompt: str) -> str:
    try:
        console.print("[blue]→ Claude API[/blue]")

        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": CLOUD_MODEL,
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=TIMEOUT_CLOUD,
        )

        r.raise_for_status()
        return r.json()["content"][0]["text"]

    except Exception as e:
        console.print(f"[red]Claude error: {e}[/red]")
        return ""

# ─── OLLAMA ───────────────────────────────────────────────

def _call_ollama(prompt: str) -> str:
    try:
        console.print("[green]→ Ollama local[/green]")

        r = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": 512
                },
            },
            timeout=TIMEOUT_LOCAL,
        )

        r.raise_for_status()
        return r.json().get("response", "")

    except Exception as e:
        console.print(f"[red]Ollama error: {e}[/red]")
        return ""

# ─── MAIN FALLBACK ENGINE ────────────────────────────────

def appeler_ollama(prompt: str) -> str:

    # 1. Claude
    if _claude_disponible():
        res = _call_claude(prompt)
        if res:
            return res

        console.print("[yellow]Fallback → Ollama[/yellow]")

    # 2. Ollama
    if _ollama_disponible():
        res = _call_ollama(prompt)
        if res:
            return res

    # 3. FAIL SAFE
    console.print("[red]ZERO TRUST FAIL: no AI available[/red]")
    return ""

# ─── JSON HANDLER ─────────────────────────────────────────

def appeler_ollama_json(prompt: str) -> dict:
    res = appeler_ollama(prompt)

    if not res:
        return {}

    try:
        # clean markdown
        res = res.replace("```json", "").replace("```", "")

        start = res.find("{")
        end = res.rfind("}")

        if start != -1 and end != -1:
            res = res[start:end+1]

        return json.loads(res)

    except Exception:
        return {"raw": res}

# ─── TEST ────────────────────────────────────────────────

if __name__ == "__main__":
    verifier_ollama()

    print("\nTEST:")
    print(appeler_ollama("Réponds juste OK"))