import os, json, requests
from rich.console import Console

console = Console()

ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '').strip()
OLLAMA_URL        = os.environ.get('OLLAMA_URL', 'http://ollama:11434')
OLLAMA_MODEL      = os.environ.get('OLLAMA_MODEL', 'llama3.2:3b')
CLOUD_MODEL       = 'claude-haiku-4-5-20251001'

_dernier_moteur = 'inconnu'

def get_dernier_moteur():
    return _dernier_moteur

def _claude_ok():
    return bool(ANTHROPIC_API_KEY and len(ANTHROPIC_API_KEY) > 20)

def _ollama_ok():
    try:
        r = requests.get(f'{OLLAMA_URL}/api/tags', timeout=5)
        models = [m['name'] for m in r.json().get('models', [])]
        base = OLLAMA_MODEL.split(':')[0]
        found = any(base in m for m in models)
        if not found:
            console.print(f'[yellow]Ollama OK mais {OLLAMA_MODEL} absent — lancer : ollama pull {OLLAMA_MODEL}[/yellow]')
        return found
    except Exception as e:
        console.print(f'[red]Ollama non joignable : {e}[/red]')
        return False

def verifier_ollama():
    c, o = _claude_ok(), _ollama_ok()
    if o: console.print(f'[green]Moteur 1 : Ollama local ({OLLAMA_MODEL})[/green]')
    if c: console.print(f'[blue]Moteur 2 : Claude API ({CLOUD_MODEL}) — standby fallback[/blue]')
    if not c and not o:
        console.print('[red]ERREUR : aucun moteur IA disponible[/red]')
        return False
    return True

def _call_claude(prompt, max_tokens=4096):
    try:
        console.print('[blue]→ Claude API...[/blue]')
        resp = requests.post(
            'https://api.anthropic.com/v1/messages',
            headers={'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'},
            json={'model': CLOUD_MODEL, 'max_tokens': max_tokens, 'messages': [{'role': 'user', 'content': prompt}]},
            timeout=120
        )
        resp.raise_for_status()
        console.print('[green]Claude OK[/green]')
        return resp.json()['content'][0]['text']
    except Exception as e:
        console.print(f'[red]Claude échoué : {e} → bascule Ollama[/red]')
        return ''

def _call_ollama(prompt, max_tokens=2048):
    try:
        console.print(f'[blue]→ Ollama local ({OLLAMA_MODEL})...[/blue]')
        resp = requests.post(
            f'{OLLAMA_URL}/api/generate',
            json={'model': OLLAMA_MODEL, 'prompt': prompt, 'stream': False,
                  'options': {'temperature': 0.1, 'num_predict': max_tokens}},
            timeout=300
        )
        resp.raise_for_status()
        console.print('[green]Ollama OK[/green]')
        return resp.json().get('response', '')
    except Exception as e:
        console.print(f'[red]Ollama échoué : {e}[/red]')
        return ''

def appeler_ollama(prompt, model=None, max_tokens=4096):
    global _dernier_moteur
    # Ollama primaire
    if _ollama_ok():
        r = _call_ollama(prompt, max_tokens=min(max_tokens, 2048))
        if r:
            _dernier_moteur = 'Ollama'
            return r
        console.print('[yellow]Ollama échoué → bascule Claude API (fallback)[/yellow]')
    # Claude standby / fallback
    if _claude_ok():
        r = _call_claude(prompt, max_tokens=max_tokens)
        if r:
            _dernier_moteur = 'Claude'
            return r
    console.print('[red]ERREUR CRITIQUE : aucun moteur IA n a repondu[/red]')
    return ''

def appeler_ollama_json(prompt, model=None):
    rep = appeler_ollama(prompt, model)
    if not rep: return {}
    t = rep.strip()
    if '```json' in t: t = t.split('```json')[1].split('```')[0]
    elif '```' in t:   t = t.split('```')[1].split('```')[0]
    d, f = t.find('{'), t.rfind('}')
    if d != -1 and f != -1: t = t[d:f+1]
    try: return json.loads(t.strip())
    except: return {'texte_brut': rep}

if __name__ == '__main__':
    console.print('=== Diagnostic moteurs IA ===')
    verifier_ollama()