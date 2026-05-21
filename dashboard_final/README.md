# ZeroTrust CI — Dashboard

Interface web pour visualiser le pipeline Jenkins en temps réel.

## Démarrage rapide

```bash
cd dashboard
pip install -r requirements.txt
python server.py
# → http://localhost:8888
```

## Fonctionnalités

| Feature | Description |
|---|---|
| Pipeline flow | Les 11 stages visuels avec animations live |
| Console Jenkins | Logs colorés par type (SAST/SCA/AI/DAST) |
| Findings panel | Toutes les vulnérabilités consolidées (SAST+SCA+DAST) |
| Fallback simulation | Bouton pour simuler la coupure Claude → Ollama |
| Métriques MTTR | CVEs, SAST findings, ZAP alerts, provider IA |
| Downloads | Téléchargement direct des rapports JSON/HTML/PDF |

## Architecture

```
dashboard/
├── server.py          ← Flask API + serveur statique
├── requirements.txt   ← flask seulement
├── templates/
│   └── index.html     ← Page principale
└── static/
    ├── css/dashboard.css
    └── js/dashboard.js
```

## API endpoints

| Route | Description |
|---|---|
| `GET /` | Interface web |
| `GET /api/status` | Métriques globales (CVEs, findings, AI provider) |
| `GET /api/findings` | Toutes les findings (SAST+SCA+DAST) |
| `GET /api/ai` | Détails de l'agent IA |
| `GET /api/reports` | Liste des fichiers disponibles |
| `GET /reports/<file>` | Téléchargement d'un rapport |

## Intégration Jenkins

Ajouter dans le `Jenkinsfile` après chaque stage :

```groovy
stage('Dashboard Update') {
    steps {
        sh 'cp ${REPORTS_DIR}/*.json dashboard/ 2>/dev/null || true'
    }
}
```

Le dashboard lit automatiquement les fichiers dans `reports/` et `agent/`.

## Mode demo

Sans serveur Jenkins, le dashboard affiche des données de démonstration
réalistes (findings, console logs, métriques MTTR).