# devsecops-zero-trust-pipeline
# DevSecOps Zero Trust Pipeline

Pipeline CI/CD avec analyse de sécurité IA (Semgrep, Trivy, Claude, Ollama).

---

## Prérequis

- [Docker Desktop pour Windows](https://www.docker.com/products/docker-desktop) (v4+)
- Git
- Une clé API Anthropic → [console.anthropic.com](https://console.anthropic.com/)

---

## Installation (première fois)

### 1. Cloner le repo

```bat
git clone <URL_DU_REPO>
cd devsecops-zero-trust-pipeline
```

### 2. Lancer le script de setup

Double-clique sur `setup.bat` ou depuis un terminal :

```bat
setup.bat
```

Le script va :
- Vérifier que Docker est installé
- Créer ton fichier `.env` (tu devras y mettre ta clé API)
- Démarrer Jenkins + Ollama via Docker
- Télécharger le modèle Ollama llama3.2:3b (~2 GB)

### 3. Ajouter le credential Jenkins (étape manuelle)

Une fois Jenkins démarré sur http://localhost:9090 :

```
Manage Jenkins → Credentials → System → Global credentials → Add Credentials
  Kind   : Secret text
  ID     : ANTHROPIC_API_KEY
  Secret : ta clé Anthropic (sk-ant-...)
```

---

## Utilisation quotidienne

Démarrer l'environnement :
```bat
docker compose up -d
```

Arrêter l'environnement :
```bat
docker compose down
```

Voir les logs Jenkins :
```bat
docker compose logs -f jenkins
```

Accès Jenkins : http://localhost:9090
Login : `admin` / mot de passe défini dans `.env`

---

## Repartir de zéro

Si tu veux réinitialiser complètement Jenkins (perte de tous les builds et config) :

```bat
docker compose down -v
docker compose up -d
```

---

## Structure du projet

```
devsecops-zero-trust-pipeline/
├── agent/                  # Agents IA (antitamper, remediation, explainer)
├── jenkins/
│   ├── casc.yaml           # Config Jenkins as Code
│   └── plugins.txt         # Liste des plugins installés automatiquement
├── test-app/               # Application de test scannée par le pipeline
├── .env.example            # Template des variables d'environnement
├── docker-compose.yml      # Jenkins + Ollama
├── Dockerfile
├── Jenkinsfile             # Définition du pipeline
└── setup.bat               # Script d'installation Windows
```

---

## Problèmes courants

**Jenkins ne démarre pas**
```bat
docker compose logs jenkins
```

**Ollama ne répond pas**
```bat
docker exec ollama ollama list
REM Si vide, relancer le pull :
docker exec ollama ollama pull llama3.2:3b
```

**Erreur "port 9090 déjà utilisé"**
Un autre service utilise le port. Changer dans `docker-compose.yml` :
```yaml
ports:
  - '9091:8080'   # changer 9090 par 9091 ou autre
```

**Credential ANTHROPIC_API_KEY manquant dans Jenkins**
Le pipeline affichera une erreur en stage `AI Security Guard`.
Ajouter le credential comme décrit dans l'étape 3 ci-dessus.
