#!/usr/bin/env bash
set -e

echo ""
echo "=========================================="
echo "  Setup Zero Trust Pipeline"
echo "=========================================="
echo ""

# ── 1. Verifier Git Bash / bash ─────────────────────────────
if [ -z "$BASH_VERSION" ]; then
    echo "[ERREUR] Ce script doit etre lance avec Git Bash."
    echo "         Clic droit sur le dossier -> 'Git Bash Here'"
    echo "         puis : bash setup.sh"
    exit 1
fi

# ── 2. Verifier Docker ───────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo "[ERREUR] Docker n'est pas installe ou pas demarre."
    echo "         Installe Docker Desktop : https://www.docker.com/products/docker-desktop"
    echo "         Puis relance ce script."
    exit 1
fi
echo "[OK] Docker detecte : $(docker --version)"

# ── 3. Verifier docker compose ───────────────────────────────
if ! docker compose version &>/dev/null; then
    echo "[ERREUR] docker compose non disponible."
    echo "         Mets a jour Docker Desktop."
    exit 1
fi
echo "[OK] docker compose detecte."

# ── 4. Verifier qu'on est dans le bon dossier ────────────────
if [ ! -f "docker-compose.yml" ]; then
    echo "[ERREUR] docker-compose.yml introuvable."
    echo "         Lance ce script depuis la racine du projet :"
    echo "         cd devsecops-zero-trust-pipeline && bash setup.sh"
    exit 1
fi

# ── 5. Creer le .env si absent ───────────────────────────────
if [ ! -f ".env" ]; then
    if [ ! -f ".env.example" ]; then
        echo "[ERREUR] Fichier .env.example introuvable."
        exit 1
    fi
    cp .env.example .env
    echo ""
    echo "[OK] Fichier .env cree depuis .env.example"
    echo ""
    echo "  !! ACTION REQUISE !!"
    echo "  Ouvre le fichier .env et remplis :"
    echo "    ANTHROPIC_API_KEY  -> ta cle Anthropic (https://console.anthropic.com)"
    echo "    JENKINS_ADMIN_PASSWORD -> ton mot de passe Jenkins"
    echo ""
    read -rp "  Appuie sur ENTREE quand c'est fait..."
else
    echo "[OK] .env deja present."
fi

# ── 6. Verifier que les variables cles sont remplies ─────────
source .env 2>/dev/null || true

if [ -z "$ANTHROPIC_API_KEY" ] || [ "$ANTHROPIC_API_KEY" = "sk-ant-XXXX" ]; then
    echo ""
    echo "[WARN] ANTHROPIC_API_KEY non definie dans .env"
    echo "       Les agents IA ne fonctionneront pas sans elle."
    echo "       Tu pourras l'ajouter plus tard dans Jenkins -> Credentials."
    echo ""
fi

if [ -z "$JENKINS_ADMIN_PASSWORD" ] || [ "$JENKINS_ADMIN_PASSWORD" = "changeme" ]; then
    echo "[WARN] JENKINS_ADMIN_PASSWORD est 'changeme' -- pense a la changer dans .env"
fi

# ── 7. Demarrer les containers ───────────────────────────────
echo ""
echo "[..] Demarrage de Jenkins et Ollama..."
docker compose up -d
echo "[OK] Containers demarres."

# ── 8. Attendre que Jenkins soit pret ────────────────────────
echo ""
echo "[..] Attente du demarrage de Jenkins (40 secondes)..."
sleep 40

# Verification que Jenkins repond
MAX_TRIES=10
COUNT=0
echo "[..] Verification que Jenkins repond..."
until curl -s -o /dev/null -w "%{http_code}" http://localhost:9090/login | grep -qE "200|403"; do
    COUNT=$((COUNT + 1))
    if [ $COUNT -ge $MAX_TRIES ]; then
        echo "[WARN] Jenkins ne repond pas encore sur http://localhost:9090"
        echo "       Il est peut-etre encore en train d'installer les plugins."
        echo "       Attends 1-2 minutes puis ouvre http://localhost:9090"
        break
    fi
    echo "       Attente... ($COUNT/$MAX_TRIES)"
    sleep 10
done
echo "[OK] Jenkins accessible."

# ── 9. Telecharger le modele Ollama ──────────────────────────
echo ""
echo "[..] Telechargement du modele Ollama llama3.2:3b (~2 GB, patience)..."
if docker exec ollama ollama pull llama3.2:3b; then
    echo "[OK] Modele Ollama pret."
else
    echo "[WARN] Le telechargement Ollama a echoue."
    echo "       Relance manuellement : docker exec ollama ollama pull llama3.2:3b"
fi

# ── 10. Resume final ─────────────────────────────────────────
echo ""
echo "=========================================="
echo "  Environnement pret !"
echo "=========================================="
echo ""
echo "  Jenkins  -->  http://localhost:9090"
echo "  Login    -->  admin"
echo "  Pass     -->  valeur de JENKINS_ADMIN_PASSWORD dans .env"
echo ""
echo "  !! ETAPE MANUELLE RESTANTE !!"
echo "  Dans Jenkins, ajouter le credential :"
echo "    Manage Jenkins -> Credentials -> Global -> Add Credentials"
echo "    Kind   : Secret text"
echo "    ID     : ANTHROPIC_API_KEY"
echo "    Secret : ta cle Anthropic"
echo ""
