# ═══════════════════════════════════════════════════
# STAGE 1 : Build — installe les dépendances
# ═══════════════════════════════════════════════════
FROM python:3.11-slim AS builder 
 #sert a intaller les dependences python 
WORKDIR /app
 
# Copier seulement requirements.txt d'abord (optimise le cache Docker)
COPY test-app/requirements.txt .
 
# Installer dans le dossier utilisateur (pas en root) pour installer les deped et librairies
RUN pip install --no-cache-dir --user -r requirements.txt
 
# ═══════════════════════════════════════════════════
# STAGE 2 : Runtime sécurisé — image finale légère
# ═══════════════════════════════════════════════════
FROM python:3.11-slim AS runtime
 
WORKDIR /app
 
# Principe Zero Trust : créer un utilisateur non-root
RUN groupadd -r appuser && useradd -r -g appuser appuser
# Copier UNIQUEMENT les dépendances compilées du stage 1 , les recupere depuis le stafe 1 
COPY --from=builder /root/.local /home/appuser/.local
 
# Copier le code de l'application
COPY test-app/ .
 
# Donner les droits à l'utilisateur non-root
RUN chown -R appuser:appuser /app
 
# Basculer vers l'utilisateur non-root
USER appuser
 
# Ajouter le PATH des packages Python installés
ENV PATH=/home/appuser/.local/bin:$PATH
 
# Exposer le port de l'application
EXPOSE 5000
 #appli ecoute sur ce port
# Commande de démarrage
CMD ["python", "app.py"]