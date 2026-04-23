# =============================================================================
# DELIBERATELY INSECURE DOCKERFILE
# For DevSecOps Zero Trust pipeline demonstration / Trivy scanning only.
# DO NOT use in production.
#
# Intentional misconfigurations:
#   - Base image pinned to python:3.9 (not a digest, not a minimal image)
#   - Running as root (no USER directive) — container escape risk
#   - No .dockerignore — may copy sensitive files into image layer
#   - Debug port 5000 exposed with Flask debug=True
# =============================================================================

FROM python:3.9

# No USER directive — process runs as root inside the container
WORKDIR /app

COPY app/ .

RUN pip install --no-cache-dir --no-build-isolation -r requirements.txt

EXPOSE 5000

# Runs the app directly as root with no process supervisor
CMD ["python", "app.py"]
