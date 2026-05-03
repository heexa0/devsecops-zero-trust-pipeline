# =============================================================================
#  HARDENED DOCKERFILE — Secure App baseline for Zero Trust pipeline
# =============================================================================
#
#  Security decisions:
#   - python:3.11-slim  : minimal Debian base, no compiler/curl/wget
#   - Non-root user     : appuser UID 1000, no shell, no home directory
#   - COPY only         : no ADD (ADD can fetch remote URLs)
#   - pip --no-cache-dir: no package cache left in image layer
#   - gunicorn entrypoint: no Flask dev server, no debug mode
#   - Port 8000         : gunicorn default, not Flask's 5000
#   - PYTHONDONTWRITEBYTECODE + PYTHONUNBUFFERED: cleaner, log-friendly
# =============================================================================

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Create a non-root user with no shell and no home directory
RUN adduser --disabled-password --no-create-home --uid 1000 appuser

COPY app/ .

RUN pip install --no-cache-dir -r requirements.txt

# Create the files directory that the /file endpoint serves from
RUN mkdir -p /app/files && chown appuser:appuser /app/files

# Drop privileges — all subsequent commands and the CMD run as appuser
USER appuser

EXPOSE 8000

# gunicorn as the WSGI server — no debug mode, no auto-reloader, no pin bypass
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "30", "app:app"]
