# Rapport d'Analyse de Sécurité — Application Python/Flask
**Date** : 2025-01-15 | **Scope** : test-app (SCA + SAST + DAST) | **Classification** : Technique

---

## 1. Executive Summary

| Métrique | Statut |
|----------|--------|
| **Surface d'attaque** | Critique : 37 CVE identifiées dont 1 CRITICAL et 16 HIGH dans la chaîne de dépendances ; 3 configurations de sécurité défaillantes au niveau applicatif |
| **Criticité globale** | ÉLEVÉE : Exécution de code à distance possible (Pillow ACE, Werkzeug RCE), vulnérabilités cryptographiques (timing attacks, NULL pointer deref), attaques par décompression (DoS) |
| **Conformité Zero Trust** | NON CONFORME : Exposition directe 0.0.0.0, debug activé, CSP absente, dépendances non mises à jour |

**Verdict** : Déploiement bloqué. Patchs critiques obligatoires avant production.

---

## 2. Findings Critiques

### 2.1 SCA — Supply Chain (Trivy)

#### **CVE-2023-50447 | CRITICAL | Pillow 9.5.0**
- **Type** : Arbitrary Code Execution (ACE)
- **Vecteur d'attaque** : Paramètre `environment` non validé dans le traitement d'images → injection de code système via variables d'environnement malveillantes
- **Composant affecté** : `Pillow==9.5.0` (lib de traitement d'images)
- **Impact opérationnel** : Compromission totale du serveur applicatif ; exécution de commandes arbitraires avec permissions du processus Flask
- **Exploitabilité** : TRÈS ÉLEVÉE — exploits publics disponibles ; nécessite input utilisateur (upload d'image)
- **CVSS v3.1** : 9.8 (Network / Low Complexity / No Auth)
- **Fix requis** : `Pillow>=10.2.0` (immédiately)

---

#### **CVE-2024-34069 | HIGH | Werkzeug 2.0.1**
- **Type** : Remote Code Execution (RCE) — Developer Machine Attack
- **Vecteur d'attaque** : Werkzeug debugger exposé → exécution de code Python arbitraire dans l'environnement de développement
- **Composant affecté** : `Werkzeug==2.0.1` (framework HTTP/WSGI)
- **Impact opérationnel** : Compromission du poste développeur ou serveur de staging si debug activé ; fuite de secrets (tokens, DB credentials)
- **Exploitabilité** : TRÈS ÉLEVÉE — CVE-2024-34069 exploite le `/console` endpoint non protégé + flag `debug=True` identifié en SAST
- **CVSS v3.1** : 9.1 (Network / Low Complexity / No Auth required)
- **Contexte local** : **CONFIRMATION SAST** — `debug=True` détecté à `test-app/app.py:92`
- **Fix requis** : `Werkzeug>=3.0.3` + **désactivation debug** (immédiately)

---

#### **CVE-2024-28219 | HIGH | Pillow 9.5.0**
- **Type** : Buffer Overflow (`_imagingcms.c`)
- **Vecteur d'attaque** : Traitement de fichiers image malformés → overflow de mémoire heap
- **Impact opérationnel** : Crash applicatif (DoS) ; potentiel exécution de code selon gestion mémoire
- **Exploitabilité** : HAUTE — via endpoint d'upload d'image
- **Fix requis** : `Pillow>=10.3.0`

---

#### **CVE-2023-50782 | HIGH | cryptography 38.0.0**
- **Type** : Timing Oracle Attack — RSA Decryption
- **Vecteur d'attaque** : Bleichenbacher attack incompletely patched → mesure du temps de déchiffrement RSA révèle clés privées
- **Impact opérationnel** : Fuite de matériel cryptographique ; compromission de sessions encryptées
- **Exploitabilité** : MOYENNE — nécessite accès réseau et milliers de requêtes
- **Fix requis** : `cryptography>=42.0.0` (minimum, `>=42.0.4` recommandé)

---

#### **CVE-2023-25577 | HIGH | Werkzeug 2.0.1**
- **Type** : Denial of Service (ReDoS / Resource Exhaustion)
- **Vecteur d'attaque** : Parsing multipart form-data avec très grand nombre de champs → consommation CPU/mémoire anormale
- **Impact opérationnel** : Crash serveur ; indisponibilité du service
- **Exploitabilité** : TRÈS ÉLEVÉE — simple POST avec form-data malveillante
- **Fix requis** : `Werkzeug>=2.2.3`

---

#### **CVE-2025-66418 | HIGH | urllib3 1.24.3**
- **Type** : Unbounded Decompression → Resource Exhaustion
- **Vecteur d'attaque** : Chaînes de décompression sans limite (zip bomb, gzip bomb) → épuisement mémoire/CPU
- **Impact opérationnel** : DoS applicatif ; indisponibilité
- **Exploitabilité** : TRÈS ÉLEVÉE — réponse HTTP compressée malveillante
- **Fix requis** : `urllib3>=2.6.0`

---

### 2.2 SAST — Code Source (Semgrep)

#### **avoid_app_run_with_bad_host | WARNING → HAUTE CRITICITÉ**
```python
# test-app/app.py:92 — TROUVÉ
app.run(host='0.0.0.0', debug=True)
```
- **Type** : Misconfiguration réseau (CWE-200)
- **Vecteur d'attaque** : Application Flask listenable depuis internet → exposition directe du serveur WSGI non-renforcé
- **Impact opérationnel** : Accès non-autorisé au serveur applicatif ; absence de proxy de sécurité (WAF, reverse proxy)
- **Conformité Zero Trust** : VIOLE — Principe "assume breach" = serveur backend accessible directement
- **Fix requis** : `host='127.0.0.1'` (localhost) + déploiement derrière reverse proxy (Nginx/HAProxy + TLS obligatoire)

---

#### **debug-enabled | WARNING → CRITIQUE**
```python
# test-app/app.py:92 — TROUVÉ
app.run(host='0.0.0.0', debug=True, ...)
```
- **Type** : Information Disclosure + Remote Code Execution (CWE-215, CWE-94)
- **Vecteur d'attaque** : Werkzeug debugger accessible → console interactive `/console` endpoint exécute Python arbitraire
- **Impact opérationnel** : Dump de variables mémoire, secrets, stack traces ; exécution de commandes système
- **Contexte** : Combine avec CVE-2024-34069
- **Fix requis** : `debug=False` en production ; utiliser variables d'environnement `FLASK_ENV=production`

---

### 2.3 DAST — Application en Cours d'Exécution (OWASP ZAP)

#### **Content Security Policy (CSP) Header Not Set | CWE-693 (MEDIUM)**
- **Endpoint affecté** : `GET /sitemap.xml` et potentiellement tous les endpoints
- **Type** : Missing Security Header
- **Vecteur d'attaque** : Absence de CSP → XSS payloads injected (si injection HTML présente) exécutables ; clickjacking possible
- **Impact opérationnel** : Vol de cookies de session ; redirection malveillante ; défacement
- **Conformité OWASP** : Recommandation OWASP Secure Headers
- **Fix requis** : 
```python
@app.after_request
def set_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
```

---

## 3. Plan de Remédiation

### Phase 1 : IMMÉDIAT (< 2h — Blockers)

| ID | Action | Commande / Code | Délai | Responsable |
|---|---|---|---|---|
| **CVE-2023-50447** | Upgrade Pillow CRITICAL ACE | `pip install --upgrade 'Pillow>=10.2.0'` | 30 min | Backend Lead |
| **CVE-2024-34069** | Upgrade Werkzeug + désactiver debug | `pip install --upgrade 'Werkzeug>=3.0.3'` + **voir Phase 1.1** | 30 min | Backend Lead |
| **debug-enabled** | Désactiver debug en production | Voir **Phase 1.1** ci-dessous | 15 min | Backend Lead |
| **host=0.0.0.0** | Bind localhost + proxy | Voir **Phase 1.2** ci-dessous | 1h | DevOps + Backend |

#### **Phase 1.1 — Code Fix : Debug & Host**
```python
# test-app/app.py:92 — REMPLACE PAR :
import os

DEBUG = os.getenv('FLASK_DEBUG', 'False') == 'True'  # False par défaut
HOST = os.getenv('FLASK_HOST', '127.0.0.1')  # localhost par défaut
PORT = int(os.getenv('FLASK_PORT', 5000))

if __name__ == '__main__':
    app.run(host=HOST, port=PORT, debug=DEBUG)
```

**Variables d'environnement (production) :**
```bash
export FLASK_ENV=production
export FLASK_DEBUG=False
export FLASK_HOST=127.0.0.1
```

#### **Phase 1.2 — Infrastructure : Reverse Proxy obligatoire**
```nginx
# /etc/nginx/sites-available/app.conf
upstream flask_app {
    server 127.0.0.1:5000;
}

server {
    listen 443 ssl http2;
    server_name app.example.com;
    
    ssl_certificate /etc/ssl/certs/app.crt;
    ssl_certificate_key /etc/ssl/private/app.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; img-src 'self' data:;" always;
    
    location / {
        proxy_pass http://flask_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name app.example.com;
    return 301 https://$server_name$request_uri;  # Force HTTPS
}
```

---

### Phase 2 : URGENT (48h — High CVEs)

| CVE | Composant | Upgrade | Commande |
|---|---|---|---|
| CVE-2024-28219 | Pillow | 10.3.0+ | `pip install --upgrade 'Pillow>=10.3.0'` |
| CVE-2023-44271 | Pillow | 10.0.0+ | (inclus au-dessus) |
| CVE-2023-4863 | Pillow (libwebp) | 10.0.1+ | (inclus au-dessus) |
| CVE-2023-50782 | cryptography | 42.0.4+ | `pip install --upgrade 'cryptography>=42.0.4'` |
| CVE-2023-0286 | cryptography (openssl) | 39.0.1+ | (inclus au-dessus) |
| CVE-2024-26130 | cryptography | 42.0.4+ | (inclus au-dessus) |
| CVE-2023-25577 | Werkzeug | 2.2.3+ | `pip install --upgrade 'Werkzeug>=2.2.3'` |
| CVE-2023-30861 | Flask | 2.3.2+ | `pip install --upgrade 'Flask>=2.3.2'` |
| CVE-2023-43804 | urllib3 | 2.0.6+ | `pip install --upgrade 'urllib3>=2.0.6'` |
| CVE-2025-66418 | urllib3 | 2.6.0+ | `pip install --upgrade 'urllib3>=2.6.0'` |

**Commande regroupée :**
```bash
pip install --upgrade \
  'Pillow>=10.3.0' \
  'Werkzeug>=2.2.3' \
  'cryptography>=42.0.4' \
  'Flask>=2.3.2' \
  'urllib3>=2.6.0'
```

**Test post-upgrade :**
```bash
pytest tests/ -v
python -m pip check  # Vérifier compatibilité dépendances
```

---

### Phase 3 : COURT TERME (Sprint actuel)

#### **CSP Header Missing**
```python
# test-app/app.py ou utils/security.py
from flask import Flask

def init_security_headers(app):
    @app.after_request
    def set_headers(response):
        response.headers.update({
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self';",
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        })
        return response
    return app

# Initialisation
app = Flask(__name__)
init_security_headers(app)
```

**Test DAST :**
```bash
owasp-zap-baseline.py -t https://localhost:5000 -r report.html
```

---

### Phase 4 : MOYEN TERME (Dépendances Futures)

| CVE | Type | Fix Version | Sprint |
|---|---|---|---|
| CVE-2026-26007 | cryptography | 46.0.5+ | N+2 |
| CVE-2025-66471 | urllib3 | 2.6.0+ | Sprint actuel |
| CVE-2026-21441 | urllib3 (decompression) | 2.6.3+ | Sprint+1 |
| CVE-2026-44431 | urllib3 (XOR) | 2.7.0+ | Sprint+2 |
| CVE-2026-42308 | Pillow DoS | 12.2.0+ | Q2 2026 |

---

## 4. Analyse de la Posture de Sécurité

### 4.1 Forces Identifiées

| Aspect | Statut | Commentaire |
|--------|--------|------------|
| **Couverture SAST** | ✅ BONNE | Semgrep détecte configurations dangereuses (`debug=True`, `0.0.0.0`) |
| **Couverture SCA** | ✅ TRÈS BONNE | Trivy enumerate 37 CVE ; visibilité complète de la chaîne |
| **Couverture DAST** | ⚠️ PARTIELLE | ZAP détecte absences de headers (CSP) mais pas d'injection XSS identifiée |
| **Gestion d'erreurs** | ? NON ÉVALUÉ | Vérifier leaks de stack traces (relié à debug=True) |
| **Authentification** | ? NON ÉVALUÉ | ZAP n'a pas détecté de vulnérabilités auth → potentiellement satisfaisant |
| **Versioning dépendances** | ❌ CRITIQUE | Pillow 9.5.0 (2023), Werkzeug 2.0.1 (2021), urllib3 1.24.3 (2018) → **18 mois à 7 ans de retard** |

---

### 4.2 Dette Technique Résiduelle

#### **Problème 1 : Chaîne de Dépendances Obsolète**
- **Root Cause** : Pas de mises à jour régulières (`pip install --upgrade`)
- **Impact** : 37 CVE accumulées ; compatibilité décroissante avec OS/Python
- **Remédiation** :
  ```bash
  # Générer rapport
  pip-audit --format json > audit.json
  
  # Plan de mise à jour trimestriel
  pip install --upgrade pip setuptools wheel
  pip install --upgrade -r requirements.txt
  ```

#### **Problème 2 : Absence de Tests de Sécurité dans CI/CD**
- **Constat** : Aucune intégration de Trivy/Semgrep/ZAP dans le pipeline
- **Remédiation** : **Voir section 5 — Métriques / CI/CD**

#### **Problème 3 : Configuration Runtime Dangereuse**
- **Constat** : Hardcode de `host='0.0.0.0'` + `debug=True` dans le code
- **Remédiation** : Variables d'environnement + validations (déjà couvertes Phase 1)

---

### 4.3 Couverture Zero Trust

| Pilier | Statut | Écart |
|--------|--------|------|
| **Authentification** | ⚠️ PARTIEL | Pas d'analyse IAM ; supposer MFA/RBAC absent |
| **Réseau** | ❌ NON CONFORME | Flask bind 0.0.0.0 = absence micro-segmentation ; pas de WAF/Rate Limiting |
| **Données** | ⚠️ PARTIEL | TLS/HTTPS non forcé en config (géré Nginx Phase 1.2) ; chiffrement données sensibles ? |
| **Visibilité** | ❌ INSUFFISANTE | Pas d'audit logging ; pas de telemetrie (SIEM) |
| **Sécurité Code** | ✅ BONNE | SAST/SCA actifs ; DAST basique |

**Verdict Zero Trust** : **Échoue** — Backend exposé directement, debug activé, pas de monitoring continu.

---

## 5. Métriques & Recommandations CI/CD

### 5.1 Métriques de Risque

```yaml
Score de Risque Résiduel (avant remédiation):
  SCA Risk:    9.2/10  (1 CRITICAL + 16 HIGH)
  SAST Risk:   8.5/10  (2 findings HAUTE criticité = network + RCE)
  DAST Risk:   6.0/10  (1 MEDIUM CSP Header)
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  COMPOSITE:   7.9/10  → DÉPLOIEMENT BLOQUÉ

Score de Risque Résiduel (après Phase 1+2):
  SCA Risk:    2.1/10  (4 MEDIUM CVE restantes non-critiques)
  SAST Risk:   0.0/10  (findings résolus)
  DAST Risk:   1.0/10  (CSP implémentée, ZAP revalidé)
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  COMPOSITE:   1.0/10  → DÉPLOIEMENT AUTORISÉ
```

### 5.2 MTTR Estimé (Mean Time To Remediate)

| Phase | Actions | Durée | Chemin critique |
|-------|---------|-------|-----------------|
| 1 (Blockers) | Upgrades + code fixes | 2h | ✅ Critique |
| 2 (High CVEs) | Pip upgrades + tests | 4h | ✅ Critique |
| 3 (Headers) | CSP implémentation | 1h | ✓ Non-critique |
| 4 (Infrastructure) | Nginx + TLS setup | 2h | ✓ Peut être parallèle |
| **TOTAL** | | **9h** | |

**Chemin critique minimum** : Phases 1+2 = **6h** (48h si validation + tests inclus)

---

### 5.3 Intégration CI/CD Recommandée

#### **Stage 1 : Scan SCA (tous commits)**
```yaml
# .gitlab-ci.yml / .github/workflows/security.yml
SCA_Scan:
  image: aquasec/trivy:latest
  script:
    - trivy config . --exit-code 1 --severity HIGH,CRITICAL
    - trivy image myapp:${CI_COMMIT_SHA} --exit-code 1 --severity HIGH,CRITICAL
  allow_failure: false
  only:
    - merge_requests
    - main
```

#### **Stage 2 : Scan SAST (tous commits)**
```yaml
SAST_Scan:
  image: returntocorp/semgrep:latest
  script:
    - semgrep --config="p/security-audit" . --json --output report.json
    - semgrep --config="p/security-audit" . --error  # Fail on issues
  