# Secure Flask App — Zero Trust DevSecOps Baseline

This app is the **secure counterpart** of the intentionally vulnerable demo app.
It is designed to produce **zero HIGH/CRITICAL findings** across all pipeline scanners
(Semgrep, Trivy filesystem, Trivy image scan).

---

## Security fixes vs vulnerabilities

| Route | Vulnerability mitigated | Secure implementation |
|---|---|---|
| `GET /ping` | Command Injection (CWE-78) | `subprocess.run([...], shell=False)` + regex whitelist on `host` |
| `POST /load` | Insecure Deserialization (CWE-502) | `json.loads()` only — no `pickle`, `marshal`, or `shelve` |
| `GET /user` | SQL Injection (CWE-89) | Parameterized query: `cursor.execute("... WHERE name = ?", (name,))` |
| `GET /secret` | Hardcoded Credentials (CWE-798) | `os.environ.get("SECRET_KEY")` — never in source code |
| App startup | Flask Debug Mode (CWE-94) | `debug=False` + gunicorn as WSGI server in production |
| `GET /file` | Path Traversal (CWE-22) | `os.path.basename()` + `os.path.abspath()` + directory jail check |
| All responses | Missing security headers | CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy |
| Dockerfile | Container runs as root | `USER appuser` (UID 1000, no shell, no home) |
| Dockerfile | Bloated attack surface | `python:3.11-slim` base, only 2 pip dependencies |

---

## Build and run

```bash
# Build
docker build -t secure-app:latest .

# Run (inject SECRET_KEY at runtime — never hardcode it)
docker run -p 8000:8000 -e SECRET_KEY=your-secret-here secure-app:latest
```

---

## Run scans locally

```bash
# SAST — Semgrep (from repo root)
semgrep --config auto secure-app/app/ --json | python -c "
import json,sys
r=json.load(sys.stdin)
print(f'Semgrep findings: {len(r.get(\"results\", []))}')"

# SCA — Trivy filesystem
trivy fs secure-app/app/ --severity HIGH,CRITICAL

# Image scan
trivy image secure-app:latest --severity HIGH,CRITICAL
```

---

## Expected scan results

| Scanner | Expected findings |
|---|---|
| Semgrep (SAST) | **0 findings** |
| Trivy filesystem (SCA) | **0 HIGH/CRITICAL CVEs** |
| Trivy image scan | **0 HIGH/CRITICAL CVEs** |
