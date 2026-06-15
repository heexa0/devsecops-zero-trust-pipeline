import sys
from rich.console import Console
from rich.markdown import Markdown

from ollama_client import verifier_ollama, appeler_ollama, get_dernier_moteur
from utils import charger_json, afficher_banniere

console = Console()


def _extraire_cves_trivy(trivy: dict) -> list:
    """Extrait les CVEs triées CRITICAL > HIGH > MEDIUM depuis le rapport Trivy."""
    order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    cves  = []
    for result in trivy.get('Results', []):
        for v in result.get('Vulnerabilities', []):
            cves.append({
                'id':       v.get('VulnerabilityID', 'N/A'),
                'pkg':      f"{v.get('PkgName', '')}@{v.get('InstalledVersion', '')}",
                'severity': v.get('Severity', ''),
                'title':    v.get('Title', '')[:100],
                'fixed':    v.get('FixedVersion', 'N/A'),
            })
    cves.sort(key=lambda x: order.get(x['severity'], 9))
    return cves


def _extraire_findings_semgrep(semgrep: dict) -> list:
    """Extrait les findings Semgrep de façon concise."""
    findings = []
    for r in semgrep.get('results', []):
        findings.append({
            'rule':     r.get('check_id', '').split('.')[-1],
            'file':     r.get('path', ''),
            'line':     r.get('start', {}).get('line', ''),
            'severity': r.get('extra', {}).get('severity', ''),
            'message':  r.get('extra', {}).get('message', '')[:150],
        })
    return findings


def _extraire_alerts_zap(zap: dict) -> list:
    """Extrait toutes les alertes de tous les sites ZAP."""
    alerts = []
    for site in zap.get('site', []):
        alerts.extend(site.get('alerts', []))
    return alerts


def generer_rapport_pedagogique(
    trivy_path='trivy-report.json',
    semgrep_path='semgrep-results.json',
    zap_path='zap-report.json'
) -> str:
    """Génère un rapport d'analyse de sécurité pour l'équipe technique."""
    trivy   = charger_json(trivy_path)   or {}
    semgrep = charger_json(semgrep_path) or {}
    zap     = charger_json(zap_path)     or {}

    # SCA — CVEs
    cves     = _extraire_cves_trivy(trivy)
    nb_cve   = len(cves)
    top_cves = cves[:20]
    cves_text = '\n'.join(
        f"- {c['id']} | {c['severity']} | {c['pkg']} | {c['title']} | fix: {c['fixed']}"
        for c in top_cves
    )

    # SAST — Semgrep
    findings  = _extraire_findings_semgrep(semgrep)
    nb_sast   = len(findings)
    sast_text = '\n'.join(
        f"- [{f['severity']}] {f['rule']} — {f['file']}:{f['line']} — {f['message']}"
        for f in findings[:10]
    )

    # DAST — ZAP
    zap_alerts     = _extraire_alerts_zap(zap)
    nb_dast_high   = sum(1 for a in zap_alerts if a.get('riskcode') == '3')
    nb_dast_medium = sum(1 for a in zap_alerts if a.get('riskcode') == '2')
    nb_dast_low    = sum(1 for a in zap_alerts if a.get('riskcode') == '1')
    dast_text = '\n'.join(
        f"- [{a.get('riskdesc','')}] {a.get('alert','')} | CWE-{a.get('cweid','')} | {(a.get('instances') or [{}])[0].get('uri','')}"
        for a in zap_alerts if a.get('riskcode') in ('3', '2')
    )

    prompt = f"""Tu es un ingénieur DevSecOps senior produisant un rapport d'analyse de sécurité destiné à une équipe technique.

Résultats des scans :
- Trivy (SCA)     : {nb_cve} CVE dans les dépendances Python
- Semgrep (SAST)  : {nb_sast} findings dans le code source
- OWASP ZAP (DAST): {nb_dast_high} High, {nb_dast_medium} Medium, {nb_dast_low} Low

CVEs Trivy (top {len(top_cves)}, triées par sévérité) :
{cves_text if cves_text else 'Aucune CVE détectée'}

Findings Semgrep :
{sast_text if sast_text else 'Aucun finding'}

Alertes ZAP High/Medium :
{dast_text if dast_text else 'Aucune alerte High/Medium'}

Génère un rapport Markdown technique structuré avec :
1. **Executive Summary** — synthèse en 3 lignes : surface d'attaque, criticité globale, statut conformité Zero Trust
2. **Findings critiques** — pour chaque finding HIGH/CRITICAL (SCA + SAST + DAST) : identifiant (CVE/CWE), vecteur d'attaque, composant affecté, impact opérationnel
3. **Plan de remédiation** — actions priorisées par sévérité avec commandes exactes (`pip install`, patches), délais (immédiat / 48h / sprint)
4. **Analyse de la posture de sécurité** — forces identifiées, dette technique résiduelle, couverture Zero Trust
5. **Métriques** — MTTR estimé, score de risque résiduel, recommandations CI/CD

Style : direct, factuel. Terminologie OWASP, CVSSv3, NIST, CWE. Pas d'emojis."""

    return appeler_ollama(prompt, max_tokens=6000)


def generer_rapport_fallback_statique(
    trivy_path='trivy-report.json',
    semgrep_path='semgrep-results.json',
    zap_path='zap-report.json'
) -> str:
    """Rapport minimal généré sans IA si tous les moteurs échouent."""
    trivy   = charger_json(trivy_path)   or {}
    semgrep = charger_json(semgrep_path) or {}
    zap     = charger_json(zap_path)     or {}

    cves      = _extraire_cves_trivy(trivy)
    findings  = _extraire_findings_semgrep(semgrep)
    zap_alerts = _extraire_alerts_zap(zap)

    critical = [c for c in cves if c['severity'] == 'CRITICAL']
    high     = [c for c in cves if c['severity'] == 'HIGH']

    md  = "# Rapport de Sécurité — Analyse Automatique (sans IA)\n\n"
    md += "## Executive Summary\n\n"
    md += f"- **SCA (Trivy)** : {len(cves)} CVE total ({len(critical)} CRITICAL, {len(high)} HIGH)\n"
    md += f"- **SAST (Semgrep)** : {len(findings)} findings\n"
    md += f"- **DAST (ZAP)** : {len(zap_alerts)} alertes\n\n"

    if critical or high:
        md += "## Findings Critiques\n\n"
        for c in (critical + high)[:10]:
            md += f"- **{c['id']}** | {c['severity']} | `{c['pkg']}` | Fix: `{c['fixed']}`\n"
            if c['title']:
                md += f"  - {c['title']}\n"
        md += "\n"

    if findings:
        md += "## Findings SAST\n\n"
        for f in findings[:5]:
            md += f"- [{f['severity']}] `{f['rule']}` — {f['file']}:{f['line']}\n"
        md += "\n"

    md += "## Plan de Remédiation\n\n"
    md += "### Immédiat\n"
    for c in critical[:3]:
        if c['fixed'] and c['fixed'] != 'N/A':
            pkg = c['pkg'].split('@')[0]
            md += f"- `pip install {pkg}>={c['fixed']}`\n"

    md += "\n*Rapport généré sans IA — moteurs indisponibles.*\n"
    return md


if __name__ == '__main__':
    afficher_banniere('Agent Explicatif — Dual AI Engine', 'green')

    if not verifier_ollama():
        console.print('[yellow]⚠ Aucun moteur IA disponible — rapport statique uniquement[/yellow]')
        rapport_md = generer_rapport_fallback_statique()
        if rapport_md:
            with open('rapport-explicatif.md', 'w', encoding='utf-8') as f:
                f.write(rapport_md)
            console.print(Markdown(rapport_md))
            console.print('[yellow]Rapport statique sauvegardé : rapport-explicatif.md[/yellow]')
        sys.exit(0)

    rapport_md = generer_rapport_pedagogique()

    if rapport_md:
        moteur = get_dernier_moteur()
        console.print(f'[blue]Rapport généré par : {moteur}[/blue]')
        console.print(Markdown(rapport_md))
        with open('rapport-explicatif.md', 'w', encoding='utf-8') as f:
            f.write(rapport_md)
        console.print('[green]Rapport sauvegardé : rapport-explicatif.md[/green]')
    else:
        console.print('[yellow]IA non disponible — génération du rapport statique[/yellow]')
        rapport_md = generer_rapport_fallback_statique()
        with open('rapport-explicatif.md', 'w', encoding='utf-8') as f:
            f.write(rapport_md)
        console.print(Markdown(rapport_md))
        console.print('[yellow]Rapport statique sauvegardé : rapport-explicatif.md[/yellow]')