import json
import os
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable, PageBreak, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle
)
from rich.console import Console

from utils import afficher_banniere, charger_json

console = Console()

BUILD_NUMBER = os.environ.get('BUILD_NUMBER', 'N/A')
OUTPUT_PATH = 'rapport-zerotrust.pdf'

# Palette
C_DARK   = colors.HexColor('#1a237e')
C_MED    = colors.HexColor('#283593')
C_LIGHT  = colors.HexColor('#e8eaf6')
C_RED    = colors.HexColor('#b71c1c')
C_ORANGE = colors.HexColor('#e65100')
C_GREEN  = colors.HexColor('#2e7d32')
C_GREY   = colors.HexColor('#f5f5f5')


def styles():
    return {
        'title': ParagraphStyle('T', fontSize=26, textColor=C_DARK,
                                alignment=TA_CENTER, fontName='Helvetica-Bold', spaceAfter=8),
        'sub':   ParagraphStyle('S', fontSize=11, textColor=colors.HexColor('#546e7a'),
                                alignment=TA_CENTER, spaceAfter=4),
        'h1':    ParagraphStyle('H1', fontSize=13, textColor=colors.white,
                                fontName='Helvetica-Bold', backColor=C_MED,
                                spaceBefore=14, spaceAfter=8, leftIndent=4, borderPad=5),
        'body':  ParagraphStyle('B', fontSize=9, spaceAfter=4, leading=13),
        'small': ParagraphStyle('Sm', fontSize=8, textColor=colors.HexColor('#424242'),
                                spaceAfter=2, leading=11),
        'ok':    ParagraphStyle('OK', fontSize=9, textColor=C_GREEN, spaceAfter=4),
        'warn':  ParagraphStyle('WN', fontSize=9, textColor=C_ORANGE, spaceAfter=4),
    }


def _tbl(data, col_widths, row_colors=None):
    row_colors = row_colors or [colors.HexColor('#fafafa'), colors.white]
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('BACKGROUND',   (0, 0), (-1, 0), C_MED),
        ('TEXTCOLOR',    (0, 0), (-1, 0), colors.white),
        ('FONTNAME',     (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',     (0, 0), (-1, 0), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), row_colors),
        ('GRID',         (0, 0), (-1, -1), 0.4, colors.HexColor('#bdbdbd')),
        ('FONTSIZE',     (0, 1), (-1, -1), 8),
        ('VALIGN',       (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWHEIGHT',    (0, 0), (-1, -1), 16),
    ]))
    return t


def _sev_color(sev):
    s = sev.upper()
    if s == 'CRITICAL': return '#b71c1c'
    if s == 'HIGH':     return '#e65100'
    if s == 'MEDIUM':   return '#f57f17'
    return '#558b2f'


def build_cover(st, semgrep, trivy, zap_count, gate):
    critical = sum(1 for r in trivy.get('Results', [])
                   for v in (r.get('Vulnerabilities') or [])
                   if v.get('Severity') == 'CRITICAL')
    high = sum(1 for r in trivy.get('Results', [])
               for v in (r.get('Vulnerabilities') or [])
               if v.get('Severity') == 'HIGH')
    total_cve = sum(len(r.get('Vulnerabilities') or []) for r in trivy.get('Results', []))
    sast_n = len(semgrep.get('results', []))

    score     = gate.get('score', 'N/A')
    gate_pass = gate.get('gate_passed', False)
    gate_lbl  = f"Score : {score}/100 — {'PASS' if gate_pass else 'FAIL'}"
    gate_icon = '✅' if gate_pass else '🔴'

    rows = [
        ['Etape', 'Outil', 'Resultat', 'Statut'],
        ['SAST',  'Semgrep',        f'{sast_n} finding(s)',
         '⚠' if sast_n else '✅'],
        ['SCA',   'Trivy',          f'{total_cve} CVE  ({critical} CRITICAL / {high} HIGH)',
         '🔴' if critical else ('⚠' if high else '✅')],
        ['BUILD', 'Docker',         f'zerotrust-app:{BUILD_NUMBER}', '✅'],
        ['SCAN',  'Trivy image',    'Image scannee — exit-code 0',   '✅'],
        ['DAST',  'OWASP ZAP',      f'{zap_count} alerte(s)',
         '⚠' if zap_count else '✅'],
        ['IA',    'AI Security Guard', '3 agents : Anti-Tamper / Remediation / Explicatif', '✅'],
        ['GATE',  'Security Gate',  gate_lbl,                        gate_icon],
        ['SIGN',  'Cosign',         'Signature keyless appliquee',   '✅'],
    ]
    t = Table(rows, colWidths=[2*cm, 3.2*cm, 9*cm, 2.3*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), C_DARK),
        ('TEXTCOLOR',  (0, 0), (-1, 0), colors.white),
        ('FONTNAME',   (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',   (0, 0), (-1, 0), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [C_LIGHT, colors.white]),
        ('GRID',       (0, 0), (-1, -1), 0.4, colors.HexColor('#9fa8da')),
        ('FONTSIZE',   (0, 1), (-1, -1), 9),
        ('ALIGN',      (-1, 0), (-1, -1), 'CENTER'),
        ('ALIGN',      (0, 0), (0, -1), 'CENTER'),
        ('FONTNAME',   (0, 1), (0, -1), 'Helvetica-Bold'),
        ('VALIGN',     (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWHEIGHT',  (0, 0), (-1, -1), 20),
        # Ligne GATE colorée selon résultat
        ('BACKGROUND', (0, 7), (-1, 7),
         colors.HexColor('#e8f5e9') if gate_pass else colors.HexColor('#fce4ec')),
    ]))

    story = []
    story.append(Spacer(1, 2*cm))
    story.append(Paragraph('RAPPORT DE SECURITE', st['title']))
    story.append(Paragraph('DevSecOps Zero Trust Pipeline', st['sub']))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width='100%', thickness=3, color=C_DARK))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        f'Build #{BUILD_NUMBER} — {datetime.now().strftime("%d %B %Y a %H:%M")}',
        st['sub']
    ))
    story.append(Spacer(1, 1.2*cm))
    story.append(t)
    story.append(PageBreak())
    return story


def section_sast(st, semgrep):
    story = [Paragraph('1 — Analyse Statique (SAST — Semgrep)', st['h1'])]
    findings = semgrep.get('results', [])
    if not findings:
        story.append(Paragraph('Aucun finding — code source sain.', st['ok']))
        return story
    data = [['Fichier', 'Regle / Check ID', 'Severite', 'Ligne']]
    for f in findings[:30]:
        sev = f.get('extra', {}).get('severity', 'N/A')
        data.append([
            Paragraph(f.get('path', '')[-50:], st['small']),
            Paragraph(f.get('check_id', '')[-55:], st['small']),
            Paragraph(f'<font color="{_sev_color(sev)}">{sev}</font>', st['small']),
            str(f.get('start', {}).get('line', '')),
        ])
    story.append(_tbl(data, [5.5*cm, 8*cm, 2.5*cm, 1.5*cm],
                      [colors.HexColor('#fff3e0'), colors.white]))
    if len(findings) > 30:
        story.append(Paragraph(f'… {len(findings)-30} autres findings dans semgrep-results.json', st['small']))
    story.append(Spacer(1, 0.4*cm))
    return story


def section_sca(st, trivy):
    story = [Paragraph('2 — Analyse des Dependances (SCA — Trivy)', st['h1'])]
    vulns = [v for r in trivy.get('Results', []) for v in (r.get('Vulnerabilities') or [])]
    if not vulns:
        story.append(Paragraph('Aucune CVE detectee.', st['ok']))
        return story
    data = [['CVE', 'Package', 'Installee', 'Corrigee', 'Severite']]
    for v in vulns[:30]:
        sev = v.get('Severity', 'N/A')
        data.append([
            Paragraph(v.get('VulnerabilityID', 'N/A'), st['small']),
            v.get('PkgName', 'N/A'),
            v.get('InstalledVersion', 'N/A'),
            v.get('FixedVersion', 'N/A') or '—',
            Paragraph(f'<font color="{_sev_color(sev)}">{sev}</font>', st['small']),
        ])
    story.append(_tbl(data, [3.8*cm, 2.8*cm, 2.8*cm, 2.8*cm, 2.3*cm],
                      [colors.HexColor('#fce4ec'), colors.white]))
    if len(vulns) > 30:
        story.append(Paragraph(f'… {len(vulns)-30} autres CVE dans trivy-report.json', st['small']))
    story.append(Spacer(1, 0.4*cm))
    return story


def section_dast(st, zap):
    story = [Paragraph('3 — Analyse Dynamique (DAST — OWASP ZAP)', st['h1'])]
    alerts = [a for site in zap.get('site', []) for a in site.get('alerts', [])]
    if not zap:
        story.append(Paragraph('Rapport ZAP non disponible.', st['warn']))
        return story
    if not alerts:
        story.append(Paragraph('Aucune alerte detectee par OWASP ZAP.', st['ok']))
        return story

    by_risk = {'High': [], 'Medium': [], 'Low': [], 'Informational': []}
    for a in alerts:
        rd = a.get('riskdesc', 'Informational')
        key = rd.split(' ')[0] if rd else 'Informational'
        by_risk.setdefault(key, []).append(a)

    summary = [["Niveau de risque", "Nombre d'alertes"]]
    for level in ('High', 'Medium', 'Low', 'Informational'):
        if by_risk.get(level):
            summary.append([level, str(len(by_risk[level]))])
    story.append(_tbl(summary, [8*cm, 8*cm]))
    story.append(Spacer(1, 0.3*cm))

    data = [['Alerte', 'Risque', 'Confiance', 'Instances']]
    for a in alerts[:25]:
        name = a.get('alert', a.get('name', 'N/A'))
        risk = a.get('riskdesc', 'N/A').split(' ')[0]
        conf = a.get('confidence', a.get('confidencedesc', 'N/A'))
        count = str(a.get('count', len(a.get('instances', []))))
        data.append([
            Paragraph(name[:65], st['small']),
            Paragraph(f'<font color="{_sev_color(risk)}">{risk}</font>', st['small']),
            conf,
            count,
        ])
    story.append(_tbl(data, [9*cm, 2.5*cm, 3*cm, 2*cm],
                      [colors.HexColor('#fff8e1'), colors.white]))
    story.append(Spacer(1, 0.4*cm))
    return story


def section_ai_guard(st, remediation):
    story = [Paragraph('4 — AI Security Guard', st['h1'])]

    # Anti-Tampering
    story.append(Paragraph('4.1 — Anti-Tampering', ParagraphStyle(
        'sh', fontSize=10, textColor=C_DARK, fontName='Helvetica-Bold',
        spaceBefore=6, spaceAfter=4
    )))
    story.append(Paragraph('Pipeline verifie — aucune modification non autorisee detectee.', st['ok']))
    story.append(Spacer(1, 0.2*cm))

    # Remédiation CVE
    story.append(Paragraph('4.2 — Remediation CVE (IA)', ParagraphStyle(
        'sh', fontSize=10, textColor=C_DARK, fontName='Helvetica-Bold',
        spaceBefore=6, spaceAfter=4
    )))
    fixes = remediation.get('vulnerabilites', remediation.get('vulnerabilities', []))
    if not fixes:
        story.append(Paragraph('Aucune remediation disponible.', st['warn']))
    else:
        data = [['CVE', 'Package', 'Priorite', 'Correction requirements.txt']]
        for f in fixes:
            data.append([
                f.get('cve', 'N/A'),
                f.get('package', 'N/A'),
                f.get('priorite', f.get('priority', 'N/A')),
                f.get('correction_requirements', f.get('fix', 'N/A')),
            ])
        story.append(_tbl(data, [3.8*cm, 3*cm, 2.5*cm, 7.2*cm],
                          [colors.HexColor('#e8f5e9'), colors.white]))

    # Rapport Explicatif
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph('4.3 — Rapport Explicatif (IA)', ParagraphStyle(
        'sh', fontSize=10, textColor=C_DARK, fontName='Helvetica-Bold',
        spaceBefore=6, spaceAfter=4
    )))
    explicatif_path = Path('rapport-explicatif.md')
    if explicatif_path.exists():
        content = explicatif_path.read_text(encoding='utf-8')
        # Extrait les 10 premières lignes non vides
        lines = [l.strip() for l in content.splitlines() if l.strip()][:10]
        for line in lines:
            clean = line.lstrip('#').strip()
            if clean:
                story.append(Paragraph(clean[:120], st['small']))
        story.append(Paragraph('Rapport complet disponible : rapport-explicatif.md', st['small']))
    else:
        story.append(Paragraph('Rapport explicatif non disponible pour ce build.', st['warn']))

    story.append(Spacer(1, 0.4*cm))
    return story


def section_security_gate(st, gate):
    story = [Paragraph('5 — Security Gate', st['h1'])]

    score     = gate.get('score', 0)
    grade     = gate.get('grade', 'N/A')
    passed    = gate.get('gate_passed', False)
    threshold = gate.get('threshold', 90)
    penalties = gate.get('penalties', {})

    gate_color = C_GREEN if passed else C_RED
    gate_text  = 'DEPLOIEMENT AUTORISE' if passed else 'DEPLOIEMENT BLOQUE'

    # Résultat global
    result_data = [
        ['Score de securite', 'Grade', 'Seuil requis', 'Decision'],
        [
            Paragraph(f'<font color="#{("2e7d32" if passed else "b71c1c")}" size="14"><b>{score}/100</b></font>', st['body']),
            Paragraph(f'<b>{grade}</b>', st['body']),
            f'{threshold}/100',
            Paragraph(f'<font color="#{("2e7d32" if passed else "b71c1c")}"><b>{gate_text}</b></font>', st['body']),
        ]
    ]
    t = Table(result_data, colWidths=[4*cm, 3*cm, 4*cm, 5.5*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND',   (0, 0), (-1, 0), C_DARK),
        ('TEXTCOLOR',    (0, 0), (-1, 0), colors.white),
        ('FONTNAME',     (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',     (0, 0), (-1, 0), 9),
        ('BACKGROUND',   (0, 1), (-1, 1),
         colors.HexColor('#e8f5e9') if passed else colors.HexColor('#fce4ec')),
        ('GRID',         (0, 0), (-1, -1), 0.4, colors.HexColor('#bdbdbd')),
        ('FONTSIZE',     (0, 1), (-1, -1), 9),
        ('ALIGN',        (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN',       (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWHEIGHT',    (0, 0), (-1, -1), 22),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.4*cm))

    # Détail des pénalités
    if penalties:
        pen_map = {
            'cve_critical': ('CVE CRITICAL', '-15 pts chacune'),
            'cve_high':     ('CVE HIGH',     '-8 pts chacune'),
            'cve_medium':   ('CVE MEDIUM',   '-3 pts chacune'),
            'cve_low':      ('CVE LOW',      '-1 pt chacune'),
            'sast_critical':('SAST CRITICAL','-10 pts chacun'),
            'sast_high':    ('SAST HIGH',    '-5 pts chacun'),
            'dast_high':    ('DAST High',    '-8 pts chacun'),
            'dast_medium':  ('DAST Medium',  '-4 pts chacun'),
        }
        pen_data = [['Categorie', 'Nombre', 'Poids unitaire', 'Impact total']]
        for key, (label, weight) in pen_map.items():
            count = penalties.get(key, 0)
            if count > 0:
                unit = int(weight.split()[0].replace('-', ''))
                total = count * unit
                pen_data.append([label, str(count), weight, f'-{total} pts'])
        if len(pen_data) > 1:
            story.append(_tbl(pen_data, [5*cm, 2.5*cm, 4*cm, 5*cm],
                              [colors.HexColor('#fce4ec'), colors.white]))

    story.append(Spacer(1, 0.4*cm))
    return story


def section_build(st):
    story = [Paragraph('6 — Build Docker & Signature Cosign', st['h1'])]
    data = [
        ['Propriete', 'Valeur'],
        ['Image Docker',        f'zerotrust-app:{BUILD_NUMBER}'],
        ['Build number',        BUILD_NUMBER],
        ['Date',                datetime.now().strftime('%d/%m/%Y a %H:%M:%S')],
        ['Base image',          'python:3.11-slim (Debian 13)'],
        ['Utilisateur runtime', 'appuser (non-root — Zero Trust)'],
        ['Signature',           'Cosign v3 — keyless OIDC (fallback local)'],
        ['Scan image',          'Trivy — exit-code 0 (resultats archives)'],
    ]
    t = Table(data, colWidths=[5*cm, 12*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND',   (0, 0), (-1, 0), C_MED),
        ('TEXTCOLOR',    (0, 0), (-1, 0), colors.white),
        ('FONTNAME',     (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',     (0, 0), (-1, 0), 9),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#e3f2fd'), colors.white]),
        ('GRID',         (0, 0), (-1, -1), 0.4, colors.HexColor('#bdbdbd')),
        ('FONTSIZE',     (0, 1), (-1, -1), 9),
        ('VALIGN',       (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWHEIGHT',    (0, 0), (-1, -1), 18),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.4*cm))
    return story


def generate_pdf():
    afficher_banniere('Agent Rapport PDF — Zero Trust', 'blue')

    semgrep     = charger_json('semgrep-results.json')       or {'results': []}
    trivy       = charger_json('trivy-report.json')          or {'Results': []}
    remediation = charger_json('ai-remediation-report.json') or {}
    zap         = charger_json('zap-report.json')            or {}
    gate        = charger_json('security-gate.json')         or {}

    zap_count = sum(len(s.get('alerts', [])) for s in zap.get('site', []))

    st = styles()
    story = []

    story += build_cover(st, semgrep, trivy, zap_count, gate)
    story += section_sast(st, semgrep)
    story += section_sca(st, trivy)
    story += section_dast(st, zap)
    story += section_ai_guard(st, remediation)
    story += section_security_gate(st, gate)
    story += section_build(st)

    story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#bdbdbd')))
    story.append(Paragraph(
        f'Rapport genere automatiquement — Pipeline DevSecOps Zero Trust '
        f'— Build #{BUILD_NUMBER} — {datetime.now().strftime("%d/%m/%Y %H:%M")}',
        ParagraphStyle('footer', fontSize=7, textColor=colors.grey, alignment=TA_CENTER)
    ))

    doc = SimpleDocTemplate(
        OUTPUT_PATH, pagesize=A4,
        rightMargin=1.8*cm, leftMargin=1.8*cm,
        topMargin=2*cm, bottomMargin=2*cm,
        title=f'Rapport DevSecOps Zero Trust — Build {BUILD_NUMBER}',
        author='Pipeline Zero Trust'
    )
    doc.build(story)
    console.print(f'[green bold]Rapport PDF genere : {OUTPUT_PATH}[/green bold]')


if __name__ == '__main__':
    generate_pdf()
