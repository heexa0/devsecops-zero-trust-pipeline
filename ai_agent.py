"""
ai_agent.py
===========
AI Security Agent for the Zero Trust DevSecOps pipeline.
Reads Trivy and Semgrep JSON reports, sends them to Claude (Anthropic),
and generates a structured markdown remediation report.
"""

import os
import json
from datetime import datetime

from dotenv import load_dotenv
import anthropic

# ─── Load environment variables ───────────────────────────────────────────────

load_dotenv()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
if not ANTHROPIC_API_KEY:
    print("❌ ANTHROPIC_API_KEY is missing. Create a .env file with ANTHROPIC_API_KEY=sk-ant-...")
    exit(1)

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)


# ─── Parse Trivy report ───────────────────────────────────────────────────────

def parse_trivy_report(filepath="trivy-report.json"):
    """
    Read trivy-report.json and extract HIGH/CRITICAL vulnerabilities.
    Returns a list of dicts with package, version, fix, CVE, severity, description.
    """
    if not os.path.exists(filepath):
        print(f"⚠️  Trivy report not found: {filepath}")
        return []

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse {filepath}: {e}")
        return []

    vulns = []
    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities") or []:
            severity = vuln.get("Severity", "UNKNOWN").upper()
            if severity not in ("HIGH", "CRITICAL"):
                continue
            vulns.append({
                "package":         vuln.get("PkgName", "unknown"),
                "installed":       vuln.get("InstalledVersion", "unknown"),
                "fixed":           vuln.get("FixedVersion") or "No fix available",
                "cve":             vuln.get("VulnerabilityID", "N/A"),
                "severity":        severity,
                "description":     vuln.get("Description", "No description available."),
            })

    return vulns


# ─── Parse Semgrep report ─────────────────────────────────────────────────────

def parse_semgrep_report(filepath="semgrep-report.json"):
    """
    Read semgrep-report.json and extract all findings.
    Returns a list of dicts with rule id, file, line, message, severity.
    """
    if not os.path.exists(filepath):
        print(f"⚠️  Semgrep report not found: {filepath}")
        return []

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse {filepath}: {e}")
        return []

    findings = []
    for item in data.get("results", []):
        findings.append({
            "rule_id":   item.get("check_id", "unknown"),
            "file":      item.get("path", "unknown"),
            "line":      item.get("start", {}).get("line", "?"),
            "message":   item.get("extra", {}).get("message", "No message."),
            "severity":  item.get("extra", {}).get("severity", "UNKNOWN").upper(),
        })

    return findings


# ─── Build the analysis prompt ────────────────────────────────────────────────

def build_prompt(trivy_vulns, semgrep_findings):
    """
    Construct a structured security analysis prompt from parsed scan results.
    """
    # Format Trivy section
    trivy_lines = []
    for v in trivy_vulns:
        trivy_lines.append(
            f"- [{v['severity']}] {v['cve']} | {v['package']} {v['installed']} → {v['fixed']}\n"
            f"  Description: {v['description']}"
        )
    trivy_block = "\n".join(trivy_lines) if trivy_lines else "No dependency vulnerabilities found."

    # Format Semgrep section
    semgrep_lines = []
    for f in semgrep_findings:
        semgrep_lines.append(
            f"- [{f['severity']}] {f['rule_id']} | {f['file']} line {f['line']}\n"
            f"  Message: {f['message']}"
        )
    semgrep_block = "\n".join(semgrep_lines) if semgrep_lines else "No code vulnerabilities found."

    prompt = f"""You are an expert DevSecOps security analyst.
Analyze the following vulnerabilities found in a Python Flask application
and provide for EACH vulnerability:
1. Simple explanation of the risk (1-2 sentences)
2. Concrete fix (exact command or code snippet)
3. Priority: Critical / High / Medium

=== DEPENDENCY VULNERABILITIES (Trivy) ===
{trivy_block}

=== CODE VULNERABILITIES (Semgrep) ===
{semgrep_block}

Format your response as a clean markdown report.
Start with a summary of total vulnerabilities found.
Then create a section for each vulnerability.
"""
    return prompt


# ─── Call Claude API ──────────────────────────────────────────────────────────

def ask_anthropic(prompt):
    """
    Send the security prompt to Claude (claude-sonnet-4-5) and return the response text.
    Uses the Anthropic SDK client syntax.
    """
    try:
        message = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text
    except Exception as e:
        print(f"❌ Claude API error: {e}")
        return None


# ─── Save the report ──────────────────────────────────────────────────────────

def save_report(response, output_file="ai-report.md"):
    """
    Write the AI response to a markdown file with a pipeline header.
    """
    header = (
        "# 🔐 AI Security Analysis Report\n"
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        "**Pipeline:** Zero Trust DevSecOps\n"
        "\n---\n\n"
    )
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(header + response)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("🔍 Loading security reports...")

    trivy_vulns = parse_trivy_report("trivy-report.json")
    print(f"   Trivy   → {len(trivy_vulns)} HIGH/CRITICAL vulnerabilities found")

    semgrep_findings = parse_semgrep_report("semgrep-report.json")
    print(f"   Semgrep → {len(semgrep_findings)} findings found")

    if not trivy_vulns and not semgrep_findings:
        print("⚠️  No reports found — run Trivy and Semgrep first (python run_scans.py)")
        exit(0)

    prompt = build_prompt(trivy_vulns, semgrep_findings)

    print("\n🤖 Sending Anthropic for security analysis...")
    response = ask_gemini(prompt)

    if not response:
        print("❌ No response from Anthropic — aborting")
        exit(1)

    save_report(response)

    print("✅ Analysis complete! Report saved to ai-report.md")
    print("\n" + "═" * 60)
    print(response)


if __name__ == "__main__":
    main()
