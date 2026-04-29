from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from groq import Groq
from dotenv import load_dotenv
import os

load_dotenv()
console = Console()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

RISK_COLORS = {
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "orange1",
    "CRITICAL": "red"
}

def render_header(vendor, score, label):
    color = RISK_COLORS.get(label, "white")
    console.print(Panel(
        f"[bold cyan]Vendor Risk Radar[/bold cyan]\n"
        f"Vendor: [bold]{vendor}[/bold]\n"
        f"Risk Score: [bold {color}]{score}/100 - {label}[/bold {color}]",
        expand=False
    ))

def render_cve_table(cves):
    table = Table(title="CVE Analysis", header_style="bold cyan", show_lines=False)
    table.add_column("CVE ID", style="cyan", width=18)
    table.add_column("CVSS", justify="center", width=8)
    table.add_column("Category", width=20)
    table.add_column("KEV", justify="center", width=6)
    table.add_column("Description", width=50)

    for cve in cves[:10]:
        score = cve.get("score")
        score_str = str(score) if score else "N/A"
        color = "red" if score and score >= 9.0 else "yellow" if score and score >= 7.0 else "green"
        kev = "[red]YES[/red]" if cve.get("is_kev") else "no"
        category = cve.get("attack_category", "other").replace("_", " ").title()
        table.add_row(
            cve["id"],
            f"[{color}]{score_str}[/{color}]",
            category,
            kev,
            cve["description"][:60] + "..."
        )
    console.print(table)

def render_penalty_breakdown(penalties):
    table = Table(title="Risk Score Breakdown", header_style="bold cyan")
    table.add_column("CVE ID", style="cyan", width=18)
    table.add_column("Category", width=20)
    table.add_column("CVSS", justify="center", width=8)
    table.add_column("KEV", justify="center", width=6)
    table.add_column("Penalty", justify="right", width=10)

    for p in penalties[:8]:
        kev = "[red]YES[/red]" if p.get("is_kev") else "no"
        category = p.get("category", "other").replace("_", " ").title()
        color = "red" if p["penalty"] > 15 else "yellow" if p["penalty"] > 8 else "white"
        table.add_row(
            p["cve_id"],
            category,
            str(p["cvss"]),
            kev,
            f"[{color}]-{p['penalty']}[/{color}]"
        )
    console.print(table)

def render_new_cves(new_cves):
    if not new_cves:
        return
    console.print(f"\n[bold yellow]⚠ {len(new_cves)} new CVE(s) since last scan:[/bold yellow]")
    for cve in new_cves:
        console.print(f"  [cyan]{cve['id']}[/cyan] - {cve['description'][:80]}...")

def render_history(history):
    if len(history) < 2:
        return
    table = Table(title="Score History", header_style="bold cyan")
    table.add_column("Scanned At", width=25)
    table.add_column("Score", justify="center", width=10)
    table.add_column("CVEs", justify="center", width=8)
    table.add_column("KEV", justify="center", width=8)

    for h in history:
        color = "green" if h["score"] >= 80 else "yellow" if h["score"] >= 60 else "red"
        table.add_row(
            h["scanned_at"][:19],
            f"[{color}]{h['score']}[/{color}]",
            str(h["cve_count"]),
            str(h["kev_count"])
        )
    console.print(table)

def render_gh_advisories(advisories):
    if not advisories:
        return
    table = Table(title="GitHub Security Advisories", header_style="bold cyan")
    table.add_column("ID", style="cyan", width=20)
    table.add_column("Severity", justify="center", width=12)
    table.add_column("CVSS", justify="center", width=8)
    table.add_column("Summary", width=55)

    for adv in advisories[:5]:
        sev = adv.get("severity", "UNKNOWN")
        color = "red" if sev == "CRITICAL" else "orange1" if sev == "HIGH" else "yellow"
        table.add_row(
            adv["id"],
            f"[{color}]{sev}[/{color}]",
            str(adv.get("cvss_score") or "N/A"),
            adv.get("summary", "")[:60] + "..."
        )
    console.print(table)

def generate_narrative(result):
    cve_summary = "\n".join([
        f"- {c['id']} (CVSS: {c['score']}, Category: {c['attack_category']}): {c['description'][:100]}"
        for c in result["cves"][:5]
    ])
    kev_summary = "\n".join([
        f"- {k['cveID']}: {k['vulnerabilityName']}"
        for k in result["kev_matches"][:3]
    ])
    penalty_summary = "\n".join([
        f"- {p['cve_id']} ({p['category']}): penalty {p['penalty']}"
        for p in result["penalties"][:5]
    ])

    prompt = f"""You are a senior security analyst writing an internal vendor risk report.

Vendor: {result['vendor']}
Risk Score: {result['score']}/100 ({result['label']} RISK)
CVEs analyzed: {result['cve_count']}
Actively exploited (KEV): {result['kev_count']}

Top CVEs:
{cve_summary if cve_summary else "None found"}

CISA Known Exploited:
{kev_summary if kev_summary else "None"}

Risk penalty breakdown:
{penalty_summary}

Write a 3 paragraph risk narrative. First paragraph: overall posture. Second: specific attack scenarios using the CVE data. Third: concrete recommendations. Do not use bullet points. Be specific and technical."""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=600
    )
    return response.choices[0].message.content

def render_full_report(result):
    render_header(result["vendor"], result["score"], result["label"])
    render_new_cves(result["new_cves"])
    render_cve_table(result["cves"])
    render_penalty_breakdown(result["penalties"])
    render_gh_advisories(result["gh_advisories"])
    render_history(result["history"])
    console.print(f"\n[cyan]Generating risk narrative...[/cyan]")
    narrative = generate_narrative(result)
    console.print(Panel(narrative, title="[bold]Risk Narrative[/bold]", border_style="cyan"))

def render_comparison(result):
    v1 = result["vendor1"]
    v2 = result["vendor2"]

    console.print(Panel(
        f"[bold cyan]Vendor Risk Radar - Compare Mode[/bold cyan]\n"
        f"[bold]{v1['vendor']}[/bold] vs [bold]{v2['vendor']}[/bold]",
        expand=False
    ))

    table = Table(title="Comparison Summary", header_style="bold cyan")
    table.add_column("Metric", width=25)
    table.add_column(v1["vendor"], justify="center", width=20)
    table.add_column(v2["vendor"], justify="center", width=20)

    def colorize(score):
        color = "green" if score >= 80 else "yellow" if score >= 60 else "red"
        return f"[{color}]{score}/100[/{color}]"

    table.add_row("Risk Score", colorize(v1["score"]), colorize(v2["score"]))
    table.add_row("CVEs Found", str(v1["cve_count"]), str(v2["cve_count"]))
    table.add_row("Actively Exploited", str(v1["kev_count"]), str(v2["kev_count"]))
    table.add_row("Risk Level", v1["label"], v2["label"])
    console.print(table)

    console.print(f"\n[bold cyan]--- {v1['vendor'].upper()} ---[/bold cyan]")
    render_cve_table(v1["cves"])
    render_penalty_breakdown(v1["penalties"])

    console.print(f"\n[bold cyan]--- {v2['vendor'].upper()} ---[/bold cyan]")
    render_cve_table(v2["cves"])
    render_penalty_breakdown(v2["penalties"])

    console.print(f"\n[cyan]Generating narratives...[/cyan]")
    n1 = generate_narrative(v1)
    n2 = generate_narrative(v2)
    console.print(Panel(n1, title=f"[bold]Risk Narrative - {v1['vendor']}[/bold]", border_style="cyan"))
    console.print(Panel(n2, title=f"[bold]Risk Narrative - {v2['vendor']}[/bold]", border_style="cyan"))

def export_pdf(result, output_path=None):
    from fpdf import FPDF
    from datetime import datetime

    vendor = result["vendor"]
    if not output_path:
        output_path = f"{vendor.lower()}_risk_report.pdf"

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 10, "Vendor Risk Radar", ln=True)
    pdf.set_font("Helvetica", "", 12)
    pdf.cell(0, 8, f"Security Risk Report - {vendor}", ln=True)
    pdf.cell(0, 8, f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", ln=True)
    pdf.ln(5)

    color_map = {"LOW": (0, 180, 0), "MEDIUM": (220, 180, 0), "HIGH": (220, 100, 0), "CRITICAL": (200, 0, 0)}
    r, g, b = color_map.get(result["label"], (100, 100, 100))
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(r, g, b)
    pdf.cell(0, 10, f"Risk Score: {result['score']}/100 - {result['label']} RISK", ln=True)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, f"CVEs Analyzed: {result['cve_count']}", ln=True)
    pdf.cell(0, 7, f"Actively Exploited (KEV): {result['kev_count']}", ln=True)
    pdf.ln(5)

    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 9, "CVE Analysis", ln=True)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(230, 230, 230)
    pdf.cell(35, 7, "CVE ID", border=1, fill=True)
    pdf.cell(18, 7, "CVSS", border=1, fill=True, align="C")
    pdf.cell(35, 7, "Category", border=1, fill=True)
    pdf.cell(15, 7, "KEV", border=1, fill=True, align="C")
    pdf.cell(0, 7, "Description", border=1, fill=True, ln=True)
    pdf.set_font("Helvetica", "", 8)

    for cve in result["cves"][:12]:
        score = str(cve.get("score") or "N/A")
        category = cve.get("attack_category", "other").replace("_", " ").title()
        kev = "YES" if cve.get("is_kev") else "no"
        desc = cve.get("description", "")[:70]
        desc = desc.encode("latin-1", errors="replace").decode("latin-1")
        pdf.cell(35, 6, cve["id"], border=1)
        pdf.cell(18, 6, score, border=1, align="C")
        pdf.cell(35, 6, category, border=1)
        pdf.cell(15, 6, kev, border=1, align="C")
        pdf.cell(0, 6, desc + "...", border=1, ln=True)

    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 9, "Risk Score Breakdown", ln=True)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(230, 230, 230)
    pdf.cell(45, 7, "CVE ID", border=1, fill=True)
    pdf.cell(40, 7, "Category", border=1, fill=True)
    pdf.cell(25, 7, "CVSS", border=1, fill=True, align="C")
    pdf.cell(20, 7, "KEV", border=1, fill=True, align="C")
    pdf.cell(0, 7, "Penalty", border=1, fill=True, align="C", ln=True)
    pdf.set_font("Helvetica", "", 8)

    for p in result["penalties"][:8]:
        category = p.get("category", "other").replace("_", " ").title()
        kev = "YES" if p.get("is_kev") else "no"
        pdf.cell(45, 6, p["cve_id"], border=1)
        pdf.cell(40, 6, category, border=1)
        pdf.cell(25, 6, str(p["cvss"]), border=1, align="C")
        pdf.cell(20, 6, kev, border=1, align="C")
        pdf.cell(0, 6, f"-{p['penalty']}", border=1, align="C", ln=True)

    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 9, "Risk Narrative", ln=True)
    pdf.set_font("Helvetica", "", 10)
    narrative = generate_narrative(result)
    clean_narrative = narrative.encode("latin-1", errors="replace").decode("latin-1")
    pdf.multi_cell(0, 6, clean_narrative)

    pdf.output(output_path)
    return output_path