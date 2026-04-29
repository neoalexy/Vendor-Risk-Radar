# Vendor Risk Radar

A CLI security intelligence tool that evaluates SaaS vendor risk by aggregating vulnerability data from multiple sources and applying a weighted scoring algorithm.

Built to answer a simple question: before your organization trusts a SaaS vendor with sensitive data, how do you actually measure their security track record?

## How it works

The tool pulls CVE data from NVD and checks each vulnerability against CISA's Known Exploited Vulnerabilities catalog. Each CVE gets mapped to an attack category (RCE, auth bypass, injection, privilege escalation, data exposure, misconfig, supply chain) and scored based on three factors:

- **CVSS base score** — severity of the vulnerability
- **Attack category weight** — RCE weighted at 1.8x, auth bypass at 1.6x, down to misconfig at 1.0x
- **Recency multiplier** — CVEs under 90 days old scored at 1.5x, over 3 years at 0.7x
- **KEV penalty** — actively exploited vulnerabilities apply a 2.5x multiplier

All scan results are stored in a local SQLite database. Running the tool twice on the same vendor shows exactly which CVEs are new since the last scan.

## Usage

```bash
# Analyze a single vendor
python vendor_risk_radar.py Okta

# Compare two vendors side by side
python vendor_risk_radar.py --compare Okta Slack

# Export full PDF report
python vendor_risk_radar.py --export Okta
```

## Output

Each scan produces:
- Risk score (0-100) with label: LOW / MEDIUM / HIGH / CRITICAL
- CVE table with attack category, CVSS score, and KEV status
- Risk score breakdown showing penalty per CVE
- New CVEs detected since last scan
- Score history across previous scans
- LLM-generated risk narrative with attack scenarios and recommendations
- PDF report export

## Setup

```bash
git clone https://github.com/neoalexy/vendor-risk-radar
cd vendor-risk-radar
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file:
GROQ_API_KEY=your_key
GITHUB_TOKEN=your_token  # optional, for GitHub Advisory feed


## Data sources

- [NVD](https://nvd.nist.gov/) — CVE database
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — actively exploited vulnerabilities
- [GitHub Security Advisories](https://github.com/advisories) — ecosystem advisories

## Stack

Python · SQLite · Groq (Llama 3.3 70B) · Rich · fpdf2
