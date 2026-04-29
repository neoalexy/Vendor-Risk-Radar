import requests
import os
from dotenv import load_dotenv

load_dotenv()

GITHUB_ADVISORY_URL = "https://api.github.com/graphql"

def fetch_advisories(vendor: str) -> list[dict]:
    token = os.getenv("GITHUB_TOKEN")
    
    query = """
    query($query: String!) {
        securityAdvisories(first: 20, query: $query) {
            nodes {
                ghsaId
                summary
                severity
                publishedAt
                cvss {
                    score
                }
                identifiers {
                    type
                    value
                }
            }
        }
    }
    """

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"bearer {token}" if token else ""
    }
    
    payload = {"query": query, "variables": {"query": vendor}}

    try:
        response = requests.post(GITHUB_ADVISORY_URL, json=payload, headers=headers, timeout=15)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"[GitHub] Error fetching advisories: {e}")
        return []

    nodes = data.get("data", {}).get("securityAdvisories", {}).get("nodes", [])
    results = []

    for node in nodes:
        cve_id = next(
            (i["value"] for i in node.get("identifiers", []) if i["type"] == "CVE"),
            node.get("ghsaId", "N/A")
        )
        results.append({
            "id": cve_id,
            "summary": node.get("summary", ""),
            "severity": node.get("severity", "UNKNOWN"),
            "cvss_score": node.get("cvss", {}).get("score"),
            "published": node.get("publishedAt", "")[:10]
        })

    return results