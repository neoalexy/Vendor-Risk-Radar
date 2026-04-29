import re
import requests
from time import sleep

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_cves(vendor: str) -> list[dict]:
    params = {
        "keywordSearch": vendor,
        "resultsPerPage": 20
    }
    
    try:
        response = requests.get(NVD_BASE, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"[NVD] Error fetching data: {e}")
        return []

    cves = data.get("vulnerabilities", [])
    results = []

    for item in cves:
        cve = item.get("cve", {})
        description = cve.get("descriptions", [{}])[0].get("value", "").lower()

        if not re.search(r'\b' + re.escape(vendor.lower()) + r'\b', description):
            continue

        cve_id = cve.get("id", "N/A")
        metrics = cve.get("metrics", {})
        cvss_score = None

        if "cvssMetricV31" in metrics:
            cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        published = cve.get("published", "")[:10]

        results.append({
            "id": cve_id,
            "description": description,
            "score": cvss_score,
            "published": published
        })

    return results[:15]