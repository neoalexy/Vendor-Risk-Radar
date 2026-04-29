import requests

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def fetch_kev(vendor: str) -> tuple[list[dict], set[str]]:
    try:
        response = requests.get(CISA_KEV_URL, timeout=15)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"[CISA] Error fetching KEV feed: {e}")
        return [], set()

    vulns = data.get("vulnerabilities", [])
    matches = [
        v for v in vulns
        if vendor.lower() in v.get("vendorProject", "").lower()
    ]
    kev_ids = set(v["cveID"] for v in matches)

    return matches, kev_ids