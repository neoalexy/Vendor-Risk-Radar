from feeds.nvd import fetch_cves
from feeds.cisa import fetch_kev
from feeds.github_advisories import fetch_advisories
from core.mapper import map_attack_category
from core.scoring import calculate_risk_score
from storage.db import (
    init_db, upsert_vendor, save_cves,
    save_risk_score, get_previous_cves, get_score_history
)

def enrich_cves(cves: list[dict], kev_ids: set[str]) -> list[dict]:
    for cve in cves:
        cve["attack_category"] = map_attack_category(cve.get("description", ""))
        cve["is_kev"] = cve["id"] in kev_ids
    return cves

def analyze(vendor: str) -> dict:
    init_db()

    vendor_id = upsert_vendor(vendor)
    previous_cves = get_previous_cves(vendor_id)

    cves = fetch_cves(vendor)
    kev_matches, kev_ids = fetch_kev(vendor)
    gh_advisories = fetch_advisories(vendor)

    cves = enrich_cves(cves, kev_ids)

    new_cves = [c for c in cves if c["id"] not in previous_cves]

    save_cves(vendor_id, cves, kev_ids)

    scoring = calculate_risk_score(cves, kev_matches)

    save_risk_score(vendor_id, scoring["score"], scoring["cve_count"], scoring["kev_count"])

    history = get_score_history(vendor)

    return {
        "vendor": vendor,
        "score": scoring["score"],
        "label": scoring["label"],
        "cve_count": scoring["cve_count"],
        "kev_count": scoring["kev_count"],
        "cves": cves,
        "kev_matches": kev_matches,
        "gh_advisories": gh_advisories,
        "penalties": scoring["penalties"],
        "new_cves": new_cves,
        "history": history
    }

def compare(vendor1: str, vendor2: str) -> dict:
    result1 = analyze(vendor1)
    result2 = analyze(vendor2)
    return {
        "vendor1": result1,
        "vendor2": result2
    }