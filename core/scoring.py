from datetime import datetime
from core.mapper import get_severity_weight, map_attack_category

def calculate_risk_score(cves: list[dict], kev_matches: list[dict]) -> dict:
    base_score = 100
    penalties = []
    
    kev_ids = set(k["cveID"] for k in kev_matches)
    
    for cve in cves:
        cvss = cve.get("score") or 0
        category = cve.get("attack_category") or map_attack_category(cve.get("description", ""))
        weight = get_severity_weight(category)
        published = cve.get("published", "")
        
        recency_multiplier = 1.0
        if published:
            try:
                pub_date = datetime.strptime(published[:10], "%Y-%m-%d")
                days_old = (datetime.utcnow() - pub_date).days
                if days_old < 90:
                    recency_multiplier = 1.5
                elif days_old < 365:
                    recency_multiplier = 1.2
                elif days_old > 1095:
                    recency_multiplier = 0.7
            except:
                pass
        
        if cve["id"] in kev_ids:
            penalty = cvss * weight * recency_multiplier * 2.5
        elif cvss >= 9.0:
            penalty = cvss * weight * recency_multiplier * 1.2
        elif cvss >= 7.0:
            penalty = cvss * weight * recency_multiplier * 0.8
        else:
            penalty = cvss * weight * recency_multiplier * 0.3
        
        penalties.append({
            "cve_id": cve["id"],
            "penalty": round(penalty, 2),
            "category": category,
            "cvss": cvss,
            "is_kev": cve["id"] in kev_ids
        })
    
    total_penalty = sum(p["penalty"] for p in penalties)
    final_score = max(0, min(100, round(base_score - total_penalty)))
    
    return {
        "score": final_score,
        "label": get_risk_label(final_score),
        "penalties": sorted(penalties, key=lambda x: x["penalty"], reverse=True),
        "kev_count": len(kev_matches),
        "cve_count": len(cves)
    }

def get_risk_label(score: int) -> str:
    if score >= 80:
        return "LOW"
    elif score >= 60:
        return "MEDIUM"
    elif score >= 40:
        return "HIGH"
    else:
        return "CRITICAL"