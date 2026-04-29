ATTACK_PATTERNS = {
    "auth_bypass": [
        "authentication bypass", "auth bypass", "improper authentication",
        "missing authentication", "weak authentication", "session fixation",
        "broken auth", "oauth", "saml", "sso", "token"
    ],
    "privilege_escalation": [
        "privilege escalation", "improper authorization", "missing permission",
        "access control", "rbac", "elevation of privilege", "sudo",
        "root access", "admin access"
    ],
    "data_exposure": [
        "information disclosure", "sensitive data", "data exposure",
        "cleartext", "plaintext", "unencrypted", "pii", "credentials exposed",
        "api key", "secret", "leak"
    ],
    "injection": [
        "sql injection", "command injection", "code injection",
        "xss", "cross-site scripting", "xxe", "xml external",
        "ldap injection", "template injection", "ssti"
    ],
    "rce": [
        "remote code execution", "arbitrary code", "rce",
        "execute commands", "code execution"
    ],
    "misconfig": [
        "misconfiguration", "default credentials", "open redirect",
        "csrf", "cross-site request forgery", "security misconfiguration",
        "exposed endpoint", "directory traversal", "path traversal"
    ],
    "supply_chain": [
        "dependency", "third-party", "supply chain", "package",
        "npm", "pypi", "open source", "upstream"
    ]
}

SEVERITY_WEIGHTS = {
    "rce": 1.8,
    "auth_bypass": 1.6,
    "privilege_escalation": 1.5,
    "data_exposure": 1.4,
    "injection": 1.3,
    "supply_chain": 1.2,
    "misconfig": 1.0
}

def map_attack_category(description: str) -> str:
    desc = description.lower()
    for category, keywords in ATTACK_PATTERNS.items():
        if any(kw in desc for kw in keywords):
            return category
    return "other"

def get_severity_weight(category: str) -> float:
    return SEVERITY_WEIGHTS.get(category, 1.0)