import csv
import os
import random
import hashlib
from datetime import datetime, timedelta

# Ensure directories exist
os.makedirs("data", exist_ok=True)

CATEGORIES = [
    "PHISHING", "MALWARE", "RANSOMWARE", "CREDENTIAL THREATS",
    "WEB THREATS", "NETWORK THREATS", "VULNERABILITY EXPOSURE",
    "SOCIAL ENGINEERING", "DATA EXPOSURE", "ACCOUNT SECURITY"
]

INDICATOR_TYPES = ["IP ADDRESS", "DOMAIN", "URL", "FILE HASH", "EMAIL/SENDER DOMAIN", "CVE ID"]

SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

STATUSES = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]

SOURCES = [
    ("Internal SOC", "A"),
    ("Security Vendor Feed", "A"),
    ("Public Threat Feed", "B"),
    ("Research Report", "B"),
    ("Community Submission", "C"),
    ("Unknown Source", "D")
]

MITRE_MAPPINGS = {
    "PHISHING": ("Initial Access", "T1566 - Phishing", "T1566.001"),
    "MALWARE": ("Execution", "T1204 - User Execution", "T1204.002"),
    "RANSOMWARE": ("Impact", "T1486 - Data Encrypted for Impact", "T1486"),
    "CREDENTIAL THREATS": ("Credential Access", "T1110 - Brute Force", "T1110"),
    "WEB THREATS": ("Initial Access", "T1190 - Exploit Public-Facing Application", "T1190"),
    "NETWORK THREATS": ("Command and Control", "T1071 - Application Layer Protocol", "T1071"),
    "VULNERABILITY EXPOSURE": ("Initial Access", "T1190 - Exploit Public-Facing Application", "T1190"),
    "SOCIAL ENGINEERING": ("Initial Access", "T1566 - Phishing", "T1566"),
    "DATA EXPOSURE": ("Exfiltration", "T1041 - Exfiltration Over C2 Channel", "T1041"),
    "ACCOUNT SECURITY": ("Persistence", "T1098 - Account Manipulation", "T1098")
}

def generate_indicator(ind_type):
    if ind_type == "IP ADDRESS":
        subnets = ["192.0.2.", "198.51.100.", "203.0.113."]
        return f"{random.choice(subnets)}{random.randint(1, 254)}"
    elif ind_type == "DOMAIN":
        domains = ["login-verify.invalid", "secure-auth.invalid", "update-checker.invalid", "cloud-sync.invalid", "api-gateway.invalid"]
        return f"{random.randint(100, 999)}.{random.choice(domains)}"
    elif ind_type == "URL":
        return f"https://example.invalid/auth/login?token={random.randint(10000, 99999)}"
    elif ind_type == "FILE HASH":
        rand_bytes = str(random.randint(0, 1000000)).encode()
        return hashlib.sha256(rand_bytes).hexdigest()
    elif ind_type == "EMAIL/SENDER DOMAIN":
        senders = ["support-secure.invalid", "hr-notification.invalid", "billing-portal.invalid", "it-helpdesk.invalid"]
        return random.choice(senders)
    elif ind_type == "CVE ID":
        return f"CVE-2026-{random.randint(1000, 9999)}"
    return "unknown.invalid"

def generate_dataset(num_records=2500):
    filepath = "data/threat_intelligence_dataset.csv"
    headers = [
        "threat_id", "timestamp", "threat_name", "threat_category",
        "indicator_type", "indicator_value", "source_name", "source_reliability",
        "confidence_score", "severity", "risk_score", "status",
        "first_seen", "last_seen", "country_or_region_optional",
        "description", "mitre_tactic", "mitre_technique", "cve_id_optional"
    ]
    
    start_date = datetime.now() - timedelta(days=90)
    
    with open(filepath, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        for i in range(1, num_records + 1):
            threat_id = f"THR-2026-{i:04d}"
            cat = random.choice(CATEGORIES)
            ind_type = random.choice(INDICATOR_TYPES)
            ind_val = generate_indicator(ind_type)
            source, reliability = random.choice(SOURCES)
            
            conf = random.randint(30, 100)
            sev = random.choice(SEVERITIES)
            
            # Weighted risk scoring simulation
            sev_weight = {"INFORMATIONAL": 10, "LOW": 30, "MEDIUM": 55, "HIGH": 80, "CRITICAL": 98}[sev]
            risk_score = int((sev_weight * 0.4) + (conf * 0.4) + (random.randint(0, 20) * 0.2))
            risk_score = min(100, max(1, risk_score))
            
            status = random.choice(STATUSES)
            
            first_delta = random.randint(1, 90)
            last_delta = random.randint(0, first_delta)
            first_seen = (start_date + timedelta(days=first_delta)).strftime("%Y-%m-%d %H:%M:%S")
            last_seen = (start_date + timedelta(days=first_delta + last_delta)).strftime("%Y-%m-%d %H:%M:%S")
            
            country = random.choice(["US", "DE", "GB", "CA", "FR", "JP", "SYNTHETIC_NET"])
            desc = f"Synthetic defensive indicator record representing observed telemetry for {cat.lower()}"
            
            tactic, technique, _ = MITRE_MAPPINGS.get(cat, ("Initial Access", "T1566 - Phishing", "T1566"))
            cve = ind_val if ind_type == "CVE ID" else (f"CVE-2026-{random.randint(1000, 9999)}" if cat == "VULNERABILITY EXPOSURE" else "")
            
            writer.writerow([
                threat_id, first_seen, f"Synthetic {cat.title()} Vector #{i}", cat,
                ind_type, ind_val, source, reliability, conf, sev, risk_score, status,
                first_seen, last_seen, country, desc, tactic, technique, cve
            ])
            
    print(f"[+] Successfully generated {num_records} synthetic threat records at {filepath}")

if __name__ == "__main__":
    generate_dataset()
