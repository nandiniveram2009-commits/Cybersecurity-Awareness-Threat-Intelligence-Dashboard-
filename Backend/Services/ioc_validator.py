import re

def validate_indicator(indicator_type, value):
    """
    Validates the syntactic correctness of an indicator.
    Validation strictly checks format, NOT maliciousness.
    """
    ipv4_regex = r"^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])$"
    ipv6_regex = r"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})$"
    domain_regex = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$"
    url_regex = r"^https?://[^\s/$.?#].[^\s]*$"
    md5_regex = r"^[a-fA-F0-9]{32}$"
    sha1_regex = r"^[a-fA-F0-9]{40}$"
    sha256_regex = r"^[a-fA-F0-9]{64}$"
    cve_regex = r"^CVE-\d{4}-\d{4,}$"
    
    val_clean = value.strip()
    is_valid = False
    norm_type = indicator_type.upper()
    notes = "Syntax verification passed."
    
    if norm_type == "IP ADDRESS":
        if re.match(ipv4_regex, val_clean) or re.match(ipv6_regex, val_clean):
            is_valid = True
        else:
            notes = "Invalid IPv4/IPv6 syntax."
    elif norm_type == "DOMAIN":
        if re.match(domain_regex, val_clean) or val_clean.endswith(".invalid"):
            is_valid = True
        else:
            notes = "Invalid domain syntax structure."
    elif norm_type == "URL":
        if re.match(url_regex, val_clean):
            is_valid = True
        else:
            notes = "Invalid URL schema format."
    elif norm_type == "FILE HASH":
        if re.match(md5_regex, val_clean) or re.match(sha1_regex, val_clean) or re.match(sha256_regex, val_clean):
            is_valid = True
        else:
            notes = "Invalid hash string length (MD5/SHA1/SHA256 expected)."
    elif norm_type == "CVE ID":
        if re.match(cve_regex, val_clean, re.IGNORECASE):
            is_valid = True
        else:
            notes = "Invalid CVE format (Expected CVE-YYYY-NNNN)."
    else:
        is_valid = True # Generic or email sender
        
    return {
        "valid": is_valid,
        "indicator_type": norm_type,
        "normalized_value": val_clean.lower(),
        "validation_notes": notes
    }
