def calculate_threat_risk(severity, confidence, observation_frequency, source_reliability_weight):
    """
    Computes a risk score (0-100) using a multi-factor weighting formula.
    Weights: Severity (30%), Confidence (25%), Recency (15%), Frequency (10%), Reliability (10%), Context (10%).
    """
    sev_map = {"INFORMATIONAL": 10, "LOW": 30, "MEDIUM": 55, "HIGH": 80, "CRITICAL": 100}
    sev_score = sev_map.get(severity.upper(), 30)
    
    freq_score = min(100, observation_frequency * 5)
    
    risk = (
        (sev_score * 0.30) +
        (confidence * 0.25) +
        (50 * 0.15) + # Recency placeholder
        (freq_score * 0.10) +
        (source_reliability_weight * 0.10) +
        (50 * 0.10) # Context placeholder
    )
    
    return int(min(100, max(0, risk)))

def classify_risk_tier(score):
    if score <= 20: return "INFORMATIONAL"
    elif score <= 40: return "LOW"
    elif score <= 60: return "MEDIUM"
    elif score <= 80: return "HIGH"
    return "CRITICAL"
