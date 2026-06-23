import re

PII_PATTERNS = {
    "credit_card":    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
    "ssn":            r"\b\d{3}-\d{2}-\d{4}\b",
    "email":          r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone_in":       r"\b[6-9]\d{9}\b",
    "aadhaar":        r"\b[2-9]{1}[0-9]{11}\b",
    "pan":            r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
    "api_key":        r"\b(sk-|pk_|rk_|AIza|ghp_)[A-Za-z0-9_\-]{20,}\b",
    "jwt_token":      r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",
}

def scan_for_pii(text: str) -> tuple[list[dict], str]:
    """
    Scan text for PII. 
    Returns: (list of findings, sanitized_text)
    """
    findings = []
    sanitized_text = text
    
    for pii_type, pattern in PII_PATTERNS.items():
        matches = re.finditer(pattern, sanitized_text)
        
        # We need to process from end to start to not mess up indices when replacing
        for match in reversed(list(matches)):
            start, end = match.span()
            matched_str = match.group(0)
            
            # Record finding
            findings.append({
                "type": pii_type,
                "position": (start, end),
                "redacted_value": f"[{pii_type.upper()}_REDACTED]"
            })
            
            # Redact in text
            sanitized_text = sanitized_text[:start] + f"[{pii_type.upper()}_REDACTED]" + sanitized_text[end:]
            
    return findings, sanitized_text
