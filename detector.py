from urllib.parse import urlparse, unquote
import ipaddress
import math
import re


# ============================================================
# CONFIGURATION
# ============================================================

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "password",
    "confirm",
    "bank",
    "billing",
    "payment",
    "wallet",
    "recover",
    "authenticate",
    "credential",
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "click",
    "top",
    "work",
    "support",
    "country",
    "gq",
    "tk",
    "ml",
    "ga",
    "cf",
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
    "rb.gy",
    "ow.ly",
}

SUSPICIOUS_PARAMETERS = {
    "password",
    "passwd",
    "pwd",
    "token",
    "auth",
    "session",
    "verify",
    "verification",
    "redirect",
    "url",
    "return",
    "next",
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def calculate_entropy(text):
    """Calculate Shannon entropy of a string."""

    if not text:
        return 0

    frequency = {}

    for character in text:
        frequency[character] = frequency.get(character, 0) + 1

    entropy = 0
    length = len(text)

    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def is_ip_address(hostname):
    """Return True if hostname is an IPv4 or IPv6 address."""

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


def get_tld(hostname):
    """Return the last domain component."""

    parts = hostname.split(".")

    if len(parts) >= 2:
        return parts[-1].lower()

    return ""


def calculate_digit_ratio(text):
    """Calculate the percentage of characters that are digits."""

    if not text:
        return 0

    digits = sum(character.isdigit() for character in text)

    return digits / len(text)


def calculate_hyphen_ratio(text):
    """Calculate the percentage of characters that are hyphens."""

    if not text:
        return 0

    hyphens = text.count("-")

    return hyphens / len(text)


def extract_suspicious_keywords(url):
    """Find suspicious keywords present in the URL."""

    url_lower = url.lower()

    found = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url_lower:
            found.append(keyword)

    return sorted(set(found))


def extract_suspicious_parameters(query):
    """Find suspicious parameter names in the query string."""

    if not query:
        return []

    found = []

    parameters = query.split("&")

    for parameter in parameters:

        parameter_name = parameter.split("=")[0].lower()

        if parameter_name in SUSPICIOUS_PARAMETERS:
            found.append(parameter_name)

    return sorted(set(found))


# ============================================================
# MAIN URL ANALYZER
# ============================================================

def analyze_url(user_url):

    score = 0
    findings = []

    # --------------------------------------------------------
    # Normalize input
    # --------------------------------------------------------

    url = user_url.strip()

    if not url:
        return 100, [], "HIGH", None

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # --------------------------------------------------------
    # Parse URL
    # --------------------------------------------------------

    try:
        parsed = urlparse(url)

    except ValueError:

        return 100, [
            {
                "severity": "HIGH",
                "score": 100,
                "message": "URL could not be parsed"
            }
        ], "HIGH", None

    hostname = parsed.hostname

    if not hostname:

        return 100, [
            {
                "severity": "HIGH",
                "score": 100,
                "message": "Missing or invalid hostname"
            }
        ], "HIGH", parsed

    hostname = hostname.lower()

    # ========================================================
    # FEATURE 1 — HTTPS
    # ========================================================

    if parsed.scheme != "https":

        score += 10

        findings.append({
            "severity": "MEDIUM",
            "score": 10,
            "message": "URL is not using HTTPS"
        })

    # ========================================================
    # FEATURE 2 — IP ADDRESS
    # ========================================================

    if is_ip_address(hostname):

        score += 30

        findings.append({
            "severity": "HIGH",
            "score": 30,
            "message": "Hostname is an IP address instead of a domain"
        })

    # ========================================================
    # FEATURE 3 — @ SYMBOL
    # ========================================================

    if "@" in url:

        score += 25

        findings.append({
            "severity": "HIGH",
            "score": 25,
            "message": "URL contains '@' which can be used for URL obfuscation"
        })

    # ========================================================
    # FEATURE 4 — URL LENGTH
    # ========================================================

    if len(url) > 100:

        score += 10

        findings.append({
            "severity": "MEDIUM",
            "score": 10,
            "message": f"URL is unusually long ({len(url)} characters)"
        })

    # ========================================================
    # FEATURE 5 — HOSTNAME LENGTH
    # ========================================================

    if len(hostname) > 50:

        score += 10

        findings.append({
            "severity": "MEDIUM",
            "score": 10,
            "message": f"Hostname is unusually long ({len(hostname)} characters)"
        })

    # ========================================================
    # FEATURE 6 — MANY SUBDOMAINS
    # ========================================================

    domain_parts = hostname.split(".")

    if not is_ip_address(hostname) and len(domain_parts) >= 4:
        score += 10

        findings.append({
            "severity": "MEDIUM",
            "score": 10,
            "message": f"Hostname contains many domain components ({len(domain_parts)})"
    })

    # ========================================================
    # FEATURE 7 — SUSPICIOUS KEYWORDS
    # ========================================================

    suspicious_keywords = extract_suspicious_keywords(url)

    for keyword in suspicious_keywords:

        score += 5

        findings.append({
            "severity": "LOW",
            "score": 5,
            "message": f"Suspicious keyword detected: '{keyword}'"
        })

    # ========================================================
    # FEATURE 8 — PUNYCODE
    # ========================================================

    if "xn--" in hostname:

        score += 15

        findings.append({
            "severity": "HIGH",
            "score": 15,
            "message": "Hostname contains Punycode"
        })

    # ========================================================
    # FEATURE 9 — MANY HYPHENS
    # ========================================================

    if hostname.count("-") >= 3:

        score += 10

        findings.append({
            "severity": "MEDIUM",
            "score": 10,
            "message": "Hostname contains many hyphens"
        })

    # ========================================================
    # FEATURE 10 — DIGIT RATIO
    # ========================================================

    digit_ratio = calculate_digit_ratio(hostname)

    if not is_ip_address(hostname) and digit_ratio > 0.30:

        score += 10

        findings.append({
            "severity": "MEDIUM",
            "score": 10,
            "message": f"Hostname contains a high percentage of digits ({digit_ratio:.0%})"
        })

    # ========================================================
    # FEATURE 11 — HYPHEN RATIO
    # ========================================================

    hyphen_ratio = calculate_hyphen_ratio(hostname)

    if hyphen_ratio > 0.15:

        score += 5

        findings.append({
            "severity": "LOW",
            "score": 5,
            "message": f"Hostname has a high hyphen ratio ({hyphen_ratio:.0%})"
        })

    # ========================================================
    # FEATURE 12 — SUSPICIOUS TLD
    # ========================================================

    tld = get_tld(hostname)

    if tld in SUSPICIOUS_TLDS:

        score += 10

        findings.append({
            "severity": "MEDIUM",
            "score": 10,
            "message": f"Domain uses a TLD commonly associated with suspicious URLs: '.{tld}'"
        })

    # ========================================================
    # FEATURE 13 — URL SHORTENER
    # ========================================================

    if hostname in SHORTENER_DOMAINS:

        score += 15

        findings.append({
            "severity": "MEDIUM",
            "score": 15,
            "message": "URL uses a known URL-shortening service"
        })

    # ========================================================
    # FEATURE 14 — PERCENT ENCODING
    # ========================================================

    encoded_values = re.findall(r"%[0-9a-fA-F]{2}", url)

    if encoded_values:

        score += 10

        findings.append({
            "severity": "MEDIUM",
            "score": 10,
            "message": f"URL contains percent-encoded characters ({len(encoded_values)} found)"
        })

    # ========================================================
    # FEATURE 15 — DOUBLE SLASH
    # ========================================================

    after_scheme = re.sub(r"^https?://", "", url)

    if "//" in after_scheme:

        score += 10

        findings.append({
            "severity": "MEDIUM",
            "score": 10,
            "message": "URL contains an additional '//' after the protocol"
        })

    # ========================================================
    # FEATURE 16 — UNUSUAL PORT
    # ========================================================

    try:

        port = parsed.port

        if port is not None and port not in (80, 443):

            score += 10

            findings.append({
                "severity": "MEDIUM",
                "score": 10,
                "message": f"URL uses a non-standard port: {port}"
            })

    except ValueError:

        score += 15

        findings.append({
            "severity": "HIGH",
            "score": 15,
            "message": "URL contains an invalid port number"
        })

    # ========================================================
    # FEATURE 17 — SUSPICIOUS QUERY PARAMETERS
    # ========================================================

    suspicious_parameters = extract_suspicious_parameters(
        parsed.query
    )

    for parameter in suspicious_parameters:

        score += 5

        findings.append({
            "severity": "LOW",
            "score": 5,
            "message": f"Suspicious query parameter detected: '{parameter}'"
        })

    # ========================================================
    # FEATURE 18 — URL ENTROPY
    # ========================================================

    hostname_entropy = calculate_entropy(hostname)

    if len(hostname) >= 15 and hostname_entropy > 3.8:

        score += 10

        findings.append({
            "severity": "MEDIUM",
            "score": 10,
            "message": f"Hostname has relatively high character entropy ({hostname_entropy:.2f})"
        })

    # ========================================================
    # FEATURE 19 — DECODED URL ANALYSIS
    # ========================================================

    decoded_url = unquote(url)

    if decoded_url.lower() != url.lower():

        decoded_keywords = extract_suspicious_keywords(decoded_url)

        new_keywords = [
            keyword
            for keyword in decoded_keywords
            if keyword not in suspicious_keywords
        ]

        if new_keywords:

            score += 10

            findings.append({
                "severity": "MEDIUM",
                "score": 10,
                "message": "Decoded URL reveals additional suspicious keywords"
            })

    # ========================================================
    # FINAL SCORE
    # ========================================================

    score = min(score, 100)

    # ========================================================
    # RISK LEVEL
    # ========================================================

    if score >= 60:

        risk = "HIGH"

    elif score >= 30:

        risk = "MEDIUM"

    else:

        risk = "LOW"

    # ========================================================
    # FEATURE DATA FOR WEB DASHBOARD
    # ========================================================

    features = {
        "https": parsed.scheme == "https",

        "ip_address": is_ip_address(hostname),

        "url_length": len(url),

        "hostname_length": len(hostname),

        "domain_components": len(domain_parts),

        "suspicious_keywords": suspicious_keywords,

        "punycode": "xn--" in hostname,

        "hyphens": hostname.count("-"),

        "digit_ratio": digit_ratio,

        "hyphen_ratio": hyphen_ratio,

        "tld": tld,

        "url_shortener": hostname in SHORTENER_DOMAINS,

        "percent_encoding": bool(encoded_values),

        "double_slash": "//" in after_scheme,

        "port": parsed.port,

        "suspicious_parameters": suspicious_parameters,

        "entropy": hostname_entropy,

        "decoded_analysis": decoded_url.lower() != url.lower()
    }


    return score, findings, risk, parsed, features


# ============================================================
# DISPLAY RESULTS
# ============================================================

def display_results(score, findings, risk, parsed):

    print("\n" + "=" * 55)
    print("                 ANALYSIS RESULTS")
    print("=" * 55)

    print(f"\nRisk Score : {score}/100")
    print(f"Risk Level : {risk}")

    if parsed:

        print(f"\nProtocol   : {parsed.scheme}")
        print(f"Hostname   : {parsed.hostname}")

        if parsed.port:

            print(f"Port       : {parsed.port}")

        print(f"Path       : {parsed.path or '/'}")

    print("\n" + "-" * 55)

    if findings:

        print("SECURITY FINDINGS")
        print("-" * 55)

        for finding in findings:

            print(
                f"[{finding['severity']}] "
                f"+{finding['score']}  "
                f"{finding['message']}"
            )

    else:

        print("No suspicious indicators detected.")

    print("\n" + "-" * 55)
    print("VERDICT")
    print("-" * 55)

    if risk == "HIGH":

        print("⚠ POTENTIAL PHISHING")

    elif risk == "MEDIUM":

        print("⚠ SUSPICIOUS URL")

    else:

        print("✓ LOW RISK")

    print("\nImportant:")
    print(
        "This detector uses static heuristics. "
        "A LOW result does not guarantee that a URL is safe."
    )

    print("=" * 55)


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

def main():

    print("=" * 55)
    print("              PHISHING URL DETECTOR v1.1")
    print("=" * 55)

    print("\nThis tool performs static URL analysis.")
    print("It does NOT visit or interact with the website.")

    url = input("\nEnter URL: ").strip()

    if not url:

        print("\nNo URL entered.")
        return

    print("\nAnalyzing...")

    score, findings, risk, parsed = analyze_url(url)

    display_results(
        score,
        findings,
        risk,
        parsed
    )


if __name__ == "__main__":

    main()