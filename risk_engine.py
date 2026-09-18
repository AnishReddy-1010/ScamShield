import re


# ============================================================
# SCAMSHIELD V2 — RISK ENGINE
# ============================================================

def analyze_message(message, spam_probability):
    """
    Combines ML probability with rule-based scam indicators.

    Returns:
        risk_score
        risk_level
        scam_type
        indicators
        recommendation
    """

    text = message.lower()

    indicators = []
    score = 0

    # ========================================================
    # 1. URGENCY / PRESSURE
    # ========================================================

    urgency_patterns = [
        "urgent",
        "immediately",
        "immediate",
        "act now",
        "today",
        "within 24 hours",
        "last chance",
        "expires today",
        "do it now",
        "respond now",
        "verify now",
    ]

    urgency_hits = find_matches(text, urgency_patterns)

    if urgency_hits:
        score += 15
        indicators.append(
            "Urgent or pressure-based language detected"
        )

    # ========================================================
    # 2. ACCOUNT THREAT
    # ========================================================

    threat_patterns = [
        "account will be blocked",
        "account will be frozen",
        "account blocked",
        "account suspended",
        "account will be suspended",
        "account frozen",
        "services will be blocked",
        "prevent account closure",
        "account closure",
        "will be deactivated",
    ]

    threat_hits = find_matches(text, threat_patterns)

    if threat_hits:
        score += 20
        indicators.append(
            "Account suspension or blocking threat detected"
        )

    # ========================================================
    # 3. KYC / IDENTITY
    # ========================================================

    kyc_patterns = [
        "kyc",
        "aadhaar",
        "aadhar",
        "pan card",
        "pan details",
        "identity verification",
        "verify your identity",
        "identity proof",
    ]

    kyc_hits = find_matches(text, kyc_patterns)

    if kyc_hits:
        score += 15
        indicators.append(
            "KYC or identity verification request detected"
        )

    # ========================================================
    # 4. OTP / PIN / CREDENTIALS
    # ========================================================

    credential_patterns = [
        "otp",
        "one time password",
        "upi pin",
        "pin",
        "password",
        "login credentials",
        "bank details",
        "account details",
        "card details",
        "cvv",
    ]

    credential_hits = find_matches(text, credential_patterns)

    if credential_hits:
        score += 20
        indicators.append(
            "Sensitive credentials or financial information requested"
        )

    # ========================================================
    # 5. PAYMENT / MONEY REQUEST
    # ========================================================

    payment_patterns = [
        "pay",
        "payment",
        "processing fee",
        "registration fee",
        "security deposit",
        "deposit",
        "transfer money",
        "send money",
        "pay rs",
        "pay ₹",
        "clearance fee",
        "delivery charge",
        "service charge",
    ]

    payment_hits = find_matches(text, payment_patterns)

    if payment_hits:
        score += 15
        indicators.append(
            "Payment or money transfer request detected"
        )

    # ========================================================
    # 6. SUSPICIOUS URL
    # ========================================================

    url_pattern = r"(https?://|www\.)"

    if re.search(url_pattern, text):
        score += 20
        indicators.append(
            "Link detected in message"
        )

    # ========================================================
    # 7. LOTTERY / REWARD
    # ========================================================

    reward_patterns = [
    "lottery",
    "lucky draw",
    "cash prize",
    "prize money",
    "jackpot",
    "claim your prize",
    "claim your reward",
    "you have won",
    "you won",
    "selected as a winner",
]

    reward_hits = find_matches(text, reward_patterns)

    if reward_hits:
        score += 20
        indicators.append(
            "Unexpected prize or reward claim detected"
        )

    # ========================================================
    # 8. JOB SCAM
    # ========================================================

    job_patterns = [
        "work from home",
        "part time job",
        "earn money",
        "earn rs",
        "earn ₹",
        "daily income",
        "monthly income",
        "selected for a job",
        "job opportunity",
        "registration fee",
        "security deposit",
    ]

    job_hits = find_matches(text, job_patterns)

    if job_hits:
        score += 15
        indicators.append(
            "Potential suspicious job or income offer detected"
        )

    # ========================================================
    # 9. PARCEL / DELIVERY
    # ========================================================

    parcel_patterns = [
        "parcel",
        "package",
        "shipment",
        "delivery charge",
        "delivery fee",
        "customs",
        "customs fee",
        "clearance fee",
        "undelivered",
        "could not be delivered",
    ]

    parcel_hits = find_matches(text, parcel_patterns)

    if parcel_hits:
        score += 15
        indicators.append(
            "Parcel or delivery-related payment request detected"
        )

    # ========================================================
    # 10. UPI / PAYMENT APP
    # ========================================================

    upi_patterns = [
        "upi",
        "upi pin",
        "scan qr",
        "qr code",
        "payment request",
        "collect request",
        "cashback",
    ]

    upi_hits = find_matches(text, upi_patterns)

    if upi_hits:
        score += 15
        indicators.append(
            "UPI or digital payment activity detected"
        )

    # ========================================================
    # 11. INVESTMENT / GUARANTEED RETURNS
    # ========================================================

    investment_patterns = [
        "guaranteed return",
        "guaranteed profit",
        "guaranteed returns",
        "double your money",
        "300% profit",
        "high return",
        "quick profit",
        "investment opportunity",
        "trading platform",
    ]

    investment_hits = find_matches(text, investment_patterns)

    if investment_hits:
        score += 20
        indicators.append(
            "Potential unrealistic investment or profit claim detected"
        )

    # ========================================================
    # 12. THREAT / FEAR
    # ========================================================

    fear_patterns = [
        "arrest",
        "police",
        "legal action",
        "cyber crime",
        "criminal case",
        "illegal activity",
        "penalty",
        "fine",
        "avoid arrest",
    ]

    fear_hits = find_matches(text, fear_patterns)

    if fear_hits:
        score += 20
        indicators.append(
            "Threat or fear-based language detected"
        )

    # ========================================================
    # COMBINATION BONUSES
    # ========================================================

    # KYC + threat
    if kyc_hits and threat_hits:
        score += 15
        indicators.append(
            "KYC request combined with account threat"
        )

    # URL + urgency
    if re.search(url_pattern, text) and urgency_hits:
        score += 10
        indicators.append(
            "Urgency combined with a link"
        )

    # Payment + reward
    if payment_hits and reward_hits:
        score += 15
        indicators.append(
            "Payment requested to claim a reward"
        )

    # Credentials + UPI
    if credential_hits and upi_hits:
        score += 15
        indicators.append(
            "Sensitive payment credentials associated with UPI"
        )

    # Job + payment
    if job_hits and payment_hits:
        score += 15
        indicators.append(
            "Payment requested for a job opportunity"
        )

    # Parcel + payment
    if parcel_hits and payment_hits:
        score += 10
        indicators.append(
            "Delivery-related payment request detected"
        )

    # ========================================================
    # ML CONTRIBUTION
    # ========================================================

    ml_score = spam_probability * 40

    score += ml_score

    # Keep score between 0 and 100
    score = min(100, max(0, score))

    # ========================================================
    # DETERMINE SCAM TYPE
    # ========================================================

    scam_type = determine_scam_type(
        kyc_hits,
        reward_hits,
        parcel_hits,
        job_hits,
        upi_hits,
        investment_hits,
        credential_hits,
        threat_hits,
        text
    )

    # ========================================================
    # DETERMINE RISK LEVEL
    # ========================================================

    if score >= 70:
        risk_level = "HIGH RISK"

    elif score >= 40:
        risk_level = "SUSPICIOUS"

    else:
        risk_level = "LOW RISK"

    # ========================================================
    # SAFE MESSAGE HANDLING
    # ========================================================

    # If there are no meaningful scam indicators,
    # don't let the ML model alone make a normal
    # transaction notification look dangerous.

    if not indicators:
        risk_level = "LOW RISK"
        score = min(score, 20)

    recommendation = get_recommendation(risk_level)

    return {
        "risk_score": round(score, 2),
        "risk_level": risk_level,
        "scam_type": scam_type,
        "indicators": indicators,
        "recommendation": recommendation,
    }


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def find_matches(text, patterns):
    """
    Returns matching patterns found in the message.
    """

    matches = []

    for pattern in patterns:

        if pattern in text:
            matches.append(pattern)

    return matches


def determine_scam_type(
    kyc,
    reward,
    parcel,
    job,
    upi,
    investment,
    credentials,
    threat,
    text
):

    # Most specific scam patterns first

    if job:
        return "Job Scam"

    if kyc and threat:
        return "KYC / Banking Scam"

    if upi and credentials:
        return "UPI / Payment Scam"

    if parcel:
        return "Parcel / Delivery Scam"

    if investment:
        return "Investment Scam"

    if reward:
        return "Lottery / Prize Scam"

    if credentials and threat:
        return "Phishing / Credential Scam"

    if "http://" in text or "https://" in text:
        return "Potential Phishing"

    return "No specific scam type detected"


def get_recommendation(risk_level):

    if risk_level == "HIGH RISK":

        return (
            "Do not click links, send money, or share OTPs, "
            "PINs, passwords, or banking information. "
            "Verify the request through the organization's official app or website."
        )

    if risk_level == "SUSPICIOUS":

        return (
            "Be cautious. Do not share sensitive information "
            "or make payments until the message is independently verified."
        )

    return (
        "No strong scam indicators detected. "
        "Still verify unexpected requests before taking action."
    )