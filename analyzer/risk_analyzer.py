"""
risk_analyzer.py — Assigns LOW / MEDIUM / HIGH risk levels to detected threats.

Risk classification rules:
    count ≥ 5  → HIGH
    count 3–4  → MEDIUM
    count < 3  → LOW
"""

from utils.logger import get_logger

logger = get_logger(__name__)


def calculate_risk(count):
    """
    Determine risk level based on occurrence count.

    Args:
        count (int): Number of threat occurrences.

    Returns:
        str: Risk level — 'HIGH', 'MEDIUM', or 'LOW'.
    """
    if count >= 5:
        return "HIGH"
    elif count >= 3:
        return "MEDIUM"
    else:
        return "LOW"


def enrich_threats_with_risk(threats):
    """
    Add a 'risk' key to each threat dictionary based on its count.

    Args:
        threats (list[dict]): Detected threats (must have 'count' key).

    Returns:
        list[dict]: Same threats with an added 'risk' field.
    """
    for threat in threats:
        threat["risk"] = calculate_risk(threat["count"])

        logger.info(
            "Risk assigned — IP: %s | Threat: %s | Count: %d | Risk: %s",
            threat["ip"], threat["threat"], threat["count"], threat["risk"]
        )

    return threats
