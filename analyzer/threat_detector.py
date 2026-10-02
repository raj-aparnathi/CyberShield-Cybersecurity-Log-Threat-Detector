"""
threat_detector.py — Detects suspicious patterns in parsed log data.

Implements two detection strategies:
    1. Brute Force Detection  — flags IPs with ≥ 5 LOGIN_FAILED events
    2. Suspicious Request Detection — flags IPs with repeated 403/404 or
       known suspicious event types (UNAUTHORIZED_ACCESS, FORBIDDEN_REQUEST)
"""

from collections import Counter
from utils.logger import get_logger

logger = get_logger(__name__)

# Events considered suspicious regardless of status code
SUSPICIOUS_EVENTS = {
    "UNAUTHORIZED_ACCESS",
    "FORBIDDEN_REQUEST",
    "LOGIN_FAILED",
}

# Status codes that indicate denied / suspicious activity
SUSPICIOUS_STATUS_CODES = {403, 404}

# Thresholds
BRUTE_FORCE_THRESHOLD = 5
SUSPICIOUS_REQUEST_THRESHOLD = 3


def detect_bruteforce(logs, threshold=BRUTE_FORCE_THRESHOLD):
    """
    Detect possible brute-force attacks by counting LOGIN_FAILED
    events per IP address.

    Args:
        logs (list[dict]): Parsed log entries.
        threshold (int): Minimum failed attempts to flag an IP.

    Returns:
        list[dict]: Detected brute-force threats, each containing
            'ip', 'threat', 'count', 'events' (sample timestamps).
    """
    failed_attempts = [
        log for log in logs
        if log["event"] == "LOGIN_FAILED"
    ]

    ip_counts = Counter(log["ip"] for log in failed_attempts)

    threats = []

    for ip, count in ip_counts.items():
        if count >= threshold:
            # Collect timestamps for this IP's failed logins
            timestamps = [
                log["timestamp"] for log in failed_attempts
                if log["ip"] == ip
            ]

            threats.append({
                "ip": ip,
                "threat": "Brute Force",
                "count": count,
                "events": timestamps,
            })

            logger.warning(
                "🔴 BRUTE FORCE — IP: %s | Failed attempts: %d", ip, count
            )

    return threats


def detect_suspicious_requests(logs, threshold=SUSPICIOUS_REQUEST_THRESHOLD):
    """
    Detect suspicious request patterns — IPs that repeatedly trigger
    403/404 status codes or known suspicious event types.

    Args:
        logs (list[dict]): Parsed log entries.
        threshold (int): Minimum occurrences to flag.

    Returns:
        list[dict]: Detected suspicious-request threats.
    """
    # Filter for suspicious activity (exclude LOGIN_FAILED — handled by brute-force)
    suspicious_logs = [
        log for log in logs
        if (
            log["event"] in SUSPICIOUS_EVENTS and log["event"] != "LOGIN_FAILED"
        ) or (
            log["status"] in SUSPICIOUS_STATUS_CODES
            and log["event"] not in ("LOGIN_FAILED",)
        )
    ]

    # Group by (ip, event)
    ip_event_counts = Counter(
        (log["ip"], log["event"]) for log in suspicious_logs
    )

    threats = []

    for (ip, event), count in ip_event_counts.items():
        if count >= threshold:
            timestamps = [
                log["timestamp"] for log in suspicious_logs
                if log["ip"] == ip and log["event"] == event
            ]

            threats.append({
                "ip": ip,
                "threat": "Suspicious Request",
                "event": event,
                "count": count,
                "events": timestamps,
            })

            logger.warning(
                "🟡 SUSPICIOUS — IP: %s | Event: %s | Count: %d",
                ip, event, count
            )

    return threats


def detect_all_threats(logs):
    """
    Run all detection strategies and return a unified list of threats.

    Args:
        logs (list[dict]): Parsed log entries.

    Returns:
        list[dict]: Combined list of all detected threats.
    """
    brute = detect_bruteforce(logs)
    suspicious = detect_suspicious_requests(logs)

    all_threats = brute + suspicious

    logger.info(
        "Detection complete — %d brute-force, %d suspicious, %d total",
        len(brute), len(suspicious), len(all_threats)
    )

    return all_threats
