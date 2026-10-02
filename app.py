"""
app.py — CyberShield Vercel & Production Web Application

Exports top-level `app` (Flask WSGI application) for Vercel Serverless Functions.
Supports:
    - Web Dashboard (UI)
    - /api/analyze (Log parser, threat detection, risk classification)
    - /api/sample (Preloaded sample log entries)
    - /api/health (Health check)
"""

import os
import sys
import json
from flask import Flask, request, jsonify, send_from_directory

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from analyzer.log_parser import parse_log_text, parse_log_file
from analyzer.threat_detector import detect_all_threats
from analyzer.risk_analyzer import enrich_threats_with_risk
from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Initialize Flask Application (Exported as top-level 'app' for Vercel)
# ---------------------------------------------------------------------------
public_dir = os.path.join(PROJECT_ROOT, "public")
app = Flask(__name__, static_folder=public_dir, static_url_path="")
application = app  # Alternative WSGI export
handler = app      # Alternative Serverless handler export


@app.route("/")
def index():
    """Serve the CyberShield Web Dashboard."""
    index_file = os.path.join(public_dir, "index.html")
    if os.path.exists(index_file):
        return send_from_directory(public_dir, "index.html")
    return jsonify({
        "status": "CyberShield API Online",
        "version": "1.0.0",
        "endpoints": ["/api/analyze", "/api/sample", "/api/health"]
    })


@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "CyberShield Cybersecurity Threat Detector",
        "version": "1.0.0"
    })


@app.route("/api/sample", methods=["GET"])
def get_sample_logs():
    """Return the raw sample log file content."""
    sample_path = os.path.join(PROJECT_ROOT, "data", "sample_server.log")
    if os.path.exists(sample_path):
        with open(sample_path, "r", encoding="utf-8") as f:
            content = f.read()
        return jsonify({"success": True, "log_content": content})
    return jsonify({"success": False, "error": "Sample log not found"}), 404


@app.route("/api/analyze", methods=["POST"])
def analyze_logs():
    """
    Parse uploaded/raw log content, run threat detection, and return risk analysis.
    Accepts JSON payload: { "log_text": "..." } or multipart form file.
    """
    raw_text = ""

    # Check if a file was uploaded
    if "file" in request.files:
        uploaded = request.files["file"]
        raw_text = uploaded.read().decode("utf-8", errors="replace")
    elif request.is_json:
        data = request.get_json(silent=True) or {}
        raw_text = data.get("log_text", "")
    else:
        raw_text = request.get_data(as_text=True)

    if not raw_text.strip():
        # Fall back to sample log if empty
        sample_path = os.path.join(PROJECT_ROOT, "data", "sample_server.log")
        if os.path.exists(sample_path):
            with open(sample_path, "r", encoding="utf-8") as f:
                raw_text = f.read()

    # Step 1: Parse logs
    parsed_logs = parse_log_text(raw_text)

    # Step 2: Detect threats
    threats = detect_all_threats(parsed_logs)

    # Step 3: Enrich with risk
    threats = enrich_threats_with_risk(threats)

    # Step 4: Compute aggregated metrics for dashboard & charts
    total_logs = len(parsed_logs)
    failed_logins = sum(1 for entry in parsed_logs if entry.get("event") == "LOGIN_FAILED")
    suspicious_ips = sorted(list({t["ip"] for t in threats}))
    total_threats = len(threats)

    # Risk level counts
    risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    threat_types = {}
    event_counts = {}

    for entry in parsed_logs:
        evt = entry.get("event", "UNKNOWN")
        event_counts[evt] = event_counts.get(evt, 0) + 1

    for t in threats:
        risk = t.get("risk", "LOW")
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

        threat_name = t.get("threat", "Unknown Threat")
        threat_types[threat_name] = threat_types.get(threat_name, 0) + 1

    return jsonify({
        "success": True,
        "metrics": {
            "total_logs": total_logs,
            "failed_logins": failed_logins,
            "suspicious_ips_count": len(suspicious_ips),
            "total_threats": total_threats,
            "risk_counts": risk_counts,
            "threat_types": threat_types,
            "event_counts": event_counts,
        },
        "threats": threats,
        "logs": parsed_logs,
    })


if __name__ == "__main__":
    # Local development server
    port = int(os.environ.get("PORT", 5000))
    print(f"🛡️ CyberShield Web Server running on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
