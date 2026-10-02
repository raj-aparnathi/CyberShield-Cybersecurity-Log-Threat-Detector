"""
app.py — CyberShield Vercel & Production Web Application

Exports top-level `app`, `application`, and `handler` for Vercel Serverless Functions.
Supports:
    - Web Dashboard (UI) served from /public
    - /api/analyze (Log parser, threat detection, risk classification)
    - /api/sample (Built-in sample log data for demonstration)
    - /api/health (Service health check)
"""

import os
import sys
from flask import Flask, jsonify, request, send_from_directory

# Ensure project root is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from analyzer.log_parser import parse_log_text, parse_log_stream
from analyzer.threat_detector import detect_all_threats
from analyzer.risk_analyzer import enrich_threats_with_risk

# Determine public directory path
public_dir = os.path.join(BASE_DIR, "public")

app = Flask(
    __name__,
    static_folder=public_dir if os.path.exists(public_dir) else None,
    static_url_path=""
)

# Export top-level references for Vercel Python runtime
application = app
handler = app

# Support upload file limit up to 500 MB
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024

# Limits for response payload to prevent browser freezing & Vercel timeouts
MAX_LOG_ENTRIES_IN_RESPONSE = 500
MAX_TIMESTAMPS_PER_THREAT = 10


@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        "success": False,
        "error": "File size exceeds the 500MB limit. Please upload a log file 500MB or below."
    }), 413


@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({
        "success": False,
        "error": f"Internal server error: {str(error)}"
    }), 500


@app.route("/")
@app.route("/index.html")
def index():
    """Serve the single-page CyberShield dashboard."""
    if os.path.exists(os.path.join(public_dir, "index.html")):
        return send_from_directory(public_dir, "index.html")
    return jsonify({
        "status": "CyberShield API Online",
        "version": "2.0.0",
        "endpoints": ["/api/analyze", "/api/sample", "/api/health"]
    })


@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint for Vercel / uptime monitors."""
    return jsonify({
        "status": "healthy",
        "service": "CyberShield Cybersecurity Threat Detector",
        "version": "2.0.0"
    })


@app.route("/api/sample", methods=["GET"])
def get_sample_logs():
    """Return bundled sample log text for instant demo / testing."""
    sample_path = os.path.join(BASE_DIR, "data", "sample_server.log")
    if os.path.exists(sample_path):
        with open(sample_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return jsonify({"success": True, "log_content": content, "filename": "sample_server.log"})

    return jsonify({"success": False, "error": "Sample log file not found."}), 404


@app.route("/api/analyze", methods=["POST"])
def analyze_logs():
    """
    Parse uploaded or raw log content, run threat detection, and return risk analysis.

    Accepts:
      - Multipart file upload (field name: 'file')
      - Form-data field: 'log_text'
      - JSON body: { "log_text": "..." }
      - Raw text body
    """
    parsed_logs = None

    # 1. Check for multipart file upload (stream line-by-line for files up to 500MB)
    if "file" in request.files:
        uploaded = request.files["file"]
        if uploaded and uploaded.filename:
            parsed_logs = parse_log_stream(uploaded.stream)

    # 2. Check for form field, JSON payload, or raw body text
    if parsed_logs is None:
        raw_text = ""
        if "log_text" in request.form:
            raw_text = request.form.get("log_text", "")
        elif request.is_json:
            data = request.get_json(silent=True) or {}
            raw_text = data.get("log_text", "")
        elif request.data:
            try:
                raw_text = request.data.decode("utf-8", errors="replace")
            except Exception:
                raw_text = ""

        if not raw_text or not raw_text.strip():
            return jsonify({
                "success": False,
                "error": "No log content provided. Please upload a .log file or provide log text."
            }), 400

        # Parse raw text logs
        parsed_logs = parse_log_text(raw_text)

    # If no lines could be parsed, provide helpful diagnostic guidance
    if not parsed_logs:
        return jsonify({
            "success": True,
            "parse_error": True,
            "message": (
                "No valid log entries could be recognized. Each log entry must follow the format: "
                "TIMESTAMP | IP_ADDRESS | EVENT | STATUS_CODE. "
                "Example: 2026-10-02 10:15:22 | 192.168.1.20 | LOGIN_FAILED | 401"
            ),
            "metrics": {
                "total_logs": 0,
                "failed_logins": 0,
                "suspicious_ips_count": 0,
                "total_threats": 0,
                "risk_counts": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "threat_types": {},
                "event_counts": {},
            },
            "threats": [],
            "logs": [],
            "truncated": False
        })

    # Step 2: Detect threats
    threats = detect_all_threats(parsed_logs)

    # Step 3: Enrich with risk classification
    threats = enrich_threats_with_risk(threats)

    # Step 4: Compute aggregated metrics
    total_logs = len(parsed_logs)
    failed_logins = sum(1 for entry in parsed_logs if entry.get("event") == "LOGIN_FAILED")
    suspicious_ips = sorted(list({t["ip"] for t in threats if "ip" in t}))
    total_threats = len(threats)

    risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    threat_types = {}
    event_counts = {}

    for entry in parsed_logs:
        event = entry.get("event", "UNKNOWN")
        event_counts[event] = event_counts.get(event, 0) + 1

    for t in threats:
        risk = t.get("risk", "LOW")
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
        threat_name = t.get("threat", "Unknown Threat")
        threat_types[threat_name] = threat_types.get(threat_name, 0) + 1

    # Step 5: Trim response payload to prevent browser freezing & network timeouts
    trimmed_threats = []
    for t in threats:
        tt = dict(t)
        all_events = tt.get("events", [])
        tt["total_events"] = len(all_events)
        if len(all_events) > MAX_TIMESTAMPS_PER_THREAT:
            tt["events"] = all_events[:MAX_TIMESTAMPS_PER_THREAT]
            tt["events_truncated"] = True
        else:
            tt["events_truncated"] = False
        trimmed_threats.append(tt)

    truncated = False
    logs_response = parsed_logs
    if len(parsed_logs) > MAX_LOG_ENTRIES_IN_RESPONSE:
        truncated = True
        half = MAX_LOG_ENTRIES_IN_RESPONSE // 2
        logs_response = parsed_logs[:half] + parsed_logs[-half:]

    return jsonify({
        "success": True,
        "metrics": {
            "total_logs": total_logs,
            "failed_logins": failed_logins,
            "suspicious_ips": suspicious_ips,
            "suspicious_ips_count": len(suspicious_ips),
            "total_threats": total_threats,
            "risk_counts": risk_counts,
            "threat_types": threat_types,
            "event_counts": event_counts,
        },
        "threats": trimmed_threats,
        "logs": logs_response,
        "truncated": truncated,
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"CyberShield Web Dashboard starting on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
