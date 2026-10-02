"""
log_parser.py — Reads log files and extracts structured data using regex.

Each log line follows the format:
    TIMESTAMP | IP_ADDRESS | EVENT | STATUS_CODE

Example:
    2026-10-02 10:15:22 | 192.168.1.20 | LOGIN_FAILED | 401
"""

import re
from utils.logger import get_logger

logger = get_logger(__name__)

# Regex pattern to match:  timestamp | ip | event | status_code
LOG_PATTERN = re.compile(
    r"^\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(\d+)\s*$"
)


def parse_log_line(line):
    """
    Parse a single log line into a structured dictionary.

    Args:
        line (str): A single line from the log file.

    Returns:
        dict or None: Parsed log entry with keys
            'timestamp', 'ip', 'event', 'status',
            or None if the line doesn't match the expected format.
    """
    match = LOG_PATTERN.match(line.strip())

    if match:
        return {
            "timestamp": match.group(1).strip(),
            "ip": match.group(2).strip(),
            "event": match.group(3).strip(),
            "status": int(match.group(4))
        }

    return None


def parse_log_file(filepath):
    """
    Parse an entire log file and return a list of structured log entries.

    Args:
        filepath (str): Path to the log file.

    Returns:
        list[dict]: List of parsed log entries (skips unparseable lines).
    """
    logs = []

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()

                if not line:
                    continue  # skip blank lines

                parsed = parse_log_line(line)

                if parsed:
                    logs.append(parsed)
                else:
                    logger.warning(
                        "Could not parse line %d: %s", line_no, line
                    )

    except FileNotFoundError:
        logger.error("Log file not found: %s", filepath)
    except Exception as e:
        logger.error("Error reading log file %s: %s", filepath, e)

    logger.info("Parsed %d log entries from %s", len(logs), filepath)
    return logs


def parse_log_text(text):
    """
    Parse log content provided as a raw string (e.g. from Streamlit upload).

    Args:
        text (str): Raw log content.

    Returns:
        list[dict]: List of parsed log entries.
    """
    logs = []

    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()

        if not line:
            continue

        parsed = parse_log_line(line)

        if parsed:
            logs.append(parsed)
        else:
            logger.warning("Could not parse uploaded line %d: %s", line_no, line)

    logger.info("Parsed %d log entries from uploaded text", len(logs))
    return logs
