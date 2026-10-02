"""
log_parser.py — Reads log files and extracts structured data using regex.

Standard format:
    TIMESTAMP | IP_ADDRESS | EVENT | STATUS_CODE

Example:
    2026-10-02 10:15:22 | 192.168.1.20 | LOGIN_FAILED | 401

Also supports fallback parsing for comma/semicolon/tab-separated logs.
"""

import re
from utils.logger import get_logger

logger = get_logger(__name__)

# Standard pipe pattern: timestamp | ip | event | status_code
PIPE_PATTERN = re.compile(
    r"^\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(\d+)\s*$"
)

# Common web/delimiter patterns (comma, tab, semicolon)
DELIM_PATTERN = re.compile(
    r"^\s*([0-9\-\:\. T]{10,25})\s*[,;\t]\s*([0-9a-fA-F\.\:]{7,45})\s*[,;\t]\s*([a-zA-Z0-9_\-\.]+)\s*[,;\t]\s*(\d{3,4})\s*$"
)


def parse_log_line(line):
    """
    Parse a single log line into a structured dictionary.

    Args:
        line (str): A single line from the log file.

    Returns:
        dict or None: Parsed log entry with keys:
            'timestamp', 'ip', 'event', 'status',
            or None if the line cannot be parsed.
    """
    if not line:
        return None

    line = line.strip()

    # 1. Standard pipe format
    match = PIPE_PATTERN.match(line)
    if match:
        return {
            "timestamp": match.group(1).strip(),
            "ip": match.group(2).strip(),
            "event": match.group(3).strip(),
            "status": int(match.group(4))
        }

    # 2. Delimiter regex (comma, semicolon, tab)
    match_delim = DELIM_PATTERN.match(line)
    if match_delim:
        return {
            "timestamp": match_delim.group(1).strip(),
            "ip": match_delim.group(2).strip(),
            "event": match_delim.group(3).strip(),
            "status": int(match_delim.group(4))
        }

    # 3. Fallback split for flexible delimiters
    for sep in ["|", ",", "\t", ";"]:
        if sep in line:
            parts = [p.strip().strip('"\'') for p in line.split(sep)]
            if len(parts) >= 4:
                status_digits = re.sub(r"[^\d]", "", parts[3])
                if status_digits:
                    return {
                        "timestamp": parts[0],
                        "ip": parts[1],
                        "event": parts[2],
                        "status": int(status_digits)
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
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                parsed = parse_log_line(line)
                if parsed:
                    logs.append(parsed)
                elif line.strip():
                    logger.debug("Could not parse line %d: %s", line_no, line.strip())

    except FileNotFoundError:
        logger.error("Log file not found: %s", filepath)
    except Exception as e:
        logger.error("Error reading log file %s: %s", filepath, e)

    logger.info("Parsed %d log entries from %s", len(logs), filepath)
    return logs


def parse_log_text(text):
    """
    Parse log content provided as a raw string.

    Args:
        text (str): Raw log content.

    Returns:
        list[dict]: List of parsed log entries.
    """
    logs = []
    if not text:
        return logs

    for line_no, line in enumerate(text.splitlines(), start=1):
        parsed = parse_log_line(line)
        if parsed:
            logs.append(parsed)
        elif line.strip():
            logger.debug("Could not parse line %d: %s", line_no, line.strip())

    logger.info("Parsed %d log entries from uploaded text", len(logs))
    return logs


def parse_log_stream(stream):
    """
    Parse log lines streaming line-by-line from a file-like object or iterator.
    Highly memory-efficient for large files up to 500MB.

    Args:
        stream: An iterable or stream yielding bytes or str lines.

    Returns:
        list[dict]: List of parsed log entries.
    """
    logs = []
    if stream is None:
        return logs

    for line_no, raw_line in enumerate(stream, start=1):
        if isinstance(raw_line, bytes):
            line = raw_line.decode("utf-8", errors="replace").strip()
        else:
            line = str(raw_line).strip()

        if not line:
            continue

        parsed = parse_log_line(line)
        if parsed:
            logs.append(parsed)
        elif line:
            logger.debug("Could not parse stream line %d: %s", line_no, line[:80])

    logger.info("Parsed %d log entries from stream", len(logs))
    return logs

