"""
logger.py — Centralized logging configuration for CyberShield.

Provides a consistent logger that writes to both the console
and a rotating log file (logs/cybershield.log).
"""

import os
import logging
from logging.handlers import RotatingFileHandler

# Shared formatter
_formatter = logging.Formatter(
    fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Ensure the logs directory exists if possible (fallback for serverless)
_file_handler = None
try:
    LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
    os.makedirs(LOG_DIR, exist_ok=True)
    LOG_FILE = os.path.join(LOG_DIR, "cybershield.log")
    _file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    _file_handler.setLevel(logging.DEBUG)
    _file_handler.setFormatter(_formatter)
except Exception:
    _file_handler = None

# Console handler
_console_handler = logging.StreamHandler()
_console_handler.setLevel(logging.INFO)
_console_handler.setFormatter(_formatter)


def get_logger(name):
    """
    Create and return a configured logger.

    Args:
        name (str): Logger name (typically __name__).

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        if _file_handler:
            logger.addHandler(_file_handler)
        logger.addHandler(_console_handler)

    return logger
