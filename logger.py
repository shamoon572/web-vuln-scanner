"""
Centralized logging configuration for the Web Vulnerability Scanner.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime


class ColorFormatter(logging.Formatter):
    """Custom formatter with color support for terminal output."""

    COLORS = {
        "DEBUG":    "\033[36m",   # Cyan
        "INFO":     "\033[32m",   # Green
        "WARNING":  "\033[33m",   # Yellow
        "ERROR":    "\033[31m",   # Red
        "CRITICAL": "\033[41m",   # Red background
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    VULN_COLOR  = "\033[35m"   # Magenta — found vulnerability
    FOUND_COLOR = "\033[92m"   # Bright green — positive finding

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{self.BOLD}{record.levelname:<8}{self.RESET}"
        record.msg = f"{color}{record.msg}{self.RESET}"
        return super().format(record)


def setup_logger(name: str = "scanner", level: int = logging.INFO,
                 log_file: str | None = None) -> logging.Logger:
    """
    Set up and return a configured logger instance.

    Args:
        name:     Logger name (defaults to 'scanner')
        level:    Logging level
        log_file: Optional path to write logs to disk
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if logger.handlers:
        return logger

    # Console handler with color
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(ColorFormatter(
        fmt="%(asctime)s  %(levelname)s  %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.addHandler(ch)

    # Optional file handler (plain text, no color codes)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            fmt="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        logger.addHandler(fh)

    return logger


# Module-level default logger
log = setup_logger("scanner")
