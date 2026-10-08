"""
LeakMind Centralized Logging System
Formats and records logs across both console and log files.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Optional


_LOGGERS = {}


def setup_logger(
    name: str = "leakmind",
    log_file: Optional[str] = "logs/leakmind.log",
    level: int = logging.INFO
) -> logging.Logger:
    """
    Initializes and returns a configured logger with console and file output.
    """
    if name in _LOGGERS:
        return _LOGGERS[name]

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)s] [%(name)s:%(lineno)d]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File Handler
    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(str(log_path), encoding="utf-8")
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Failed to create file handler for {log_file}: {e}")

    _LOGGERS[name] = logger
    return logger


def get_logger(name: str = "leakmind") -> logging.Logger:
    """
    Returns an existing logger or creates a standard one.
    """
    if name in _LOGGERS:
        return _LOGGERS[name]
    return setup_logger(name)
