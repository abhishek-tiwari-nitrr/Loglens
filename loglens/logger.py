from __future__ import annotations
import os, logging
from logging.handlers import RotatingFileHandler
from loglens.constants.config import (
    LOG_DIR,
    LOG_FILE_DIR,
    LOGGER_NAME,
    MAX_LOG_FILE_SIZE,
    LOG_BACKUP_COUNT,
    LOG_LEVEL,
    LOG_FORMAT,
    LOG_DATE_FORMAT,
)


def _setup_logger() -> logging.Logger:
    """
    Build and configure the application-wide logger.

    Returns:
        logging.Logger: A configured logger instance name `LOGGER_NAME` from config
    """
    log = logging.getLogger(LOGGER_NAME)
    if log.handlers:
        return log

    os.makedirs(LOG_DIR, exist_ok=True)
    handler = RotatingFileHandler(
        filename=LOG_FILE_DIR,
        mode="a",
        encoding="utf-8",
        maxBytes=MAX_LOG_FILE_SIZE,  # default 5 MB
        backupCount=LOG_BACKUP_COUNT,  # default 5 backups
    )

    handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT))

    log.addHandler(handler)
    log.setLevel(LOG_LEVEL)

    log.propagate = False

    return log


logger: logging.Logger = _setup_logger()
