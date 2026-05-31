from __future__ import annotations
import os, logging

#  Directory & file paths
LOG_DIR: str = os.path.join(os.getcwd(), "logs")
LOG_FILE_NAME: str = "app.log"
LOG_FILE_DIR: str = os.path.join(LOG_DIR, LOG_FILE_NAME)

# Rotation settings
# Number of rotated backups to keep (app.log.1 ... app.log.N)
LOG_BACKUP_COUNT: int = 5
# Maximum size in bytes before the log file is rotated
MAX_LOG_FILE_SIZE: int = 5 * 1024 * 1024


#  Logger format settings
LOGGER_NAME: str = "loglens"
LOG_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"
LOG_FORMAT: str = (
    "[ %(asctime)s ] [ %(levelname)-8s ] [ %(name)s:%(lineno)d ] - %(message)s"
)

# Minimum severity to record. Options: DEBUG, INFO, WARNING, ERROR, CRITICAL 
LOG_LEVEL = logging.INFO
