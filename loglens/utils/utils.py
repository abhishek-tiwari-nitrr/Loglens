from __future__ import annotations
from pathlib import Path
import gzip
import bz2
from datetime import datetime
from loglens.entity.log_entity import LogLevel
from loglens.utils.log_patterns import SYSLOG_YEAR


def open_log_file(path: Path):
    """
    Open a log file, transparently handling gzip and bzip2 compression
    """
    suffix = path.suffix.lower()
    if suffix == ".gz":
        return gzip.open
    if suffix in (".bz2", ".bzip2"):
        return bz2.open
    return open


def map_level(raw: str) -> LogLevel:
    """
    Normalise raw level string to LogLevel enum
    """
    mapping = {
        "DEBUG": LogLevel.DEBUG,
        "TRACE": LogLevel.DEBUG,
        "INFO": LogLevel.INFO,
        "NOTICE": LogLevel.INFO,
        "WARNING": LogLevel.WARNING,
        "WARN": LogLevel.WARNING,
        "ERROR": LogLevel.ERROR,
        "FATAL": LogLevel.CRITICAL,
        "CRITICAL": LogLevel.CRITICAL,
    }
    return mapping.get(raw.upper(), LogLevel.UNKNOWN)


def parse_timestamp(raw_ts: str) -> datetime | None:
    """
    Try to parse a timestamp string using multiple known formats
    """
    raw_ts = raw_ts.strip()
    for fmt in [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%Y/%m/%d %H:%M:%S",
        "%b %d %H:%M:%S",
        "%b  %d %H:%M:%S",
    ]:
        try:
            dt = datetime.strptime(raw_ts, fmt)
            # Patch missing year for syslog
            if dt.year == 1900:
                dt = dt.replace(year=SYSLOG_YEAR)
            return dt
        except ValueError:
            continue
    return None
