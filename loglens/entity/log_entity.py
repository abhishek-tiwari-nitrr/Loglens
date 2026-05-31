from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class LogLevel(str, Enum):
    """
    Log severity levels
    """

    DEBUG: str = "DEBUG"
    INFO: str = "INFO"
    WARNING: str = "WARNING"
    ERROR: str = "ERROR"
    CRITICAL: str = "CRITICAL"
    UNKNOWN: str = "UNKNOWN"


@dataclass
class LogEntry:
    """
    Represents a single parsed log entry
    """

    raw: str
    line_number: int
    level: LogLevel = LogLevel.UNKNOWN
    timestamp: datetime | None = None
    message: str = ""
    source: str = ""
    extra: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        """
        Runs automatically after dataclass initialization to perform additional setup, validation or derived-field computation
        """
        if not self.message:
            self.message = self.raw.strip()

    @property
    def is_error(self) -> bool:
        return self.level in (LogLevel.ERROR, LogLevel.CRITICAL)

    @property
    def timestamp_str(self) -> str:
        if self.timestamp:
            return self.timestamp.isoformat()
        return ""
