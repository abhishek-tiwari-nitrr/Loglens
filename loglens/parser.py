from __future__ import annotations
import re
from datetime import datetime
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field
import logging
import gzip
from collections.abc import Iterator

logger = logging.getLogger(__name__)


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    UNKOWN = "UNKOWN"


@dataclass
class LogEntry:
    raw: str
    line_number: int
    level: LogLevel = LogLevel.UNKOWN
    timestamp: datetime | None = None
    message: str = ""
    source: str = ""
    extra: dict = field(default_factory=dict)

    def _post_init__(self) -> None:
        if not self.message:
            self.message = self.raw.strip()

    @property
    def _is_error(self) -> bool:
        return self.level in (LogLevel.ERROR, LogLevel.CRITICAL)

    @property
    def timestamp_str(self) -> str:
        if self.timestamp:
            return self.timestamp.isoformat()
        return ""


##Built in Patterns formats

# Apache Combined Log Format
APACHE_PATTERN = re.compile(
    r"(?P<host>\S+)\s+\S+\s+\S+\s+"
    r"\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<request>[^"]+)"\s+'
    r"(?P<status>\d{3})\s+"
    r"(?P<size>\S+)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

# Nginx error log
NGINX_ERROR_PATTERN = re.compile(
    r"(?P<time>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\[(?P<level>\w+)\]\s+"
    r"(?P<pid>\d+)#\d+:\s+"
    r"(?P<message>.*)"
)

# Syslog format
SYSLOG_PATTERN = re.compile(
    r"(?P<time>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^:]+):\s+"
    r"(?P<message>.*)"
)

# Generic application log (Python logging, Log4j style)
GENERIC_PATTERN = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s*"
    r"[-\s]*(?P<level>DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|FATAL|NOTICE|TRACE)[-\s:]*"
    r"(?P<message>.*)",
    re.IGNORECASE,
)

# Level-only detection (fallback)
LEVEL_PATTERN = re.compile(
    r"\b(DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|FATAL|NOTICE|TRACE)\b",
    re.IGNORECASE,
)

# Timestamp patterns (multiple formats)
TIMESTAMP_PATTERNS = [
    # ISO 8601
    (
        re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)"),
        "%Y-%m-%dT%H:%M:%S",
    ),
    (
        re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)"),
        "%Y-%m-%d %H:%M:%S",
    ),
    # Apache/Nginx style
    (
        re.compile(r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})"),
        "%d/%b/%Y:%H:%M:%S %z",
    ),
    # Syslog style
    (re.compile(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"), "%b %d %H:%M:%S"),
    # Simple date time
    (re.compile(r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})"), "%Y/%m/%d %H:%M:%S"),
]

APACHE_TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_timestamp():
    pass


def _extact_timestamp():
    pass


def _map_level():
    pass


class LogParser:
    def __inti__(
        self,
        custom_pattern: re.Pattern | None = None,
        encoding: str = "utf-8",
        error: str = "replace",
    ) -> None:
        self.custom_pattern = custom_pattern
        self.encoding = encoding
        self.error = error

    def parse_file(
        self,
        path: str | Path,
        levels: list[str] | None = None,
        pattern_filter: re.Pattern | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
    ) -> Iterator[LogEntry]:
        path = Path(path)
        if not path.exists():
            # Logger uses lazy %s formatting; exceptions use f-strings to build the message immediately
            logger.error("Log file not found: %s", path)
            raise FileNotFoundError(f"Log file not found: {path}")

        logger.info(
            "Parsing %s (levels=%s, pattern=%s, from=%s, to=%s)",
            path.name,
            levels or "all",
            pattern_filter.pattern if pattern_filter else None,
            date_from,
            date_to,
        )

        normalised_levels = {lv.upper() for lv in (levels, [])}
        opener = self._get_opener(path)

        try:
            pass
        except:
            pass

    def parse_line():
        pass

    def count_lines():
        pass

    def _get_opener(self, path: Path):
        suffix = path.suffix.lower()
        if suffix == ".gz":
            return gzip.open
        return open

    def _parse_line():
        """ """
        pass
