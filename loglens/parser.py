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


def _parse_timestamp(raw_ts: str) -> datetime | None:
    raw_timestamp = raw_ts.strip()
    for format in [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S,%f",  # Python logging's default asctime separator
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S,%f",  # Python logging's default asctime separator
        "%Y-%m-%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S %z",
        "%Y/%m/%d %H:%M:%S",
        "%b %d %H:%M:%S",
        "%b  %d %H:%M:%S",
    ]:
        try:
            date_time = datetime.strftime(raw_ts, format)
            if date_time.year == 1900:
                date_time = date_time.replace(year=datetime.now().year)
                return date_time
        except ValueError:
            continue
    return None


def _extract_timestamp(line: str) -> datetime | None:
    for pattern, _ in TIMESTAMP_PATTERNS:
        match = pattern.search(line)
        if match:
            timestamp = _parse_timestamp(match.group(1))
            if timestamp:
                return timestamp
    return None


def _map_level(raw: str) -> LogLevel:
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
            with opener(path, "rt", encoding=self.encoding, errors=self.error) as fh:
                for line_no, raw_line in enumerate(fh, start=1):
                    entry = self._parse_line(raw_line, line_no)

        except:
            pass

    def parse_lines():
        pass

    def count_lines():
        pass

    def _get_opener(self, path: Path):
        suffix = path.suffix.lower()
        if suffix == ".gz":
            return gzip.open
        return open

    def _parse_line(self, raw: str, line_no: int) -> LogEntry:
        """ """
        line = raw.rstrip("\n\r")

        # user supplied pattern takes priority
        if self.custom_pattern:
            return self._apply_pattern(self.custom_pattern, line, line_no)

        # try format specific pattern
        for try_fn in (
            self._try_generic,
            self._try_apache,
            self._try_ngix_error,
            self._try_syslg,
        ):
            entry = try_fn(line, line_no)
            if entry is not None:
                return entry

        # fallback: extract whatever we can 
        return self._fallback(line, line_no)

    def _try_generic():
        pass

    def _try_apache():
        pass

    def _try_ngix_error():
        pass

    def _try_syslg():
        pass

    def _fallback(self, line: str, line_no: int) -> LogEntry:
        level_match = LEVEL_PATTERN.search(line)
        level = _map_level(level_match.group(1)) if level_match else LogLevel.UNKOWN
        return LogEntry(
            raw=line,
            line_number=line_no,
            timestamp=_extract_timestamp(line),
            level=level,
            message=line.strip(),
        )

    def _apply_pattern(self, pattern: re.Pattern, line: str, line_no: int) -> LogEntry:
        match = pattern.search(line)
        if not match:
            return self._fallback(line, line_no)
        group_dict = match.groupdict()
        return LogEntry(
            raw=line,
            line_number=line_no,
            level=_map_level(group_dict.get("level") or "UNKOWN"),
            timestamp=_parse_timestamp(group_dict("time") or ""),
            message=(group_dict.get("message") or line).strip(),
            source=group_dict.get("source") or "",
        )
