"""
Loglens Parser Module

High-performance streaming log parser supporting multiple log formats: Apache, Nginx, syslog, and custom application logs.

`Parses line-by-line without loading entire files into memory.`

"""
from __future__ import annotations
import re
from datetime import datetime
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field
import logging
import gzip
from collections.abc import Iterator
from loglens.exceptions import ApplicationException

logger = logging.getLogger(__name__)


class LogLevel(str, Enum):
    """
    Represent the normalized severity levels understood by LogLens.

    Log files may use different names for the same severity level. The parser normalizes those names into this common set so callers can work with a consistent representation regardless of the source log format.

    `UNKOWN` is used when the parser cannot identify a known severity level.
    """
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    UNKOWN = "UNKOWN"


@dataclass
class LogEntry:
    """
    Represent one parsed log entry.

    A `LogEntry` contains both the original log line and the structured information extracted from it. Fields that cannot be identified from the source line are left at their default values.

    Parameters:
    ---------
    raw: 
        The original log line after newline characters are removed.
    line_number: 
        The one-based line number where the entry was found.
    level: 
        Normalized severity level of the entry.
    timestamp: 
        Parsed timestamp, if one could be extracted.
    message: 
        Main message content extracted from the log entry.
    source: 
        Host, service or other source identifier when available.
    extra: 
        Additional format-specific fields extracted from the entry.
    """
    raw: str
    line_number: int
    level: LogLevel = LogLevel.UNKOWN
    timestamp: datetime | None = None
    message: str = ""
    source: str = ""
    extra: dict = field(default_factory=dict)

    def _post_init__(self) -> None:
        """
        Use the raw log line as the message when no message was extracted.

        This provides a useful fallback for log formats where the parser cannot identify a dedicated message field.
        """
        if not self.message:
            self.message = self.raw.strip()

    @property
    def _is_error(self) -> bool:
        """
        Return whether this entry represents an error-level event.

        An entry is considered an error when its severity is `ERROR` or `CRITICAL`
        """
        return self.level in (LogLevel.ERROR, LogLevel.CRITICAL)

    @property
    def timestamp_str(self) -> str:
        """
        Return the parsed timestamp in ISO 8601 format.

        Returns an empty string when no timestamp could be extracted from the log entry.
        """
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
    """
    Parse a timestamp using LogLens' supported timestamp formats.

    The parser tries several common formats, including ISO 8601, Apache/Nginx-style timestamps, syslog timestamps and simple date-time formats.

    Parameters:
    ----------
        raw_ts (str): 
            Timestamp text extracted from a log line.

    Returns:
    -------
        datetime | None
    """
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
    """
    Find and parse the first supported timestamp in a log line.

    Each configured timestamp pattern is searched against the complete log line. When a matching timestamp is found, it is passed to `_parse_timestamp()` for conversion into a `datetime` object.

    Parameters:
    ---------
        line (str): 
            Complete log line to inspect.

    Returns:
    -------
        The first successfully parsed timestamp, or `None` when the line does not contain a supported timestamp.
    """
    for pattern, _ in TIMESTAMP_PATTERNS:
        match = pattern.search(line)
        if match:
            timestamp = _parse_timestamp(match.group(1))
            if timestamp:
                return timestamp
    return None


def _map_level(raw: str) -> LogLevel:
    """
    Normalize a raw severity name to a `LogLevel`.

    Different logging systems use aliases for severity levels. For example,     `WARN` maps to `WARNING`, `TRACE` maps to `DEBUG` and `FATAL` maps to `CRITICAL`.

    Parameters:
    ---------
        raw (str): 
            Raw severity name extracted from a log line.

    Returns:
    -------
        LogLevel: 
            The corresponding `LogLevel` value. Unknown values are mapped to the unknown severity level.
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


class LogParser:
    """
    Streaming log parser with multi-format auto-detection.
    
    Parses log files line-by-line for memory efficiency, even on multi-gigabyte log files. Supports gzip compressed files.

    Parameters
    ----------
    custom_pattern:
        Optional compiled regex with named groups `level`, `time`, `message`. Overrides auto-detection.
    encoding:
        File encoding (default: utf-8).
    errors:
        Error handling for decode errors ('ignore', 'replace', 'strict').
    """
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
        """
        Parse a log file and yield entries that match the supplied filters.

        Parameters:
        ----------
            path (str | Path): 
                Path to the log file.
            levels (list[str] | None, optional): 
                Optional list of severity levels to include. When omitted, entries of all levels are returned.
            pattern_filter (re.Pattern | None, optional): 
                Optional regular expression. Only lines matching this expression are returned.
            date_from (datetime | None, optional): 
                Optional lower timestamp boundary. Entries before this timestamp are skipped.
            date_to (datetime | None, optional): 
                Optional upper timestamp boundary. Entries after this timestamp are skipped.

        Raises:
        -------
            FileNotFoundError: 
                If the specified log file does not exist.
            ApplicationException: 
                If the file cannot be read because of an operating system or text-decoding error.

        Yields:
        ------
            Iterator[LogEntry]: Parsed ``LogEntry`` objects that satisfy all supplied filters.
        """
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

                    if normalised_levels and entry.level.value not in normalised_levels:
                        continue
                    if pattern_filter and not pattern_filter.search(raw_line):
                        continue
                    if date_from and entry.timestamp and entry.timestamp < date_from:
                        continue
                    if date_to and entry.timestamp and entry.timestamp > date_to:
                        continue

                    yield entry

        except (OSError, UnicodeDecodeError) as e:
            logger.exception("Failed to read log file %s", path)
            raise ApplicationException(
                f"Could not read log file '{path}': {e}", e
            ) from e


    def _get_opener(self, path: Path):
        """
        Return appropriate opener for plain / gzip files.

        Parameters:
        ----------
            path (Path): 
                Path to the log file.

        Returns:
        -------
            _type_: 
                `gzip.open` for gzip-compressed files, otherwise `open`.
        """
        suffix = path.suffix.lower()
        if suffix == ".gz":
            return gzip.open
        return open

    def _parse_line(self, raw: str, line_no: int) -> LogEntry:
        """
        Parse a single raw log line into a `LogEntry`.

        Parsing is attempted in the following order:
            1. The user-supplied custom pattern, when configured.
            2. Generic application log format.
            3. Apache combined log format.
            4. Nginx error log format.
            5. Syslog format.
            6. The fallback parser when no specific format matches.
        
        This order allows application-specific parsing rules to take precedence while still providing automatic format detection for common log formats.
        """
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

    def _try_generic(self, line: str, line_no: int) -> LogEntry | None:
        """
        Try to parse a line using the generic application-log format.
        """
        match = GENERIC_PATTERN.match(line)
        if not match:
            return None

        return LogEntry(
            raw=line,
            line_number=line_no,
            level=_map_level(match.group("level")),
            timestamp=_parse_timestamp(match.group("time")),
            message=match.group("message").strip(),
        )

    def _try_apache(self, line: str, line_no: int) -> LogEntry | None:
        """
        Try to parse a line using the Apache Combined Log Format.
        """
        match = APACHE_PATTERN.match(line)
        if not match:
            return None
        status = int(match.group("status"))
        level = (
            LogLevel.ERROR
            if status >= 500
            else (LogLevel.WARNING if status >= 400 else LogLevel.INFO)
        )
        return LogEntry(
            raw=line,
            line_number=line_no,
            level=level,
            timestamp=_parse_timestamp(match.group("time")),
            message=match.group("request"),
            source=match.group("host"),
            extra={"status": status, "size": match.group("size")},
        )

    def _try_ngix_error(self, line: str, line_no: int) -> LogEntry | None:
        """
        Try to parse a line using the Nginx error-log format.
        """
        match = NGINX_ERROR_PATTERN.match(line)
        if not match:
            return None
        return LogEntry(
            raw=line,
            line_number=line_no,
            level=_map_level(match.group("level")),
            timestamp=_parse_timestamp(match.group("timne")),
            message=match.group("message").strip(),
            source="ngix",
            extra={"pid": match.group("pid")},
        )

    def _try_syslg(self, line: str, line_no: int) -> LogEntry | None:
        """
        Try to parse a line using the syslog format.
        """
        match = SYSLOG_PATTERN.match(line)
        if not match:
            return None
        message = match.group("message")
        level_match = LEVEL_PATTERN.match(message)
        level = _map_level(level_match.group(1)) if level_match else LogLevel.INFO
        return LogEntry(
            raw=line,
            line_number=line_no,
            level=level,
            message=message,
            timestamp=_parse_timestamp(match.group("time")),
            source=match.group("host"),
            extra={"process": match.group("process")},
        )

    def _fallback(self, line: str, line_no: int) -> LogEntry:
        """
        Create a best-effort entry when no specific format matches.

        The fallback parser does not require the log line to follow one of the supported structured formats. Instead, it attempts to extract a recognizable severity and timestamp while preserving the complete line as the message.

        This allows LogLens to return useful information even when a log format is only partially understood.
        """
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
        """
        Parse a log line using a user-supplied regular expression.

        The custom pattern is expected to provide named groups such as `level`, `time`, `message`, and `source` when those fields are available.

        If the custom pattern does not match the line, parsing falls back to the standard fallback strategy.

        """
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
