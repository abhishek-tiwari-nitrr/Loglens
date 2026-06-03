from __future__ import annotations
import re
from pathlib import Path
from datetime import datetime
from typing import Iterator
from loglens.entity.log_entity import LogEntry, LogLevel
from loglens.utils.utils import open_log_file, map_level, parse_timestamp
from loglens.utils.log_patterns import PYTHON_LOG_PATTERN, LEVEL_PATTERN
from loglens.logger import logger
from loglens.exceptions import ApplicationException


class LogParser:
    def __init__(
        self,
        custom_pattern: re.Pattern | None = None,
        encoding: str = "utf-8",
        error: str = "replace",
    ) -> None:
        self.custom_pattern = custom_pattern
        self.encoding = encoding
        self.error = error

    def parse_lines(self, lines: list[str]) -> list[LogEntry]:
        return [self._parse_line(line, i) for i, line in enumerate(lines, start=1)]

    def _parse_line(self, raw: str, line_number: int) -> LogEntry:
        line = raw.rstrip("\n\r")

        if self.custom_pattern:
            return self._apply_pattern(self.custom_pattern, line, line_number)

        for try_fn in self._try_python:
            entry = try_fn(line, line_number)
            if entry is not None:
                return entry

        return self._fallback(line, line_number)

    def parse_file(
        self,
        path: str | Path,
        pattern_filter: re.Pattern | None = None,
        levels: list[str] | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
    ) -> Iterator[LogEntry]:
        path = Path(path)
        if not path.exists():
            logger.error(f"Log File not found: {path}")
            raise FileNotFoundError(f"Log File not found: {path}")

        logger.info(
            f"Parsing: {path.name} (levels = {levels or "all"}, pattern = {pattern_filter.pattern if pattern_filter else None}, from = {date_from}, to = {date_to})"
        )

        normalised_levels = {lv.upper() for lv in (levels or [])}
        opener = open_log_file(path)

        try:
            with opener(path, "rt", encoding=self.encoding, errors=self.error) as f:
                for (
                    line_number,
                    raw_line,
                ) in enumerate(f, start=1):
                    entry = self._parse_line(raw_line, line_number)

                    # Level filter
                    if normalised_levels and entry.level.value not in normalised_levels:
                        continue
                    # Pattern (regex) filter
                    if pattern_filter and not pattern_filter.search(raw_line):
                        continue
                    # Date "from" filter (lower bound)
                    if date_from and entry.timestamp and entry.timestamp < date_from:
                        continue
                    # Date "to" filter (upper bound)
                    if date_to and entry.timestamp and entry.timestamp > date_to:
                        continue

                    yield entry

        except Exception as e:
            logger.exception("Failed to read log file %s", path)
            raise ApplicationException(f"Could not read log file: {path}", e) from e

    def count_lines(self, path: str | Path) -> int:
        path = Path(path)
        opener = open_log_file(path)
        count = 0
        try:
            with opener(path, "rt", encoding=self.encoding, errors=self.error) as f:
                for _ in f:
                    count += 1
            return count
        except Exception as e:
            logger.error("Failed to count the lines of file %s", path)
            raise ApplicationException(
                f"Failed to count the lines of file: {path}", e
            ) from e

    def _try_python(self, line: str, line_number: int) -> LogEntry:
        level_match = PYTHON_LOG_PATTERN.match(line)
        if not level_match:
            return None
        return LogEntry(
            raw=line,
            line_number=line_number,
            level=map_level(level_match.group("level")),
            timestamp=parse_timestamp(level_match.group("time")),
            message=level_match.group("message").strip(),
        )

    def _fallback(self, line: str, line_number: int) -> LogEntry:
        level_match = LEVEL_PATTERN.search(line)
        # first gp
        level = map_level(level_match.group(1)) if level_match else LogLevel.UNKNOWN
        return LogEntry(
            raw=line,
            line_number=line_number,
            level=level,
            timestamp=parse_timestamp(line),
            message=line.strip(),
        )

    def _apply_pattern(
        self, pattern: re.Pattern, line: str, line_number: int
    ) -> LogEntry:
        m = pattern.search(line)
        if not m:
            return self._fallback(line, line_number)
        group_dict = m.groupdict()
        return LogEntry(
            raw=line,
            line_number=line_number,
            level=map_level(group_dict.get("level", "UNKNOWN")),
            timestamp=parse_timestamp(group_dict.get("time", "")),
            message=group_dict.get("message", line).strip(),
            source=group_dict.get("source", ""),
        )
