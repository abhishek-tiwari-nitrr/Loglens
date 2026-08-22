from __future__ import annotations
from loglens.parser import LogParser, LogEntry, LogLevel
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
import time, logging, re
from loglens.exceptions import ApplicationException
from collections import Counter, defaultdict
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)

logger = logging.getLogger(__name__)
console = Console(stderr=True)


@dataclass
class AnalysisResult:
    # meta data
    file_path: str = ""
    file_size_bytes: int = 0
    total_lines: int = 0
    parsed_lines: int = 0
    analysis_duration_seconds: float = 0.0
    analyzed_at: str = field(default_factory=lambda: datetime.now().isoformat())

    # level count
    level_counts: dict[str, int] = field(default_factory=dict)

    # message
    top_errors: list[tuple[str, int]] = field(default_factory=list)
    top_warnings: list[tuple[str, int]] = field(default_factory=list)
    top_messages: list[tuple[str, int]] = field(default_factory=list)

    # timeline
    timeline: dict[str, dict[str, int]] = field(
        default_factory=dict
    )  # min -> level -> count
    hourly_distribution: dict[str, dict[str, int]] = field(
        default_factory=dict
    )  # hour -> level -> count
    daily_distribution: dict[str, dict[str, int]] = field(
        default_factory=dict
    )  # date -> level -> count
    first_timestamp: str | None = None
    last_timestamp: str | None = None

    # source
    sources: dict[str, int] = field(default_factory=dict)

    # raw entries
    sample_errors: list[dict] = field(default_factory=list)
    sample_warnings: list[dict] = field(default_factory=list)

    # anomalies 
    anomalies: list[dict] = field(default_factory=list)

    @property
    def error_rate(self) -> float:
        if not self.parsed_lines:
            return 0.0
        errors = self.level_counts.get("ERROR", 0) + self.level_counts.get("CRITICAL", 0)
        return round(100 * errors / self.parsed_lines, 2) 

    @property
    def summary_stats(self) -> dict:
        return {
            "total_lines": self.total_lines,
            "parsed_lines": self.parsed_lines,
            "error_rate_pct": self.error_rate,
            "level_counts": self.level_counts,
            "top_error": self.top_errors[:5],
            "anomaly_count": len(self.anomalies)
        }

    def to_dict(self) -> dict:
        return {
            "metadata": {
                "file_path": self.file_path,
                "file_size_bytes": self.file_size_bytes,
                "total_lines": self.total_lines,
                "parsed_lines": self.parsed_lines,
                "analysis_duration_seconds": self.analysis_duration_seconds,
                "analyzed_at": self.analyzed_at,
                "first_timestamp": self.first_timestamp,
                "last_timestamp": self.last_timestamp,
            },
            "level_counts": self.level_counts,
            "error_rate_pct": self.error_rate,
            "top_errors": self.top_errors,
            "top_warnings": self.top_warnings,
            "top_messages": self.top_messages,
            "timeline": self.timeline,
            "hourly_distribution": self.hourly_distribution,
            "daily_distribution": self.daily_distribution,
            "sources": self.sources,
            "sample_errors": self.sample_errors,
            "sample_warnings": self.sample_warnings,
            "anomalies": self.anomalies
        }


class LogAnalyzer:
    def __init__(
        self,
        top_n: int = 20,
        sample_size: int = 50,
        show_progress: bool = True,
        parser: LogParser | None = None,
    ) -> None:
        self.top_n = top_n
        self.sample_size = sample_size
        self.show_progress = show_progress
        self.parser = parser or LogParser()

    def analyzer(
        self,
        path: str | Path,
        levels: list[str] | None = None,
        pattern_filter: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
    ) -> AnalysisResult:

        path = Path(path)
        start_time = time.perf_counter()
        logger.info("Starting analysis %s", path)

        try:
            compiled_pattern = (
                re.compile(pattern_filter, re.IGNORECASE) if pattern_filter else None
            )
        except re.error as e:
            logger.error("Invalid regex pattern %r: %s", pattern_filter, e)
            raise ApplicationException(
                f"Invalid regex pattern `{pattern_filter}`: {e}", e
            ) from e

        result = AnalysisResult(
            file_path=str(path.resolve()),
            file_size_bytes=path.stat().st_size if path.exists() else 0,
        )

        # count total lines for progress bar
        if self.show_progress:
            console.print(f"[dim]Counting lines in [bold]{path.name}[/bold]…[/dim]")

        total_line = self.parser.count_lines(path)
        result.total_lines = total_line

        # accumulators
        level_counter: Counter[str] = Counter()
        error_counter: Counter[str] = Counter()
        warning_counter: Counter[str] = Counter()
        message_counter: Counter[str] = Counter()
        source_counter: Counter[str] = Counter()

        timeline: defaultdict[str, Counter] = defaultdict(Counter)
        hourly: defaultdict[str, Counter] = defaultdict(Counter)
        daily: defaultdict[str, Counter] = defaultdict(Counter)
        first_timestamp: datetime | None = None
        last_timestamp: datetime | None = None

        sample_errors: list[dict] = []
        sample_warnings: list[dict] = []

        entries = self.parser.parse_file(
            path,
            pattern_filter=compiled_pattern,
            date_from=date_from,
            date_to=date_to,
            levels=levels,
        )

        if self.show_progress:
            entries = self._wrap_progress(entries, total_line, path.name)

        parsed = 0

        for entry in entries:
            parsed += 1
            self._process_entry(
                entry,
                level_counter,
                error_counter,
                warning_counter,
                message_counter,
                source_counter,
                timeline,
                hourly,
                daily,
                sample_errors,
                sample_warnings,
            )
            if entry.timestamp:
                if first_timestamp is None or entry.timestamp < first_timestamp:
                    first_timestamp = entry.timestamp
                if last_timestamp is None or entry.timestamp > last_timestamp:
                    last_timestamp = entry.timestamp

        # result
        result.parsed_lines = parsed
        result.level_counts = dict(level_counter)
        result.top_errors = error_counter.most_common(self.top_n)
        result.top_warnings = warning_counter.most_common(self.top_n)
        result.top_messages = message_counter.most_common(self.top_n)
        result.sources = dict(source_counter)
        result.timeline = {k: dict(v) for k, v in sorted(timeline.items())}
        result.hourly_distribution = {k: dict(v) for k, v in sorted(hourly.items())}
        result.daily_distribution = {k: dict(v) for k, v in sorted(daily.items())}
        result.first_timestamp = first_timestamp.isoformat() if first_timestamp else None
        result.last_timestamp = last_timestamp.isoformat() if last_timestamp else None
        result.sample_errors = sample_errors
        result.sample_warnings = sample_warnings
        result.analysis_duration_seconds = round(time.perf_counter() - start_time, 3)

        logger.info(
            "Analysis complete: %s — parsed %d lines in %.3fs (errors=%d, critical=%d, error_rate=%.2f%%)",
            path.name,
            result.parsed_lines,
            result.analysis_duration_seconds,
            result.level_counts.get("ERROR", 0),
            result.level_counts.get("CRITICAL", 0),
            result.error_rate,
        )

        return result


    def _wrap_progress(self, entries: object, total: int, filename: str):
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), TimeRemainingColumn(), console=console, transient=True) as progress:
            task = progress.add_task(f"Analyzing [bold cyan]{filename}[/]", total=total)
            for entry in entries:
                progress.advance(task)
                yield entry
            

    def _process_entry(self, entry: LogEntry, level_counter: Counter, error_counter: Counter, warning_counter: Counter, message_counter: Counter, source_counter: Counter, timeline: defaultdict, hourly: defaultdict, daily: defaultdict, sample_errors: list, sample_warnings: list) -> None:
        level = entry.level.value
        level_counter[level] += 1
        message_counter[entry.message[:200]] += 1

        if entry.sources:
            source_counter[entry.sources] += 1

        if entry.level in (LogLevel.ERROR, LogLevel.CRITICAL):
            error_counter[entry.message[:200]] += 1
            if len(sample_errors) < self.sample_size:
                sample_errors.append(self._entry_to_dict(entry))

        if entry.level == LogLevel.WARNING:
            warning_counter[entry.message[:200]] += 1
            if len(sample_warnings) < self.sample_size:
                sample_warnings.append(self._entry_to_dict(entry))

        if entry.timestamp:
            minute_key = entry.timestamp.strftime("%Y-%m-%dT%H:%M")
            hour_key = entry.timestamp.strftime("%Y-%m-%dT%H")
            day_key = entry.timestamp.strftime("%Y-%m-%d")
            timeline[minute_key][level] +=1
            hourly[hour_key][level] += 1
            daily[day_key][level] += 1


    @staticmethod
    def _entry_to_dict(entry: LogEntry) -> dict:
        return {
            "line_number": entry.line_number,
            "level": entry.level.value,
            "timestamp": entry.timestamp_str,
            "message": entry.message,
            "sources": entry.sources
        }
