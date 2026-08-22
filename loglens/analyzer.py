"""
Core log analysis engine for LogLens.

This module coordinates the analysis pipeline for log files. It uses `LogParser` to read and filter log entries, then aggregates the parsed entries into statistics such as log level counts, frequently occurring messages, source frequencies, time based distributions and representative error/warning samples.

The main public API is `LogAnalyzer.analyze()`, which returns an `AnalysisResult` containing both the raw analysis metadata and the calculated statistics.

The analyzer processes entries as a stream rather than loading the entire log file into memory. This allows large log files to be analyzed while keeping memory usage bounded by the configured `top_n` and `sample_size` limits.

Progress reporting is optional and uses Rich when `show_progress=True`.
"""

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
    """
    Container for all statistics and metadata produced by log analysis.

    `AnalysisResult` is the data object returned by `LogAnalyzer.analyze`. It keeps the analysis output separate from the processing logic, making the results easy to serialize, inspect, display or pass to other parts of LogLens.

    The result contains several categories of information:

    - File metadata such as path, size, line counts and analysis duration.
    - Counts grouped by log level.
    - Most frequently occurring errors, warnings and messages.
    - Minute, hour and day level distributions of log events.
    - First and last timestamps encountered in the analyzed entries.
    - Counts grouped by log source.
    - A bounded set of representative error and warning entries.
    - Anomaly results, which can be populated by the anomaly detection stage.

    Sample collections are intentionally bounded so that analyzing a large log file does not cause the result object to grow with the number of matching entries.
    """
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
        """
        Return the percentage of parsed entries classified as errors.

        Both `ERROR` and `CRITICAL` entries are considered errors. The rate is calculated against `parsed_lines` rather than `total_lines` so that lines excluded by parsing or analysis filters do not affect the percentage.

        Returns
        -------
        float
            Error percentage rounded to two decimal places. Returns `0.0` when no entries were successfully parsed.
        """
        if not self.parsed_lines:
            return 0.0
        errors = self.level_counts.get("ERROR", 0) + self.level_counts.get("CRITICAL", 0)
        return round(100 * errors / self.parsed_lines, 2) 

    @property
    def summary_stats(self) -> dict:
        """
        Return a compact set of the most useful analysis statistics.

        This property provides a lightweight summary for consumers that do not need the complete `AnalysisResult` structure. The returned dictionary includes parsed/total line counts, error rate, log-level counts, the five most common errors, and the number of detected anomalies.

        Returns
        -------
        dict:
            Dictionary containing the primary high-level analysis metrics.

        Notes
        -----
        `top_errors` is limited to five entries here even when `top_n` was configured to retain more entries in the full result.
        """
        return {
            "total_lines": self.total_lines,
            "parsed_lines": self.parsed_lines,
            "error_rate_pct": self.error_rate,
            "level_counts": self.level_counts,
            "top_error": self.top_errors[:5],
            "anomaly_count": len(self.anomalies)
        }

    def to_dict(self) -> dict:
        """
        Convert the analysis result into a JSON-serializable dictionary.
        """
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
    """
    Streaming log analyzer that parses and aggregates log-file statistics.

    `LogAnalyzer` coordinates the LogLens analysis pipeline. It delegates log parsing and filtering to `LogParser` and incrementally aggregates the resulting `LogEntry` objects into counters, time-based distributions, frequent-message lists, source statistics, and bounded error/warning samples.

    The analyzer does not retain every parsed entry in memory. Instead, it maintains only the aggregate statistics and the configured number of representative samples. This makes it suitable for processing large log files.

    Parameters
    ----------
    top_n:
        Maximum number of most-frequent messages, errors and warnings to retain in the final result.
    sample_size:
        Maximum number of representative error and warning entries to store.
    show_progress:
        If `True`, display a Rich progress indicator while processing the file.
    parser:
        Optional `LogParser` instance. Supplying one allows callers to customize or reuse parser configuration.

    Notes
    -----
    `LogAnalyzer` is responsible for aggregation, not log parsing. Parsing rules and entry filtering are delegated to `LogParser`.
    """
    def __init__(
        self,
        top_n: int = 20,
        sample_size: int = 50,
        show_progress: bool = True,
        parser: LogParser | None = None,
    ) -> None:
        """
        Initialize a log analyzer with aggregation and parser settings
        """
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
        """
        Analyze a log file and return its aggregated statistics.

        The file is processed as a stream through `LogParser` rather than loading all log entries into memory at once. Each parsed entry is incrementally added to counters and time-based distributions, while only the configured number of representative error and warning samples are retained.

        Filtering is performed by the parser before entries reach the aggregation stage. The optional filters can therefore be combined to analyze only the portion of the log relevant to the caller.

        Parameters
        ----------
        path:
            Path to the log file to analyze.
        pattern_filter:
            Optional regular-expression pattern. Only log lines matching this pattern are included in the analysis. The pattern is compiled with case-insensitive matching.
        date_from:
            Optional inclusive lower bound for the entry timestamp.
        date_to:
            Optional inclusive upper bound for the entry timestamp.
        levels:
            Optional list of log levels to include, for example `["ERROR", "CRITICAL"]`.

        Returns
        -------
        AnalysisResult
            Complete analysis result containing file metadata, level counts, frequent messages, time distributions, source counts, representative samples and analysis timing information.

        Raises
        ------
        ApplicationException
            If `pattern_filter` is not a valid regular expression. The original `re.error` is chained as the cause.

        Notes
        -----
        `total_lines` represents the number of physical lines in the file, while `parsed_lines` represents entries that passed parsing and the supplied filters.

        The returned `error_rate` is calculated from `parsed_lines` and counts both `ERROR` and `CRITICAL` entries as errors.

        The analyzer records the earliest and latest timestamps encountered among the entries that were actually processed.
        """

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
        """
        Lazily wrap a log-entry iterator with a Rich progress display
        """
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), TimeRemainingColumn(), console=console, transient=True) as progress:
            task = progress.add_task(f"Analyzing [bold cyan]{filename}[/]", total=total)
            for entry in entries:
                progress.advance(task)
                yield entry
            

    def _process_entry(self, entry: LogEntry, level_counter: Counter, error_counter: Counter, warning_counter: Counter, message_counter: Counter, source_counter: Counter, timeline: defaultdict, hourly: defaultdict, daily: defaultdict, sample_errors: list, sample_warnings: list) -> None:
        """
        Add one parsed log entry to the analyzer's aggregate statistics
        """
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
        """
        Convert a parsed ``LogEntry`` into the dictionary format used for samples
        """
        return {
            "line_number": entry.line_number,
            "level": entry.level.value,
            "timestamp": entry.timestamp_str,
            "message": entry.message,
            "sources": entry.sources
        }
