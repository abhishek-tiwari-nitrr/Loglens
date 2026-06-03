from __future__ import annotations
import re
from datetime import datetime

PYTHON_LOG_PATTERN = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s*"
    r"[-\s]*(?P<level>DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|FATAL|NOTICE|TRACE)[-\s:]*"
    r"(?P<message>.*)",
    re.IGNORECASE
)

SYSLOG_YEAR = datetime.now().year

# Level-only detection (fallback)
LEVEL_PATTERN = re.compile(
    r'\b(DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|FATAL|NOTICE|TRACE)\b',
    re.IGNORECASE,
)