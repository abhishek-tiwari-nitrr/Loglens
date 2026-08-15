"""
Custom Exception was used across the package.

Provides:
--------
- Class: ApplicationException keeps the track of where the error happened and can include extra context such as the file, model run, or batch caused the error.

"""

from __future__ import annotations
import sys
from typing import Any


class ApplicationException(Exception):
    """
    Exception that captures the location and context of a failure. It gives error messages with contextual debugging information such as the file name and line number where the original exception occurred.

    Parameters:
    ----------
    error_message (_type_):
        readable error message
    sys_error_details (Exception | None):
        Original exception instance. Defaults to None.
    **context:
        Arbitrary keyword pairs describing the failure site - which file, which run id, which row count. They are appended tot the rendered message and available as the ``context`` arttibute.

    Attributes:
    ----------
    lineno (int | str):
        Line number where the exception was raised
    filename (str):
        Name of the file where the exception occurred
    error_message (str):
        The provided message.
    context (dict):
        The keyword context, possibly empty


    Example:
    -------
    try:
        df = pd.read_parquet(path)
    except Exception as e:
        raise ApplicationException("Failed to read input", e, file=(path)) from e


    """

    def __init__(
        self,
        error_message: str,
        sys_error_details: BaseException | None = None,
        **context: Any,
    ) -> None:
        _, _, tb = sys.exc_info()
        if tb is not None:
            # trying to caught where the error actually happened not where it was caught
            while tb.tb_next is not None:
                tb = tb.tb_next
            self.lineno: Any = tb.tb_lineno
            self.filename: str = tb.tb_frame.f_code.co_filename
        else:
            self.lineno = "NA"
            self.filename = "NA"

        self.error_message = error_message
        self.sys_error_details = sys_error_details
        self.context = context
        super().__init__(self.error_message)

    def __str__(self) -> str:
        """
        Render the exception in a single log-friendly line.

        Render as: `filename:lineno | message | context ``[key = "value" ...]```

        Returns:
        -------
            str:
                Compact one-line representation.
        """
        base = f"{self.filename}:{self.lineno} | {self.args[0]}"
        if self.context:
            rendered = " ".join(f"{k}={v!r}" for k, v in self.context.items())
            return f"{base} | {rendered}"
        return base

    def __repr__(self) -> str:
        """
        Return an unambiguous string representation of the exception.

        Returns:
        -------
            str:
                representation of the exception.
        """
        return (
            f"ApplicationException(filename={self.filename!r}, "
            f"lineno={self.lineno!r}, message={self.args[0]!r}), "
            f"contect={self.context!r}"
        )
