from __future__ import annotations
import sys
from typing import Any


class ApplicationException(Exception):
    """
    Custom exception that gives error messages with contextual debugging information such as the file name and line number where the original exception occurred.

    Attributes:
        - lineno (int | str): Line number where the exception was raised
        - filename (str): Name of the file where the exception occurred

    Args:
        error_message (_type_): readable error message
        sys_error_details (Exception | None): Original exception instance. Defaults to None.

    """

    def __init__(
        self,
        error_message: str,
        sys_error_details: BaseException | None = None,
        **context: Any
    ) -> None:
        _, _, tb = sys.exc_info()
        if tb is not None:
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

        Format: `filename:lineno | message | context`

        Returns:
            str: Compact one-line representation.
        """
        base =  f"{self.filename}:{self.lineno} | {self.args[0]}"
        if self.context:
            rendered = " ".join(f"{k}={v!r}" for k, v in self.context.items())
            return f"{base} | {rendered}"
        return base

    def __repr__(self) -> str:
        """
        Return an unambiguous string representation of the exception.

        Returns:
            str: Developer-friendly representation of the exception.
        """
        return (
            f"ApplicationException(filename={self.filename!r}, "
            f"lineno={self.lineno!r}, message={self.args[0]!r}), "
            f"contect={self.context!r}"
        )
