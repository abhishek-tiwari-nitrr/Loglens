""" 
Logger for the Application, Scripts and Notebooks.

Nothing in this module runs at import time. Call `get_logger` when you actually want a configured logger:

    from loglens import get_logger

    log = get_logger("etl")
    log.info("starting run")

By default this attaches a console handler and a rotating file handler (`./logs/<name>.log`). Every aspect can be overridden per call or via `LOGLENS_*` environment variables (see `loglens.constant.config`).

Repeated calls with the same name return the same logger without duplicating handlers, so it is safe to call `get_logger` at the top of every module and safe to rerun notebook cells.
"""

from __future__ import annotations
import os, logging, sys
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path
from loglens.rotation import CompressTimedRotatingFileHandler

__all__ = ["get_logger", "reset_logger", "DEFAULT_FORMAT"]
DEFAULT_FORMAT = "[%(acetime)s] [%(levelname)-8s] [%(name)s: %(lineno)d] %(message)s"
_configured: set[str] = set()


def _coerce_level(level: int | str | None, default: int) -> int:
    """
    Turn a log level into the numeric value expected by the logging module.

    If no level is given use the default. Numbers are returned as in while name like "INFO" converted in the matching logging value.

    Raise ValueError:
    --------------
        If the given log level isn't a valid logging level.

    """
    if level is None:
        return default
    if isinstance(level, int):
        return level
    name = str(level).upper()
    mapping = getattr(logging, "getLevelNamesMapping", lambda: logging._nameToLevel)()
    try:
        return mapping[name]
    except KeyError:
        raise ValueError(f"Unkown log level: {level!r}") from None


def _in_notebook() -> bool:
    """
    Check whether the code is running inside the Jupyter/IPython notebook or Google Colab

    If Ipython is not installed or we are not running the code in interactive notebook session it will return False.

    """
    try:
        from IPython import get_ipython

        shell = get_ipython()
        if shell is None:
            return False
        return shell.__class__.__name__ in ("ZMQInteractiveShell", "Shell")
    except ImportError:
        return False


def _build_file_handler(
    log_file: Path,
    rotation: str,
    max_bytes: int,
    backup_count: int,
    compress: bool,
    compression_format: str,
    rotation_time: str,
) -> logging.Handler:
    """
    Create the right file handler based on the chosen rotation settings.

    Daily rotation uses a time based handler with optional compression. Size based rotation uses a handler that starts a new file once it reaches the configured size.

    Parameters:
    ----------
        log_file (Path):
            Path where the log file will be stored.
        rotation (str):
            How log should rotates: `'daily'` or `'size'`
        max_bytes (int):
            Maximum file size before rotating when using `'size'`.
        backup_count (int):
            Number of old log files to keep.
        compress (bool):
            Whether to compress rotated files.
        compression_format (str):
            Compression format to use for rotated files.
        rotation_time (str):
            Time interval used for daily rotation.

    Returns:
    -------
        logging.Handler:
            A configured file logging handler.


    Raises:
    ------
        ValueError:
            If an unsupported rotation type is provided.
    """
    if rotation == "daily":
        if compress:
            return CompressTimedRotatingFileHandler(
                filename=str(log_file),
                when=rotation_time,
                interval=1,
                backupCount=backup_count,
                encoding="utf-8",
                compression_format=compression_format,
            )
        else:
            return TimedRotatingFileHandler(
                filename=str(log_file),
                when=rotation_time,
                interval=1,
                backupCount=backup_count,
                encoding="utf-8",
            )

    if rotation == "size":
        return RotatingFileHandler(
            filename=str(log_file),
            mode="a",
            encoding="utf-8",
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
    raise ValueError(f"Rotation must be 'daily', 'size' or 'none', got {rotation!r}")


def get_logger(
    name: str | None = None,
    *,
    level: int | str | None = None,
    log_dir: str | Path | None = None,
    log_file: str | Path | None = None,
    console: bool = True,
    file: bool = True,
    rotation: str | None = None,
    max_bytes: int | None = None,
    backup_count: int | None = None,
    compress: bool | None = None,
    fmt: str | None = None,
    datefmt: str | None = None,
    force: bool = False,
) -> logging.Logger:
    """
    Create and Configure a logger for the Application.

    By default, logs are written to the console and to a log file. The logger can be customized with different log level, file locations, rotation settings, formatting and compression.

    If a logger with the same name is already configured, it is returned as is. Pass force = True, if you want to remove the existing handlers and configured it again.

    Parameters:
    ----------
        name (str | None, optional):
            Logger Name. Defaults to `'loglens.app'` so it never collides with the package's own internal loggers.
        level (int | str | None, optional):
            Minimum serverity - an int `(logging.DEBUG)` or name `('debug')`. Defaults to `LOGLENS_LOG_LEVEL` or `INFO`.
        log_dir (str | Path | None, optional):
            Directory for log files. Defaults to `LOGLENS_LOG_DIR` or `./logs`. Created on first use not on import.
        log_file (str | Path | None, optional):
            Path for the log file Overrides `log_dir`. Defaults to `<log_dir>/<name>`.
        console (bool, optional):
            Attach a stream handler writing to stderr. Defaults to True.
        file (bool, optional):
            Attach a rotating file handler. Defaults to True. Set to `False` for a console only logger. e.g. in CI
        rotation (str | None, optional):
            `'daily'` (rotate at midnight, gzip old files). `'size'` (rotates at `max_bytes`) or `'none'`.Defaults to `LOGLENS_ROTATION_MODE` or `'daily'`.
        max_bytes (int | None, optional):
            Size threshold for `rotation='size'`. Defaults to 5 MB.
        backup_count (int | None, optional):
            Rotated files to keep. Defaults to 5.
        compress (bool | None, optional):
            GZip rotated file when `rotation='daily'`. Defaults to True.
        fmt (str | None, optional):
            Formatter Pattern
        datefmt (str | None, optional):
            Date Format
        force (bool, optional):
            Tear down existing handlers and rebuild. Without this, callig `get_logger` again with the same name returns the existing logger untouched.

    Returns:
    --------
        logging.Logger:
            A configured instance.

    Raises:
    ------
        ValueError: If logging level or rotation mode is invalid.

    Example:
    -------
    Console + daily rotated file under ./logs:
        ` log = get_logger("etl") `
    Console only, debug level:
        ` log = get_logger("etl", file = False, level="debug")`
    Everything into one explicit file, no console noise:
        ` log = get_logger("etl", console=False, log_file="runs/batch.log", rotation="size")`
    """
    from loglens.constants import config

    name = name or "loglens.app"
    log = logging.getLogger(name)

    if log.handlers and not force:
        return log
    if force:
        for handler in list(log.handlers):
            handler.close()
            log.removeHandler(handler)
    resolved_level = _coerce_level(level, config.LOG_LEVEL)
    formatter = logging.Formatter(
        fmt or config.LOG_FORMAT or DEFAULT_FORMAT,
        datefmt=datefmt or config.DATE_FORMAT,
    )

    if console:
        stream = sys.stdout if _in_notebook() else sys.stderr
        console_handle = logging.StreamHandler(stream)
        console_handle.setFormatter(formatter)
        log.addHandler(console_handle)

    resolved_rotation = (rotation or config.ROTATION_MODE).lower()

    if resolved_rotation not in (
        "daily",
        "size",
        "none",
    ):
        raise ValueError(
            f"Rotation must be 'daily', 'size' or 'none', got {resolved_rotation!r}"
        )

    if file:
        if log_file is not None:
            file_path = Path(log_file)
        else:
            base_dir = Path(log_dir) if log_dir is not None else Path(config.LOG_DIR)
            safe_name = name.replace("/", "_").replace("\\", "_")
            file_path = base_dir / f"{safe_name}.log"
        file_path.parent.mkdir(parents=True, exist_ok=True)

        if resolved_rotation == "none":
            file_handler = logging.Handler = logging.FileHandler(
                str(file_path), encoding="utf-8"
            )
        else:
            file_handler = _build_file_handler(
                log_file=file_path,
                rotation=resolved_rotation,
                max_bytes=(
                    max_bytes if max_bytes is not None else config.MAX_LOG_FILE_SIZE
                ),
                backup_count=(
                    backup_count
                    if backup_count is not None
                    else config.LOG_BACKUP_COUNT
                ),
                compress=(
                    compress if compress is not None else config.COMPRESS_ON_ROTATE
                ),
                compression_format=config.COMPRESSION_FORMAT,
                rotation_time=config.ROTATION_TIME,
            )
        file_handler.setFormatter(formatter)
        log.addHandler(file_handler)

    log.setLevel(resolved_level)
    log.propagate = False
    _configured.add(name)
    return log


def reset_logger(name: str | None = None) -> None:
    targets = [name] if name else list(_configured)
    for target in targets:
        log = logging.getLogger(target)
        a = get_logger()
        for handler in list(log.handlers):
            handler.close()
            log.removeHandler(handler)
            _configured.discard(handler)
