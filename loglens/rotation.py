"""
Rotation and Compression Module

Provides:
--------

- Functions: compress_file and decompress_file standalone helper for manual compression operations.
- Function: compress_old_logs (find log files older than N days in a dir and compress each).
- Class: CompressTimedRotatingFileHandler it extends class `logging.handlers.TimedRotatingFileHandler` to gzip the rotated file immediately after rollover.

"""

from __future__ import annotations
import gzip
from pathlib import Path
import shutil
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime, timedelta


def compress_file(
    src: str | Path,
    fmt: str = "gz",
    *,
    keep_original: bool = False,
    chunk_size: int = 64 * 1024,
) -> Path:
    """
    Compress `src` into `<src>.gz` streaming chunk by chunk.

    Parameters:
    ----------
        src (str | Path):
            Path to the plain log file to compress.
        fmt (str, optional):
            compression format: `"gz"`
        keep_original (bool, optional):
            If False (default), the source file is removed once compression succeds. If True, the original stays.
        chunk_size (int, optional):
            Bytes per read - keep memory usage low even on multi-GB logs.

    Returns:
    -------
            Path:
                Path of the new compressed file.

    Raises:
    ------
        FileNotFoundError:
            If `src` does not exists.
        ValueError:
            If format is not `"gz"`.
        RuntimeError:
            If not able to compress the file.
    """
    src_path = Path(src)
    if not src_path.exists():
        raise FileNotFoundError(f"Cannot compress - Source not found: {src_path}")
    if not src_path.is_file():
        raise ValueError(f"Cannot compress a Directory: {src_path}")

    fmt = fmt.lower().lstrip(".")
    if fmt == "gz":
        suffix = ".gz"
        opener = gzip.open
    else:
        raise ValueError(f"Unsuppported Compression Format: {fmt!r} (use 'gz')")

    dst_path = src_path.with_suffix(src_path.suffix + suffix)

    try:
        with open(src_path, "rb") as src_fh, opener(dst_path, "wb") as dst_fh:
            shutil.copyfileobj(src_fh, dst_fh, length=chunk_size)
    except Exception as e:
        raise RuntimeError(f"Failed to copy {src_path} to {dst_path}") from e

    if not keep_original:
        src_path.unlink()

    return dst_path


def decompress_file(
    src: str | Path, *, keep_compressed: bool = True, chunk_size: int = 64 * 1024
) -> Path:
    """
    Decompress a `".gz"` file back to its plain form.

    Parameters:
    ----------
        src (str | Path):
            Path to the compressed file.
        keep_compressed (bool, optional):
            If True (default), the compressed file remains. If False, removed.
        chunk_size (int, optional):
            Streaming chunk size.

    Returns:
    -------
            Path:
                Path of the decompressed file (the compressed suffix stripped).

    Raises:
    ------
        FileNotFoundError:
            If `src` does not exists.
        ValueError:
            If format is not `"gz"`.
        RuntimeError:
            If not able to compress the file.
    """
    src_path = Path(src)
    if not src_path.exists():
        raise FileNotFoundError(f"Cannot decompress - Source not found: {src_path}")

    extension = src_path.suffix.lower()
    if extension == ".gz":
        opener = gzip.open
    else:
        raise ValueError(f"Not supported compressed file: {src_path}")

    # strip the .gz
    dst_path = src_path.with_suffix("")

    try:
        with opener(src_path, "rb") as src_fh, open(dst_path, "wb") as dst_fh:
            shutil.copyfileobj(src_fh, dst_fh, length=chunk_size)
    except Exception as e:
        raise RuntimeError(f"Failed to copy {src_path} to {dst_path}") from e

    if not keep_compressed:
        src_path.unlink()

    return dst_path


def compress_old_logs(
    directory: str | Path,
    *,
    older_than_days: int = 1,
    fmt: str = "gz",
    glob_pattern: str = "*.log",
    skip_active: str | None = None,
) -> list[Path]:
    """
    Compress every log file in directory whose `mtime` is older then `older_than_days` days. Already compressed files are skipped.

    Parameters:
    ----------
        directory (str | Path):
            Folder to scan.
        older_than_days (int, optional):
            Files modified strictly more than this many days ago are compressed. Defaults to 1 (yesterday and earlier).
        fmt (str, optional):
            `"gz"`
        glob_pattern (str, optional):
            which files to considered. Defaults to `"*.log"`.
        skip_active (str | None, optional):
            Filename to skip even if it matches the pattern - typically the currently - active log file. Pass just the basename.

    Returns:
    -------
            list[Path]: Paths of every newly created compressed file (empty if nothing comes).

    Raises:
    ------
        NotADirectoryError:
            If Folder is not received.
    """
    dir = Path(directory)
    if not dir.is_dir():
        raise NotADirectoryError(f"Not a directory: {dir}")
    cutoff = datetime.now() - timedelta(days=older_than_days)
    compressed: list[Path] = []

    for path in sorted(dir.glob(glob_pattern)):
        if path.suffix.lower() in (".gz",):
            continue
        if skip_active and path.name == skip_active:
            continue
        if not path.is_file():
            continue
        mtime = datetime.fromtimestamp(path.stat().st_mtime)
        if mtime > cutoff:
            continue
        compressed.append(compress_file(path, fmt=fmt))

    return compressed


class CompressTimedRotatingFileHandler(TimedRotatingFileHandler):
    """
    A class `TimedRotatingFileHandler` that gzip compresses each rotated file immediately after the rollover.

    Example:
    -------
        app.log (active - today's log)
        app.2026-08-15.log.gz
        app.2026-08-14.log.gz

    Parameters:
    ----------
        All the parameters are forwarded to class `logging.Handler.TimedRotatingFileHandler` excpet compression_format.
    """

    def __init__(
        self,
        filename: str,
        when: str = "midnight",
        interval: int = 1,
        backupCount: int = 7,
        encoding: str | None = "utf-8",
        delay: bool = False,
        utc: bool = False,
        compression_format: str = "gz",
    ) -> None:
        super().__init__(
            filename=filename,
            when=when,
            interval=interval,
            backupCount=backupCount,
            encoding=encoding,
            delay=delay,
            utc=utc,
        )
        fmt = compression_format.lower().lstrip(".")
        if fmt not in ("gz",):
            raise ValueError(f"Unsupported compression format: {fmt!r}")
        self.compression_format = compression_format

    def doRollover(self) -> None:
        super().doRollover()
        log_dir = Path(self.baseFilename).parent
        active_name = Path(self.baseFilename).name
        for path in log_dir.iterdir():
            if not path.is_file():
                continue
            if path.name == active_name:
                continue
            if path.suffix.lower() in (".gz",):
                continue
            if not path.name.startswith(active_name + "."):
                continue
            try:
                compress_file(path, fmt=self.compression_format)
            except OSError:
                pass
