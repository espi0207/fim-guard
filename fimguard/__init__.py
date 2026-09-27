"""Monitor de integridad de archivos (FIM) con línea base firmada con HMAC."""

from .baseline import BaselineError, BaselineTampered
from .diff import Change, compare
from .scanner import FileRecord, scan

__all__ = ["BaselineError", "BaselineTampered", "Change", "FileRecord", "compare", "scan"]
__version__ = "1.0.0"
