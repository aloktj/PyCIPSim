"""Logging helpers for PyCIPSim."""
from __future__ import annotations

import logging
from typing import Optional

from rich.logging import RichHandler


def configure_logging(verbose: bool = False, level: Optional[int] = None) -> None:
    """Configure logging with sensible defaults."""

    resolved_level = level or (logging.DEBUG if verbose else logging.INFO)
    logging.basicConfig(
        level=resolved_level,
        format="%(message)s",
        datefmt="%H:%M:%S",
        handlers=[RichHandler(rich_tracebacks=True, show_time=False)],
    )
    logging.getLogger("pycomm3").setLevel(logging.WARNING)
