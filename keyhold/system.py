"""Small operating-system differences (Linux and macOS)."""

from __future__ import annotations

import sys
import time

IS_MACOS = sys.platform == "darwin"


def clock() -> float:
    """Seconds from a clock that keeps counting while the computer sleeps.

    Linux: CLOCK_BOOTTIME (CLOCK_MONOTONIC stops during suspend there).
    macOS: CLOCK_MONOTONIC, which Apple documents as continuing during sleep.
    """
    clock_id = getattr(time, "CLOCK_BOOTTIME", None)
    if clock_id is None:
        clock_id = time.CLOCK_MONOTONIC
    return time.clock_gettime(clock_id)


def shortcut_label(keys: str) -> str:
    """'Ctrl+L' on Linux, '⌘L' on macOS (GTK's <Primary> is ⌘ there)."""
    return keys.replace("Ctrl+", "⌘") if IS_MACOS else keys
