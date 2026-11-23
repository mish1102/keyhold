"""Entry point: ``python -m keyhold``."""

from __future__ import annotations

import ctypes
import os
import resource
import sys

PR_SET_DUMPABLE = 4


def harden_process() -> None:
    """Keep decrypted secrets out of core dumps and away from same-user
    debuggers (ptrace) where the OS allows it. Best effort."""
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    except (OSError, AttributeError):
        pass
    os.umask(0o077)


def main() -> int:
    harden_process()
    from .ui.app import main as ui_main

    return ui_main(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
