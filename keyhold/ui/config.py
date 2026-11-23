"""Non-secret UI preferences that are needed before unlocking (theme, window
size). Stored unencrypted in ~/.config/keyhold/config.json. Never put anything
about vault contents here."""

from __future__ import annotations

import json
import os
from pathlib import Path

ALLOWED = {"theme", "width", "height"}


def path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    if os.environ.get("KEYHOLD_DATA_DIR"):
        return Path(os.environ["KEYHOLD_DATA_DIR"]) / "config.json"
    return Path(base) / "keyhold" / "config.json"


def load() -> dict:
    try:
        data = json.loads(path().read_text())
        return {k: v for k, v in data.items() if k in ALLOWED} if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def update(**values) -> None:
    data = load()
    data.update({k: v for k, v in values.items() if k in ALLOWED})
    p = path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data))
    except OSError:
        pass  # cosmetic settings only
