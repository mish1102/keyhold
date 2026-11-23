import time

from keyhold import system


def test_clock_uses_boottime_where_available(monkeypatch):
    calls = []
    monkeypatch.setattr(system.time, "CLOCK_BOOTTIME", 7, raising=False)
    monkeypatch.setattr(system.time, "clock_gettime", lambda cid: calls.append(cid) or 1.0)
    system.clock()
    assert calls == [7]


def test_clock_falls_back_to_monotonic_clock_on_macos(monkeypatch):
    # macOS has no CLOCK_BOOTTIME; its CLOCK_MONOTONIC keeps counting during sleep.
    calls = []
    monkeypatch.delattr(system.time, "CLOCK_BOOTTIME", raising=False)
    monkeypatch.setattr(system.time, "clock_gettime", lambda cid: calls.append(cid) or 1.0)
    system.clock()
    assert calls == [time.CLOCK_MONOTONIC]


def test_shortcut_labels(monkeypatch):
    monkeypatch.setattr(system, "IS_MACOS", False)
    assert system.shortcut_label("Ctrl+Shift+C") == "Ctrl+Shift+C"
    monkeypatch.setattr(system, "IS_MACOS", True)
    assert system.shortcut_label("Ctrl+Shift+C") == "⌘Shift+C"
