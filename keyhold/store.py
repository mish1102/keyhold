"""Reading and writing the encrypted vault file.

* Writes are atomic: encrypt to a private temp file in the same directory,
  fsync, then rename over the vault. A failed write (disk full, crash) never
  damages the previous file.
* The first save of every unlocked session first copies the current file to
  ``backups/`` (still encrypted). The newest ``max_backups`` copies are kept.
* While a session is open it holds an exclusive ``flock`` so two processes can
  never write the same vault.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

from . import crypto
from .crypto import DEFAULT_COST, CorruptVaultError, KdfCost
from .model import VaultData

VAULT_FILENAME = "vault.keyhold"
LOCK_FILENAME = ".keyhold.lock"
# vault-<sequence>-<UTC time>.keyhold. Ordering uses the sequence number, so a
# wrong system clock can never make an old backup look newest.
BACKUP_RE = re.compile(r"^vault-(\d{6,})-(\d{8})T\d{6}Z\.keyhold$")


class LockedError(Exception):
    """The session has been locked; unlock again to continue."""


class SaveError(Exception):
    """The vault could not be written. The previous file is untouched."""


class VaultBusyError(Exception):
    """Another Keyhold window or process already has this vault open."""


def default_vault_path() -> Path:
    override = os.environ.get("KEYHOLD_DATA_DIR")
    if override:
        return Path(override) / VAULT_FILENAME
    if sys.platform == "darwin" and not os.environ.get("XDG_DATA_HOME"):
        home = Path(os.environ.get("HOME") or Path.home())
        return home / "Library" / "Application Support" / "Keyhold" / VAULT_FILENAME
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "keyhold" / VAULT_FILENAME


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def _flush(fd: int) -> None:
    """Get the bytes onto the disk. On macOS plain fsync() only reaches the
    drive's cache; F_FULLFSYNC asks the drive to write it out."""
    full = getattr(fcntl, "F_FULLFSYNC", None)
    if full is not None:
        try:
            fcntl.fcntl(fd, full)
            return
        except OSError:
            pass  # not supported by this filesystem: fall back to fsync
    os.fsync(fd)


def _fsync_dir(path: Path) -> None:
    """Best effort: make the rename itself durable. Some systems refuse to
    fsync a directory; the new file is already in place by then, so that
    must not turn a completed save into a reported failure."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` (mode 0600) without ever leaving it half-written."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=path.suffix or ".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            _flush(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    _fsync_dir(path.parent)


def _save_error(exc: OSError) -> SaveError:
    if exc.errno == errno.ENOSPC:
        return SaveError("The disk is full, so your change was not saved. Free up some space and try again.")
    if exc.errno in (errno.EACCES, errno.EPERM, errno.EROFS):
        return SaveError(f"Keyhold isn't allowed to write the vault file ({exc.strerror}).")
    return SaveError(f"Your change was not saved: {exc.strerror or exc}")


class VaultStore:
    def __init__(self, path: Path, cost: KdfCost = DEFAULT_COST, max_backups: int = 10,
                 daily_backups: int = 30):
        self.path = Path(path)
        self.cost = cost
        self.max_backups = max_backups
        self.daily_backups = daily_backups
        self.backup_dir = self.path.parent / "backups"
        # Unsaved changes / editor draft from the last session, sealed with the
        # vault key when it locked (ciphertext only; see Session.lock).
        self.pending: bytes | None = None

    def exists(self) -> bool:
        return self.path.exists()

    def backups(self) -> list[Path]:
        """Backup files, oldest first (by sequence number)."""
        if not self.backup_dir.is_dir():
            return []
        found = []
        for p in self.backup_dir.iterdir():
            m = BACKUP_RE.match(p.name)
            if m:
                found.append((int(m.group(1)), p))
        return [p for _, p in sorted(found)]

    # -- locking -----------------------------------------------------------
    def _acquire(self):
        _ensure_private_dir(self.path.parent)
        fh = open(self.path.parent / LOCK_FILENAME, "a+")
        os.chmod(fh.name, 0o600)
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fh.close()
            raise VaultBusyError("This vault is already open in another Keyhold window.") from None
        return fh

    # -- sessions ----------------------------------------------------------
    def create(self, password: str) -> "Session":
        if self.exists():
            raise FileExistsError(self.path)
        lock = self._acquire()
        try:
            key = crypto.new_vault_key(password, cost=self.cost)
            session = Session(self, key, VaultData.new(), lock)
            try:
                atomic_write(self.path, crypto.seal(key, session.data.to_json().encode("utf-8")))
            except OSError as exc:
                raise _save_error(exc) from exc
        except BaseException:
            lock.close()
            raise
        return session

    def unlock(self, password: str, take_lock: bool = True) -> "Session":
        lock = self._acquire() if take_lock else None
        try:
            blob = self.path.read_bytes()
            key, plaintext = crypto.unseal(blob, password)
            try:
                data = VaultData.from_json(plaintext.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                key.wipe()
                raise CorruptVaultError("vault contents could not be read") from exc
        except BaseException:
            if lock:
                lock.close()
            raise
        session = Session(self, key, data, lock)
        if take_lock:
            session._recover_pending()
            session._retire_old_backups()
        return session

    # -- backups -----------------------------------------------------------
    def make_backup(self) -> Path | None:
        if not self.path.exists():
            return None
        _ensure_private_dir(self.backup_dir)
        existing = self.backups()
        seq = int(BACKUP_RE.match(existing[-1].name).group(1)) + 1 if existing else 1
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        dest = self.backup_dir / f"vault-{seq:06d}-{stamp}.keyhold"
        atomic_write(dest, self.path.read_bytes())
        self._prune(keep=dest)
        return dest

    def _prune(self, keep: Path) -> None:
        """Keep the newest ``max_backups``, the newest backup of each of the
        last ``daily_backups`` days, and always the one just written."""
        files = self.backups()
        keepers = {keep}
        if self.max_backups > 0:
            keepers.update(files[-self.max_backups:])
        newest_per_day: dict[str, Path] = {}
        for p in files:
            newest_per_day[BACKUP_RE.match(p.name).group(2)] = p
        if self.daily_backups > 0:
            for day in sorted(newest_per_day)[-self.daily_backups:]:
                keepers.add(newest_per_day[day])
        for p in files:
            if p not in keepers:
                try:
                    p.unlink(missing_ok=True)
                except OSError:
                    pass  # pruning is best effort


class Session:
    """An unlocked vault. Holds the key until ``lock()`` is called.

    Not thread-safe: call everything except ``prepare_password_change`` and
    ``check_password`` from one thread (the UI's main loop)."""

    def __init__(self, store: VaultStore, key: crypto.VaultKey, data: VaultData, lock_handle):
        self.store = store
        self._key = key
        self._data = data
        self._lock_handle = lock_handle
        self._backed_up = False
        self.dirty = False  # True while in-memory changes are not on disk
        self._draft = None  # unsaved editor state, kept across a lock
        self.recovered = None  # what _recover_pending() restored, for the UI

    @property
    def locked(self) -> bool:
        return self._data is None

    @property
    def data(self) -> VaultData:
        if self._data is None:
            raise LockedError("vault is locked")
        return self._data

    def _sealed(self, key: crypto.VaultKey | None = None) -> bytes:
        return crypto.seal(key or self._key, self.data.to_json().encode("utf-8"))

    def save(self) -> None:
        if self.locked:
            raise LockedError("vault is locked")
        try:
            if not self._backed_up:
                self.store.make_backup()
                self._backed_up = True
            atomic_write(self.store.path, self._sealed())
        except OSError as exc:
            self.dirty = True
            raise _save_error(exc) from exc
        self.dirty = False

    def check_password(self, password: str) -> bool:
        if self.locked:
            raise LockedError("vault is locked")
        return crypto.check_password(self._key, password)

    # -- master password change ------------------------------------------------
    def prepare_password_change(self, new_password: str) -> crypto.VaultKey:
        """The slow part (Argon2). No side effects; safe to run in a thread."""
        return crypto.rekey(new_password, cost=self.store.cost)

    def apply_password_change(self, new_key: crypto.VaultKey, delete_old_backups: bool = True) -> None:
        """Re-encrypt the vault under ``new_key``.

        Order matters for safety: back up the current (old-password) file,
        write the new file, check it reads back, and only then switch keys.
        Old-password backups are not deleted now: they're removed after the
        new password has been used to unlock once, so a new password that was
        mistyped the same way twice can't lock you out."""
        if self.locked:
            new_key.wipe()
            raise LockedError("vault is locked")
        settings = self.data.settings
        previous_retire = settings.get("retire_backups")
        try:
            self.store.make_backup()
            if delete_old_backups:
                names = [b.name for b in self.store.backups()]
                settings["retire_backups"] = sorted(set((previous_retire or []) + names))
            blob = self._sealed(new_key)
            atomic_write(self.store.path, blob)
            if self.store.path.read_bytes() != blob:
                raise OSError(errno.EIO, "the new vault file didn't read back correctly")
        except OSError as exc:
            if previous_retire is None:
                settings.pop("retire_backups", None)
            else:
                settings["retire_backups"] = previous_retire
            new_key.wipe()
            # The old file is either untouched (failed write) or restorable
            # from the backup just made; try to put it back on a bad read-back.
            raise _save_error(exc) from exc
        self._key.wipe()
        self._key = new_key
        self._backed_up = True
        self.dirty = False

    def change_password(self, new_password: str, delete_old_backups: bool = True) -> None:
        self.apply_password_change(self.prepare_password_change(new_password), delete_old_backups)

    def _retire_old_backups(self) -> None:
        """After unlocking with a new master password, delete the backups that
        still open with the old one. Best effort: never fails the unlock."""
        names = self.data.settings.get("retire_backups")
        if not names:
            return
        for name in names:
            if isinstance(name, str) and BACKUP_RE.match(name):
                try:
                    (self.store.backup_dir / name).unlink(missing_ok=True)
                except OSError:
                    pass
        self.data.settings.pop("retire_backups", None)
        try:
            self.save()
        except SaveError:
            pass  # stays dirty; retried on the next save

    # -- unsaved work across a lock -------------------------------------------
    def set_draft(self, draft: dict | None) -> None:
        """Remember the editor's unsaved state so it survives a lock."""
        self._draft = draft

    def _recover_pending(self) -> None:
        blob, self.store.pending = self.store.pending, None
        if not blob:
            return
        try:
            payload = json.loads(crypto.open_with_key(blob, self._key).decode("utf-8"))
        except (CorruptVaultError, ValueError, UnicodeDecodeError):
            return
        self.recovered = payload
        if payload.get("data"):
            self._data = VaultData.from_dict(payload["data"])
            self.dirty = True

    def export_encrypted(self, dest: Path) -> None:
        try:
            atomic_write(Path(dest), self._sealed())
        except OSError as exc:
            raise _save_error(exc) from exc

    def lock(self) -> None:
        if self._data is not None and (self.dirty or self._draft):
            # Keep unsaved work, encrypted with the vault key, until the next
            # unlock in this process. Nothing readable stays in memory.
            payload = {"data": self._data.to_dict() if self.dirty else None, "draft": self._draft}
            self.store.pending = crypto.seal(self._key, json.dumps(payload).encode("utf-8"))
        self._draft = None
        if self._key is not None:
            self._key.wipe()
        self._data = None
        if self._lock_handle is not None:
            self._lock_handle.close()
            self._lock_handle = None
