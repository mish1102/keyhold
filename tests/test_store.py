import errno
import os
import stat

import pytest

from keyhold import model, store
from keyhold.crypto import KdfCost, WrongPasswordError
from keyhold.store import LockedError, SaveError, VaultBusyError, VaultStore

FAST = KdfCost(memory_kib=1024, iterations=1, lanes=1)


@pytest.fixture
def vs(tmp_path):
    return VaultStore(tmp_path / "data" / "vault.keyhold", cost=FAST, max_backups=3)


def add_login(session, title="Mail", password="pw"):
    item = model.new_item("login", vault_id=session.data.vaults[0].id, now=1.0)
    item.title = title
    item.field("password").value = password
    session.data.add_item(item)
    return item


def test_create_then_unlock_returns_saved_items(vs):
    s = vs.create("master pw")
    add_login(s)
    s.save()
    s.lock()
    s2 = vs.unlock("master pw")
    assert [i.title for i in s2.data.items] == ["Mail"]


def test_create_refuses_to_overwrite_an_existing_vault(vs):
    vs.create("a").lock()
    with pytest.raises(FileExistsError):
        vs.create("b")


def test_unlock_with_wrong_password(vs):
    vs.create("right").lock()
    with pytest.raises(WrongPasswordError):
        vs.unlock("wrong")


def test_vault_file_and_directory_are_private(vs):
    vs.create("pw").lock()
    assert stat.S_IMODE(os.stat(vs.path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(vs.path.parent).st_mode) == 0o700


def test_vault_file_contains_no_plaintext(vs):
    s = vs.create("pw")
    add_login(s, title="VerySecretTitle", password="hunter2hunter2")
    s.save()
    raw = vs.path.read_bytes()
    assert b"VerySecretTitle" not in raw
    assert b"hunter2hunter2" not in raw


def test_failed_save_leaves_previous_file_intact_and_no_temp_files(vs, monkeypatch):
    s = vs.create("pw")
    add_login(s, title="Kept")
    s.save()
    before = vs.path.read_bytes()
    add_login(s, title="Lost")

    def boom(*a, **k):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(store.os, "replace", boom)
    with pytest.raises(SaveError):
        s.save()
    assert vs.path.read_bytes() == before
    leftovers = [p.name for p in vs.path.parent.iterdir() if p.name.startswith(".")]
    assert not s.locked
    assert leftovers == [".keyhold.lock"]


def test_first_save_of_each_session_backs_up_the_previous_file(vs):
    s = vs.create("pw")
    assert vs.backups() == []  # nothing to back up for a brand-new vault
    add_login(s)
    s.save()
    s.save()
    assert len(vs.backups()) == 1
    s.lock()
    s = vs.unlock("pw")
    s.save()
    assert len(vs.backups()) == 2


def test_backups_are_pruned_to_the_newest_max(vs):
    s = vs.create("pw")
    s.lock()
    for _ in range(5):
        s = vs.unlock("pw")
        s.save()
        s.lock()
    assert len(vs.backups()) == 3


def test_backup_opens_with_the_master_password(vs):
    s = vs.create("pw")
    add_login(s, title="Original")
    s.save()
    s.lock()
    s = vs.unlock("pw")
    s.data.items[0].title = "Changed"
    s.save()
    backup = VaultStore(vs.backups()[-1], cost=FAST)
    old = backup.unlock("pw", take_lock=False)
    assert old.data.items[0].title == "Original"


def test_lock_wipes_access(vs):
    s = vs.create("pw")
    s.lock()
    assert s.locked
    with pytest.raises(LockedError):
        _ = s.data
    with pytest.raises(LockedError):
        s.save()


def test_second_unlock_while_open_is_refused(vs):
    s = vs.create("pw")
    with pytest.raises(VaultBusyError):
        vs.unlock("pw")
    s.lock()
    vs.unlock("pw").lock()


def test_change_password_switches_key_and_keeps_old_backups_until_next_unlock(vs):
    s = vs.create("old pw")
    add_login(s)
    s.save()
    s.lock()
    s = vs.unlock("old pw")
    s.save()  # backup made under the old password
    old_backups = vs.backups()
    s.change_password("new pw", delete_old_backups=True)
    assert s.check_password("new pw")
    assert not s.check_password("old pw")
    # Until the new password has been used to unlock, old-password backups stay:
    # they are the way back if the new password was mistyped twice.
    assert all(b.exists() for b in old_backups)
    assert any(_opens(b, "old pw") for b in vs.backups())
    s.lock()
    with pytest.raises(WrongPasswordError):
        vs.unlock("old pw")
    s = vs.unlock("new pw")
    assert len(s.data.items) == 1
    assert "retire_backups" not in s.data.settings
    assert vs.backups(), "a fresh backup under the new password exists"
    for b in vs.backups():
        assert _opens(b, "new pw")


def _opens(path, password):
    try:
        VaultStore(path, cost=FAST).unlock(password, take_lock=False)
        return True
    except WrongPasswordError:
        return False


def test_change_password_keeping_old_backups(vs):
    s = vs.create("old pw")
    s.save()
    s.change_password("new pw", delete_old_backups=False)
    s.lock()
    vs.unlock("new pw").lock()
    assert any(_opens(b, "old pw") for b in vs.backups())


def test_change_password_write_failure_changes_nothing(vs, monkeypatch):
    s = vs.create("old pw")
    add_login(s)
    s.save()

    def boom(*a, **k):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(store.os, "replace", boom)
    with pytest.raises(SaveError):
        s.change_password("new pw")
    monkeypatch.undo()
    assert s.check_password("old pw")
    assert "retire_backups" not in s.data.settings
    s.save()
    s.lock()
    vs.unlock("old pw")


def test_change_password_in_two_steps_does_slow_work_without_side_effects(vs):
    s = vs.create("old pw")
    before = vs.path.read_bytes()
    new_key = s.prepare_password_change("new pw")
    assert vs.path.read_bytes() == before
    s.apply_password_change(new_key)
    s.lock()
    vs.unlock("new pw")


def test_unsaved_changes_survive_lock_encrypted_in_memory(vs, monkeypatch):
    s = vs.create("pw")
    s.save()

    def boom(*a, **k):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(store.os, "replace", boom)
    add_login(s, title="Unsaved", password="unsaved-secret-value")
    with pytest.raises(SaveError):
        s.save()
    assert s.dirty
    s.lock()
    monkeypatch.undo()
    assert vs.pending is not None
    assert b"unsaved-secret-value" not in vs.pending and b"Unsaved" not in vs.pending
    with pytest.raises(WrongPasswordError):
        vs.unlock("wrong")
    assert vs.pending is not None, "a failed unlock keeps the pending changes"
    s = vs.unlock("pw")
    assert vs.pending is None
    assert [i.title for i in s.data.items] == ["Unsaved"]
    assert s.dirty and s.recovered["data"]
    s.save()
    s.lock()
    assert [i.title for i in vs.unlock("pw").data.items] == ["Unsaved"]


def test_editor_draft_survives_lock(vs):
    s = vs.create("pw")
    draft = {"item": {"id": "x", "category": "login", "title": "Half typed"}, "is_new": True}
    s.set_draft(draft)
    s.lock()
    s = vs.unlock("pw")
    assert s.recovered["draft"] == draft
    assert not s.dirty


def test_clean_lock_leaves_nothing_pending(vs):
    s = vs.create("pw")
    s.lock()
    assert vs.pending is None
    assert vs.unlock("pw").recovered is None


def test_backups_are_ordered_by_sequence_not_clock(vs, monkeypatch):
    s = vs.create("pw")
    s.lock()
    real_gmtime = store.time.gmtime
    monkeypatch.setattr(store.time, "gmtime", lambda *a: real_gmtime(4_000_000_000))  # clock in 2096
    s = vs.unlock("pw"); s.save(); s.lock()
    monkeypatch.undo()
    for _ in range(4):
        s = vs.unlock("pw"); s.save(); s.lock()
    names = [b.name for b in vs.backups()]
    assert "2096" not in names[-1], "newest is decided by sequence, not by the (wrong) clock"
    real = [n for n in names if "2096" not in n]
    assert [n.split("-")[1] for n in real] == ["000003", "000004", "000005"], "recent real backups survive"


def test_backup_just_written_is_never_pruned(tmp_path):
    vs0 = VaultStore(tmp_path / "vault.keyhold", cost=FAST, max_backups=0, daily_backups=0)
    s = vs0.create("pw")
    s.save()
    assert len(vs0.backups()) == 1


def test_one_backup_per_day_is_kept_for_older_days(vs):
    s = vs.create("pw")
    vs.backup_dir.mkdir(exist_ok=True)
    data = vs.path.read_bytes()
    for seq, day in enumerate(["20260101", "20260101", "20260102", "20260103"], start=1):
        (vs.backup_dir / f"vault-{seq:06d}-{day}T120000Z.keyhold").write_bytes(data)
    for _ in range(4):
        s.lock()
        s = vs.unlock("pw")
        s.save()
    names = [b.name for b in vs.backups()]
    assert "vault-000002-20260101T120000Z.keyhold" in names  # newest of Jan 1
    assert "vault-000001-20260101T120000Z.keyhold" not in names
    assert "vault-000003-20260102T120000Z.keyhold" in names
    assert "vault-000004-20260103T120000Z.keyhold" in names


def test_export_encrypted_copy(vs, tmp_path):
    s = vs.create("pw")
    add_login(s, title="Exported")
    s.save()
    dest = tmp_path / "backup.keyhold"
    s.export_encrypted(dest)
    copy = VaultStore(dest, cost=FAST).unlock("pw", take_lock=False)
    assert copy.data.items[0].title == "Exported"
    assert stat.S_IMODE(os.stat(dest).st_mode) == 0o600


def test_default_data_dir_honors_env(monkeypatch, tmp_path):
    monkeypatch.setenv("KEYHOLD_DATA_DIR", str(tmp_path / "x"))
    assert store.default_vault_path() == tmp_path / "x" / "vault.keyhold"
    monkeypatch.delenv("KEYHOLD_DATA_DIR")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert store.default_vault_path() == tmp_path / "xdg" / "keyhold" / "vault.keyhold"
