from keyhold import model
from keyhold.model import Field, VaultData


def test_new_vault_data_has_one_personal_vault_and_defaults():
    data = VaultData.new()
    assert [v.name for v in data.vaults] == ["Personal"]
    assert data.items == []
    assert data.settings["auto_lock_minutes"] == 10
    assert data.settings["clipboard_clear_seconds"] == 90
    assert data.settings["online_checks"] is False


def test_login_template_has_username_password_otp_and_website_fields():
    item = model.new_item("login", vault_id="v1", now=100.0)
    purposes = [f.purpose for f in item.fields]
    assert purposes == ["username", "password", "totp", "website"]
    assert item.created == item.modified == 100.0
    assert item.title == ""


def test_every_category_has_a_template_and_labels():
    for cat_id, cat in model.CATEGORIES.items():
        item = model.new_item(cat_id, vault_id="v", now=1.0)
        assert item.category == cat_id
        assert cat.label and cat.plural and cat.icon


def test_item_accessors_read_purpose_fields():
    item = model.new_item("login", vault_id="v", now=1.0)
    item.field("username").value = "wendy"
    item.field("password").value = "pw"
    item.field("website").value = "https://example.com/login"
    assert item.username == "wendy"
    assert item.password == "pw"
    assert item.websites == ["https://example.com/login"]
    assert item.totp == ""


def test_apply_edit_updates_modified_and_records_password_history():
    old = model.new_item("login", vault_id="v", now=1.0)
    old.title = "Mail"
    old.field("password").value = "first"
    new = old.copy()
    new.field("password").value = "second"
    result = model.apply_edit(old, new, now=50.0)
    assert result.modified == 50.0
    assert result.password_changed == 50.0
    assert [(h["value"], h["replaced_at"]) for h in result.password_history] == [("first", 50.0)]


def test_apply_edit_without_password_change_keeps_history_untouched():
    old = model.new_item("login", vault_id="v", now=1.0)
    old.field("password").value = "same"
    new = old.copy()
    new.title = "Renamed"
    result = model.apply_edit(old, new, now=9.0)
    assert result.password_history == []
    assert result.password_changed is None
    assert result.modified == 9.0


def test_setting_a_first_password_does_not_create_history():
    old = model.new_item("login", vault_id="v", now=1.0)
    new = old.copy()
    new.field("password").value = "brand new"
    result = model.apply_edit(old, new, now=2.0)
    assert result.password_history == []
    assert result.password_changed == 2.0


def test_copy_is_deep():
    item = model.new_item("login", vault_id="v", now=1.0)
    clone = item.copy()
    clone.field("username").value = "changed"
    clone.tags.append("x")
    assert item.username == ""
    assert item.tags == []


def test_serialization_round_trip():
    data = VaultData.new()
    item = model.new_item("credit_card", vault_id=data.vaults[0].id, now=3.0)
    item.title = "Visa"
    item.tags = ["finance"]
    item.favorite = True
    item.fields.append(Field.new("Branch code", "text", "1234"))
    data.add_item(item)
    restored = VaultData.from_json(data.to_json())
    assert restored.to_json() == data.to_json()
    assert restored.items[0].title == "Visa"
    assert restored.items[0].fields[-1].label == "Branch code"


def test_trash_restore_and_purge():
    data = VaultData.new()
    item = model.new_item("login", vault_id=data.vaults[0].id, now=1.0)
    data.add_item(item)
    data.trash(item.id, now=5.0)
    assert data.get(item.id).trashed_at == 5.0
    data.restore(item.id)
    assert data.get(item.id).trashed_at is None
    data.trash(item.id, now=6.0)
    data.purge(item.id)
    assert data.get(item.id) is None


def test_replace_item_swaps_by_id():
    data = VaultData.new()
    item = model.new_item("login", vault_id=data.vaults[0].id, now=1.0)
    data.add_item(item)
    edited = item.copy()
    edited.title = "New"
    data.replace_item(edited)
    assert data.get(item.id).title == "New"
    assert len(data.items) == 1


def test_all_tags_sorted_unique_ignoring_trash():
    data = VaultData.new()
    v = data.vaults[0].id
    a = model.new_item("login", vault_id=v, now=1.0)
    a.tags = ["work", "email"]
    b = model.new_item("login", vault_id=v, now=1.0)
    b.tags = ["Email", "home"]
    c = model.new_item("login", vault_id=v, now=1.0)
    c.tags = ["old"]
    for i in (a, b, c):
        data.add_item(i)
    data.trash(c.id, now=2.0)
    assert data.all_tags() == ["Email", "email", "home", "work"]


def test_from_json_tolerates_unknown_keys_from_newer_versions():
    data = VaultData.new()
    doc = data.to_dict()
    doc["future_feature"] = {"x": 1}
    doc["vaults"][0]["color"] = "blue"
    restored = VaultData.from_dict(doc)
    assert restored.vaults[0].name == "Personal"


def test_from_dict_clamps_impossible_timestamps():
    item = model.Item.from_dict({"id": "a", "category": "login", "vault_id": "v", "created": 1e300,
                                 "modified": float("nan"), "password_changed": -5, "trashed_at": "x"})
    assert item.created == 0.0 and item.modified == 0.0
    assert item.password_changed is None and item.trashed_at is None
    ok = model.Item.from_dict({"id": "b", "category": "login", "vault_id": "v", "created": 1700000000.0,
                               "trashed_at": 1700000001})
    assert ok.created == 1700000000.0 and ok.trashed_at == 1700000001.0
