"""Tests for keyhold.importers: reading other password managers' exports, and CSV export."""

import csv
import io
import json
import zipfile
from datetime import datetime, timezone

import pytest

from keyhold import importers, model
from keyhold.importers import ImportFormatError, ImportResult, export_csv, import_file

NOW = 1_700_000_000.0
VAULT = "vault-1"


# -- helpers ---------------------------------------------------------------


def write(tmp_path, name, content):
    path = tmp_path / name
    path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    return path


def load(tmp_path, name, content) -> ImportResult:
    return import_file(write(tmp_path, name, content), VAULT, NOW)


def by_title(result):
    titles = [i.title for i in result.items]
    assert len(set(titles)) == len(titles), titles
    return {i.title: i for i in result.items}


def value(item, label):
    """Value of the first field with this label."""
    matches = [f for f in item.fields if f.label == label]
    assert matches, f"no field {label!r} in {[f.label for f in item.fields]}"
    return matches[0].value


def extras(item):
    """Fields beyond the category template that are not purpose fields: {label: (kind, value)}."""
    template_len = len(model.CATEGORIES[item.category].template)
    extra = [f for f in item.fields[template_len:] if f.purpose is None]
    labels = [f.label for f in extra]
    assert len(set(labels)) == len(labels), labels
    return {f.label: (f.kind, f.value) for f in extra}


def ts(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


def assert_common(result):
    for item in result.items:
        assert item.vault_id == VAULT
        assert item.category in model.CATEGORIES
        assert item.trashed_at is None
        assert item.title.strip()
        assert all(f.kind in model.FIELD_KINDS for f in item.fields)
    assert len({i.id for i in result.items}) == len(result.items)


# -- Chrome / Edge / Brave -------------------------------------------------

CHROME = (
    "name,url,username,password,note\n"
    'accounts.google.com,https://accounts.google.com/signin,alice@gmail.com,"p@ss,word""1",\n'
    ',https://www.example.com/login,bob,hunter2,"first line\nsecond, with comma"\n'
    ",,carol,pw3,\n"
    ",,,pw4,\n"
)


def test_chrome_csv(tmp_path):
    res = load(tmp_path, "Chrome Passwords.csv", CHROME)
    assert_common(res)
    assert res.source == "Chrome CSV"
    assert res.warnings == []
    assert [i.title for i in res.items] == ["accounts.google.com", "example.com", "carol", "Untitled"]
    google = res.items[0]
    assert google.category == "login"
    assert google.username == "alice@gmail.com"
    assert google.password == 'p@ss,word"1'
    assert google.websites == ["https://accounts.google.com/signin"]
    assert google.notes == ""
    assert google.created == google.modified == NOW
    assert res.items[1].notes == "first line\nsecond, with comma"
    assert res.items[3].password == "pw4"
    for item in res.items:
        assert extras(item) == {}
        assert item.tags == []
        assert item.favorite is False


def test_csv_with_utf8_bom_and_crlf_line_endings(tmp_path):
    res = load(tmp_path, "c.csv", "﻿" + CHROME.replace("\n", "\r\n"))
    assert res.source == "Chrome CSV"
    assert len(res.items) == 4
    assert res.items[0].password == 'p@ss,word"1'
    assert res.items[1].notes == "first line\nsecond, with comma"


def test_csv_with_utf8_bom_written_by_codec(tmp_path):
    data = ("Title,URL,Username,Password,Notes,OTPAuth\nZoë's café,https://café.example/,zoë,pässwörd,,\n").encode(
        "utf-8-sig"
    )
    res = load(tmp_path, "safari.csv", data)
    assert res.source == "Safari CSV"
    (item,) = res.items
    assert item.title == "Zoë's café"
    assert item.username == "zoë"
    assert item.password == "pässwörd"


def test_header_detection_ignores_case_and_surrounding_spaces(tmp_path):
    res = load(tmp_path, "c.csv", " Name , URL ,USERNAME,Password , Note\nSite,https://s.example,u,p,n\n")
    assert res.source == "Chrome CSV"
    (item,) = res.items
    assert (item.title, item.username, item.password, item.notes) == ("Site", "u", "p", "n")


def test_quoted_multiline_notes_commas_and_quotes_survive(tmp_path):
    notes = 'Line 1, with comma\nLine 2 "quoted"\n\nLine 4 after blank line'
    password = ' lead,ing "space" '
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["name", "url", "username", "password", "note"])
    writer.writerow(["Tricky, Inc.", "https://tricky.example", "user,name", password, notes])
    writer.writerow(["Next", "https://next.example", "n", "p", ""])
    res = load(tmp_path, "c.csv", buf.getvalue())
    tricky, nxt = res.items
    assert tricky.title == "Tricky, Inc."
    assert tricky.username == "user,name"
    assert tricky.password == password  # whitespace in passwords is significant: never stripped
    assert tricky.notes == notes
    assert nxt.title == "Next"


def test_unterminated_quote_is_an_error_not_silently_merged_rows(tmp_path):
    content = 'name,url,username,password,note\nA,https://a.example,u,"p,\nB,https://b.example,u2,p2,\n'
    path = write(tmp_path, "c.csv", content)
    with pytest.raises(ImportFormatError, match="line"):
        import_file(path, VAULT, NOW)


def test_csv_with_old_mac_cr_line_endings(tmp_path):
    res = load(tmp_path, "c.csv", CHROME.replace("\n", "\r"))
    assert res.source == "Chrome CSV"
    assert [i.title for i in res.items] == ["accounts.google.com", "example.com", "carol", "Untitled"]
    assert res.items[1].notes == "first line\nsecond, with comma"


def test_excel_sep_hint_line(tmp_path):
    res = load(tmp_path, "c.csv", "sep=;\nname;url;username;password;note\nSite;https://s.example;u;p;\n")
    assert res.source == "Chrome CSV"
    assert res.items[0].username == "u"


def test_semicolon_delimited_csv(tmp_path):
    res = load(tmp_path, "c.csv", "name;url;username;password;note\nSite;https://s.example;u;p,w;n\n")
    assert res.source == "Chrome CSV"
    assert res.items[0].password == "p,w"


# -- Firefox ---------------------------------------------------------------

FIREFOX = (
    '"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed",'
    '"timePasswordChanged"\n'
    '"https://www.mozilla.org","alice","s3cret",,"https://www.mozilla.org",'
    '"{6b3e2a4c-1111-4d5e-9f00-aaaaaaaaaaaa}","1600000000123","1650000000000","1610000000500"\n'
    '"https://login.example.net:8443","","pw-only","Restricted Area",,'
    '"{7c4f3b5d-2222-4e6f-8a11-bbbbbbbbbbbb}","1600000000000","1600000000000","1600000000000"\n'
)


def test_firefox_csv_titles_from_hostname_and_ms_timestamps(tmp_path):
    res = load(tmp_path, "logins.csv", FIREFOX)
    assert_common(res)
    assert res.source == "Firefox CSV"
    mozilla, example = res.items
    assert mozilla.title == "mozilla.org"
    assert (mozilla.username, mozilla.password) == ("alice", "s3cret")
    assert mozilla.websites == ["https://www.mozilla.org"]
    assert mozilla.created == pytest.approx(1600000000.123)
    assert mozilla.modified == pytest.approx(1610000000.5)
    assert mozilla.password_changed == pytest.approx(1610000000.5)
    assert example.title == "login.example.net"
    assert example.password == "pw-only"
    assert example.created == pytest.approx(1600000000.0)
    # guid, httpRealm, formActionOrigin and timeLastUsed are noise
    assert extras(mozilla) == {}
    assert extras(example) == {}


# -- Safari ----------------------------------------------------------------


def test_safari_csv(tmp_path):
    otp = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    content = (
        "Title,URL,Username,Password,Notes,OTPAuth\n"
        f"example.com (alice),https://example.com/,alice,pw1,Some note,{otp}\n"
        "shop.example (bob),https://shop.example/,bob,pw2,,\n"
    )
    res = load(tmp_path, "Passwords.csv", content)
    assert_common(res)
    assert res.source == "Safari CSV"
    items = by_title(res)
    alice = items["example.com (alice)"]
    assert alice.totp == otp
    assert alice.notes == "Some note"
    assert alice.websites == ["https://example.com/"]
    assert items["shop.example (bob)"].totp == ""


# -- Bitwarden CSV ---------------------------------------------------------

BITWARDEN_CSV = (
    "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
    'Social,1,login,Twitter,My notes,"Security question: First pet\nPIN: 1234\nRecovery: a: b",0,'
    '"https://twitter.com,https://x.com",alice,tw-pass,JBSWY3DPEHPK3PXP\n'
    ',,note,Wifi codes,"Home: abc123\nOffice: xyz",,0,,,,\n'
    ",0,login,Plain,,,0,https://plain.example,u,p,\n"
)


def test_bitwarden_csv(tmp_path):
    res = load(tmp_path, "bitwarden_export.csv", BITWARDEN_CSV)
    assert_common(res)
    assert res.source == "Bitwarden CSV"
    items = by_title(res)
    tw = items["Twitter"]
    assert tw.category == "login"
    assert tw.favorite is True
    assert tw.tags == ["Social"]
    assert tw.websites == ["https://twitter.com", "https://x.com"]
    assert all(f.kind == "url" for f in tw.fields if f.purpose == "website")
    assert (tw.username, tw.password, tw.totp) == ("alice", "tw-pass", "JBSWY3DPEHPK3PXP")
    assert tw.notes == "My notes"
    assert extras(tw) == {
        "Security question": ("text", "First pet"),
        "PIN": ("concealed", "1234"),
        "Recovery": ("text", "a: b"),
    }
    wifi = items["Wifi codes"]
    assert wifi.category == "secure_note"
    assert wifi.notes == "Home: abc123\nOffice: xyz"
    assert wifi.tags == []
    assert wifi.favorite is False
    plain = items["Plain"]
    assert plain.favorite is False
    assert plain.tags == []
    assert extras(plain) == {}


# -- 1Password CSV ---------------------------------------------------------


def test_1password_csv_tags_favorite_and_archived(tmp_path):
    content = (
        "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n"
        "GitHub,https://github.com/login,alice,gh-pass,otpauth://totp/GitHub:alice?secret=ABC,true,false,"
        '"dev, work;personal","Recovery codes:\n1111 2222"\n'
        "Old Forum,https://forum.example.org,al,old,,false,true,,\n"
    )
    res = load(tmp_path, "1PasswordExport.csv", content)
    assert_common(res)
    assert res.source == "1Password CSV"
    items = by_title(res)
    gh = items["GitHub"]
    assert gh.favorite is True
    assert gh.tags == ["dev", "work", "personal"]
    assert gh.totp == "otpauth://totp/GitHub:alice?secret=ABC"
    assert gh.notes == "Recovery codes:\n1111 2222"
    old = items["Old Forum"]
    assert old.trashed_at is None
    assert old.tags == ["archived"]
    assert old.favorite is False


# -- KeePassXC -------------------------------------------------------------


def test_keepassxc_csv_groups_and_iso_timestamps(tmp_path):
    content = (
        '"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"\n'
        '"Root","Bank","alice","bank-pw","https://bank.example.com","","","0",'
        '"2023-05-01T10:00:00Z","2020-01-01T00:00:00Z"\n'
        '"Root/Email","Webmail","alice@example.com","mail-pw","https://mail.example.com","a note",'
        '"otpauth://totp/Mail?secret=XYZ","1","2023-06-01T12:30:00Z","2021-02-03T04:05:06Z"\n'
    )
    res = load(tmp_path, "keepass.csv", content)
    assert_common(res)
    assert res.source == "KeePassXC CSV"
    items = by_title(res)
    bank = items["Bank"]
    assert bank.tags == []
    assert bank.created == ts("2020-01-01T00:00:00+00:00")
    assert bank.modified == ts("2023-05-01T10:00:00+00:00")
    assert extras(bank) == {}  # Icon is noise
    mail = items["Webmail"]
    assert mail.tags == ["Email"]
    assert mail.totp == "otpauth://totp/Mail?secret=XYZ"
    assert mail.notes == "a note"
    assert mail.created == ts("2021-02-03T04:05:06+00:00")


def test_unparseable_timestamp_is_kept_as_field_with_warning(tmp_path):
    content = (
        "Group,Title,Username,Password,URL,Notes,TOTP,Icon,Last Modified,Created\n"
        "Root,Bank,alice,pw,,,,0,last tuesday,2020-01-01T00:00:00Z\n"
    )
    res = load(tmp_path, "keepass.csv", content)
    (bank,) = res.items
    assert bank.created == ts("2020-01-01T00:00:00+00:00")
    assert bank.modified == bank.created
    assert extras(bank) == {"Last Modified": ("text", "last tuesday")}
    assert any("date" in w.lower() for w in res.warnings)


# -- LastPass --------------------------------------------------------------


def test_lastpass_csv_secure_notes_and_grouping(tmp_path):
    content = (
        "url,username,password,totp,extra,name,grouping,fav\n"
        "https://www.amazon.com/,alice@example.com,amz-pass,,Gift card in drawer,Amazon,Shopping,1\n"
        'http://sn,,,,"NoteType:Server\nHostname:db.local",DB Server,Work\\Servers,0\n'
        "https://bank.example/,bob,pw,JBSWY3DPEHPK3PXP,,,,0\n"
    )
    res = load(tmp_path, "lastpass_export.csv", content)
    assert_common(res)
    assert res.source == "LastPass CSV"
    items = by_title(res)
    amazon = items["Amazon"]
    assert amazon.category == "login"
    assert amazon.favorite is True
    assert amazon.tags == ["Shopping"]
    assert amazon.notes == "Gift card in drawer"
    assert amazon.websites == ["https://www.amazon.com/"]
    note = items["DB Server"]
    assert note.category == "secure_note"
    assert note.notes == "NoteType:Server\nHostname:db.local"
    assert note.tags == ["Work\\Servers"]
    assert extras(note) == {}  # the http://sn marker is not a website
    bank = items["bank.example"]
    assert bank.totp == "JBSWY3DPEHPK3PXP"


# -- generic / unknown CSV -------------------------------------------------


def test_generic_csv_maps_synonyms_and_keeps_unknown_columns(tmp_path):
    content = (
        "Account,Login Name,Password,Web Site,Comments,Security Answer,Customer No\n"
        "My Bank,alice,bank-pw,https://bank.example,joint account,blue,C-123\n"
    )
    res = load(tmp_path, "keepass2.csv", content)
    assert_common(res)
    assert res.source == "Generic CSV"
    (bank,) = res.items
    assert bank.title == "My Bank"
    assert (bank.username, bank.password) == ("alice", "bank-pw")
    assert bank.websites == ["https://bank.example"]
    assert bank.notes == "joint account"
    assert extras(bank) == {"Security Answer": ("concealed", "blue"), "Customer No": ("text", "C-123")}


def test_generic_csv_email_column_becomes_username_when_no_username_column(tmp_path):
    res = load(tmp_path, "x.csv", "Name,Email,Password,Username2\nShop,a@b.example,pw,other\n")
    (item,) = res.items
    assert (item.title, item.username, item.password) == ("Shop", "a@b.example", "pw")
    assert extras(item) == {"Username2": ("text", "other")}


def test_generic_csv_reads_epoch_ms_seconds_and_iso_timestamps(tmp_path):
    content = (
        "Title,Username,Password,Created,Modified\n"
        "A,u,p,1600000000123,2023-05-01T10:00:00Z\n"
        "B,u,p,1600000000,\n"
    )
    a, b = load(tmp_path, "x.csv", content).items
    assert a.created == pytest.approx(1600000000.123)
    assert a.modified == ts("2023-05-01T10:00:00+00:00")
    assert b.created == b.modified == 1600000000.0


def test_bitwarden_organization_csv_collections_become_tags(tmp_path):
    content = (
        "collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
        '"Eng,Ops",login,Server,,,0,https://s.example,u,p,\n'
    )
    res = load(tmp_path, "org.csv", content)
    assert res.source == "Bitwarden CSV"
    (item,) = res.items
    assert item.tags == ["Eng", "Ops"]
    assert extras(item) == {}


def test_keepassxc_csv_tags_column(tmp_path):
    content = 'Group,Title,Username,Password,URL,Notes,TOTP,Icon,Last Modified,Created,Tags\nRoot/Web,Shop,u,p,,,,0,,,"a;b"\n'
    (item,) = load(tmp_path, "kp.csv", content).items
    assert item.tags == ["a", "b", "Web"]
    assert extras(item) == {}


def test_generic_csv_other_common_column_names(tmp_path):
    content = "name,username,password,notesPlain,createTime,modifyTime\nProton,u,p,hello,1600000000,1650000000\n"
    (item,) = load(tmp_path, "proton.csv", content).items
    assert item.notes == "hello"
    assert (item.created, item.modified) == (1600000000.0, 1650000000.0)
    assert extras(item) == {}


def test_csv_without_username_or_password_column_is_rejected(tmp_path):
    path = write(tmp_path, "x.csv", "foo,bar\n1,2\n")
    with pytest.raises(ImportFormatError, match="(?i)column"):
        import_file(path, VAULT, NOW)


def test_known_format_keeps_unknown_columns_and_stray_cells(tmp_path):
    content = (
        "name,url,username,password,note,Recovery Email\n"
        "Site,https://site.example,u,p,,rec@example.com,stray cell\n"
    )
    res = load(tmp_path, "c.csv", content)
    assert res.source == "Chrome CSV"
    (item,) = res.items
    assert extras(item) == {"Recovery Email": ("email", "rec@example.com"), "Column 7": ("text", "stray cell")}
    assert any("column" in w.lower() for w in res.warnings)


def test_empty_rows_are_skipped_with_a_warning(tmp_path):
    content = "name,url,username,password,note\n\nSite,https://s.example,u,p,\n,,,,\n   ,  ,,,\n"
    res = load(tmp_path, "c.csv", content)
    assert [i.title for i in res.items] == ["Site"]
    assert any("3 empty rows" in w for w in res.warnings)


def test_header_only_csv_gives_no_items_and_a_warning(tmp_path):
    res = load(tmp_path, "c.csv", "name,url,username,password,note\n")
    assert res.items == []
    assert res.warnings


# -- Bitwarden JSON --------------------------------------------------------

BW_PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"


def bitwarden_export():
    return {
        "encrypted": False,
        "folders": [{"id": "f1", "name": "Finance"}, {"id": "f2", "name": "Social"}],
        "items": [
            {
                "id": "i1",
                "organizationId": None,
                "folderId": "f2",
                "type": 1,
                "reprompt": 0,
                "name": "Twitter",
                "notes": "personal account",
                "favorite": True,
                "fields": [
                    {"name": "Recovery email", "value": "alt@example.com", "type": 0, "linkedId": None},
                    {"name": "Backup code", "value": "9876-5432", "type": 1, "linkedId": None},
                    {"name": "Verified", "value": "true", "type": 2, "linkedId": None},
                    {"name": "Username", "value": None, "type": 3, "linkedId": 100},
                ],
                "login": {
                    "uris": [{"match": None, "uri": "https://twitter.com"}, {"match": 3, "uri": "https://x.com"}],
                    "username": "alice",
                    "password": "tw-pass",
                    "totp": "otpauth://totp/X:alice?secret=JBSWY3DPEHPK3PXP",
                    "passwordRevisionDate": "2023-03-01T10:00:00.000Z",
                    "fido2Credentials": [],
                },
                "passwordHistory": [{"lastUsedDate": "2022-01-01T00:00:00.000Z", "password": "old-pass"}],
                "revisionDate": "2023-03-01T10:00:00.000Z",
                "creationDate": "2021-01-01T00:00:00.000Z",
                "deletedDate": None,
                "collectionIds": None,
            },
            {
                "id": "i2",
                "folderId": None,
                "type": 2,
                "name": "Alarm code",
                "notes": "1234#",
                "favorite": False,
                "secureNote": {"type": 0},
                "revisionDate": "2023-01-01T00:00:00.000Z",
                "creationDate": "2023-01-01T00:00:00.000Z",
            },
            {
                "id": "i3",
                "folderId": "f1",
                "type": 3,
                "name": "Visa",
                "notes": None,
                "favorite": False,
                "card": {
                    "cardholderName": "Alice Smith",
                    "brand": "Visa",
                    "number": "4111111111111111",
                    "expMonth": "3",
                    "expYear": "2027",
                    "code": "123",
                },
            },
            {
                "id": "i4",
                "type": 4,
                "name": "Me",
                "favorite": False,
                "identity": {
                    "title": "Ms",
                    "firstName": "Alice",
                    "middleName": "B",
                    "lastName": "Smith",
                    "address1": "1 Main St",
                    "address2": "Apt 2",
                    "address3": None,
                    "city": "Springfield",
                    "state": "IL",
                    "postalCode": "62701",
                    "country": "US",
                    "company": "Acme",
                    "email": "alice@example.com",
                    "phone": "555-1234",
                    "ssn": "123-45-6789",
                    "username": "asmith",
                    "passportNumber": "X123",
                    "licenseNumber": None,
                },
            },
            {
                "id": "i5",
                "type": 5,
                "name": "Server key",
                "favorite": False,
                "sshKey": {"privateKey": BW_PRIVATE_KEY, "publicKey": "ssh-ed25519 AAAA", "keyFingerprint": "SHA256:xyz"},
            },
        ],
    }


def test_bitwarden_json(tmp_path):
    res = load(tmp_path, "bitwarden_export.json", json.dumps(bitwarden_export()))
    assert_common(res)
    assert res.source == "Bitwarden JSON"
    items = by_title(res)

    tw = items["Twitter"]
    assert tw.category == "login"
    assert tw.tags == ["Social"]
    assert tw.favorite is True
    assert (tw.username, tw.password) == ("alice", "tw-pass")
    assert tw.totp == "otpauth://totp/X:alice?secret=JBSWY3DPEHPK3PXP"
    assert tw.websites == ["https://twitter.com", "https://x.com"]
    assert [(f.kind, f.purpose) for f in tw.fields if f.value.startswith("https://x")] == [("url", "website")]
    assert tw.notes == "personal account"
    assert extras(tw) == {
        "Recovery email": ("email", "alt@example.com"),
        "Backup code": ("concealed", "9876-5432"),
        "Verified": ("text", "true"),
    }
    assert tw.created == ts("2021-01-01T00:00:00+00:00")
    assert tw.modified == ts("2023-03-01T10:00:00+00:00")
    assert tw.password_changed == ts("2023-03-01T10:00:00+00:00")
    assert tw.password_history == [{"value": "old-pass", "replaced_at": ts("2022-01-01T00:00:00+00:00")}]

    note = items["Alarm code"]
    assert note.category == "secure_note"
    assert note.notes == "1234#"
    assert note.tags == []

    visa = items["Visa"]
    assert visa.category == "credit_card"
    assert visa.tags == ["Finance"]
    assert value(visa, "cardholder name") == "Alice Smith"
    assert value(visa, "type") == "Visa"
    assert value(visa, "number") == "4111111111111111"
    assert value(visa, "verification number") == "123"
    assert value(visa, "expiry date") == "03/2027"
    assert visa.created == visa.modified == NOW
    assert visa.notes == ""

    me = items["Me"]
    assert me.category == "identity"
    assert value(me, "first name") == "Alice"
    assert value(me, "last name") == "Smith"
    assert value(me, "email") == "alice@example.com"
    assert value(me, "phone") == "555-1234"
    assert value(me, "company") == "Acme"
    assert value(me, "address") == "1 Main St\nApt 2\nSpringfield, IL 62701\nUS"
    me_extras = extras(me)
    assert me_extras["title"] == ("text", "Ms")
    assert me_extras["middle name"] == ("text", "B")
    assert me_extras["social security number"] == ("concealed", "123-45-6789")
    assert me_extras["username"] == ("text", "asmith")
    assert me_extras["passport number"] == ("concealed", "X123")
    assert "license number" not in me_extras

    key = items["Server key"]
    assert key.category == "secure_note"
    values = {f.value: f.kind for f in key.fields}
    assert values[BW_PRIVATE_KEY] == "concealed"
    assert values["ssh-ed25519 AAAA"] == "text"
    assert values["SHA256:xyz"] == "text"
    assert any("secure note" in w.lower() for w in res.warnings)


def test_bitwarden_json_card_with_only_partial_expiry_keeps_the_data(tmp_path):
    export = {
        "encrypted": False,
        "folders": [],
        "items": [{"type": 3, "name": "Card", "card": {"number": "5555", "expMonth": None, "expYear": "2030"}}],
    }
    (card,) = load(tmp_path, "bw.json", json.dumps(export)).items
    assert value(card, "expiry date") == ""
    assert "2030" in [f.value for f in card.fields]


@pytest.mark.parametrize(
    "export",
    [
        {
            "encrypted": True,
            "passwordProtected": True,
            "salt": "c2FsdA==",
            "kdfType": 0,
            "kdfIterations": 600000,
            "encKeyValidation_DO_NOT_EDIT": "2.aaa|bbb",
            "data": "2.ccc|ddd",
        },
        {
            "encrypted": True,
            "encKeyValidation_DO_NOT_EDIT": "2.aaa|bbb",
            "folders": [],
            "items": [{"type": 1, "name": "2.abc|def", "login": {"username": "2.x|y"}}],
        },
    ],
)
def test_encrypted_bitwarden_json_asks_for_unencrypted_export(tmp_path, export):
    path = write(tmp_path, "bitwarden_encrypted_export.json", json.dumps(export))
    with pytest.raises(ImportFormatError, match="(?i)unencrypted"):
        import_file(path, VAULT, NOW)


# -- 1Password 1PUX --------------------------------------------------------

BIRTHDATE = int(datetime(1990, 5, 15, 12, tzinfo=timezone.utc).timestamp())


def section(title, *fields):
    return {"title": title, "name": title.lower() or "s", "fields": list(fields)}


def sfield(title, fid, val):
    return {"title": title, "id": fid, "value": val, "guarded": False, "multiline": False}


def onepux_items_personal():
    return [
        {
            "uuid": "u1",
            "favIndex": 1,
            "createdAt": 1600000000,
            "updatedAt": 1650000000,
            "state": "active",
            "categoryUuid": "001",
            "overview": {
                "title": "GitHub",
                "url": "https://github.com",
                "urls": [
                    {"label": "", "url": "https://github.com"},
                    {"label": "enterprise", "url": "https://github.example.com"},
                ],
                "tags": ["dev"],
                "ps": 100,
            },
            "details": {
                "loginFields": [
                    {"value": "alice", "id": "", "name": "login", "fieldType": "T", "designation": "username"},
                    {"value": "gh-pass", "id": "", "name": "password", "fieldType": "P", "designation": "password"},
                    {"value": "✓", "id": "", "name": "remember", "fieldType": "C"},
                ],
                "notesPlain": "notes here",
                "sections": [
                    section("", sfield("one-time password", "TOTP_x", {"totp": "otpauth://totp/GitHub?secret=ABC"})),
                    section(
                        "Recovery",
                        sfield("recovery code", "r1", {"concealed": "rc-1"}),
                        sfield("recovery email", "r2", {"email": {"email_address": "alt@example.com", "provider": None}}),
                        sfield("weird", "w1", {"futureType": {"a": 1}}),
                        sfield("blank", "b1", {"string": ""}),
                    ),
                ],
                "passwordHistory": [{"value": "old", "time": 1500000000}],
            },
        },
        {
            "uuid": "u2",
            "favIndex": 0,
            "createdAt": 1600000000,
            "updatedAt": 1600000500,
            "state": "active",
            "categoryUuid": "002",
            "overview": {"title": "Amex", "tags": []},
            "details": {
                "loginFields": [],
                "notesPlain": "",
                "sections": [
                    section(
                        "",
                        sfield("cardholder name", "cardholder", {"string": "Alice Smith"}),
                        sfield("type", "type", {"creditCardType": "amex"}),
                        sfield("number", "ccnum", {"creditCardNumber": "378282246310005"}),
                        sfield("verification number", "cvv", {"concealed": "1234"}),
                        sfield("expiry date", "expiry", {"monthYear": 202708}),
                        sfield("valid from", "validFrom", {"monthYear": 202208}),
                        sfield("issuing bank", "bank", {"string": "Amex Bank"}),
                        sfield("credit limit", "creditLimit", {"string": ""}),
                    ),
                    section("Contact Information", sfield("phone (toll free)", "phoneTollFree", {"phone": "1-800-123"})),
                    section("Additional Details", sfield("PIN", "pin", {"concealed": "9999"})),
                ],
            },
        },
        {
            "uuid": "u4",
            "favIndex": 0,
            "createdAt": 1600000000,
            "updatedAt": 1600000000,
            "state": "active",
            "categoryUuid": "003",
            "overview": {"title": "Safe combo", "tags": []},
            "details": {"notesPlain": "12-34-56", "sections": []},
        },
        {
            "uuid": "u5",
            "favIndex": 0,
            "createdAt": 1600000000,
            "updatedAt": 1600000000,
            "state": "active",
            "categoryUuid": "005",
            "overview": {"title": "Router admin"},
            "details": {"password": "standalone-pw", "sections": []},
        },
        {
            "uuid": "u6",
            "favIndex": 0,
            "createdAt": 1600000000,
            "updatedAt": 1600000000,
            "state": "active",
            "categoryUuid": "101",
            "overview": {"title": "Checking"},
            "details": {
                "sections": [
                    section(
                        "",
                        sfield("bank name", "bankName", {"string": "First Bank"}),
                        sfield("name on account", "owner", {"string": "Alice Smith"}),
                        sfield("type", "accountType", {"menu": "checking"}),
                        sfield("routing number", "routingNo", {"string": "021000021"}),
                        sfield("account number", "accountNo", {"string": "000123456789"}),
                        sfield("SWIFT", "swift", {"string": "FBANKUS33"}),
                        sfield("IBAN", "iban", {"string": "DE89370400440532013000"}),
                        sfield("PIN", "telephonePin", {"concealed": "4321"}),
                    )
                ]
            },
        },
        {
            "uuid": "u7",
            "favIndex": 0,
            "createdAt": 1600000000,
            "updatedAt": 1600000000,
            "state": "active",
            "categoryUuid": "110",
            "overview": {"title": "DB server"},
            "details": {
                "notesPlain": "prod box",
                "sections": [
                    section(
                        "",
                        sfield("URL", "url", {"string": "db.example.internal"}),
                        sfield("username", "username", {"string": "root"}),
                        sfield("password", "password", {"concealed": "root-pw"}),
                    )
                ],
            },
        },
        {
            "uuid": "u8",
            "favIndex": 0,
            "createdAt": 1600000000,
            "updatedAt": 1600000000,
            "state": "active",
            "categoryUuid": "006",
            "overview": {"title": "Passport scan"},
            "details": {
                "documentAttributes": {"fileName": "passport.pdf", "documentId": "d1", "decryptedSize": 1234},
                "sections": [],
            },
        },
    ]


def onepux_items_work():
    return [
        {
            "uuid": "u3",
            "favIndex": 0,
            "createdAt": 1600000000,
            "updatedAt": 1600000000,
            "state": "archived",
            "categoryUuid": "004",
            "overview": {"title": "Work identity", "tags": []},
            "details": {
                "sections": [
                    section(
                        "Identification",
                        sfield("first name", "firstname", {"string": "Alice"}),
                        sfield("last name", "lastname", {"string": "Smith"}),
                        sfield("birth date", "birthdate", {"date": BIRTHDATE}),
                        sfield("company", "company", {"string": "Acme"}),
                        sfield("job title", "jobtitle", {"string": "Engineer"}),
                    ),
                    section(
                        "Address",
                        sfield(
                            "address",
                            "address",
                            {"address": {"street": "1 Main St", "city": "Springfield", "state": "IL", "zip": "62701", "country": "us"}},
                        ),
                        sfield("default phone", "defphone", {"phone": "555-1234"}),
                        sfield("mobile", "cellphone", {"phone": "555-9999"}),
                    ),
                    section("Internet Details", sfield("email", "email", {"email": {"email_address": "alice@acme.example"}})),
                ]
            },
        }
    ]


def make_1pux(tmp_path, vaults, name="export.1pux"):
    data = {
        "accounts": [
            {
                "attrs": {"accountName": "Alice", "name": "Alice", "email": "a@example.com", "uuid": "acc", "domain": "x"},
                "vaults": [
                    {"attrs": {"uuid": f"v{i}", "name": vname, "type": "P"}, "items": items}
                    for i, (vname, items) in enumerate(vaults)
                ],
            }
        ]
    }
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("export.attributes", json.dumps({"version": 3, "description": "1PUX export", "createdAt": 1}))
        zf.writestr("export.data", json.dumps(data))
        zf.writestr("files/d1__passport.pdf", b"%PDF-1.4 fake")
    return path


def test_1pux_import(tmp_path):
    path = make_1pux(tmp_path, [("Personal", onepux_items_personal()), ("Work", onepux_items_work())])
    res = import_file(path, VAULT, NOW)
    assert_common(res)
    assert res.source == "1Password (1PUX)"
    items = by_title(res)
    assert len(items) == 8

    gh = items["GitHub"]
    assert gh.category == "login"
    assert gh.tags == ["dev", "Personal"]  # vault name as tag: the export has two vaults
    assert gh.favorite is True
    assert (gh.created, gh.modified) == (1600000000.0, 1650000000.0)
    assert (gh.username, gh.password) == ("alice", "gh-pass")
    assert gh.totp == "otpauth://totp/GitHub?secret=ABC"
    assert gh.websites == ["https://github.com", "https://github.example.com"]
    assert [f.label for f in gh.fields if f.purpose == "website"] == ["website", "enterprise"]
    assert gh.notes == "notes here"
    gh_extras = extras(gh)
    assert gh_extras["remember"] == ("text", "✓")
    assert gh_extras["recovery code"] == ("concealed", "rc-1")
    assert gh_extras["recovery email"] == ("email", "alt@example.com")
    kind, raw = gh_extras["weird"]
    assert kind == "text"
    assert json.loads(raw) == {"a": 1}
    assert "blank" not in gh_extras
    assert gh.password_history == [{"value": "old", "replaced_at": 1500000000.0}]

    amex = items["Amex"]
    assert amex.category == "credit_card"
    assert value(amex, "cardholder name") == "Alice Smith"
    assert value(amex, "type") == "American Express"
    assert value(amex, "number") == "378282246310005"
    assert value(amex, "verification number") == "1234"
    assert value(amex, "expiry date") == "08/2027"
    assert value(amex, "valid from") == "08/2022"
    assert value(amex, "PIN") == "9999"
    assert extras(amex) == {"issuing bank": ("text", "Amex Bank"), "phone (toll free)": ("phone", "1-800-123")}
    assert amex.tags == ["Personal"]

    ident = items["Work identity"]
    assert ident.category == "identity"
    assert ident.trashed_at is None
    assert ident.tags == ["Work", "archived"]
    assert value(ident, "first name") == "Alice"
    assert value(ident, "last name") == "Smith"
    assert value(ident, "birth date") == "1990-05-15"
    assert value(ident, "address") == "1 Main St\nSpringfield, IL 62701\nus"
    assert value(ident, "email") == "alice@acme.example"
    assert value(ident, "phone") == "555-1234"
    assert value(ident, "company") == "Acme"
    assert value(ident, "job title") == "Engineer"
    assert extras(ident) == {"mobile": ("phone", "555-9999")}

    assert items["Safe combo"].category == "secure_note"
    assert items["Safe combo"].notes == "12-34-56"

    router = items["Router admin"]
    assert router.category == "password"
    assert router.password == "standalone-pw"

    bank = items["Checking"]
    assert bank.category == "bank_account"
    assert value(bank, "bank name") == "First Bank"
    assert value(bank, "name on account") == "Alice Smith"
    assert value(bank, "type") == "checking"
    assert value(bank, "account number") == "000123456789"
    assert value(bank, "routing number") == "021000021"
    assert value(bank, "SWIFT / IBAN") == "FBANKUS33"
    assert value(bank, "PIN") == "4321"
    assert extras(bank) == {"IBAN": ("text", "DE89370400440532013000")}

    server = items["DB server"]
    assert server.category == "secure_note"
    assert server.notes == "prod box"
    assert extras(server) == {
        "URL": ("text", "db.example.internal"),
        "username": ("text", "root"),
        "password": ("concealed", "root-pw"),
    }

    doc = items["Passport scan"]
    assert doc.category == "secure_note"
    assert extras(doc) == {"attachment": ("text", "passport.pdf")}

    joined = "\n".join(res.warnings)
    assert "Server" in joined
    assert "Document" in joined
    assert "passport.pdf" in joined


def test_imported_items_survive_vault_serialization(tmp_path):
    items = import_file(make_1pux(tmp_path, [("A", onepux_items_personal()), ("B", onepux_items_work())]), VAULT, NOW).items
    items += load(tmp_path, "bw.json", json.dumps(bitwarden_export())).items
    data = model.VaultData.new()
    for item in items:
        data.add_item(item)
    restored = model.VaultData.from_json(data.to_json())
    assert [snapshot(i) for i in restored.items] == [snapshot(i) for i in items]
    assert [i.password_history for i in restored.items] == [i.password_history for i in items]


def test_1pux_single_vault_does_not_tag_vault_name(tmp_path):
    path = make_1pux(tmp_path, [("Personal", onepux_items_personal()[:1])])
    res = import_file(path, VAULT, NOW)
    (gh,) = res.items
    assert gh.tags == ["dev"]
    assert res.warnings == []


def test_1pux_without_export_data_is_rejected(tmp_path):
    path = tmp_path / "other.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("readme.txt", "hello")
    with pytest.raises(ImportFormatError, match="1Password"):
        import_file(path, VAULT, NOW)


# -- garbage ---------------------------------------------------------------


@pytest.mark.parametrize(
    "name,content",
    [
        ("empty.csv", b""),
        ("blank.csv", b"   \n\n"),
        ("random.bin", bytes(range(256)) * 4),
        ("image.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 100),
        ("notes.txt", b"Just some text\nnothing to see here\n"),
        ("broken.json", b'{"encrypted": false, "items": [ '),
        ("other.json", b'{"hello": "world"}'),
        ("list.json", b"[1, 2, 3]"),
        ("bw-bad-items.json", b'{"encrypted": false, "items": "nope"}'),
        ("fake.1pux", b"PK\x03\x04 not really a zip"),
        ("nul.csv", b"name,url,username,password\nx\x00y,u,p,q\n"),
        ("latin1.csv", "name,url,username,password\nCafé,u,p,q\n".encode("latin-1")),
    ],
)
def test_garbage_files_raise_import_format_error(tmp_path, name, content):
    path = write(tmp_path, name, content)
    with pytest.raises(ImportFormatError):
        import_file(path, VAULT, NOW)


def test_structurally_odd_json_values_do_not_crash(tmp_path):
    bitwarden = {
        "encrypted": False,
        "folders": [{"id": {"x": 1}, "name": "F"}, "junk"],
        "items": [{"type": [1], "name": "Odd", "folderId": ["f1"], "notes": "kept", "fields": "nope"}, "junk"],
    }
    res = load(tmp_path, "bw.json", json.dumps(bitwarden))
    (odd,) = res.items
    assert odd.category == "secure_note"
    assert odd.notes == "kept"
    assert any("weren't items" in w for w in res.warnings)

    item = onepux_items_personal()[0]
    item["details"]["loginFields"][2]["fieldType"] = ["C"]
    item["details"]["sections"] = "nope"
    res = import_file(make_1pux(tmp_path, [("Personal", [item, "junk"])]), VAULT, NOW)
    (gh,) = res.items
    assert gh.password == "gh-pass"
    assert extras(gh)["remember"] == ("text", "✓")


def test_bad_1pux_json_is_rejected(tmp_path):
    path = tmp_path / "bad.1pux"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("export.data", "{not json")
    with pytest.raises(ImportFormatError):
        import_file(path, VAULT, NOW)


def test_missing_file_raises_import_format_error(tmp_path):
    with pytest.raises(ImportFormatError):
        import_file(tmp_path / "does-not-exist.csv", VAULT, NOW)


# -- Keyhold CSV export / import -------------------------------------------


def keyhold_items():
    login = model.new_item("login", VAULT, 1.0)
    login.title = "Mail, personal"
    login.field("username").value = "alice@example.com"
    login.field("password").value = 'pa,ss"word with spaces '
    login.field("totp").value = "otpauth://totp/Mail:alice?secret=JBSWY3DPEHPK3PXP"
    login.field("website").value = "https://mail.example.com"
    login.fields.append(model.Field.new("website", "url", "https://webmail.example.com", "website"))
    login.fields.append(model.Field.new("recovery code", "concealed", "1111-2222"))
    login.fields.append(model.Field.new("admin site", "url", "https://admin.example.com", "website"))
    login.tags = ["email", "personal"]
    login.favorite = True
    login.notes = "line one\nline two, with comma"

    card = model.new_item("credit_card", VAULT, 1.0)
    card.title = "Visa"
    for label, val in [
        ("cardholder name", "Alice Smith"),
        ("type", "Visa"),
        ("number", "4111111111111111"),
        ("verification number", "123"),
        ("expiry date", "03/2027"),
        ("PIN", "0000"),
    ]:
        next(f for f in card.fields if f.label == label).value = val
    card.fields.append(model.Field.new("issuing bank", "text", "Big Bank"))

    ident = model.new_item("identity", VAULT, 1.0)
    ident.title = "Me"
    for label, val in [
        ("first name", "Alice"),
        ("last name", "Smith"),
        ("birth date", "1990-05-15"),
        ("address", "1 Main St\nSpringfield"),
        ("email", "alice@example.com"),
    ]:
        next(f for f in ident.fields if f.label == label).value = val
    ident.tags = ["family"]

    note = model.new_item("secure_note", VAULT, 1.0)
    note.title = "Alarm"
    note.notes = 'Code: 1234#\n"quoted" text'

    trashed = model.new_item("login", VAULT, 1.0)
    trashed.title = "Old trashed login"
    trashed.field("password").value = "gone"
    trashed.trashed_at = 5.0
    return [login, card, ident, note, trashed]


def snapshot(item):
    return {
        "category": item.category,
        "title": item.title,
        "notes": item.notes,
        "tags": item.tags,
        "favorite": item.favorite,
        "fields": [(f.label, f.kind, f.value, f.purpose) for f in item.fields],
    }


def test_export_csv_layout(tmp_path):
    text = export_csv(keyhold_items())
    rows = list(csv.reader(io.StringIO(text, newline="")))
    assert rows[0] == ["Category", "Title", "Url", "Username", "Password", "OTPAuth", "Favorite", "Tags", "Notes", "Fields"]
    assert len(rows) == 5  # header + 4; trashed item excluded
    assert "Old trashed login" not in text
    assert "gone" not in text
    login = dict(zip(rows[0], rows[1]))
    assert login["Category"] == "login"
    assert login["Url"] == "https://mail.example.com"
    assert login["Username"] == "alice@example.com"
    assert login["Password"] == 'pa,ss"word with spaces '
    assert login["OTPAuth"].startswith("otpauth://")
    assert login["Tags"] == "email, personal"
    assert login["Notes"] == "line one\nline two, with comma"
    fields = json.loads(login["Fields"])
    assert fields[0]["value"] == "https://webmail.example.com"
    assert fields[1] == {"label": "recovery code", "kind": "concealed", "value": "1111-2222"}
    note = dict(zip(rows[0], rows[4]))
    assert note["Category"] == "secure_note"
    assert note["Fields"] == ""


def test_keyhold_csv_round_trip(tmp_path):
    originals = keyhold_items()
    path = write(tmp_path, "keyhold-export.csv", export_csv(originals))
    res = import_file(path, "other-vault", NOW)
    assert res.source == "Keyhold CSV"
    assert res.warnings == []
    active = [i for i in originals if i.trashed_at is None]
    assert [snapshot(i) for i in res.items] == [snapshot(i) for i in active]
    for item in res.items:
        assert item.vault_id == "other-vault"
        assert item.created == item.modified == NOW
    login = res.items[0]
    assert login.websites == ["https://mail.example.com", "https://webmail.example.com", "https://admin.example.com"]


def test_keyhold_csv_with_missing_columns_still_imports(tmp_path):
    res = load(tmp_path, "k.csv", "Category,Title,OTPAuth,Fields,Password,Extra\nlogin,Site,,,pw,kept\n")
    assert res.source == "Keyhold CSV"
    (item,) = res.items
    assert item.password == "pw"
    assert extras(item) == {"Extra": ("text", "kept")}


def test_keyhold_csv_unknown_category_becomes_secure_note_with_warning(tmp_path):
    content = "Category,Title,Url,Username,Password,OTPAuth,Favorite,Tags,Notes,Fields\nspaceship,Ship,,cap,pw,,,,,\n"
    res = load(tmp_path, "k.csv", content)
    (item,) = res.items
    assert item.category == "secure_note"
    assert (item.username, item.password) == ("cap", "pw")
    assert any("spaceship" in w for w in res.warnings)


def test_keyhold_csv_with_damaged_fields_cell_keeps_the_text(tmp_path):
    content = (
        "Category,Title,Url,Username,Password,OTPAuth,Favorite,Tags,Notes,Fields\n"
        'login,Site,https://s.example,u,p,,false,,,"[{""label"": broken"\n'
    )
    res = load(tmp_path, "k.csv", content)
    (item,) = res.items
    assert item.password == "p"
    assert '[{"label": broken' in [f.value for f in item.fields]
    assert res.warnings


def test_oversized_file_is_rejected_before_reading(tmp_path):
    big = tmp_path / "huge.csv"
    with open(big, "wb") as fh:  # sparse: takes no real disk space
        fh.truncate(importers.MAX_IMPORT_BYTES + 1)
    with pytest.raises(ImportFormatError, match="too large"):
        importers.import_file(big, "v", 1_700_000_000.0)


def test_1pux_with_oversized_contents_is_rejected(tmp_path, monkeypatch):
    import zipfile as _zip

    path = tmp_path / "bomb.1pux"
    with _zip.ZipFile(path, "w", compression=_zip.ZIP_DEFLATED) as zf:
        zf.writestr("export.data", '{"accounts": []}' + " " * 5000)
    monkeypatch.setattr(importers, "MAX_EXPORT_DATA_BYTES", 1000)
    with pytest.raises(ImportFormatError, match="too large"):
        importers.import_file(path, "v", 1_700_000_000.0)


def test_absurd_timestamps_fall_back_to_now(tmp_path):
    path = tmp_path / "ff.csv"
    path.write_text(
        "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n"
        "https://a.example.com,u,p,,,{x},1e300,1e300,1e300\n")
    item = importers.import_file(path, "v", 1_700_000_000.0).items[0]
    assert item.created == 1_700_000_000.0
