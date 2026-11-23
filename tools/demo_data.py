"""Fictional demo items for screenshots and manual testing. Never use for real data."""

from __future__ import annotations

import time

from keyhold import generator, model
from keyhold.model import Field, VaultData

DAY = 86400


def populate(data: VaultData) -> None:
    now = time.time()
    personal = data.vaults[0].id
    work = data.add_vault("Work").id
    shared_pw = generator.random_password(18)

    def login(title, user, url, password=None, totp="", fav=False, tags=(), vault=personal, age_days=400,
              notes=""):
        item = model.new_item("login", vault_id=vault, now=now - age_days * DAY)
        item.title = title
        item.field("username").value = user
        item.field("password").value = password if password is not None else generator.random_password(20)
        item.field("website").value = url
        item.field("totp").value = totp
        item.favorite = fav
        item.tags = list(tags)
        item.notes = notes
        item.modified = now - (age_days // 3) * DAY
        item.password_changed = item.created
        data.add_item(item)
        return item

    login("eBay", "alex.rivera", "https://www.ebay.com/signin", fav=True, tags=["shopping"])
    login("Etsy", "alexrivera", "https://www.etsy.com/signin", tags=["shopping"])
    ev = login("Evernote", "alex-rivera", "https://www.evernote.com/Login.action", fav=True,
               totp="JBSWY3DPEHPK3PXP", tags=["notes"], age_days=900)
    ev.password_history = [{"value": "OldNotes!2019", "replaced_at": now - 200 * DAY}]
    login("Facebook", "alex.rivera@example.com", "https://www.facebook.com", password=shared_pw, tags=["social"])
    login("Fitbit", "alex.rivera@example.com", "https://www.fitbit.com/login", password=shared_pw)
    login("Forums", "Night Owl", "http://forums.example.net/login", password="Summer2024!")
    login("Gmail (personal)", "alex.rivera.home", "https://accounts.google.com",
          totp="otpauth://totp/Google:alex?secret=KRSXG5CTMVRXEZLU&issuer=Google", fav=True)
    login("Hilton Honors", "Hilton Worldwide", "https://www.hilton.com/en/hilton-honors/login/")
    login("GitHub", "arivera-dev", "https://github.com/login", vault=work, tags=["work"],
          totp="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    login("Jira", "a.rivera@company.example", "https://company.example.atlassian.net", vault=work, tags=["work"])

    note = model.new_item("secure_note", vault_id=personal, now=now - 300 * DAY)
    note.title = "Garage Door Code"
    note.notes = "Keypad code: 4417\nRemote is in the kitchen drawer."
    data.add_item(note)

    card = model.new_item("credit_card", vault_id=personal, now=now - 700 * DAY)
    card.title = "Visa Platinum"
    values = {"cardholder name": "Alex Rivera", "type": "Visa", "number": "4111 1111 1111 1111",
              "verification number": "123", "expiry date": time.strftime("%m/%Y", time.localtime(now)),
              "PIN": "9264"}
    for f in card.fields:
        f.value = values.get(f.label, "")
    data.add_item(card)

    ident = model.new_item("identity", vault_id=personal, now=now - 800 * DAY)
    ident.title = "Alex Rivera"
    values = {"first name": "Alex", "last name": "Rivera", "email": "alex.rivera@example.com",
              "phone": "+1 555 0100", "address": "12 Example Street\nSpringfield"}
    for f in ident.fields:
        f.value = values.get(f.label, "")
    data.add_item(ident)

    wifi = model.new_item("password", vault_id=personal, now=now - 100 * DAY)
    wifi.title = "Home Wi-Fi"
    wifi.field("password").value = generator.passphrase(4)
    wifi.fields.append(Field.new("network name", "text", "RiveraHome-5G"))
    data.add_item(wifi)
