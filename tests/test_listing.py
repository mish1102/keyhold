from datetime import datetime

from keyhold import listing, model
from keyhold.listing import View
from keyhold.model import VaultData


def build():
    data = VaultData.new()
    personal = data.vaults[0].id
    work = data.add_vault("Work").id

    def add(cat, title, vault, user="", tags=(), fav=False, url="", modified=1.0):
        item = model.new_item(cat, vault_id=vault, now=1.0)
        item.title = title
        item.modified = modified
        if item.field("username"):
            item.field("username").value = user
        if url:
            item.field("website").value = url
        item.tags = list(tags)
        item.favorite = fav
        data.add_item(item)
        return item

    items = {
        "ebay": add("login", "eBay", personal, "wendy.appleseed", fav=True, url="https://ebay.com"),
        "etsy": add("login", "Etsy", personal, "wendyappleseed", tags=["shopping"]),
        "evernote": add("login", "Evernote", work, "wendy-appleseed", tags=["work"], fav=True),
        "facebook": add("login", "Facebook", personal, "wendy.h.appleseed@gmail.com"),
        "garage": add("secure_note", "Garage Door Code", personal),
        "visa": add("credit_card", "Visa", personal),
        "num": add("login", "1Up", personal),
    }
    return data, items


def titles(items):
    return [i.title for i in items]


def test_all_items_sorted_by_title_case_insensitively():
    data, _ = build()
    result = listing.select(data, View("all"))
    assert titles(result) == ["1Up", "eBay", "Etsy", "Evernote", "Facebook", "Garage Door Code", "Visa"]


def test_vault_filter():
    data, _ = build()
    work = data.vaults[1].id
    assert titles(listing.select(data, View("all", vault_id=work))) == ["Evernote"]


def test_favorites_category_and_tag_views():
    data, _ = build()
    assert titles(listing.select(data, View("favorites"))) == ["eBay", "Evernote"]
    assert titles(listing.select(data, View("category", "secure_note"))) == ["Garage Door Code"]
    assert titles(listing.select(data, View("tag", "work"))) == ["Evernote"]


def test_trash_view_shows_only_trashed():
    data, items = build()
    data.trash(items["etsy"].id, now=2.0)
    assert "Etsy" not in titles(listing.select(data, View("all")))
    assert titles(listing.select(data, View("trash"))) == ["Etsy"]


def test_watchtower_view_uses_report():
    data, items = build()
    report = {"weak": {items["facebook"].id}}
    assert titles(listing.select(data, View("watchtower", "weak"), report=report)) == ["Facebook"]


def test_search_matches_title_username_url_and_tags_all_tokens():
    data, _ = build()
    assert titles(listing.select(data, View("all"), query="wendy.h")) == ["Facebook"]
    assert titles(listing.select(data, View("all"), query="EBAY.com")) == ["eBay"]
    assert titles(listing.select(data, View("all"), query="shopping")) == ["Etsy"]
    assert titles(listing.select(data, View("all"), query="garage code")) == ["Garage Door Code"]
    assert titles(listing.select(data, View("all"), query="garage nope")) == []


def test_search_never_matches_secret_values():
    data, items = build()
    items["etsy"].field("password").value = "supersecretvalue"
    assert listing.select(data, View("all"), query="supersecret") == []


def test_group_by_first_letter():
    data, _ = build()
    groups = listing.group(listing.select(data, View("all")), "title")
    assert [(h, titles(g)) for h, g in groups] == [
        ("#", ["1Up"]),
        ("E", ["eBay", "Etsy", "Evernote"]),
        ("F", ["Facebook"]),
        ("G", ["Garage Door Code"]),
        ("V", ["Visa"]),
    ]


def test_sort_by_modified_newest_first_and_grouped_by_period():
    data, items = build()
    now = datetime(2026, 6, 15, 12).timestamp()
    items["visa"].modified = now - 60
    items["etsy"].modified = now - 86400 * 40
    result = listing.select(data, View("all"), sort="modified")
    assert titles(result)[:2] == ["Visa", "Etsy"]
    headers = [h for h, _ in listing.group(result, "modified", now=now)]
    assert headers[0] == "Today"


def test_counts_per_view():
    data, items = build()
    c = listing.counts(data)
    assert c["all"] == 7
    assert c["favorites"] == 2
    assert c["category"]["login"] == 5
    assert c["tag"]["work"] == 1
    assert c["trash"] == 0


def test_absurd_timestamps_do_not_break_sorting_grouping_or_formatting():
    data, items = build()
    items["visa"].modified = 1e300
    items["etsy"].created = -1e300
    for sort in ("modified", "created"):
        listing.group(listing.select(data, View("all"), sort=sort), sort)
    assert listing.format_time(1e300) == "—"
    assert listing.format_time(None) == "—"
    assert "2024" in listing.format_time(datetime(2024, 9, 14, 13, 50).timestamp())
