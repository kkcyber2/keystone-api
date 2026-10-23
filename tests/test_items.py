from conftest import auth


def _editor(client, admin_token, email="ed@example.com"):
    r = client.post(
        "/auth/register",
        json={"email": email, "password": "password-123", "role": "editor"},
    )
    return r.json()["access_token"]


def test_viewer_cannot_create_item(client, admin_token):
    r = client.post(
        "/auth/register",
        json={"email": "v@example.com", "password": "password-123", "role": "viewer"},
    )
    token = r.json()["access_token"]
    resp = client.post("/items", json={"name": "x", "price_cents": 100}, headers=auth(token))
    assert resp.status_code == 403


def test_editor_can_create_and_read_back(client, admin_token):
    token = _editor(client, admin_token)
    created = client.post(
        "/items", json={"name": "widget", "price_cents": 1999}, headers=auth(token)
    )
    assert created.status_code == 201
    item_id = created.json()["id"]
    got = client.get(f"/items/{item_id}", headers=auth(token))
    assert got.status_code == 200
    assert got.json()["name"] == "widget"


def test_other_user_cannot_read_someone_elses_item(client, admin_token):
    owner = _editor(client, admin_token, "owner@example.com")
    other = _editor(client, admin_token, "other@example.com")
    item_id = client.post(
        "/items", json={"name": "secret", "price_cents": 1}, headers=auth(owner)
    ).json()["id"]
    assert client.get(f"/items/{item_id}", headers=auth(other)).status_code == 404


def test_admin_can_read_any_item(client, admin_token):
    owner = _editor(client, admin_token, "owner2@example.com")
    item_id = client.post(
        "/items", json={"name": "shared", "price_cents": 1}, headers=auth(owner)
    ).json()["id"]
    assert client.get(f"/items/{item_id}", headers=auth(admin_token)).status_code == 200


def test_pagination_walks_every_row_exactly_once(client, admin_token):
    token = _editor(client, admin_token, "pager@example.com")
    for i in range(7):
        client.post("/items", json={"name": f"n{i}", "price_cents": i}, headers=auth(token))
    seen, cursor, pages = [], None, 0
    while True:
        url = "/items?limit=3" + (f"&cursor={cursor}" if cursor else "")
        page = client.get(url, headers=auth(token)).json()
        seen.extend(i["id"] for i in page["items"])
        pages += 1
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert len(seen) == 7
    assert len(set(seen)) == 7
    assert pages == 3


def test_update_rejects_negative_price(client, admin_token):
    token = _editor(client, admin_token, "neg@example.com")
    item_id = client.post(
        "/items", json={"name": "n", "price_cents": 5}, headers=auth(token)
    ).json()["id"]
    r = client.patch(f"/items/{item_id}", json={"price_cents": -1}, headers=auth(token))
    assert r.status_code == 422


def test_only_admin_can_delete(client, admin_token):
    token = _editor(client, admin_token, "del@example.com")
    item_id = client.post(
        "/items", json={"name": "d", "price_cents": 5}, headers=auth(token)
    ).json()["id"]
    assert client.delete(f"/items/{item_id}", headers=auth(token)).status_code == 403
    assert client.delete(f"/items/{item_id}", headers=auth(admin_token)).status_code == 204
    assert client.get(f"/items/{item_id}", headers=auth(admin_token)).status_code == 404
