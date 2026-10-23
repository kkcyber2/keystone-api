from conftest import auth


def test_first_user_becomes_admin(client):
    r = client.post("/auth/register", json={"email": "a@example.com", "password": "password-123"})
    assert r.status_code == 201
    me = client.get("/auth/me", headers=auth(r.json()["access_token"]))
    assert me.json()["role"] == "admin"


def test_second_user_keeps_requested_role(client, admin_token):
    r = client.post(
        "/auth/register",
        json={"email": "b@example.com", "password": "password-123", "role": "editor"},
    )
    assert r.status_code == 201
    me = client.get("/auth/me", headers=auth(r.json()["access_token"]))
    assert me.json()["role"] == "editor"


def test_duplicate_email_is_rejected(client, admin_token):
    r = client.post("/auth/register", json={"email": "admin@example.com", "password": "password-123"})
    assert r.status_code == 409


def test_login_rejects_wrong_password(client, admin_token):
    r = client.post("/auth/login", json={"email": "admin@example.com", "password": "nope-nope-nope"})
    assert r.status_code == 401


def test_login_accepts_correct_password(client, admin_token):
    r = client.post("/auth/login", json={"email": "admin@example.com", "password": "admin-password-1"})
    assert r.status_code == 200
    assert r.json()["token_type"] == "bearer"


def test_missing_token_is_401(client):
    assert client.get("/auth/me").status_code == 401


def test_tampered_token_is_401(client, admin_token):
    head, claims, _ = admin_token.split(".")
    forged = f"{head}.{claims}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    assert client.get("/auth/me", headers=auth(forged)).status_code == 401


def test_short_password_is_rejected(client):
    r = client.post("/auth/register", json={"email": "c@example.com", "password": "short"})
    assert r.status_code == 422
