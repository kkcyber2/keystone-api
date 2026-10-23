import pytest
from fastapi.testclient import TestClient

from keystone import app as app_module


@pytest.fixture()
def client():
    app_module.store.clear()
    app_module.limiter.reset()
    with TestClient(app_module.app) as c:
        yield c


@pytest.fixture()
def admin_token(client):
    r = client.post(
        "/auth/register",
        json={"email": "admin@example.com", "password": "admin-password-1"},
    )
    assert r.status_code == 201, r.text
    return r.json()["access_token"]


def auth(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}
