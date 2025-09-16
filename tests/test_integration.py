from __future__ import annotations

import uuid
from typing import Dict

from fastapi.testclient import TestClient


def register_and_login(client: TestClient, username: str, password: str) -> str:
    r = client.post("/auth/register", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    return token


def auth_headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_posts_crud_and_authentication(client: TestClient):
    # Unique username per test run
    unique_user = f"user_{uuid.uuid4().hex[:8]}"
    token = register_and_login(client, unique_user, "strongpassword")

    # Create post
    r = client.post(
        "/api/posts",
        headers=auth_headers(token),
        json={"title": "Hello <b>World</b>", "content": "<script>alert(1)</script> Safe"},
    )
    assert r.status_code == 201, r.text
    post = r.json()
    assert post["title"] == "Hello &lt;b&gt;World&lt;/b&gt;"
    assert "script" not in post["content"].lower()

    # List posts requires auth
    r = client.get("/api/posts", headers=auth_headers(token))
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list) and len(data) >= 1

    # Access without token is denied
    r = client.get("/api/posts")
    assert r.status_code == 401


def test_cannot_create_post_without_auth(client: TestClient):
    """Test that creating a post without authentication is rejected."""
    r = client.post(
        "/api/posts",
        json={"title": "Unauthorized Post", "content": "This should fail"},
    )
    assert r.status_code == 401
    assert "Not authenticated" in r.json()["detail"]


def test_cannot_get_posts_without_auth(client: TestClient):
    """Test that getting posts without authentication is rejected."""
    r = client.get("/api/posts")
    assert r.status_code == 401
    assert "Not authenticated" in r.json()["detail"]
