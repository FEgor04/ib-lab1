from __future__ import annotations

import time
import uuid
from typing import Dict

import jwt
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


def test_cannot_get_posts_with_expired_jwt(client: TestClient):
    unique_user = f"user_{uuid.uuid4().hex[:8]}"
    register_and_login(client, unique_user, "strongpassword")

    expired_payload = {"sub": unique_user, "exp": int(time.time()) - 3600}
    expired_token = jwt.encode(expired_payload, "dev-secret-change-me", algorithm="HS256")

    r = client.get("/api/posts", headers=auth_headers(expired_token))
    assert r.status_code == 401
    assert "Token expired" in r.json()["detail"]


def test_cannot_get_posts_with_invalid_jwt_signature(client: TestClient):
    unique_user = f"user_{uuid.uuid4().hex[:8]}"
    register_and_login(client, unique_user, "strongpassword")

    invalid_payload = {"sub": unique_user, "exp": int(time.time()) + 3600}
    invalid_token = jwt.encode(invalid_payload, "wrong-secret", algorithm="HS256")

    r = client.get("/api/posts", headers=auth_headers(invalid_token))
    assert r.status_code == 401
    assert "Invalid token" in r.json()["detail"]


def test_cannot_get_posts_with_malformed_jwt(client: TestClient):
    malformed_tokens = [
        "not.a.jwt",
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid",
        "invalid.jwt.token",
        "",
        "Bearer invalid-token",
    ]

    for token in malformed_tokens:
        r = client.get("/api/posts", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401
        detail = r.json()["detail"]
        assert "Invalid token" in detail or "Not authenticated" in detail


def test_cannot_get_posts_with_missing_sub_claim(client: TestClient):
    invalid_payload = {"exp": int(time.time()) + 3600}
    invalid_token = jwt.encode(invalid_payload, "dev-secret-change-me", algorithm="HS256")

    r = client.get("/api/posts", headers=auth_headers(invalid_token))
    assert r.status_code == 401
    assert "Invalid token" in r.json()["detail"]


def test_cannot_get_posts_with_nonexistent_user(client: TestClient):
    invalid_payload = {
        "sub": "nonexistent_user",
        "exp": int(time.time()) + 3600,
    }
    invalid_token = jwt.encode(invalid_payload, "dev-secret-change-me", algorithm="HS256")

    r = client.get("/api/posts", headers=auth_headers(invalid_token))
    assert r.status_code == 401
    assert "User not found" in r.json()["detail"]
