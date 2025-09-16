from __future__ import annotations

import uuid
from typing import Dict

from fastapi.testclient import TestClient
import sqlite3
import os


def register_and_login(client: TestClient, username: str, password: str) -> str:
    r = client.post("/auth/register", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    return token


def auth_headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_sqli_protection_in_post_creation(client: TestClient):
    unique_user = f"user_{uuid.uuid4().hex[:8]}"
    token = register_and_login(client, unique_user, "strongpassword")

    sqli_payloads = [
        "'; DROP TABLE posts; --",
        "' OR '1'='1",
        "'; INSERT INTO users (username, password_hash) VALUES ('hacker', 'hash'); --",
        "' UNION SELECT username, password_hash FROM users --",
        "'; UPDATE users SET password_hash='hacked' WHERE username='admin'; --",
        "1' OR 1=1 --",
        "admin'--",
        "' OR 1=1 LIMIT 1 OFFSET 0 --",
        "'; DELETE FROM posts; --",
        "' OR 'x'='x",
    ]

    for i, payload in enumerate(sqli_payloads):
        r = client.post(
            "/api/posts",
            headers=auth_headers(token),
            json={"title": payload, "content": f"Content {i}"},
        )
        assert r.status_code == 201, f"SQL injection in title failed for payload: {payload}"

        r = client.post(
            "/api/posts",
            headers=auth_headers(token),
            json={"title": f"Title {i}", "content": payload},
        )
        assert r.status_code == 201, f"SQL injection in content failed for payload: {payload}"


def test_sqli_protection_in_user_registration(client: TestClient):
    sqli_payloads = [
        "admin'; DROP TABLE users; --",
        "' OR '1'='1",
        "'; INSERT INTO users (username, password_hash) VALUES ('hacker', 'hash'); --",
        "' UNION SELECT username, password_hash FROM users --",
        "admin'--",
        "1' OR 1=1 --",
    ]

    for i, payload in enumerate(sqli_payloads):
        r = client.post("/auth/register", json={"username": payload, "password": "password123"})

        assert r.status_code in [200, 400, 422], f"Unexpected status for payload: {payload}"

        if r.status_code == 400:
            assert "already exists" in r.json()["detail"] or "validation" in str(r.json()).lower()
        elif r.status_code == 422:
            assert "validation" in str(r.json()).lower()


def test_sqli_protection_in_user_login(client: TestClient):
    unique_user = f"user_{uuid.uuid4().hex[:8]}"
    password = "password123"

    r = client.post("/auth/register", json={"username": unique_user, "password": password})
    assert r.status_code == 200

    sqli_payloads = [
        "admin'; DROP TABLE users; --",
        "' OR '1'='1",
        "'; INSERT INTO users (username, password_hash) VALUES ('hacker', 'hash'); --",
        "' UNION SELECT username, password_hash FROM users --",
        "admin'--",
        "1' OR 1=1 --",
        f"{unique_user}' OR '1'='1",
        f"{unique_user}'; --",
    ]

    for payload in sqli_payloads:
        r = client.post("/auth/login", json={"username": payload, "password": password})
        assert (
            r.status_code == 401
        ), f"SQL injection in login username succeeded for payload: {payload}"
        assert "Incorrect username or password" in r.json()["detail"]

        r = client.post("/auth/login", json={"username": unique_user, "password": payload})
        assert (
            r.status_code == 401
        ), f"SQL injection in login password succeeded for payload: {payload}"
        assert "Incorrect username or password" in r.json()["detail"]


def test_sqli_protection_preserves_data_integrity(client: TestClient):
    users = []
    for i in range(3):
        username = f"user_{uuid.uuid4().hex[:8]}"
        password = "password123"

        r = client.post("/auth/register", json={"username": username, "password": password})
        assert r.status_code == 200
        users.append((username, password))

    user_tokens = []
    for username, password in users:
        r = client.post("/auth/login", json={"username": username, "password": password})
        assert r.status_code == 200
        token = r.json()["access_token"]
        user_tokens.append(token)

        r = client.post(
            "/api/posts",
            headers=auth_headers(token),
            json={"title": f"Post by {username}", "content": f"Content by {username}"},
        )
        assert r.status_code == 201

    sqli_payloads = [
        "'; DROP TABLE posts; --",
        "'; DELETE FROM posts; --",
        "'; UPDATE posts SET title='HACKED'; --",
    ]

    for payload in sqli_payloads:
        r = client.post(
            "/api/posts",
            headers=auth_headers(user_tokens[0]),
            json={"title": payload, "content": "SQL injection attempt"},
        )
        assert r.status_code == 201

    for token in user_tokens:
        r = client.get("/api/posts", headers=auth_headers(token))
        assert r.status_code == 200

        posts = r.json()
        assert len(posts) >= 1

        original_posts = [p for p in posts if not p["title"].startswith("';")]
        assert len(original_posts) >= 1


def test_sqli_protection_with_complex_payloads(client: TestClient):
    unique_user = f"user_{uuid.uuid4().hex[:8]}"
    token = register_and_login(client, unique_user, "strongpassword")

    complex_payloads = [
        "'; EXEC xp_cmdshell('dir'); --",
        "'; SELECT * FROM information_schema.tables; --",
        "'; SHOW TABLES; --",
        "'; SELECT version(); --",
        "'; SELECT user(); --",
        "'; SELECT database(); --",
        "'; LOAD_FILE('/etc/passwd'); --",
        "'; INTO OUTFILE '/tmp/hack.txt'; --",
        "'; SELECT * FROM mysql.user; --",
        "'; GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%'; --",
    ]

    for i, payload in enumerate(complex_payloads):
        r = client.post(
            "/api/posts",
            headers=auth_headers(token),
            json={"title": f"Complex SQLi {i}", "content": payload},
        )

        assert r.status_code == 201, f"Complex SQL injection failed for payload: {payload}"

        post = r.json()
        assert payload in post["content"], f"Payload not stored as literal: {payload}"

        r = client.get("/api/posts", headers=auth_headers(token))
        assert r.status_code == 200
        posts = r.json()
        assert len(posts) >= i + 1
