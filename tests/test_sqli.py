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


def test_sqli_protection_in_post_creation(client: TestClient):
    """Test that SQL injection attacks in post creation are prevented."""
    unique_user = f"user_{uuid.uuid4().hex[:8]}"
    token = register_and_login(client, unique_user, "strongpassword")

    # Various SQL injection payloads
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
        # Try SQL injection in title
        r = client.post(
            "/api/posts",
            headers=auth_headers(token),
            json={"title": payload, "content": f"Content {i}"},
        )
        # Should succeed (payload treated as literal string, not SQL)
        assert r.status_code == 201, f"SQL injection in title failed for payload: {payload}"

        # Try SQL injection in content
        r = client.post(
            "/api/posts",
            headers=auth_headers(token),
            json={"title": f"Title {i}", "content": payload},
        )
        # Should succeed (payload treated as literal string, not SQL)
        assert r.status_code == 201, f"SQL injection in content failed for payload: {payload}"


def test_sqli_protection_in_user_registration(client: TestClient):
    """Test that SQL injection attacks in user registration are prevented."""
    # Various SQL injection payloads for username
    sqli_payloads = [
        "admin'; DROP TABLE users; --",
        "' OR '1'='1",
        "'; INSERT INTO users (username, password_hash) VALUES ('hacker', 'hash'); --",
        "' UNION SELECT username, password_hash FROM users --",
        "admin'--",
        "1' OR 1=1 --",
    ]

    for i, payload in enumerate(sqli_payloads):
        # Try SQL injection in username
        r = client.post("/auth/register", json={"username": payload, "password": "password123"})

        # Should either succeed (payload treated as literal) or fail with validation error
        # But should NOT cause SQL errors or database corruption
        assert r.status_code in [200, 400, 422], f"Unexpected status for payload: {payload}"

        if r.status_code == 400:
            # Username already exists or validation error - this is expected
            assert "already exists" in r.json()["detail"] or "validation" in str(r.json()).lower()
        elif r.status_code == 422:
            # Validation error - this is expected for malformed input
            assert "validation" in str(r.json()).lower()


def test_sqli_protection_in_user_login(client: TestClient):
    """Test that SQL injection attacks in user login are prevented."""
    # Create a legitimate user first
    unique_user = f"user_{uuid.uuid4().hex[:8]}"
    password = "password123"

    r = client.post("/auth/register", json={"username": unique_user, "password": password})
    assert r.status_code == 200

    # Various SQL injection payloads for login
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
        # Try SQL injection in username
        r = client.post("/auth/login", json={"username": payload, "password": password})

        # Should fail with authentication error (not SQL error)
        assert (
            r.status_code == 401
        ), f"SQL injection in login username succeeded for payload: {payload}"
        assert "Incorrect username or password" in r.json()["detail"]

        # Try SQL injection in password
        r = client.post("/auth/login", json={"username": unique_user, "password": payload})

        # Should fail with authentication error (not SQL error)
        assert (
            r.status_code == 401
        ), f"SQL injection in login password succeeded for payload: {payload}"
        assert "Incorrect username or password" in r.json()["detail"]


def test_sqli_protection_preserves_data_integrity(client: TestClient):
    """Test that SQL injection attempts don't corrupt existing data."""
    # Create multiple legitimate users and posts
    users = []
    for i in range(3):
        username = f"user_{uuid.uuid4().hex[:8]}"
        password = "password123"

        r = client.post("/auth/register", json={"username": username, "password": password})
        assert r.status_code == 200
        users.append((username, password))

    # Create posts for each user
    user_tokens = []
    for username, password in users:
        r = client.post("/auth/login", json={"username": username, "password": password})
        assert r.status_code == 200
        token = r.json()["access_token"]
        user_tokens.append(token)

        # Create a post
        r = client.post(
            "/api/posts",
            headers=auth_headers(token),
            json={"title": f"Post by {username}", "content": f"Content by {username}"},
        )
        assert r.status_code == 201

    # Attempt SQL injection attacks
    sqli_payloads = [
        "'; DROP TABLE posts; --",
        "'; DELETE FROM posts; --",
        "'; UPDATE posts SET title='HACKED'; --",
    ]

    for payload in sqli_payloads:
        # Try SQL injection in post creation
        r = client.post(
            "/api/posts",
            headers=auth_headers(user_tokens[0]),
            json={"title": payload, "content": "SQL injection attempt"},
        )
        assert r.status_code == 201  # Should succeed (payload treated as literal)

    # Verify all original data is still intact
    for token in user_tokens:
        r = client.get("/api/posts", headers=auth_headers(token))
        assert r.status_code == 200

        posts = r.json()
        # Should have at least the original post plus any SQL injection attempts (treated as normal posts)
        assert len(posts) >= 1

        # Verify original posts are still there with correct titles
        original_posts = [p for p in posts if not p["title"].startswith("';")]
        assert len(original_posts) >= 1


def test_sqli_protection_with_complex_payloads(client: TestClient):
    """Test protection against complex SQL injection payloads."""
    unique_user = f"user_{uuid.uuid4().hex[:8]}"
    token = register_and_login(client, unique_user, "strongpassword")

    # Complex SQL injection payloads
    complex_payloads = [
        "'; EXEC xp_cmdshell('dir'); --",  # SQL Server command execution
        "'; SELECT * FROM information_schema.tables; --",  # Information disclosure
        "'; SHOW TABLES; --",  # MySQL table enumeration
        "'; SELECT version(); --",  # Version disclosure
        "'; SELECT user(); --",  # User disclosure
        "'; SELECT database(); --",  # Database name disclosure
        "'; LOAD_FILE('/etc/passwd'); --",  # File reading attempt
        "'; INTO OUTFILE '/tmp/hack.txt'; --",  # File writing attempt
        "'; SELECT * FROM mysql.user; --",  # User table access
        "'; GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%'; --",  # Privilege escalation
    ]

    for i, payload in enumerate(complex_payloads):
        # Try complex SQL injection in post creation
        r = client.post(
            "/api/posts",
            headers=auth_headers(token),
            json={"title": f"Complex SQLi {i}", "content": payload},
        )

        # Should succeed (payload treated as literal string)
        assert r.status_code == 201, f"Complex SQL injection failed for payload: {payload}"

        # Verify the payload was stored as literal text, not executed
        post = r.json()
        assert payload in post["content"], f"Payload not stored as literal: {payload}"

        # Verify no SQL commands were executed by checking post count
        r = client.get("/api/posts", headers=auth_headers(token))
        assert r.status_code == 200
        posts = r.json()
        # Should have expected number of posts (no unexpected deletions or modifications)
        assert len(posts) >= i + 1
