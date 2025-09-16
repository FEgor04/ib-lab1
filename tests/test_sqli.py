from __future__ import annotations

import uuid
from typing import Dict

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

import app.db as db_module
import app.models as models_module


def register_and_login(client: TestClient, username: str, password: str) -> str:
    r = client.post("/auth/register", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    r = client.post("/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    return token


def auth_headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def get_db_session() -> Session:
    return db_module.SessionLocal()


def check_table_exists(table_name: str) -> bool:
    with get_db_session() as session:
        result = session.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name=:table_name"),
            {"table_name": table_name},
        )
        return result.fetchone() is not None


def get_table_schema(table_name: str) -> list:
    with get_db_session() as session:
        result = session.execute(text(f"PRAGMA table_info({table_name})"))
        return result.fetchall()


def count_table_records(table_name: str) -> int:
    with get_db_session() as session:
        result = session.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
        return result.fetchone()[0]


def get_all_users() -> list:
    with get_db_session() as session:
        result = session.execute(text("SELECT id, username, created_at FROM users"))
        return result.fetchall()


def get_all_posts() -> list:
    with get_db_session() as session:
        result = session.execute(
            text("SELECT id, title, content, created_at, author_id FROM posts")
        )
        return result.fetchall()


def verify_database_integrity():
    assert check_table_exists("users"), "Users table should exist"
    assert check_table_exists("posts"), "Posts table should exist"

    users_schema = get_table_schema("users")
    posts_schema = get_table_schema("posts")

    user_columns = [col[1] for col in users_schema]
    post_columns = [col[1] for col in posts_schema]

    expected_user_columns = ["id", "username", "password_hash", "created_at"]
    expected_post_columns = ["id", "title", "content", "created_at", "author_id"]

    for col in expected_user_columns:
        assert col in user_columns, f"Users table missing column: {col}"

    for col in expected_post_columns:
        assert col in post_columns, f"Posts table missing column: {col}"

    return True


def verify_data_integrity_with_orm():
    with get_db_session() as session:
        users = session.query(models_module.User).all()
        posts = session.query(models_module.Post).all()

        for user in users:
            assert user.id is not None
            assert user.username is not None
            assert user.password_hash is not None
            assert user.created_at is not None

        for post in posts:
            assert post.id is not None
            assert post.title is not None
            assert post.content is not None
            assert post.created_at is not None
            assert post.author_id is not None

            author = (
                session.query(models_module.User)
                .filter(models_module.User.id == post.author_id)
                .first()
            )
            assert (
                author is not None
            ), f"Post {post.id} references non-existent user {post.author_id}"

    return True


def count_users_with_orm() -> int:
    with get_db_session() as session:
        return session.query(models_module.User).count()


def count_posts_with_orm() -> int:
    with get_db_session() as session:
        return session.query(models_module.Post).count()


def test_sqli_protection_in_post_creation(client: TestClient):
    unique_user = f"user_{uuid.uuid4().hex[:8]}"
    token = register_and_login(client, unique_user, "strongpassword")

    initial_user_count = count_users_with_orm()
    initial_post_count = count_posts_with_orm()

    verify_database_integrity()
    verify_data_integrity_with_orm()

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

        verify_database_integrity()
        verify_data_integrity_with_orm()
        assert (
            count_users_with_orm() == initial_user_count
        ), f"User count changed after payload: {payload}"
        assert (
            count_posts_with_orm() >= initial_post_count + (i + 1) * 2
        ), f"Post count not as expected after payload: {payload}"

    final_user_count = count_users_with_orm()
    final_post_count = count_posts_with_orm()

    assert (
        final_user_count == initial_user_count
    ), "User count should remain unchanged after SQL injection attempts"
    assert (
        final_post_count == initial_post_count + len(sqli_payloads) * 2
    ), "Post count should only increase by legitimate posts"


def test_sqli_protection_in_user_registration(client: TestClient):
    initial_user_count = count_users_with_orm()
    initial_post_count = count_posts_with_orm()

    verify_database_integrity()
    verify_data_integrity_with_orm()

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

        verify_database_integrity()
        verify_data_integrity_with_orm()
        assert (
            count_posts_with_orm() == initial_post_count
        ), f"Post count changed after user registration payload: {payload}"

    final_user_count = count_users_with_orm()
    final_post_count = count_posts_with_orm()

    assert (
        final_user_count >= initial_user_count
    ), "User count should not decrease after SQL injection attempts"
    assert (
        final_post_count == initial_post_count
    ), "Post count should remain unchanged after user registration attempts"


def test_sqli_protection_in_user_login(client: TestClient):
    unique_user = f"user_{uuid.uuid4().hex[:8]}"
    password = "password123"

    r = client.post("/auth/register", json={"username": unique_user, "password": password})
    assert r.status_code == 200

    initial_user_count = count_users_with_orm()
    initial_post_count = count_posts_with_orm()

    verify_database_integrity()
    verify_data_integrity_with_orm()

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

        verify_database_integrity()
        verify_data_integrity_with_orm()
        assert (
            count_users_with_orm() == initial_user_count
        ), f"User count changed after login payload: {payload}"
        assert (
            count_posts_with_orm() == initial_post_count
        ), f"Post count changed after login payload: {payload}"

    final_user_count = count_users_with_orm()
    final_post_count = count_posts_with_orm()

    assert (
        final_user_count == initial_user_count
    ), "User count should remain unchanged after SQL injection login attempts"
    assert (
        final_post_count == initial_post_count
    ), "Post count should remain unchanged after SQL injection login attempts"


def test_sqli_protection_preserves_data_integrity(client: TestClient):
    initial_user_count = count_users_with_orm()
    initial_post_count = count_posts_with_orm()

    verify_database_integrity()
    verify_data_integrity_with_orm()

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

    verify_database_integrity()
    verify_data_integrity_with_orm()

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

        verify_database_integrity()
        verify_data_integrity_with_orm()

    for token in user_tokens:
        r = client.get("/api/posts", headers=auth_headers(token))
        assert r.status_code == 200

        posts = r.json()
        assert len(posts) >= 1

        original_posts = [p for p in posts if not p["title"].startswith("';")]
        assert len(original_posts) >= 1

    final_user_count = count_users_with_orm()
    final_post_count = count_posts_with_orm()

    assert final_user_count == initial_user_count + 3, "Should have exactly 3 new users"
    assert final_post_count >= initial_post_count + 3 + len(
        sqli_payloads
    ), "Should have original posts plus new posts"


def test_sqli_protection_with_complex_payloads(client: TestClient):
    unique_user = f"user_{uuid.uuid4().hex[:8]}"
    token = register_and_login(client, unique_user, "strongpassword")

    initial_user_count = count_users_with_orm()
    initial_post_count = count_posts_with_orm()

    verify_database_integrity()
    verify_data_integrity_with_orm()

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

        verify_database_integrity()
        verify_data_integrity_with_orm()
        assert (
            count_users_with_orm() == initial_user_count
        ), f"User count changed after complex payload: {payload}"
        assert (
            count_posts_with_orm() >= initial_post_count + i + 1
        ), f"Post count not as expected after complex payload: {payload}"

        r = client.get("/api/posts", headers=auth_headers(token))
        assert r.status_code == 200
        posts = r.json()
        assert len(posts) >= i + 1

    final_user_count = count_users_with_orm()
    final_post_count = count_posts_with_orm()

    assert (
        final_user_count == initial_user_count
    ), "User count should remain unchanged after complex SQL injection attempts"
    assert final_post_count == initial_post_count + len(
        complex_payloads
    ), "Post count should only increase by legitimate posts"
