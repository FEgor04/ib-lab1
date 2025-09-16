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


def test_xss_protection_in_post_title(client: TestClient):
    unique_user = f"user_{uuid.uuid4().hex[:8]}"
    token = register_and_login(client, unique_user, "strongpassword")

    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')></iframe>",
        "<b>Bold</b> <i>Italic</i>",  # Basic HTML tags
        "Hello <script>alert(1)</script> World",
    ]

    for payload in xss_payloads:
        # Create post with XSS payload
        r = client.post(
            "/api/posts",
            headers=auth_headers(token),
            json={"title": payload, "content": "Safe content"},
        )
        assert r.status_code == 201, f"Failed for payload: {payload}"

        post = r.json()
        title = post["title"]

        assert "<script>" not in title.lower(), f"Script tag not escaped in: {title}"
        if "<" in payload and ">" in payload:
            assert "&lt;" in title or "&gt;" in title, f"HTML not properly escaped in: {title}"


def test_xss_protection_in_post_content(client: TestClient):
    unique_user = f"user_{uuid.uuid4().hex[:8]}"
    token = register_and_login(client, unique_user, "strongpassword")

    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')></iframe>",
        "<b>Bold</b> <i>Italic</i>",  # Basic HTML tags
        "Hello <script>alert(1)</script> World",
        "Normal text with <script>alert('XSS')</script> injection",
    ]

    for payload in xss_payloads:
        # Create post with XSS payload
        r = client.post(
            "/api/posts",
            headers=auth_headers(token),
            json={"title": "Safe title", "content": payload},
        )
        assert r.status_code == 201, f"Failed for payload: {payload}"

        post = r.json()
        content = post["content"]

        assert "<script>" not in content.lower(), f"Script tag not escaped in: {content}"
        assert "<img" not in content.lower(), f"Img tag not escaped in: {content}"
        assert "<svg" not in content.lower(), f"Svg tag not escaped in: {content}"
        assert "<iframe" not in content.lower(), f"Iframe tag not escaped in: {content}"
        assert "<b>" not in content.lower(), f"Bold tag not escaped in: {content}"
        assert "<i>" not in content.lower(), f"Italic tag not escaped in: {content}"


def test_xss_protection_in_list_posts(client: TestClient):
    unique_user = f"user_{uuid.uuid4().hex[:8]}"
    token = register_and_login(client, unique_user, "strongpassword")

    xss_payloads = [
        "<script>alert('XSS1')</script>",
        "<img src=x onerror=alert('XSS2')>",
        "Hello <b>World</b>",
    ]

    for i, payload in enumerate(xss_payloads):
        r = client.post(
            "/api/posts",
            headers=auth_headers(token),
            json={"title": f"Title {i}: {payload}", "content": f"Content {i}: {payload}"},
        )
        assert r.status_code == 201

    r = client.get("/api/posts", headers=auth_headers(token))
    assert r.status_code == 200

    posts = r.json()
    assert len(posts) >= len(xss_payloads)

    for post in posts:
        title = post["title"]
        content = post["content"]

        assert "<script>" not in title.lower()
        assert "&lt;" in title or "&gt;" in title

        assert "<script>" not in content.lower()
        assert "&lt;" in content or "&gt;" in content


def test_xss_protection_prevents_execution(client: TestClient):
    unique_user = f"user_{uuid.uuid4().hex[:8]}"
    token = register_and_login(client, unique_user, "strongpassword")

    malicious_payload = """
    <script>
        document.body.innerHTML = '<h1>HACKED!</h1>';
        fetch('/api/posts', {
            method: 'POST',
            headers: {'Authorization': 'Bearer ' + localStorage.getItem('token')},
            body: JSON.stringify({title: 'Hacked Post', content: 'This was hacked'})
        });
    </script>
    <img src="x" onerror="alert('XSS')">
    <svg onload="alert('XSS')">
    """

    r = client.post(
        "/api/posts",
        headers=auth_headers(token),
        json={"title": "Safe title", "content": malicious_payload},
    )
    assert r.status_code == 201

    post = r.json()
    content = post["content"]

    assert "<script>" not in content.lower()
    assert "&lt;" in content or "&gt;" in content
