from __future__ import annotations

from datetime import datetime

import bleach
from pydantic import BaseModel, Field, field_serializer


def escape_html(value: str) -> str:
    # Escape all HTML tags/attrs to mitigate XSS; keep text as-is
    return bleach.clean(value, tags=[], attributes={}, protocols=[], strip=False)


def strip_html(value: str) -> str:
    # Remove all HTML tags entirely (useful for large content fields)
    return bleach.clean(value, tags=[], attributes={}, protocols=[], strip=True)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=6, max_length=200)


class UserOut(BaseModel):
    id: int
    username: str
    created_at: datetime

    model_config = {"from_attributes": True}


class PostCreate(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=1, max_length=4000)


class PostOut(BaseModel):
    id: int
    title: str
    content: str
    created_at: datetime
    author_id: int

    @field_serializer("title", when_used="json")
    def serialize_title(self, value: str):  # type: ignore[override]
        return escape_html(value)

    @field_serializer("content", when_used="json")
    def serialize_content(self, value: str):  # type: ignore[override]
        return strip_html(value)

    model_config = {"from_attributes": True}
