from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    posts: Mapped[list[Post]] = relationship("Post", back_populates="author")


class Post(Base):
    __tablename__ = "posts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(200))
    content: Mapped[str] = mapped_column(String(4000))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))

    author: Mapped[User] = relationship("User", back_populates="posts")
