from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DEFAULT_DB_URL = "sqlite:///./app.db"
SQLALCHEMY_DATABASE_URL = os.environ.get("DATABASE_URL", DEFAULT_DB_URL)


class Base(DeclarativeBase):
    pass


engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def db_session() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
