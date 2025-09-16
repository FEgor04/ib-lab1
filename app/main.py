from __future__ import annotations

from fastapi import FastAPI

from . import models  # noqa: F401  Ensure models are imported so metadata includes tables
from .db import Base, engine
from .routers_auth import router as auth_router
from .routers_posts import router as posts_router


def create_app() -> FastAPI:
    Base.metadata.create_all(bind=engine)
    app = FastAPI(title="IB Lab 1 Secure API")
    app.include_router(auth_router)
    app.include_router(posts_router)
    return app


app = create_app()
