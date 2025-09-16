from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from .db import get_db
from .models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = HTTPBearer(auto_error=False)

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
JWT_EXP_MIN = int(os.environ.get("JWT_EXP_MIN", "60"))


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.now(tz=timezone.utc) + (expires_delta or timedelta(minutes=JWT_EXP_MIN))
    payload = {"sub": subject, "exp": expire}
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
    return token


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        username: str = payload.get("sub")  # type: ignore[assignment]
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user
