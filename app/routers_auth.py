from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .db import get_db
from .models import User
from .schemas import Token, UserCreate, UserOut
from .security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserOut)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == user_in.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    user = User(username=user_in.username, password_hash=hash_password(user_in.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=Token)
def login(user_in: UserCreate, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == user_in.username).first()
    if not user or not verify_password(user_in.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token(subject=user.username)
    return Token(access_token=token)
