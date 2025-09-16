from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .db import get_db
from .models import Post, User
from .schemas import PostCreate, PostOut
from .security import get_current_user

router = APIRouter(prefix="/api/posts", tags=["posts"])


@router.get("", response_model=List[PostOut])
def list_posts(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    posts = db.query(Post).order_by(Post.created_at.desc()).all()
    return [PostOut.model_validate(p).model_dump() for p in posts]


@router.post("", response_model=PostOut, status_code=201)
def create_post(
    post_in: PostCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    post = Post(title=post_in.title, content=post_in.content, author_id=current_user.id)
    db.add(post)
    db.commit()
    db.refresh(post)
    return PostOut.model_validate(post).model_dump()
