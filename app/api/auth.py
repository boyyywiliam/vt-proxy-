"""
Auth router: /auth/login, /auth/logout, /auth/me, /login (serve halaman login)
"""
from fastapi import APIRouter, Depends, Form, HTTPException, Response, Cookie
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from typing import Optional
from app.database import get_db
from app.models.user import User
from app.utils.auth import verify_password, create_access_token, decode_access_token
import os

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login")
def login(
    response: Response,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    """
    Login endpoint.
    - Cek username & password di DB.
    - Kalau valid → set cookie `access_token` & return 200.
    - Kalau invalid → 401.
    """
    user = db.query(User).filter(
        User.username == username,
        User.is_active == True
    ).first()

    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Username atau password salah.")

    # Update last_login
    user.last_login = func.now()
    db.commit()

    token = create_access_token(data={"sub": user.username, "name": user.full_name})

    # Set cookie HttpOnly — browser tidak bisa baca via JS (lebih aman)
    response = Response(content='{"status":"ok"}', media_type="application/json")
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        max_age=12 * 3600,   # 12 jam
        samesite="lax",
        secure=False,         # Set True kalau pakai HTTPS
    )
    return response


@router.post("/logout")
def logout():
    """Hapus cookie → user keluar."""
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("access_token")
    return response


@router.get("/logout")
def logout_get():
    """Support GET logout juga (dari tombol di dashboard)."""
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("access_token")
    return response


@router.get("/me")
def get_me(
    access_token: Optional[str] = Cookie(default=None),
    db: Session = Depends(get_db),
):
    """Return info user yang sedang login (dibaca dari cookie JWT)."""
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_access_token(access_token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token invalid atau expired")
    username = payload.get("sub")
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="User tidak ditemukan")
    return {
        "username": user.username,
        "full_name": user.full_name,
        "last_login": str(user.last_login) if user.last_login else None,
    }
