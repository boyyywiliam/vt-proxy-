"""
Dependency FastAPI: cek token dari cookie.
- Kalau valid  → return username
- Kalau invalid → redirect ke /login
"""
from fastapi import Cookie, Depends
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from typing import Optional
from app.database import get_db
from app.models.user import User
from app.utils.auth import decode_access_token


def get_current_user_or_redirect(
    access_token: Optional[str] = Cookie(default=None),
    db: Session = Depends(get_db),
):
    """
    Dependency guard untuk endpoint yang butuh login.
    Kalau belum login → raise 401 (frontend redirect ke /login).
    """
    if not access_token:
        return None
    payload = decode_access_token(access_token)
    if not payload:
        return None
    username = payload.get("sub")
    if not username:
        return None
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    return user


def require_login(
    access_token: Optional[str] = Cookie(default=None),
    db: Session = Depends(get_db),
):
    """
    Dependency guard STRICT: user HARUS login, kalau tidak → redirect /login.
    Pakai ini di endpoint yang serve HTML (UI).
    """
    user = get_current_user_or_redirect(access_token, db)
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    return user
