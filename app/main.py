from fastapi import FastAPI, Depends, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy.orm import Session
from typing import Optional
from app.database import get_db, init_db, SessionLocal
from app.models import VTAPIKey, APIUsageLog
from app.models.user import User
from app.config import settings
from app.api import keys, scan, dashboard
from app.api.api_router import router as api_router
from app.api.auth import router as auth_router
from app.scheduler import start_scheduler, stop_scheduler
from app.utils.auth import decode_access_token
from app.utils.seed_users import seed_users
import uvicorn
import os

app = FastAPI(
    title="Threat Intelligence MTM",
    description="Multi-source threat intelligence proxy with load balancing",
    version="1.0.0"
)

# ========== CORS ==========
# allow_credentials=True wajib biar browser boleh kirim cookie HttpOnly ke server.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== ROUTERS ==========
app.include_router(auth_router)       # /auth/*
app.include_router(keys.router)       # /keys/*  (legacy)
app.include_router(scan.router)       # /scan/*  (legacy + /scan/multi)
app.include_router(dashboard.router)  # /dashboard/* (legacy)
app.include_router(api_router)        # /api/* (clean, baru)

# ========== EVENTS ==========
@app.on_event("startup")
def startup():
    init_db()
    start_scheduler()
    # Seed user MTM waktu startup
    db = SessionLocal()
    try:
        seed_users(db)
    finally:
        db.close()
    print("[STARTUP] Database initialized! Scheduler started! Users seeded!")

@app.on_event("shutdown")
def shutdown():
    stop_scheduler()
    print("[SHUTDOWN] Scheduler stopped!")

# ========== HELPER: cek token dari cookie ==========
def _get_user_from_cookie(access_token: Optional[str]) -> Optional[str]:
    """Return username kalau token valid, None kalau tidak."""
    if not access_token:
        return None
    payload = decode_access_token(access_token)
    if not payload:
        return None
    return payload.get("sub")

# ========== ENDPOINTS ==========

@app.get("/login")
def serve_login(access_token: Optional[str] = Cookie(default=None)):
    """Halaman login. Kalau sudah login, langsung redirect ke /ui."""
    if _get_user_from_cookie(access_token):
        return RedirectResponse(url="/ui", status_code=302)
    login_path = os.path.join(os.path.dirname(__file__), "..", "login.html")
    if os.path.exists(login_path):
        return FileResponse(login_path)
    return {"error": "login.html not found"}


@app.get("/ui")
def serve_ui(access_token: Optional[str] = Cookie(default=None)):
    """Dashboard utama. WAJIB login — kalau belum, redirect ke /login."""
    if not _get_user_from_cookie(access_token):
        return RedirectResponse(url="/login", status_code=302)
    ui_path = os.path.join(os.path.dirname(__file__), "..", "dashboard.html")
    if os.path.exists(ui_path):
        return FileResponse(ui_path)
    return {"error": "dashboard.html not found"}


@app.get("/")
def root(access_token: Optional[str] = Cookie(default=None)):
    """Root redirect: kalau sudah login → dashboard, belum → login."""
    if _get_user_from_cookie(access_token):
        return RedirectResponse(url="/ui", status_code=302)
    return RedirectResponse(url="/login", status_code=302)


@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    total_keys = db.query(VTAPIKey).count()
    active_keys = db.query(VTAPIKey).filter(VTAPIKey.is_active == True).count()
    return {
        "status": "healthy",
        "total_keys": total_keys,
        "active_keys": active_keys
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)