"""
Seed 5 user MTM ke database waktu startup (hanya kalau belum ada).
"""
import logging
from sqlalchemy.orm import Session
from app.models.user import User
from app.utils.auth import hash_password

logger = logging.getLogger(__name__)

MTM_USERS = [
    {"username": "Attalarik", "full_name": "Attalarik", "password": "attalarik@2026"},
    {"username": "Dailam",    "full_name": "Dailam",    "password": "dailam@2026"},
    {"username": "Rafky",     "full_name": "Rafky",     "password": "rafky@2026"},
    {"username": "Farandio",  "full_name": "Farandio",  "password": "farandio@2026"},
    {"username": "Jefri",     "full_name": "Jefri",     "password": "jefri@2026"},
]


def seed_users(db: Session) -> None:
    added = 0
    for u in MTM_USERS:
        exists = db.query(User).filter(User.username == u["username"]).first()
        if not exists:
            db.add(User(
                username=u["username"],
                full_name=u["full_name"],
                hashed_password=hash_password(u["password"]),
                is_active=True,
            ))
            added += 1
    if added:
        db.commit()
        logger.info(f"[SEED] {added} user MTM berhasil ditambahkan ke database.")
    else:
        logger.info("[SEED] Semua user MTM sudah ada di database.")
