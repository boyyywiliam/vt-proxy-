from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    # Simpan password dalam bentuk bcrypt hash — JANGAN plaintext
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True, server_default="1")
    created_at = Column(DateTime, default=func.now(), server_default=func.now())
    last_login = Column(DateTime, nullable=True)
