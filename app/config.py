from pydantic_settings import BaseSettings
from pydantic import model_validator
from dotenv import load_dotenv
import os

load_dotenv()

def _env(name: str, default: str = "") -> str:
    """Ambil env var dan buang whitespace di ujung (.env sering kebawa spasi)."""
    return (os.getenv(name) or default).strip()

# Placeholder saja — kredensial asli WAJIB lewat .env (MYSQL_URL / DATABASE_URL),
# jangan pernah ditulis di sini karena file ini ikut ter-commit ke repo publik.
DEFAULT_MYSQL_URL = "mysql+pymysql://CHANGE_ME:CHANGE_ME@localhost:3306/vt_proxy"
DEFAULT_SQLITE_URL = "sqlite:///./vt_proxy.db"

class Settings(BaseSettings):
    # ===== DATABASE (dual support: mysql / sqlite) =====
    # DB_BACKEND yang menentukan dipakai yang mana:
    #   DB_BACKEND=mysql   -> pakai MYSQL_URL
    #   DB_BACKEND=sqlite  -> pakai SQLITE_URL
    #   DB_BACKEND kosong  -> fallback ke DATABASE_URL (perilaku lama)
    DB_BACKEND: str = _env("DB_BACKEND", "")
    MYSQL_URL: str = _env("MYSQL_URL") or _env("DATABASE_URL") or DEFAULT_MYSQL_URL
    SQLITE_URL: str = _env("SQLITE_URL") or DEFAULT_SQLITE_URL

    # URL yang benar-benar dipakai engine. Diisi otomatis dari DB_BACKEND.
    DATABASE_URL: str = _env("DATABASE_URL", DEFAULT_MYSQL_URL)

    SECRET_KEY: str = _env("SECRET_KEY", "supersecretkey")
    VT_API_BASE_URL: str = _env("VT_API_BASE_URL", "https://www.virustotal.com/api/v3")
    AUTO_REFRESH_INTERVAL_DAYS: int = int(_env("AUTO_REFRESH_INTERVAL_DAYS", "3"))
    CACHE_TTL_DAYS: int = int(_env("CACHE_TTL_DAYS", "7"))  # Default 7 hari (1 minggu)
    LOG_LEVEL: str = _env("LOG_LEVEL", "INFO")

    # ===== MULTI-SOURCE THREAT INTELLIGENCE =====
    ABUSEIPDB_API_BASE_URL: str = _env("ABUSEIPDB_API_BASE_URL", "https://api.abuseipdb.com/api/v2")
    URLHAUS_API_BASE_URL: str = _env("URLHAUS_API_BASE_URL", "https://urlhaus-api.abuse.ch/v1")
    MXTOOLBOX_API_BASE_URL: str = _env("MXTOOLBOX_API_BASE_URL", "https://mxtoolbox.com/api/v1")

    # Window laporan AbuseIPDB (hari). Makin panjang makin sensitif.
    ABUSEIPDB_MAX_AGE_DAYS: int = int(_env("ABUSEIPDB_MAX_AGE_DAYS", "90"))
    # Lookup MxToolbox default buat domain/email
    MXTOOLBOX_COMMAND: str = _env("MXTOOLBOX_COMMAND", "blacklist")
    HTTP_TIMEOUT_SECONDS: float = float(_env("HTTP_TIMEOUT_SECONDS", "15"))

    @model_validator(mode="after")
    def _resolve_database_url(self):
        backend = (self.DB_BACKEND or "").strip().lower()

        if backend == "sqlite":
            self.DATABASE_URL = self.SQLITE_URL
        elif backend in ("mysql", "mariadb"):
            self.DATABASE_URL = self.MYSQL_URL
        elif backend:
            raise ValueError(
                f"DB_BACKEND tidak dikenal: {backend!r}. Pakai 'mysql' atau 'sqlite'."
            )
        elif not self.DATABASE_URL:
            self.DATABASE_URL = self.MYSQL_URL

        self.DB_BACKEND = backend or (
            "sqlite" if self.DATABASE_URL.startswith("sqlite") else "mysql"
        )
        return self

    @property
    def IS_SQLITE(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite")

settings = Settings()
