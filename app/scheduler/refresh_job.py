from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import VTAPIKey, CacheScan
from app.config import settings
import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def refresh_api_keys():
    """
    Auto-refresh API key pool & cleanup expired cache (> 7 hari / 1 minggu)
    """
    db = SessionLocal()
    try:
        # 1. Reset error flag untuk key yang masih aktif tapi error
        reset_count = db.query(VTAPIKey).filter(
            VTAPIKey.is_active == True,
            VTAPIKey.is_error == True,
            VTAPIKey.error_count < 5  # Maks 5 error, kalo lebih dari itu matiin
        ).update({"is_error": False, "error_count": 0})
        
        # 2. Matikan key yang error lebih dari 5 kali
        dead_keys = db.query(VTAPIKey).filter(
            VTAPIKey.is_active == True,
            VTAPIKey.error_count >= 5
        ).update({"is_active": False})
        
        # 3. Matikan key yang expired (kalo ada)
        expired_keys = db.query(VTAPIKey).filter(
            VTAPIKey.is_active == True,
            VTAPIKey.expires_at != None,
            VTAPIKey.expires_at < datetime.datetime.now()
        ).update({"is_active": False})

        # 4. Auto-delete cache hasil pindaian yang sudah lebih dari 7 hari (1 minggu)
        cache_cutoff = datetime.datetime.now() - datetime.timedelta(days=getattr(settings, "CACHE_TTL_DAYS", 7))
        deleted_caches = db.query(CacheScan).filter(
            CacheScan.scan_date < cache_cutoff
        ).delete()
        
        db.commit()
        
        logger.info(f"[AUTO-REFRESH] Reset {reset_count} keys, deactivated {dead_keys + expired_keys} keys, deleted {deleted_caches} expired caches (>7d)")
        
        # 4. Total key aktif
        total_active = db.query(VTAPIKey).filter(VTAPIKey.is_active == True).count()
        logger.info(f"[AUTO-REFRESH] Total active keys: {total_active}")
        
        return {
            "status": "success",
            "reset_count": reset_count,
            "deactivated": dead_keys + expired_keys,
            "total_active": total_active
        }
        
    except Exception as e:
        logger.error(f"[AUTO-REFRESH] Error: {e}")
        db.rollback()
        return {"status": "error", "message": str(e)}
    finally:
        db.close()

# Fungsi buat nambah key dari external source (misal: file, API, dll)
def fetch_keys_from_source():
    """
    Ambil API key dari source eksternal
    Ini contoh, nanti lu bisa ganti sesuai kebutuhan
    """
    # Contoh: baca dari file txt
    # with open("keys.txt", "r") as f:
    #     return [line.strip() for line in f if line.strip()]
    
    # Contoh: dari API
    # response = httpx.get("https://api.example.com/keys")
    # return response.json()
    
    # Kalo ga ada, return empty list
    return []

def add_keys_from_source():
    """Tambah key baru dari source eksternal"""
    db = SessionLocal()
    try:
        new_keys = fetch_keys_from_source()
        added = 0
        
        for key_str in new_keys:
            existing = db.query(VTAPIKey).filter(VTAPIKey.api_key == key_str).first()
            if not existing:
                new_key = VTAPIKey(
                    api_key=key_str,
                    source="auto_refresh"
                )
                db.add(new_key)
                added += 1
        
        db.commit()
        logger.info(f"[AUTO-REFRESH] Added {added} new keys from source")
        return added
    except Exception as e:
        logger.error(f"[AUTO-REFRESH] Error adding keys: {e}")
        db.rollback()
        return 0
    finally:
        db.close()