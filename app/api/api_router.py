"""
Router /api/* — clean, terpusat, dipakai dashboard baru.

Semua endpoint lama (/scan/*, /dashboard/*, /keys/*) tetap ada
dan tidak diubah — backward-compatible.

Endpoint baru ini:
  POST   /api/scan          — multi-source scan (VT + AbuseIPDB + URLhaus + MxToolbox)
  GET    /api/scan/detect   — preview auto-detect + routing plan (tanpa call API)

  GET    /api/keys          — list semua key + metadata per provider
  POST   /api/keys          — tambah key baru (auto-detect + verify)
  DELETE /api/keys/{id}     — hapus key
  POST   /api/keys/{id}/health  — health check satu key
  POST   /api/keys/health-check-all — health check semua key aktif

  GET    /api/cache         — list cache (opsional ?source=)
  POST   /api/cache/clear   — kosongkan cache (opsional ?source=)
  DELETE /api/cache/{id}    — hapus 1 entri cache

  GET    /api/stats         — statistik dashboard
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field

from app.database import get_db
from app.models import VTAPIKey, CacheScan
from app.services.aggregator import (
    INPUT_TYPE_LABELS, detect_input_type, routing_plan, run_multi_scan,
)
from app.services.key_detector import (
    SOURCE_META, VALID_TYPES, VIRUSTOTAL,
    detect_api_type, get_meta, normalize_api_type,
)
from app.services import key_validator
from app.services.registry import health_check_key as route_health_check, key_stats
from sqlalchemy import func

router = APIRouter(prefix="/api", tags=["API v2"])


# ================================================================
# PYDANTIC MODELS
# ================================================================

class ScanRequest(BaseModel):
    input: str
    input_type: Optional[str] = None  # kosong = auto-detect


class KeyAddRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    api_key: str
    notes: Optional[str] = None
    api_type: Optional[str] = None
    verify: bool = Field(True, alias="validate")
    reject_invalid: bool = False


# ================================================================
# SCAN
# ================================================================

@router.post("/scan")
def api_scan(request: ScanRequest, db: Session = Depends(get_db)):
    """
    Multi-source scan — auto-detect tipe, panggil semua API yang relevan.

    Input type otomatis terdeteksi:
      IP     → VirusTotal + AbuseIPDB
      Domain → VirusTotal + URLhaus
      URL    → VirusTotal + URLhaus
      Hash   → VirusTotal
      Email  → MxToolbox

    Response berisi: sources[] (box per API) + final verdict + confidence.
    """
    value = (request.input or "").strip()
    if not value:
        raise HTTPException(status_code=400, detail="Input tidak boleh kosong")

    input_type = (request.input_type or "").strip().lower() or None
    if input_type and input_type not in INPUT_TYPE_LABELS:
        raise HTTPException(
            status_code=400,
            detail=f"input_type harus salah satu dari: {', '.join(INPUT_TYPE_LABELS)}",
        )

    return run_multi_scan(db, value, input_type)


@router.get("/scan/detect")
def api_detect(value: str = Query(..., description="Input yang mau dideteksi tipenya")):
    """Preview auto-detect tipe + rencana routing tanpa memanggil API mana pun."""
    t = detect_input_type(value)
    return {
        "input": value,
        "input_type": t,
        "input_type_label": INPUT_TYPE_LABELS.get(t, "Unknown"),
        "routing": routing_plan(t),
    }


# ================================================================
# API KEYS
# ================================================================

@router.get("/keys")
def api_get_keys(db: Session = Depends(get_db)):
    """List semua API key + metadata provider + status health."""
    keys = db.query(VTAPIKey).all()
    out = []
    for k in keys:
        api_type = k.api_type or VIRUSTOTAL
        meta = get_meta(api_type)
        out.append({
            "id": k.id,
            "api_key": k.api_key[:10] + "..." if len(k.api_key) > 10 else k.api_key,
            "full_key": k.api_key,
            "api_type": api_type,
            "api_label": meta["label"],
            "api_emoji": meta["emoji"],
            "api_color": meta["color"],
            "api_icon":  meta["icon"],
            "usage_count": k.usage_count,
            "is_active": k.is_active,
            "is_error": k.is_error,
            "error_count": k.error_count,
            "health_status": k.health_status or "unknown",
            "last_checked": k.last_checked,
            "last_used": k.last_used,
            "notes": k.notes,
            "verified": _verified_flag(k.health_status),
            "verification_label": _verification_label(k.health_status),
            "status_label": (
                "🟢 Active" if k.is_active and not k.is_error
                else "🔴 Error" if not k.is_active
                else "🟡 Rate Limited"
            ),
        })
    return out


@router.post("/keys/validate")
def api_validate_key(data: KeyAddRequest, db: Session = Depends(get_db)):
    """
    Test ping key ke provider aslinya TANPA menyimpan.
    Dipakai tombol "Test Key" di dashboard sebelum user klik Simpan.
    """
    if data.api_type and not normalize_api_type(data.api_type):
        raise HTTPException(
            status_code=400,
            detail=f"api_type harus salah satu dari: {', '.join(VALID_TYPES)}",
        )
    result = key_validator.identify_key(db, data.api_key, data.api_type)
    return result


@router.post("/keys")
def api_add_key(data: KeyAddRequest, db: Session = Depends(get_db)):
    """Tambah API key baru — jenisnya diverifikasi lewat test ping ke provider."""
    existing = db.query(VTAPIKey).filter(VTAPIKey.api_key == data.api_key).first()
    if existing:
        raise HTTPException(status_code=400, detail="API key already exists")

    if data.api_type and not normalize_api_type(data.api_type):
        raise HTTPException(
            status_code=400,
            detail=f"api_type harus salah satu dari: {', '.join(VALID_TYPES)}",
        )

    if data.verify:
        result = key_validator.identify_key(db, data.api_key, data.api_type)
    else:
        result = key_validator.unvalidated(data.api_key, data.api_type)

    if data.reject_invalid and result["validation_status"] == key_validator.RESULT_INVALID:
        raise HTTPException(status_code=400, detail=result["message"])

    new_key = VTAPIKey(
        api_key=data.api_key,
        api_type=result["api_type"],
        notes=data.notes,
    )
    db.add(new_key)
    db.commit()

    health = key_validator.apply_to_key(db, new_key, result)
    db.commit()
    db.refresh(new_key)

    return {
        "message": _add_message(result),
        "id": new_key.id,
        "api_type": new_key.api_type,
        "api_label": result["label"],
        "api_emoji": result["emoji"],
        "api_color": result["color"],
        "verified": result["verified"],
        "validation_status": result["validation_status"],
        "validation_message": result["message"],
        "health_status": health,
        "is_active": new_key.is_active,
        "confidence": result["confidence"],
        "reason": result["reason"],
    }


@router.delete("/keys/{key_id}")
def api_delete_key(key_id: int, db: Session = Depends(get_db)):
    """Hapus API key permanen."""
    key = db.query(VTAPIKey).filter(VTAPIKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    db.delete(key)
    db.commit()
    return {"message": "Key deleted", "id": key_id}


@router.post("/keys/{key_id}/toggle")
def api_toggle_key(key_id: int, db: Session = Depends(get_db)):
    """Aktifkan atau nonaktifkan API key secara instan."""
    key = db.query(VTAPIKey).filter(VTAPIKey.id == key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    key.is_active = not key.is_active
    if key.is_active:
        key.is_error = False
    db.commit()
    db.refresh(key)
    return {
        "id": key.id,
        "is_active": key.is_active,
        "message": f"Key {'diaktifkan' if key.is_active else 'dinonaktifkan'}"
    }


@router.post("/keys/{key_id}/health")
def api_health_check_key(key_id: int, db: Session = Depends(get_db)):
    """Health check satu key — hemat kuota, pakai probe ke provider aslinya."""
    result = route_health_check(db, key_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/keys/health-check-all")
def api_health_check_all(db: Session = Depends(get_db)):
    """
    Health check semua key aktif — tiap key dites ke provider-nya masing-masing.
    Key AbuseIPDB/URLhaus/MxToolbox tidak salah divonis dead gara-gara ditembak
    ke endpoint VirusTotal.
    """
    import concurrent.futures

    keys = db.query(VTAPIKey).filter(VTAPIKey.is_active == True).all()
    results = []
    
    def _check_key(key):
        # We need a new session per thread to avoid SQLAlchemy connection issues
        from app.database import SessionLocal
        local_db = SessionLocal()
        try:
            result = route_health_check(local_db, key.id)
            api_type = key.api_type or VIRUSTOTAL
            meta = get_meta(api_type)
            
            # Note: route_health_check (from base_client.py) returns the health string in the "status" field,
            # so we use result.get("status") as the health_status.
            health_val = result.get("status", "unknown")
            return {
                "id": key.id,
                "api_key": key.api_key[:10] + "..." if len(key.api_key) > 10 else key.api_key,
                "api_type": api_type,
                "api_label": meta["label"],
                "api_emoji": meta["emoji"],
                "api_color": meta["color"],
                "health_status": health_val,
                "status": health_val,
                "message": result.get("message"),
            }
        finally:
            local_db.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(_check_key, keys))

    # Ringkasan per provider
    summary = {}
    for r in results:
        t = r["api_type"]
        if t not in summary:
            summary[t] = {
                "api_type": t,
                "api_label": r["api_label"],
                "api_emoji": r["api_emoji"],
                "api_color": r["api_color"],
                "total": 0, "fresh": 0, "rate_limited": 0, "dead": 0, "unknown": 0,
            }
        summary[t]["total"] += 1
        hs = r["health_status"]
        if hs in summary[t]:
            summary[t][hs] += 1
        else:
            summary[t]["unknown"] += 1
    return {
        "total": len(results),
        "results": results,
        "summary": list(summary.values()),
    }


@router.get("/keys/status")
def api_keys_status(db: Session = Depends(get_db)):
    """
    Ringkasan status semua key per provider — TANPA melakukan health check baru.
    Hanya membaca health_status yang sudah tersimpan di database.
    Cocok untuk ditampilkan di dashboard overview (murah, tidak pakai kuota API).
    """
    keys = db.query(VTAPIKey).all()
    from app.services.registry import SOURCE_ORDER
    summary = {}
    for api_type in SOURCE_ORDER:
        meta = get_meta(api_type)
        summary[api_type] = {
            "api_type": api_type,
            "api_label": meta["label"],
            "api_emoji": meta["emoji"],
            "api_color": meta["color"],
            "api_icon": meta["icon"],
            "total": 0, "active": 0,
            "fresh": 0, "rate_limited": 0, "dead": 0, "unknown": 0,
            "inactive": 0,
        }

    for k in keys:
        t = k.api_type or VIRUSTOTAL
        if t not in summary:
            meta = get_meta(t)
            summary[t] = {
                "api_type": t,
                "api_label": meta["label"],
                "api_emoji": meta["emoji"],
                "api_color": meta["color"],
                "api_icon": meta["icon"],
                "total": 0, "active": 0,
                "fresh": 0, "rate_limited": 0, "dead": 0, "unknown": 0,
                "inactive": 0,
            }
        s = summary[t]
        s["total"] += 1
        if k.is_active:
            s["active"] += 1
        else:
            s["inactive"] += 1
        hs = k.health_status or "unknown"
        if hs in s:
            s[hs] += 1
        else:
            s["unknown"] += 1

    return {
        "providers": list(summary.values()),
        "total_keys": len(keys),
        "active_keys": sum(1 for k in keys if k.is_active),
    }


@router.get("/keys/types")
def api_key_types():
    """Metadata semua provider yang didukung (label, emoji, warna)."""
    return list(SOURCE_META.values())


# ================================================================
# CACHE
# ================================================================

@router.get("/cache")
def api_get_cache(
    source: Optional[str] = Query(None, description="Filter per sumber: virustotal | abuseipdb | urlhaus | mxtoolbox"),
    db: Session = Depends(get_db),
):
    """List cache scan (opsional difilter per sumber API). Max 200 entri terbaru."""
    query = db.query(CacheScan)
    if source:
        query = query.filter(CacheScan.source == source.lower())
    caches = query.order_by(CacheScan.scan_date.desc()).limit(200).all()

    out = []
    for c in caches:
        src = c.source or VIRUSTOTAL
        meta = get_meta(src)
        out.append({
            "id": c.id,
            "scan_type": c.scan_type,
            "identifier": c.identifier,
            "source": src,
            "source_label": meta["label"],
            "source_emoji": meta["emoji"],
            "source_color": meta["color"],
            "hits": c.hits,
            "scan_date": c.scan_date,
            "created_at": c.created_at,
        })
    return out


@router.post("/cache/clear")
def api_clear_cache(
    source: Optional[str] = Query(None, description="Kosongkan hanya sumber ini. Kosong = semua."),
    db: Session = Depends(get_db),
):
    """Kosongkan cache (semua, atau hanya satu sumber)."""
    query = db.query(CacheScan)
    if source:
        query = query.filter(CacheScan.source == source.lower())
    count = query.delete()
    db.commit()
    scope = f" ({get_meta(source)['label']})" if source else ""
    return {"message": f"Cache cleared{scope}", "deleted": count}


@router.delete("/cache/{cache_id}")
def api_delete_cache(cache_id: int, db: Session = Depends(get_db)):
    """Hapus 1 entri cache berdasarkan ID."""
    cache = db.query(CacheScan).filter(CacheScan.id == cache_id).first()
    if not cache:
        raise HTTPException(status_code=404, detail="Cache entry not found")
    db.delete(cache)
    db.commit()
    return {"message": "Cache entry deleted", "id": cache_id}


# ================================================================
# STATS
# ================================================================

@router.get("/stats")
def api_get_stats(db: Session = Depends(get_db)):
    """Statistik dashboard: total key, cache, hits, breakdown per provider."""
    total_keys  = db.query(VTAPIKey).count()
    active_keys = db.query(VTAPIKey).filter(VTAPIKey.is_active == True).count()
    error_keys  = db.query(VTAPIKey).filter(VTAPIKey.is_error == True).count()
    total_cache = db.query(CacheScan).count()
    total_hits  = db.query(func.sum(CacheScan.hits)).scalar() or 0

    cache_rows = (
        db.query(CacheScan.source, func.count(CacheScan.id), func.sum(CacheScan.hits))
        .group_by(CacheScan.source)
        .all()
    )
    cache_by_source = {}
    for src, cnt, hits in cache_rows:
        k = src or VIRUSTOTAL
        cache_by_source[k] = {"entries": int(cnt or 0), "hits": int(hits or 0)}

    sources = key_stats(db)
    for s in sources:
        c = cache_by_source.get(s["source"], {"entries": 0, "hits": 0})
        s["cache_entries"] = c["entries"]
        s["cache_hits"]    = c["hits"]

    return {
        "total_keys":  total_keys,
        "active_keys": active_keys,
        "error_keys":  error_keys,
        "total_cache": total_cache,
        "total_hits":  total_hits,
        "sources":     sources,
        "cache_by_source": cache_by_source,
    }


# ================================================================
# HELPERS (private)
# ================================================================

def _verified_flag(health_status):
    if health_status in ("fresh", "rate_limited"):
        return True
    if health_status == "dead":
        return False
    return None


def _verification_label(health_status):
    return {
        "fresh": "🟢 Verified",
        "rate_limited": "🟡 Verified (rate limited)",
        "dead": "❌ Invalid",
    }.get(health_status, "❓ Unknown")


def _add_message(result: dict) -> str:
    label  = result["label"]
    status = result["validation_status"]
    if status == key_validator.RESULT_VALID:
        return f"{result['emoji']} Key terverifikasi sebagai {label} 🟢 dan berhasil ditambahkan"
    if status == key_validator.RESULT_INVALID:
        return "❌ Key ditolak semua provider — disimpan sebagai Invalid dan dinonaktifkan"
    if status == key_validator.RESULT_UNKNOWN:
        return f"❓ Key disimpan sebagai {label} (belum terverifikasi — provider tidak menjawab)"
    return f"{result['emoji']} Key disimpan sebagai {label} (tanpa validasi)"
