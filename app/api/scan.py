from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.services.vt_client import VTClient
from app.services.analyzer import analyze
from app.services.aggregator import (
    INPUT_TYPE_LABELS, detect_input_type, routing_plan, run_multi_scan,
    clean_indicator,
)
from pydantic import BaseModel
from typing import List, Optional

router = APIRouter(prefix="/scan", tags=["Scan"])

class URLScanRequest(BaseModel):
    url: str

class HashScanRequest(BaseModel):
    hash: str

class IPScanRequest(BaseModel):
    ip: str

class DomainScanRequest(BaseModel):
    domain: str

class BulkScanRequest(BaseModel):
    items: List[str]

class MultiScanRequest(BaseModel):
    """Input bebas — tipe & routing API ditentukan otomatis."""
    input: str
    # Isi kalau mau paksa tipe tertentu (hash/url/ip/domain/email)
    input_type: Optional[str] = None


class BulkMultiScanRequest(BaseModel):
    """Bulk scan dengan smart routing multi-source per item."""
    items: List[str]


def _wrap(raw: dict) -> dict:
    """Wrap raw VT result with analysis summary."""
    if "error" in raw:
        return raw
    return {
        "raw": raw,
        "analysis": analyze(raw)
    }


# ================================================================
# MULTI-SOURCE SCAN (smart routing)
# ================================================================

@router.post("/multi")
def scan_multi(request: MultiScanRequest, db: Session = Depends(get_db)):
    """
    Scan multi-source dengan smart routing.

    Input dideteksi otomatis (hash/url/ip/domain/email), lalu API yang relevan
    aja yang dipanggil:
        IP      -> VirusTotal + AbuseIPDB
        Domain  -> VirusTotal + URLhaus
        URL     -> VirusTotal + URLhaus
        Hash    -> VirusTotal
        Email   -> MxToolbox

    API yang tidak relevan tetap ikut di response dengan status 'skipped',
    supaya dashboard bisa menampilkan box "tidak dipanggil".
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


@router.get("/detect")
def detect_type(value: str):
    """Preview hasil auto-detect + rencana routing tanpa memanggil API mana pun."""
    t = detect_input_type(value)
    return {
        "input": value,
        "input_type": t,
        "input_type_label": INPUT_TYPE_LABELS.get(t, "Unknown"),
        "routing": routing_plan(t),
    }


# ================================================================
# SINGLE SCAN ENDPOINTS (VirusTotal — dipertahankan apa adanya)
# ================================================================

@router.post("/url")
def scan_url(request: URLScanRequest, db: Session = Depends(get_db)):
    """Scan URL menggunakan VirusTotal (dengan cache + analisa otomatis)"""
    client = VTClient(db)
    result = client.scan_url(request.url)
    if "error" in result:
        raise HTTPException(status_code=503, detail=result["error"])
    return _wrap(result)

@router.post("/hash")
def scan_hash(request: HashScanRequest, db: Session = Depends(get_db)):
    """Cek hash file di VirusTotal (dengan cache + analisa otomatis)"""
    client = VTClient(db)
    result = client.scan_hash(request.hash)
    if "error" in result:
        raise HTTPException(status_code=503, detail=result["error"])
    return _wrap(result)

@router.post("/ip")
def scan_ip(request: IPScanRequest, db: Session = Depends(get_db)):
    """Cek IP di VirusTotal (dengan cache + analisa otomatis)"""
    client = VTClient(db)
    result = client.scan_ip(request.ip)
    if "error" in result:
        raise HTTPException(status_code=503, detail=result["error"])
    return _wrap(result)

@router.post("/domain")
def scan_domain(request: DomainScanRequest, db: Session = Depends(get_db)):
    """Cek domain di VirusTotal (dengan cache + analisa otomatis)"""
    client = VTClient(db)
    result = client.scan_domain(request.domain)
    if "error" in result:
        raise HTTPException(status_code=503, detail=result["error"])
    return _wrap(result)


# ================================================================
# BULK SCAN ENDPOINTS
# ================================================================

@router.post("/bulk/multi")
def bulk_scan_multi(request: BulkMultiScanRequest, db: Session = Depends(get_db)):
    """
    Bulk scan multi-source dengan smart routing — ENDPOINT UTAMA BULK SCAN.

    Tiap item dideteksi tipenya otomatis, lalu semua provider yang relevan
    dipanggil bersama:
        IP     → VirusTotal + AbuseIPDB
        Domain → VirusTotal + URLhaus
        URL    → VirusTotal + URLhaus
        Hash   → VirusTotal
        Email  → MxToolbox

    Ini versi yang benar — bukan single-provider.
    """
    results = []
    for raw_item in request.items:
        item = clean_indicator((raw_item or "").strip())
        if not item:
            continue
        try:
            result = run_multi_scan(db, item)
            results.append({
                "input": item,
                "input_type": result.get("input_type"),
                "status": "success",
                "data": result,
            })
        except Exception as e:
            results.append({
                "input": item,
                "status": "error",
                "error": str(e),
            })
    return {"scan_type": "multi", "total": len(results), "results": results}


@router.post("/bulk/hash")
def bulk_scan_hash(request: BulkScanRequest, db: Session = Depends(get_db)):
    """
    Bulk scan hash — menggunakan multi-source routing.
    Hash selalu diarahkan ke VirusTotal (satu-satunya provider yang cek hash).
    """
    results = []
    for raw_item in request.items:
        item = clean_indicator((raw_item or "").strip())
        if not item:
            continue
        try:
            result = run_multi_scan(db, item, input_type="hash")
            results.append({
                "input": item,
                "input_type": "hash",
                "status": "success",
                "data": result,
            })
        except Exception as e:
            results.append({"input": item, "status": "error", "error": str(e)})
    return {"scan_type": "hash", "total": len(results), "results": results}


@router.post("/bulk/url")
def bulk_scan_url(request: BulkScanRequest, db: Session = Depends(get_db)):
    """
    Bulk scan URL — VirusTotal + URLhaus (multi-source).
    """
    results = []
    for raw_item in request.items:
        item = clean_indicator((raw_item or "").strip())
        if not item:
            continue
        try:
            result = run_multi_scan(db, item, input_type="url")
            results.append({
                "input": item,
                "input_type": "url",
                "status": "success",
                "data": result,
            })
        except Exception as e:
            results.append({"input": item, "status": "error", "error": str(e)})
    return {"scan_type": "url", "total": len(results), "results": results}


@router.post("/bulk/ip")
def bulk_scan_ip(request: BulkScanRequest, db: Session = Depends(get_db)):
    """
    Bulk scan IP — VirusTotal + AbuseIPDB (multi-source).
    """
    results = []
    for raw_item in request.items:
        item = clean_indicator((raw_item or "").strip())
        if not item:
            continue
        try:
            result = run_multi_scan(db, item, input_type="ip")
            results.append({
                "input": item,
                "input_type": "ip",
                "status": "success",
                "data": result,
            })
        except Exception as e:
            results.append({"input": item, "status": "error", "error": str(e)})
    return {"scan_type": "ip", "total": len(results), "results": results}


@router.post("/bulk/domain")
def bulk_scan_domain(request: BulkScanRequest, db: Session = Depends(get_db)):
    """
    Bulk scan domain — VirusTotal + URLhaus (multi-source).
    """
    results = []
    for raw_item in request.items:
        item = clean_indicator((raw_item or "").strip())
        if not item:
            continue
        try:
            result = run_multi_scan(db, item, input_type="domain")
            results.append({
                "input": item,
                "input_type": "domain",
                "status": "success",
                "data": result,
            })
        except Exception as e:
            results.append({"input": item, "status": "error", "error": str(e)})
    return {"scan_type": "domain", "total": len(results), "results": results}