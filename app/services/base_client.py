"""
Base class buat semua client threat intelligence.

Yang di-share ke semua provider (VirusTotal, AbuseIPDB, URLhaus, MxToolbox):
  - cache multi-source (satu tabel cache_scans, dibedakan kolom `source`)
  - load balancer + auto-failover antar key milik provider yang sama
  - bentuk hasil yang seragam, biar dashboard bisa render box per API
    tanpa tahu detail tiap vendor.

Tiap subclass cukup isi: api_type, base_url, _auth_headers(), dan method scan-nya.
"""

import httpx
from datetime import timedelta
from typing import Optional
from sqlalchemy.orm import Session

from app.config import settings
from app.models import CacheScan, VTAPIKey
from app.services.key_detector import get_meta
from app.services.load_balancer import LoadBalancer
from app.utils.timeutil import now_local

# Umur maksimum cache yang masih dianggap valid (setelah 7 hari / 1 minggu, hit API lagi)
CACHE_TTL_DAYS = getattr(settings, "CACHE_TTL_DAYS", 7)

# Status per-sumber yang dipakai di aggregated report
STATUS_OK = "ok"          # API dipanggil, data ketemu
STATUS_ERROR = "error"    # API dipanggil, gagal
STATUS_SKIPPED = "skipped"  # sengaja tidak dipanggil (input tidak relevan)
STATUS_NO_KEY = "no_key"    # relevan, tapi belum ada API key terdaftar

# ============================================================
# HASIL TEST PING KEY (dipakai key_validator + dashboard)
# ============================================================
PROBE_VALID = "valid"                  # key diterima provider ini
PROBE_INVALID = "invalid"              # key ditolak (401/403) — jelas bukan punya provider ini
PROBE_RATE_LIMITED = "rate_limited"    # auth lolos, cuma kuota habis → key tetap SAH
PROBE_UNREACHABLE = "unreachable"      # jaringan/DNS/timeout — TIDAK boleh dibaca sebagai invalid
PROBE_INCONCLUSIVE = "inconclusive"    # jawaban provider tidak bisa dipakai menyimpulkan apa pun

# Status yang artinya "key ini memang milik provider tersebut"
PROBE_ACCEPTED = (PROBE_VALID, PROBE_RATE_LIMITED)


class BaseThreatClient:
    api_type: str = "base"
    base_url: str = ""
    # Kalau True, API bisa dipanggil tanpa API key (URLhaus punya mode publik)
    key_optional: bool = False

    # Endpoint paling ringan yang cuma dipakai buat memverifikasi key.
    # Diisi tiap subclass; formatnya:
    #   {"endpoint": "...", "method": "GET", "params": {...}, "data": {...}}
    probe: dict = None

    def __init__(self, db: Session):
        self.db = db
        self.load_balancer = LoadBalancer(db)

    # ============================================================
    # METADATA
    # ============================================================
    @property
    def meta(self) -> dict:
        return get_meta(self.api_type)

    def has_key(self) -> bool:
        return self.load_balancer.has_key(self.api_type)

    # ============================================================
    # CACHE (multi-source: identifier + scan_type + source)
    # ============================================================
    def _check_cache(self, identifier: str, scan_type: str) -> Optional[dict]:
        """Cek apakah hasil scan dari SUMBER INI udah ada di cache dan masih fresh (< 3 hari)."""
        cutoff = now_local() - timedelta(days=CACHE_TTL_DAYS)
        cache = self.db.query(CacheScan).filter(
            CacheScan.identifier == identifier,
            CacheScan.scan_type == scan_type,
            CacheScan.source == self.api_type,
            CacheScan.scan_date >= cutoff,   # TTL: abaikan cache yang sudah kadaluarsa
        ).first()

        if cache:
            cache.hits += 1
            self.db.commit()
            return cache.vt_response
        return None

    def _save_cache(self, identifier: str, scan_type: str, data: dict):
        """
        Simpan hasil scan ke cache.
        Pakai upsert manual: kalau row-nya udah ada (race antara dua request
        yang sama-sama cache miss), di-update, bukan insert yang bakal kena
        unique constraint.
        """
        existing = self.db.query(CacheScan).filter(
            CacheScan.identifier == identifier,
            CacheScan.scan_type == scan_type,
            CacheScan.source == self.api_type,
        ).first()

        if existing:
            existing.vt_response = data
            self.db.commit()
            return

        cache = CacheScan(
            identifier=identifier,
            scan_type=scan_type,
            source=self.api_type,
            vt_response=data,
        )
        self.db.add(cache)
        try:
            self.db.commit()
        except Exception:
            # Kalah balapan sama request lain — cache-nya udah keisi, gak fatal.
            self.db.rollback()

    # ============================================================
    # HTTP + FAILOVER ANTAR KEY
    # ============================================================
    def _auth_headers(self, api_key: Optional[str]) -> dict:
        """Di-override subclass — tiap vendor beda skema header."""
        raise NotImplementedError

    def _is_empty_result(self, payload: dict) -> bool:
        """
        Override kalau vendor balikin 200 OK tapi isinya "tidak ketemu".
        Dipakai supaya hasil kosong tetap di-cache & tetap dianggap sukses.
        """
        return False

    def _request(
        self,
        endpoint: str,
        method: str = "GET",
        params: dict = None,
        data: dict = None,
    ) -> dict:
        """
        Panggil API vendor ini dengan auto-fallback ke key berikutnya.
        Return dict response, atau {"error": "..."} kalau semua key gagal.
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        timeout = settings.HTTP_TIMEOUT_SECONDS

        max_retries = self.load_balancer.count_active(self.api_type)

        # Mode tanpa key (URLhaus publik): tembak sekali aja
        if max_retries == 0:
            if not self.key_optional:
                return {
                    "error": f"No active {self.meta['label']} API key available",
                    "error_kind": STATUS_NO_KEY,
                }
            return self._single_call(url, method, params, data, key=None)

        last_error = f"All {self.meta['label']} API keys exhausted or failed"

        for _ in range(max_retries):
            key: VTAPIKey = self.load_balancer.get_best_key(self.api_type)
            if not key:
                break

            try:
                response = httpx.request(
                    method,
                    url,
                    headers=self._auth_headers(key.api_key),
                    params=params,
                    data=data,
                    timeout=timeout,
                )

                if response.status_code == 200:
                    self.load_balancer.mark_success(key.id)
                    try:
                        return response.json()
                    except Exception:
                        last_error = f"{self.meta['label']} mengembalikan response non-JSON"
                        self.load_balancer.mark_error(key.id)
                        continue

                elif response.status_code == 429:
                    last_error = f"{self.meta['label']} rate limited (429)"
                    self.load_balancer.mark_error(key.id)
                    continue

                elif response.status_code in (401, 403):
                    last_error = f"{self.meta['label']} menolak API key (HTTP {response.status_code})"
                    key.is_active = False
                    key.is_error = True
                    self.db.commit()
                    continue

                elif response.status_code == 404:
                    # 404 = "tidak ditemukan di database vendor", bukan key rusak.
                    # Key-nya sehat, jadi tetap dihitung sukses.
                    self.load_balancer.mark_success(key.id)
                    return {
                        "error": f"Tidak ditemukan di database {self.meta['label']}",
                        "error_kind": "not_found",
                        "http_status": 404,
                    }

                else:
                    last_error = f"{self.meta['label']} HTTP {response.status_code}"
                    # 405 = method/endpoint salah — bukan masalah key, stop langsung
                    if response.status_code == 405:
                        return {"error": f"{self.meta['label']} HTTP 405 (Method Not Allowed)", "error_kind": STATUS_ERROR}
                    self.load_balancer.mark_error(key.id)
                    continue

            except Exception as e:
                last_error = f"{self.meta['label']} request gagal: {e}"
                self.load_balancer.mark_error(key.id)
                continue

        return {"error": last_error, "error_kind": STATUS_ERROR}

    def _single_call(self, url, method, params, data, key=None) -> dict:
        """Panggilan tanpa load balancer (mode publik tanpa key)."""
        try:
            response = httpx.request(
                method,
                url,
                headers=self._auth_headers(key),
                params=params,
                data=data,
                timeout=settings.HTTP_TIMEOUT_SECONDS,
            )
            if response.status_code == 200:
                return response.json()
            if response.status_code in (401, 403):
                return {
                    "error": f"{self.meta['label']} sekarang butuh Auth-Key (HTTP {response.status_code})",
                    "error_kind": STATUS_NO_KEY,
                }
            return {
                "error": f"{self.meta['label']} HTTP {response.status_code}",
                "error_kind": STATUS_ERROR,
            }
        except Exception as e:
            return {"error": f"{self.meta['label']} request gagal: {e}", "error_kind": STATUS_ERROR}

    # ============================================================
    # TEST PING — verifikasi satu API key TANPA harus tersimpan di DB
    # ============================================================
    def probe_spec(self) -> dict:
        """Endpoint ringan buat verifikasi key. Wajib diisi tiap subclass."""
        if not self.probe:
            raise NotImplementedError(
                f"{type(self).__name__} belum punya atribut `probe` — "
                "test ping tidak bisa dijalankan."
            )
        return self.probe

    def _raw_probe(self, api_key: Optional[str], timeout: float = 10.0):
        """
        Tembak endpoint probe sekali. Return httpx.Response, atau None kalau
        request-nya sendiri gagal (DNS mati, timeout, TLS error).

        Sengaja TIDAK lewat _request(): waktu verifikasi, key-nya belum tentu
        ada di DB dan kita justru butuh lihat status mentahnya — bukan
        di-failover ke key lain atau dinonaktifkan otomatis.
        """
        spec = self.probe_spec()
        url = f"{self.base_url}/{spec['endpoint'].lstrip('/')}"
        try:
            return httpx.request(
                spec.get("method", "GET"),
                url,
                headers=self._auth_headers(api_key),
                params=spec.get("params"),
                data=spec.get("data"),
                timeout=timeout,
            )
        except Exception:
            return None

    def _interpret_probe(self, response) -> tuple:
        """
        Terjemahkan response probe jadi (status, pesan).
        Override kalau vendor bisa menolak key sambil tetap balas HTTP 200.
        """
        label = self.meta["label"]
        code = response.status_code

        if code == 200:
            return PROBE_VALID, f"✅ Key valid & diterima {label}"
        if code == 429:
            # Auth-nya LOLOS, cuma kuota habis — key ini sah milik provider ini.
            return PROBE_RATE_LIMITED, f"🟡 Key valid tapi {label} sedang rate limited (429)"
        if code in (401, 403):
            return PROBE_INVALID, f"🔴 Key ditolak {label} (HTTP {code})"
        if code >= 500:
            return PROBE_UNREACHABLE, f"⚠️ {label} sedang bermasalah (HTTP {code}) — status key belum bisa dipastikan"
        return PROBE_INCONCLUSIVE, f"❓ Jawaban {label} tidak bisa disimpulkan (HTTP {code})"

    def probe_result(self, status: str, message: str, http_status: int = None) -> dict:
        """Bentuk hasil test ping yang seragam buat semua provider."""
        m = self.meta
        return {
            "api_type": self.api_type,
            "label": m["label"],
            "emoji": m["emoji"],
            "color": m["color"],
            "icon": m["icon"],
            # True = milik provider ini, False = jelas ditolak,
            # None = belum bisa disimpulkan (jangan divonis apa pun!)
            "valid": True if status in PROBE_ACCEPTED else False if status == PROBE_INVALID else None,
            "status": status,
            "http_status": http_status,
            "message": message,
        }

    def test_key(self, api_key: str, timeout: float = 10.0) -> dict:
        """
        Cek apakah `api_key` benar-benar diterima provider ini.

        Ini sumber kebenaran buat jenis key — tebakan regex di key_detector
        cuma dipakai buat menentukan provider mana yang dites duluan.
        """
        key = (api_key or "").strip()
        if not key:
            return self.probe_result(PROBE_INVALID, "Key kosong.")

        response = self._raw_probe(key, timeout=timeout)
        if response is None:
            return self.probe_result(
                PROBE_UNREACHABLE,
                f"⚠️ Tidak bisa menghubungi {self.meta['label']} — cek koneksi internet/proxy.",
            )

        status, message = self._interpret_probe(response)
        return self.probe_result(status, message, http_status=response.status_code)

    def call_with_cache(
        self,
        scan_type: str,
        identifier: str,
        endpoint: str,
        method: str = "GET",
        params: dict = None,
        data: dict = None,
        cache_key: str = None,
    ) -> dict:
        """
        Cache dulu → kalau miss baru tembak API → simpan hasilnya.
        cache_key dipakai kalau identifier yang disimpan beda sama input
        (mis. MxToolbox yang menyimpan per-command).
        """
        ident = cache_key or identifier

        cached = self._check_cache(ident, scan_type)
        if cached is not None:
            # Tandai supaya dashboard bisa bilang "dari cache"
            if isinstance(cached, dict):
                return {**cached, "_from_cache": True}
            return cached

        result = self._request(endpoint, method=method, params=params, data=data)

        if result and "error" not in result:
            self._save_cache(ident, scan_type, result)

        return result

    # ============================================================
    # HEALTH CHECK — satu implementasi buat semua provider,
    # berdiri di atas test_key() supaya "valid" versi tombol Health Check
    # dan "valid" versi validasi key gak pernah beda jawaban.
    # ============================================================
    def apply_probe_to_key(self, key: VTAPIKey, result: dict) -> str:
        """
        Tulis hasil test ping ke row key. Return health_status finalnya.
        Catatan: status unreachable/inconclusive sengaja TIDAK mengubah
        is_active — internet putus bukan alasan mematikan key orang.
        """
        status = result.get("status")
        key.last_checked = now_local()

        if status == PROBE_VALID:
            key.health_status = "fresh"
            key.is_error = False
            key.is_active = True
        elif status == PROBE_RATE_LIMITED:
            key.health_status = "rate_limited"
            key.is_error = True
        elif status == PROBE_INVALID:
            key.health_status = "dead"
            key.is_active = False
            key.is_error = True
        else:
            key.health_status = "unknown"

        self.db.commit()
        return key.health_status

    def health_check_key(self, key_id: int) -> dict:
        """Cek satu key yang sudah tersimpan, lalu update status kesehatannya."""
        key = self.db.query(VTAPIKey).filter(VTAPIKey.id == key_id).first()
        if not key:
            return {"error": "Key not found"}

        result = self.test_key(key.api_key)
        health = self.apply_probe_to_key(key, result)
        return {
            "status": health,
            "message": result["message"],
            "api_type": self.api_type,
            "label": self.meta["label"],
            "http_status": result.get("http_status"),
        }

    # ============================================================
    # BENTUK HASIL SERAGAM (dipakai aggregated report)
    # ============================================================
    def envelope(
        self,
        status: str,
        verdict: str = "UNKNOWN",
        fields: list = None,
        summary: dict = None,
        raw: dict = None,
        reason: str = None,
        cached: bool = False,
    ) -> dict:
        """Bungkus hasil satu API jadi format box yang dipahami dashboard."""
        m = self.meta
        return {
            "source": self.api_type,
            "label": m["label"],
            "emoji": m["emoji"],
            "color": m["color"],
            "icon": m["icon"],
            "called": status in (STATUS_OK, STATUS_ERROR),
            "cached": cached,
            "status": status,
            "verdict": (verdict or "UNKNOWN").upper(),
            "reason": reason,
            "fields": fields or [],
            "summary": summary or {},
            "raw": raw,
        }

    def skipped(self, reason: str) -> dict:
        """Box untuk API yang memang tidak relevan sama input ini."""
        return self.envelope(STATUS_SKIPPED, verdict="N/A", reason=reason)

    def no_key(self) -> dict:
        return self.envelope(
            STATUS_NO_KEY,
            verdict="N/A",
            reason=f"Belum ada API key {self.meta['label']} terdaftar — tambahkan di menu API Keys.",
        )

    def error(self, message: str, raw: dict = None) -> dict:
        return self.envelope(STATUS_ERROR, verdict="UNKNOWN", reason=message, raw=raw)


def field(label: str, value, tone: str = None, mono: bool = False) -> dict:
    """
    Satu baris di dalam box API.
    tone: ok | warn | crit | none  → dipakai dashboard buat mewarnai nilai.
    """
    return {"label": label, "value": value, "tone": tone, "mono": mono}
