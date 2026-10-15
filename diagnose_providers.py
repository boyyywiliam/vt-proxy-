"""
SCRIPT DIAGNOSA FINAL — Verifikasi bahwa semua API key di database
benar-benar HIT ke 4 provider yang sesuai (VirusTotal, AbuseIPDB, URLhaus, MxToolbox).

Jalankan dari root project:
  python diagnose_providers.py

Script ini akan:
1. Load semua key dari database
2. Grup per api_type
3. Untuk tiap grup: ambil key dari load balancer, lalu hit endpoint probe
4. Print status detail termasuk HTTP status code dan response snippet
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Ensure utf-8 output on Windows terminal
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import httpx
from app.database import SessionLocal
from app.models import VTAPIKey
from app.services.registry import get_client, SOURCE_ORDER
from app.services.key_detector import get_meta, VIRUSTOTAL
from app.services.load_balancer import LoadBalancer
from app.config import settings

# ============================================================
# Warna terminal
# ============================================================
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):    print(f"  {GREEN}✅ {msg}{RESET}")
def warn(msg):  print(f"  {YELLOW}⚠️  {msg}{RESET}")
def err(msg):   print(f"  {RED}❌ {msg}{RESET}")
def info(msg):  print(f"  {CYAN}ℹ️  {msg}{RESET}")
def header(msg):print(f"\n{BOLD}{'='*60}{RESET}\n{BOLD}{msg}{RESET}\n{BOLD}{'='*60}{RESET}")

def probe_key_direct(api_type: str, api_key: str, db) -> dict:
    """Hit endpoint probe LANGSUNG ke provider — sama persis dengan cara test_key()."""
    client = get_client(api_type, db)
    try:
        resp = client._raw_probe(api_key, timeout=15.0)
        if resp is None:
            return {"status": "unreachable", "http_code": None, "msg": "Tidak bisa konek ke provider (timeout/DNS)"}
        
        status, msg = client._interpret_probe(resp)
        return {
            "status": status,
            "http_code": resp.status_code,
            "msg": msg,
            "body_snippet": resp.text[:200] if resp.text else ""
        }
    except Exception as e:
        return {"status": "error", "http_code": None, "msg": str(e)}

def main():
    db = SessionLocal()
    
    try:
        header("🔍 DIAGNOSA API KEY → 4 PROVIDER")
        
        # ---- 1. Baca semua key dari DB ----
        all_keys = db.query(VTAPIKey).all()
        total = len(all_keys)
        active = [k for k in all_keys if k.is_active]
        
        print(f"\n📦 Database: {total} key total, {len(active)} aktif\n")
        
        if not all_keys:
            err("Tidak ada API key sama sekali di database!")
            err("Tambahkan key lewat dashboard: Settings → API Keys → Add Key")
            return
        
        # ---- 2. Ringkasan per provider ----
        header("📊 RINGKASAN KEY PER PROVIDER")
        
        per_type = {}
        for k in all_keys:
            t = k.api_type or VIRUSTOTAL
            per_type.setdefault(t, []).append(k)
        
        lb = LoadBalancer(db)
        for api_type in SOURCE_ORDER:
            meta = get_meta(api_type)
            keys_this = per_type.get(api_type, [])
            active_this = lb.count_active(api_type)
            
            print(f"\n  {meta['emoji']} {BOLD}{meta['label']}{RESET}")
            print(f"     Total key : {len(keys_this)}")
            print(f"     Aktif     : {active_this}")
            if not keys_this:
                warn(f"Tidak ada key {meta['label']} → provider ini TIDAK akan dipanggil!")
            elif active_this == 0:
                warn(f"Semua key {meta['label']} nonaktif/error → provider ini TIDAK akan dipanggil!")
            else:
                ok(f"Load balancer siap: {active_this} key aktif")
        
        # ---- 3. Test ping SETIAP key ke provider ASLINYA ----
        header("🌐 TEST PING KE PROVIDER (HTTP CALL NYATA)")
        
        print("Menguji setiap key — ini mungkin butuh 5-30 detik...\n")
        
        total_ok = 0
        total_fail = 0
        total_unknown = 0
        
        for api_type in SOURCE_ORDER:
            meta = get_meta(api_type)
            keys_this = per_type.get(api_type, [])
            
            if not keys_this:
                print(f"  {meta['emoji']} {meta['label']}: tidak ada key, skip\n")
                continue
            
            print(f"  {meta['emoji']} {BOLD}{meta['label']}{RESET} — {len(keys_this)} key")
            print(f"     Endpoint probe: {settings.__dict__.get(f'{api_type.upper()}_API_BASE_URL', '?')}")
            
            for k in keys_this:
                key_preview = k.api_key[:12] + "..." if len(k.api_key) > 12 else k.api_key
                status_flag = "🟢 aktif" if k.is_active else "🔴 nonaktif"
                
                result = probe_key_direct(api_type, k.api_key, db)
                
                http_info = f"HTTP {result['http_code']}" if result['http_code'] else "no response"
                
                if result["status"] in ("valid", "rate_limited"):
                    ok(f"  [{status_flag}] {key_preview} → {http_info} → {result['msg']}")
                    total_ok += 1
                elif result["status"] == "invalid":
                    err(f"  [{status_flag}] {key_preview} → {http_info} → {result['msg']}")
                    total_fail += 1
                elif result["status"] == "unreachable":
                    warn(f"  [{status_flag}] {key_preview} → {http_info} → {result['msg']}")
                    total_unknown += 1
                else:
                    warn(f"  [{status_flag}] {key_preview} → {http_info} → {result['msg']}")
                    total_unknown += 1
                
                if result.get("body_snippet"):
                    info(f"    Response snippet: {result['body_snippet'][:120]}")
            
            print()
        
        # ---- 4. Test load balancer selection ----
        header("⚖️ TEST LOAD BALANCER SELECTION")
        
        for api_type in SOURCE_ORDER:
            meta = get_meta(api_type)
            best = lb.get_best_key(api_type)
            if best:
                preview = best.api_key[:12] + "..."
                ok(f"{meta['label']}: load balancer pilih key [{best.id}] {preview} (usage={best.usage_count})")
            else:
                err(f"{meta['label']}: load balancer TIDAK bisa pilih key (tidak ada key aktif/eligible)")
        
        # ---- 5. Test routing aggregator ----
        header("🗺️  TEST ROUTING AGGREGATOR (tanpa hit API)")
        
        from app.services.aggregator import detect_input_type, sources_for, INPUT_TYPE_LABELS
        
        test_inputs = [
            ("8.8.8.8", "IP Address"),
            ("google.com", "Domain"),
            ("https://example.com/malware", "URL"),
            ("44d88612fea8a8f36de82e1278abb02f", "MD5 Hash"),
            ("admin@gmail.com", "Email"),
        ]
        
        for sample, label in test_inputs:
            detected = detect_input_type(sample)
            providers = sources_for(detected)
            provider_labels = " + ".join(get_meta(p)["label"] for p in providers)
            print(f"  Input: {sample!r:45s} → [{detected}] → {provider_labels}")
        
        # ---- Ringkasan akhir ----
        header("📋 RINGKASAN AKHIR")
        
        print(f"\n  Total key diuji : {total_ok + total_fail + total_unknown}")
        if total_ok > 0:
            ok(f"Key valid (hit provider) : {total_ok}")
        if total_fail > 0:
            err(f"Key invalid/ditolak      : {total_fail}")
        if total_unknown > 0:
            warn(f"Key unknown/unreachable  : {total_unknown}")
        
        if total_ok == 0:
            print(f"\n{RED}{BOLD}⚠️  PERHATIAN: Tidak ada key yang berhasil hit provider!{RESET}")
            print("   Kemungkinan penyebab:")
            print("   1. Key sudah expired atau salah format")
            print("   2. Koneksi internet / server proxy bermasalah")
            print("   3. Provider sedang maintenance")
        else:
            print(f"\n{GREEN}{BOLD}✅ Sistem siap: {total_ok} key aktif dan berhasil hit provider.{RESET}")
        
        # Cek provider mana yang belum punya key sama sekali
        missing = []
        for api_type in SOURCE_ORDER:
            if not per_type.get(api_type):
                missing.append(get_meta(api_type)["label"])
        
        if missing:
            print(f"\n{YELLOW}{BOLD}⚠️  Provider tanpa key: {', '.join(missing)}{RESET}")
            print("   Provider ini tidak akan dipanggil saat scan.")
            print("   Tambahkan key lewat dashboard → API Keys → Add Key")

    finally:
        db.close()


if __name__ == "__main__":
    main()
