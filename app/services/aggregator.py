"""
Smart routing + aggregated multi-source report.

Alur:
  1. detect_input_type()  -> hash | url | ip | domain | email
  2. ROUTING              -> API mana aja yang relevan buat tipe itu
  3. run_multi_scan()     -> panggil API yang relevan, sisanya dibikin box
                             "tidak dipanggil" (tetap tampil di dashboard)
  4. build_final_verdict()-> gabung semua vonis jadi 1 keputusan + rekomendasi

Semua penilaian di sini dihitung lokal (gratis, tanpa API tambahan).
"""

import re
from sqlalchemy.orm import Session

from app.services.base_client import STATUS_OK
from app.services.key_detector import (
    ABUSEIPDB, MXTOOLBOX, URLHAUS, VIRUSTOTAL, SOURCE_META,
)
from app.services.registry import SOURCE_ORDER, get_client
from app.utils.timeutil import now_local

# ============================================================
# 1. AUTO-DETECT TIPE INPUT
# ============================================================
_RE_EMAIL = re.compile(r"^[^@\s]+@[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$")
_RE_URL = re.compile(r"^https?://", re.I)
_RE_IPV4_LIKE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::\d+)?$")
_RE_HASH = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
# Domain WAJIB berakhiran TLD alfabetik (bukan angka murni) dan minimal 2 karakter TLD
_RE_DOMAIN = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}(?::\d+)?$")

INPUT_TYPE_LABELS = {
    "hash": "File Hash",
    "url": "URL",
    "ip": "IP Address",
    "domain": "Domain",
    "email": "Email / Mail Domain",
}


def clean_indicator(raw: str) -> str:
    """
    Normalisasi & refang IOC indicator:
    - Bersihkan whitespace, petik, kurung sudut.
    - Refang karakter yang biasa didefang oleh SOC analyst (misal: google[.]com -> google.com, hxxps:// -> https://).
    CATATAN: () tidak distrip karena bisa menjadi bagian legitimate URL.
    """
    v = (raw or "").strip().strip("\"'<>")
    if not v:
        return ""
    # Refang dot  [.] (.) {.}
    v = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", v)
    # Refang colon  [:] (:)
    v = re.sub(r"\[:\]|\(:\)", ":", v)
    # Refang scheme  hxxp:// hXXps://
    v = re.sub(r"^h[xX]{2}p://", "http://", v)
    v = re.sub(r"^h[xX]{2}ps://", "https://", v)
    # Refang email  [at] (at)
    v = re.sub(r"\[at\]|\(at\)", "@", v, flags=re.IGNORECASE)
    # Strip sisa kurung kotak di sekitar indicator jika tidak ada konten URL
    # (misal [192.168.1.1] -> 192.168.1.1, tapi jangan strip kalau sudah ada ://)
    if "://" not in v:
        v = v.strip("[]")
    return v


def detect_input_type(raw: str) -> str:
    """
    Deteksi tipe input secara cerdas:
    1. Refang & bersihkan format umum (google[.]com, hxxps://)
    2. Email
    3. URL dengan skema
    4. IPv4 format (4 blok angka dengan dot) -> selalu IP, bukan domain!
    5. IPv6
    6. File Hash (MD5, SHA1, SHA256)
    7. URL tanpa skema (mengandung path / atau parameter ?)
    8. Domain (harus memiliki TLD alfabetik, misal .com, .id, .org)
    """
    v = clean_indicator(raw)
    if not v:
        return None

    # 1. Email
    if _RE_EMAIL.match(v):
        return "email"

    # 2. Explicit URL
    if _RE_URL.match(v):
        return "url"

    # 3. IPv4 pattern (4 blok angka dipisah titik, dengan atau tanpa port)
    # PENTING: Jika 4 blok angka, ini SELALU format IP (tidak boleh lolos ke regex domain!)
    if _RE_IPV4_LIKE.match(v):
        return "ip"

    # 4. IPv6
    v_clean = v.strip("[]")
    if ":" in v_clean:
        try:
            import ipaddress
            candidate = v_clean.split("]:")[0].strip("[") if "]:" in v_clean else v_clean
            if ipaddress.ip_address(candidate).version == 6:
                return "ip"
        except (ValueError, Exception):
            pass

    # 5. File Hash
    if _RE_HASH.match(v):
        return "hash"

    # 6. Implicit URL (punya path / atau query ?)
    if "/" in v or "?" in v:
        return "url"

    # 7. Domain name
    if _RE_DOMAIN.match(v):
        return "domain"

    return "hash"


# ============================================================
# 2. SMART ROUTING — API mana yang dipanggil per tipe input
# ============================================================
ROUTING = {
    "ip":     [VIRUSTOTAL, ABUSEIPDB],
    "domain": [VIRUSTOTAL, URLHAUS],
    "url":    [VIRUSTOTAL, URLHAUS],
    "hash":   [VIRUSTOTAL],
    "email":  [MXTOOLBOX],
}

# Alasan yang ditampilkan di box "tidak dipanggil"
SKIP_REASONS = {
    VIRUSTOTAL: "API tidak dipanggil (input bukan hash/URL/IP/domain)",
    ABUSEIPDB: "API tidak dipanggil (input bukan IP Address)",
    URLHAUS: "API tidak dipanggil (input bukan URL/Domain)",
    MXTOOLBOX: "API tidak dipanggil (input bukan Email/Mail Domain)",
}


def sources_for(input_type: str) -> list:
    return ROUTING.get(input_type, [VIRUSTOTAL])


def routing_plan(input_type: str) -> list:
    """Rencana routing buat ditampilkan di UI sebelum/ sesudah scan."""
    active = sources_for(input_type)
    return [
        {
            "source": s,
            "label": SOURCE_META[s]["label"],
            "emoji": SOURCE_META[s]["emoji"],
            "color": SOURCE_META[s]["color"],
            "will_call": s in active,
        }
        for s in SOURCE_ORDER
    ]


# ============================================================
# 3. EKSEKUSI MULTI-SOURCE
# ============================================================
def run_multi_scan(db: Session, identifier: str, input_type: str = None) -> dict:
    """
    Jalankan scan ke semua API yang relevan, lalu susun laporan gabungan.
    API yang tidak relevan tetap masuk hasil dengan status 'skipped' supaya
    dashboard bisa menampilkan box-nya (biar keliatan kenapa gak dipanggil).
    """
    raw_input = (identifier or "").strip()
    identifier = clean_indicator(raw_input)
    input_type = input_type or detect_input_type(identifier)

    # Validasi & normalisasi spesifik per tipe input
    if input_type == "ip":
        clean_ip = re.sub(r":\d+$", "", identifier.strip("[]"))
        m_v4 = _RE_IPV4_LIKE.match(clean_ip)
        if m_v4:
            invalid_octets = [g for g in m_v4.groups() if int(g) > 255]
            if invalid_octets:
                # Format 4 blok angka tetapi ada angka > 255 (misal 283 > 255)
                # Tangani langsung tanpa memanggil API pihak ketiga agar tidak membakar key
                return {
                    "input": raw_input,
                    "input_type": "ip",
                    "input_type_label": "IP Address (Format Invalid)",
                    "scan_date": now_local().strftime("%Y-%m-%d %H:%M:%S"),
                    "routed_to": [VIRUSTOTAL, ABUSEIPDB],
                    "sources": [
                        {
                            "source": VIRUSTOTAL,
                            "label": SOURCE_META[VIRUSTOTAL]["label"],
                            "emoji": SOURCE_META[VIRUSTOTAL]["emoji"],
                            "color": SOURCE_META[VIRUSTOTAL]["color"],
                            "status": "error",
                            "verdict": "ERROR",
                            "reason": f"Format IP tidak valid: nilai oktet '{invalid_octets[0]}' melebihi batas 255",
                        },
                        {
                            "source": ABUSEIPDB,
                            "label": SOURCE_META[ABUSEIPDB]["label"],
                            "emoji": SOURCE_META[ABUSEIPDB]["emoji"],
                            "color": SOURCE_META[ABUSEIPDB]["color"],
                            "status": "error",
                            "verdict": "ERROR",
                            "reason": f"Format IP tidak valid: nilai oktet '{invalid_octets[0]}' melebihi batas 255",
                        },
                        get_client(URLHAUS, db).skipped(SKIP_REASONS[URLHAUS]),
                        get_client(MXTOOLBOX, db).skipped(SKIP_REASONS[MXTOOLBOX]),
                    ],
                    "final": {
                        "verdict": "UNKNOWN",
                        "confidence": 0,
                        "recommendation": "PERIKSA FORMAT INPUT",
                        "recommendation_detail": f"Nilai '{raw_input}' bukan alamat IP yang valid karena oktet '{invalid_octets[0]}' melebihi batas IPv4 (0-255). Pastikan tidak ada kesalahan ketik.",
                        "reason": f"Oktet {invalid_octets[0]} > 255",
                    },
                }
        identifier = clean_ip

    elif input_type == "domain":
        # Bersihkan port dan trailing slash: google.com:443/ -> google.com
        identifier = re.sub(r":\d+$", "", identifier.rstrip("/"))

    elif input_type == "url":
        if not re.match(r"^https?://", identifier, re.I):
            identifier = "http://" + identifier

    targets = sources_for(input_type)

    boxes = []
    for api_type in SOURCE_ORDER:
        client = get_client(api_type, db)
        if api_type in targets:
            try:
                boxes.append(client.report(input_type, identifier))
            except Exception as e:
                boxes.append(client.error(f"Gagal memproses hasil: {e}"))
        else:
            boxes.append(client.skipped(SKIP_REASONS[api_type]))

    final = build_final_verdict(boxes)

    return {
        "input": identifier,
        "input_type": input_type,
        "input_type_label": INPUT_TYPE_LABELS.get(input_type, "Unknown"),
        "scan_date": now_local().strftime("%Y-%m-%d %H:%M:%S"),
        "routed_to": targets,
        "sources": boxes,
        "final": final,
    }


# ============================================================
# 4. FINAL VERDICT + RECOMMENDATION
# ============================================================
def _signal_strength(box: dict) -> int:
    """
    Seberapa kuat sinyal dari satu sumber (0-100).
    Untuk vonis MALICIOUS/SUSPICIOUS: makin tinggi makin yakin berbahaya.
    Untuk vonis CLEAN: makin tinggi makin yakin bersih.
    """
    s = box.get("summary") or {}
    src = box.get("source")
    verdict = box.get("verdict")

    if src == VIRUSTOTAL:
        mal = s.get("malicious") or 0
        sus = s.get("suspicious") or 0
        if verdict in ("MALICIOUS", "SUSPICIOUS"):
            return min(100, mal * 12 + sus * 5)
        # bersih: makin banyak engine yang scan, makin meyakinkan
        undetected = s.get("undetected") or 0
        return min(95, 45 + undetected // 2)

    if src == ABUSEIPDB:
        score = s.get("abuse_score") or 0
        if verdict in ("MALICIOUS", "SUSPICIOUS"):
            return int(score)
        reports = s.get("total_reports") or 0
        base = 85 if reports == 0 else 60
        return 95 if s.get("is_whitelisted") else base

    if src == URLHAUS:
        if verdict == "MALICIOUS":
            return 95
        if verdict == "SUSPICIOUS":
            return 70
        return 65  # tidak terdaftar — sinyal bersih tapi cakupannya terbatas

    if src == MXTOOLBOX:
        failed = s.get("failed_count") or 0
        warns = s.get("warning_count") or 0
        if verdict == "MALICIOUS":
            return min(95, 60 + failed * 10)
        if verdict == "SUSPICIOUS":
            return min(70, 35 + warns * 8)
        return 70

    return 50


def build_final_verdict(boxes: list) -> dict:
    """Gabungkan vonis semua sumber jadi satu keputusan akhir."""
    ok = [b for b in boxes if b.get("status") == STATUS_OK]

    malicious = [b for b in ok if b.get("verdict") == "MALICIOUS"]
    suspicious = [b for b in ok if b.get("verdict") == "SUSPICIOUS"]
    clean = [b for b in ok if b.get("verdict") == "CLEAN"]

    names = lambda arr: ", ".join(b["label"] for b in arr)

    # --- Tidak ada data sama sekali ---
    if not ok:
        errored = [b for b in boxes if b.get("status") == "error"]
        no_key = [b for b in boxes if b.get("status") == "no_key"]
        if no_key and not errored:
            reason = f"Belum ada API key untuk sumber yang relevan ({names(no_key)})."
        elif errored:
            reason = f"Semua sumber gagal dipanggil ({names(errored)})."
        else:
            reason = "Tidak ada sumber intel yang relevan untuk input ini."
        return {
            "verdict": "UNKNOWN",
            "tone": "none",
            "confidence": 0,
            "recommendation": "MANUAL REVIEW",
            "recommendation_detail": "Tidak ada data — perlu pemeriksaan manual",
            "reason": reason,
            "sources_ok": 0,
            "sources_malicious": 0,
            "sources_suspicious": 0,
            "sources_clean": 0,
            "agreement": None,
            "conflict": None,
        }

    # --- Ada minimal satu sumber bilang MALICIOUS ---
    if malicious:
        strengths = [_signal_strength(b) for b in malicious]
        confidence = min(99, max(strengths) + (len(malicious) - 1) * 8)
        verdict, tone = "MALICIOUS", "crit"
        if confidence >= 80:
            rec, detail = "BLOCK", "High confidence — blokir sekarang"
        elif confidence >= 50:
            rec, detail = "BLOCK & INVESTIGATE", "Medium confidence — blokir lalu telusuri"
        else:
            rec, detail = "QUARANTINE", "Low confidence — karantina dulu, verifikasi manual"
        reason = f"{len(malicious)} dari {len(ok)} sumber menandai berbahaya ({names(malicious)})."

    # --- Tidak ada MALICIOUS, tapi ada SUSPICIOUS ---
    elif suspicious:
        strengths = [_signal_strength(b) for b in suspicious]
        confidence = min(75, sum(strengths) // len(strengths))
        verdict, tone = "SUSPICIOUS", "warn"
        rec, detail = "MONITOR", "Perlu verifikasi manual sebelum diblokir"
        reason = f"{len(suspicious)} dari {len(ok)} sumber menandai mencurigakan ({names(suspicious)})."

    # --- Semua bersih ---
    else:
        strengths = [_signal_strength(b) for b in clean]
        confidence = min(95, sum(strengths) // len(strengths) + (len(clean) - 1) * 5)
        verdict, tone = "CLEAN", "ok"
        if confidence >= 75:
            rec, detail = "ALLOW", "Tidak ada indikasi ancaman dari sumber mana pun"
        else:
            rec, detail = "ALLOW WITH MONITORING", "Bersih, tapi cakupan data terbatas"
        reason = f"Semua sumber yang dipanggil ({names(clean)}) menyatakan bersih."

    # --- Catatan kalau sumber saling bertentangan ---
    conflict = None
    if (malicious or suspicious) and clean:
        flagged = names(malicious + suspicious)
        conflict = f"Sumber tidak sepakat: {flagged} menandai berisiko, sementara {names(clean)} menyatakan bersih."

    return {
        "verdict": verdict,
        "tone": tone,
        "confidence": int(confidence),
        "recommendation": rec,
        "recommendation_detail": detail,
        "reason": reason,
        "sources_ok": len(ok),
        "sources_malicious": len(malicious),
        "sources_suspicious": len(suspicious),
        "sources_clean": len(clean),
        "agreement": f"{len(malicious) + len(suspicious)}/{len(ok)} sumber menandai berisiko",
        "conflict": conflict,
    }
