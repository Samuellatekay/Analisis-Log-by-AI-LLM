import asyncio
import json
import logging
import os
import httpx

# Import IrisClient yang sudah Anda buat sebelumnya
from iris_client import IrisClient

logging.basicConfig(
    level="INFO",
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("stream-receiver")

# URL stream yang akan didengarkan
TARGET_STREAM_URL = os.getenv("TARGET_STREAM_URL", "http://38.47.66.253:17772/stream")


# ============================================================
# NORMALISASI DATA KE FORMAT IRIS
# ============================================================

def normalize_for_iris(raw_data: dict) -> dict:
    """
    Mengubah data mentah dari stream menjadi format IRIS, 
    dengan format deskripsi risiko sesuai permintaan.
    """
    # 1. Cocokkan berdasarkan UUID (log_uuid)
    log_uuid = (
        raw_data.get("log_uuid") or 
        raw_data.get("id") or 
        raw_data.get("uuid") or 
        str(hash(json.dumps(raw_data, sort_keys=True))) # Fallback jika tidak ada UUID
    )
    
    # 2. Ambil data risiko (dukung format nested 'risk' atau flat)
    risk_data = raw_data.get("risk", {})
    score = risk_data.get("score", raw_data.get("score", 0.0))
    level = str(risk_data.get("level", raw_data.get("level", "medium"))).lower()
    asset_crit = risk_data.get("asset_criticality", raw_data.get("asset_criticality", 0))
    severity = risk_data.get("event_severity", raw_data.get("event_severity", 0))
    outcome = risk_data.get("event_outcome", raw_data.get("event_outcome", 0))
    threat = risk_data.get("threat_weight", raw_data.get("threat_weight", 0))
    repeat = risk_data.get("repeat_count", raw_data.get("repeat_count", 0))
    
    # 3. Buat teks deskripsi sesuai format yang Anda minta
    risk_summary_text = (
        f"Risiko\n"
        f"Skor: {score} ({level})\n"
        f"Faktor: kritikalitas aset {asset_crit}, severity {severity}, "
        f"outcome {outcome}, ancaman {threat}, pengulangan {repeat}"
    )
    
    # 4. Susun payload final untuk IRIS
    return {
        "log_uuid": log_uuid, # UUID untuk pencocokan/deduplikasi
        "data_source": raw_data.get("data_source", "stream_receiver"),
        
        "risk": {
            "level": level,
            "score": float(score),
            "asset_criticality": float(asset_crit),
            "event_severity": float(severity),
            "event_outcome": int(outcome),
            "threat_weight": float(threat),
            "repeat_count": int(repeat)
        },
        
        "event": {
            "action": raw_data.get("title", raw_data.get("action", "Stream Event")),
            "outcome": "alert",
            "category": raw_data.get("category", ["external"]),
            "wazuh_level": int(raw_data.get("wazuh_level", 0))
        },
        
        "source": {
            "ip": raw_data.get("source_ip", raw_data.get("src_ip", "0.0.0.0")),
            "asset": {"name": raw_data.get("source_host", "Unknown")}
        },
        
        "destination": {
            "ip": raw_data.get("dest_ip", "0.0.0.0"),
            "asset": {"name": raw_data.get("dest_host", "Target")}
        },
        
        # ⭐ INI ADALAH BAGIAN YANG ANDA MINTA ⭐
        "summary": risk_summary_text, 
        
        "original": raw_data # Simpan data mentah untuk referensi
    }


# ============================================================
# MAIN: STREAM LISTENER & IRIS SENDER
# ============================================================

async def run_receiver():
    log.info("🎧 Receiver aktif (Mode: Stream to IRIS).")
    
    # 1. Inisialisasi IRIS Client
    env = {
        "IRIS_ENABLED": "true",
        "IRIS_URL": os.getenv("IRIS_URL", "https://iris.local"),
        "IRIS_API_KEY": os.getenv("IRIS_API_KEY", ""),
        "IRIS_CA_CERT": os.getenv("IRIS_CA_CERT", ""),
        "IRIS_VERIFY_SSL": os.getenv("IRIS_VERIFY_SSL", "true"),
        "IRIS_CUSTOMER_ID": os.getenv("IRIS_CUSTOMER_ID", "1"),
        "IRIS_API_VERSION": os.getenv("IRIS_API_VERSION", "v2"),
    }
    
    try:
        iris_client = IrisClient.from_env(env)
        if not iris_client:
            log.error("❌ IRIS Client gagal diinisialisasi. Cek variabel IRIS_ di .env")
            return
        status, msg = await iris_client.check()
        log.info("✅ Koneksi ke IRIS: %s - %s", status, msg)
    except Exception as e:
        log.critical("❌ Gagal membuat IRIS Client: %s", e)
        return

    # 2. Loop Mendengarkan Stream
    log.info("🔌 Menghubungkan ke stream: %s", TARGET_STREAM_URL)
    
    async with httpx.AsyncClient(timeout=None) as client:
        while True:
            try:
                async with client.stream("GET", TARGET_STREAM_URL) as response:
                    response.raise_for_status()
                    log.info("✅ Terhubung ke /stream! Menunggu data real-time...")
                    
                    async for line in response.aiter_lines():
                        line = line.strip()
                        if not line:
                            continue
                        
                        try:
                            # Parse JSON dari stream
                            raw_data = json.loads(line)
                            
                            # Normalisasi data (termasuk formatting teks Risiko)
                            doc = normalize_for_iris(raw_data)
                            
                            # Cek filter (opsional, tergantung konfigurasi IrisClient Anda)
                            if hasattr(iris_client, 'allows') and not iris_client.allows(doc):
                                log.debug("⏭️ Data dilewati oleh filter IRIS.")
                                continue
                            
                            # Kirim ke IRIS
                            log.info("📤 Memproses data ke IRIS (UUID: %s)...", doc.get("log_uuid"))
                            alert_id = await iris_client.create_alert(doc)
                            
                            if alert_id:
                                log.info("🎯 BERHASIL! Alert ID %s dibuat di IRIS.", alert_id)
                            else:
                                log.warning("⚠️ Gagal mendapatkan ID Alert dari IRIS (mungkin deduplikasi UUID).")
                                
                        except json.JSONDecodeError:
                            log.warning("⚠️ Data dari stream bukan format JSON valid: %s", line[:50])
                        except Exception as e:
                            log.error("❌ Error saat memproses data ke IRIS: %s", e)
                            
            except httpx.RequestError as e:
                log.error("❌ Koneksi ke stream terputus: %s", e)
            except Exception as e:
                log.error("❌ Error tidak terduga: %s", e)
            
            # Auto-reconnect jika putus
            log.info("🔄 Mencoba menghubungkan ulang dalam 5 detik...")
            await asyncio.sleep(5)


if __name__ == "__main__":
    try:
        log.info("🚀 Stream Receiver to IRIS dimulai.")
        asyncio.run(run_receiver())
    except KeyboardInterrupt:
        log.info("🛑 Receiver dihentikan secara manual.")