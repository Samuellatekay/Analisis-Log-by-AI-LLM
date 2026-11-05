import asyncio
import json
import logging
import os
import httpx

# Import IrisClient yang sudah Anda buat
from iris_client import IrisClient

logging.basicConfig(
    level="INFO",
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("stream-receiver")

# ============================================================
# KONFIGURASI
# ============================================================

# URL endpoint /stream dari server sumber (bisa dari vm-receiver atau iris-stream)
# Contoh: "http://vm-receiver:17772/stream" atau "http://38.47.66.253:17772/stream"
TARGET_STREAM_URL = os.getenv("TARGET_STREAM_URL", "http://vm-receiver:17772/stream")

# ============================================================
# NORMALISASI DATA
# ============================================================

def normalize_for_iris(raw_data: dict) -> dict:
    """
    Mengubah data mentah dari /stream menjadi format 'doc' yang dimengerti IrisClient.
    Sesuaikan field di sini dengan struktur JSON yang dikirim oleh server /stream Anda.
    """
    # Buat UUID unik jika tidak ada di data
    log_uuid = raw_data.get("log_uuid") or raw_data.get("id") or str(hash(json.dumps(raw_data, sort_keys=True)))

    return {
        "log_uuid": log_uuid,
        "data_source": "stream_receiver",
        
        "risk": {
            "level": str(raw_data.get("severity", raw_data.get("level", "medium"))).lower(),
            "score": float(raw_data.get("score", 50)),
            "asset_criticality": 3,
            "event_severity": 3,
            "event_outcome": 1,
            "threat_weight": 3,
            "repeat_count": 1
        },
        
        "event": {
            "action": raw_data.get("title", raw_data.get("action", "Stream Event")),
            "outcome": "alert",
            "category": ["external_stream"],
            "wazuh_level": 0
        },
        
        "source": {
            "ip": raw_data.get("source_ip", "0.0.0.0"),
            "asset": {"name": raw_data.get("source_host", "Unknown")}
        },
        
        "destination": {
            "ip": raw_data.get("dest_ip", "0.0.0.0"),
            "asset": {"name": raw_data.get("dest_host", "Target")}
        },
        
        "enrichment": {"observables": []},
        "geolocation": {"available": False},
        
        # Summary ini yang akan muncul paling atas di IRIS
        "summary": raw_data.get("summary", raw_data.get("description", "Data dari stream receiver")),
        
        # Simpan data mentah
        "original": raw_data 
    }

# ============================================================
# MAIN: STREAM RECEIVER -> IRIS
# ============================================================

async def run_receiver():
    # 1. Inisialisasi IRIS Client
    log.info("🔧 Menginisialisasi IRIS Client...")
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

    # 2. Loop Mendengarkan /stream
    log.info("🎧 Receiver aktif. Menghubungkan ke stream: %s", TARGET_STREAM_URL)
    
    async with httpx.AsyncClient(timeout=None) as client:
        while True:
            try:
                # Connect ke endpoint /stream
                async with client.stream("GET", TARGET_STREAM_URL) as response:
                    response.raise_for_status()
                    log.info("✅ Terhubung ke /stream! Menunggu data real-time...")
                    
                    # Baca data baris demi baris
                    async for line in response.aiter_lines():
                        line = line.strip()
                        if not line:
                            continue
                        
                        try:
                            # Parse JSON
                            raw_data = json.loads(line)
                            
                            # Normalisasi ke format IRIS
                            doc = normalize_for_iris(raw_data)
                            
                            # Cek filter
                            if not iris_client.allows(doc):
                                continue
                                
                            # Kirim ke IRIS
                            log.info("📤 Memproses data (UUID: %s)...", doc.get("log_uuid"))
                            # alert_id = await iris_client.create_alert(doc)
                            
                            if alert_id:
                                log.info("🎯 BERHASIL! Alert ID %s dibuat di IRIS.", alert_id)
                            else:
                                log.warning("⚠️ Gagal mendapatkan ID Alert dari IRIS.")
                                
                        except json.JSONDecodeError:
                            log.warning("⚠️ Data dari stream bukan JSON valid: %s", line[:50])
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