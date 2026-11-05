import asyncio
import json
import logging
import os
import httpx

from iris_client import IrisClient

logging.basicConfig(
    level="INFO",
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("stream-receiver")

TARGET_STREAM_URL = os.getenv("TARGET_STREAM_URL", "http://38.47.66.253:17772/stream")

async def find_and_append_risk(iris_client: IrisClient, raw_data: dict) -> bool:
    # 1. Ambil UUID dari data
    log_uuid = str(raw_data.get("log_uuid") or raw_data.get("id") or raw_data.get("uuid", "")).strip()
    if not log_uuid or log_uuid == "UNKNOWN-UUID":
        log.warning("⚠️ Tidak ada UUID valid dalam data. Melewati.")
        return False

    # 2. Format teks risiko yang akan DITAMBAHKAN DI BAWAH
    risk_data = raw_data.get("risk", {})
    score = risk_data.get("score", raw_data.get("score", 0.0))
    level = str(risk_data.get("level", raw_data.get("level", "medium"))).lower()
    asset_crit = risk_data.get("asset_criticality", raw_data.get("asset_criticality", 0))
    severity = risk_data.get("event_severity", raw_data.get("event_severity", 0))
    outcome = risk_data.get("event_outcome", raw_data.get("event_outcome", 0))
    threat = risk_data.get("threat_weight", raw_data.get("threat_weight", 0))
    repeat = risk_data.get("repeat_count", raw_data.get("repeat_count", 0))

    append_text = (
        f"\n\n--- 🔄 Update Informasi Risiko Terbaru ---\n"
        f"**Risiko**\n"
        f"- **Skor**: {score} ({level})\n"
        f"- **Faktor**: kritikalitas aset {asset_crit}, severity {severity}, "
        f"outcome {outcome}, ancaman {threat}, pengulangan {repeat}\n"
        f"---------------------------------------------"
    )

    # 3. Cari Alert ID di IRIS berdasarkan UUID
    log.info("🔍 Mencari alert di IRIS dengan UUID: %s...", log_uuid)
    alert_id = None
    
    try:
        # Gunakan client yang sudah terautentikasi dari iris_client
        resp = await iris_client._client.get("/api/v2/alerts", params={"per_page": 100, "page": 1})
        resp.raise_for_status()
        resp_json = resp.json()
        alerts = resp_json.get("data", []) if isinstance(resp_json, dict) else resp_json
        
        for alert in alerts:
            a_id = alert.get("id")
            title = str(alert.get("alert_title", ""))
            desc = str(alert.get("alert_description", ""))
            source_ref = str(alert.get("alert_source_ref", ""))
            
            # Cek kecocokan UUID di title, description, source_ref, atau ID
            if str(log_uuid) in title or str(log_uuid) in desc or str(log_uuid) == source_ref or str(a_id) == str(log_uuid):
                alert_id = a_id
                log.info("✅ Alert DITEMUKAN! ID: %s", alert_id)
                break
                
    except Exception as e:
        log.error("❌ Gagal mencari alert di IRIS: %s", e)
        return False

    # 4. Jika TIDAK ditemukan, JANGAN buat alert baru (sesuai permintaan)
    if not alert_id:
        log.warning("⚠️ Alert dengan UUID '%s' TIDAK DITEMUKAN di IRIS. Melewati (Tidak membuat alert baru).", log_uuid)
        return False

    # 5. Jika DITEMUKAN, tambahkan (append) teks di bawah deskripsi yang sudah ada
    success = await iris_client.append_alert_description(alert_id, append_text)
    return success


async def run_receiver():
    log.info("🎧 Receiver aktif (Mode: Cari & TAMBAH di bawah, JANGAN buat baru).")
    
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
            log.error("❌ IRIS Client gagal diinisialisasi.")
            return
        status, msg = await iris_client.check()
        log.info("✅ Koneksi ke IRIS: %s", msg)
    except Exception as e:
        log.critical("❌ Gagal membuat IRIS Client: %s", e)
        return

    log.info("🔌 Menghubungkan ke stream: %s", TARGET_STREAM_URL)
    
    async with httpx.AsyncClient(timeout=None) as client:
        while True:
            try:
                async with client.stream("GET", TARGET_STREAM_URL) as response:
                    response.raise_for_status()
                    log.info("✅ Terhubung ke /stream! Menunggu data...")
                    
                    async for line in response.aiter_lines():
                        line = line.strip()
                        if not line:
                            continue
                        
                        try:
                            raw_data = json.loads(line)
                            await find_and_append_risk(iris_client, raw_data)
                        except json.JSONDecodeError:
                            log.warning("⚠️ Data bukan JSON valid: %s", line[:50])
                        except Exception as e:
                            log.error("❌ Error memproses data: %s", e)
                            
            except httpx.RequestError as e:
                log.error("❌ Koneksi stream terputus: %s", e)
            except Exception as e:
                log.error("❌ Error tidak terduga: %s", e)
            
            log.info("🔄 Reconnect dalam 5 detik...")
            await asyncio.sleep(5)

if __name__ == "__main__":
    try:
        log.info("🚀 Stream Receiver (Append Mode) dimulai.")
        asyncio.run(run_receiver())
    except KeyboardInterrupt:
        log.info("🛑 Receiver dihentikan.")