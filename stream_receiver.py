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

async def inject_incident_report(iris_client: IrisClient, raw_data: dict) -> bool:
    # 1. Ambil UUID dan incident_report
    log_uuid = str(raw_data.get("log_uuid") or raw_data.get("id", "")).strip()
    incident_report = raw_data.get("incident_report")
    
    # Jika tidak ada incident_report, abaikan (ini adalah Pesan 1: Raw Log biasa)
    if not incident_report:
        log.debug("ℹ️ Tidak ada incident_report di data ini. Melewati (mungkin raw log).")
        return False
        
    if not log_uuid:
        log.warning("⚠️ Ada incident_report tapi Tidak ada UUID. Melewati.")
        return False

    log.info("🔍 Mencari alert di IRIS dengan UUID: %s...", log_uuid)
    target_alert_id = None
    
    try:
        resp = await iris_client._client.get("/api/v2/alerts", params={"per_page": 50, "page": 1, "sort": "alert_source_event_time:desc"})
        resp.raise_for_status()
        resp_json = resp.json()
        
        alerts = resp_json.get("data", []) if isinstance(resp_json, dict) else resp_json
        
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
                
            # Ekstraksi ID dengan berbagai kemungkinan nama key (ROBUST)
            a_id = alert.get("id") or alert.get("alert_id")
            if a_id is None and isinstance(alert.get("data"), dict):
                a_id = alert["data"].get("id") or alert["data"].get("alert_id")
            
            # Fallback: cari key apa saja yang berisi 'id' dan bernilai integer
            if a_id is None:
                for key, val in alert.items():
                    if "id" in key.lower() and isinstance(val, int):
                        a_id = val
                        break
                        
            source_ref = str(alert.get("alert_source_ref", ""))
            desc = str(alert.get("alert_description", ""))
            title = str(alert.get("alert_title", ""))
            
            # Cek kecocokan UUID di source_ref, description, atau title
            if str(log_uuid) == source_ref or str(log_uuid) in desc or str(log_uuid) in title:
                target_alert_id = a_id
                if target_alert_id:
                    log.info("✅ Alert DITEMUKAN! ID: %s", target_alert_id)
                else:
                    log.warning("⚠️ Alert cocok ditemukan, tapi ID-nya None! Keys tersedia: %s", list(alert.keys()))
                break
                
    except Exception as e:
        log.error("❌ Gagal mencari alert di IRIS: %s", e)
        return False

    if not target_alert_id:
        log.warning("⚠️ Alert dengan UUID '%s' TIDAK DITEMUKAN. Melewati.", log_uuid)
        return False

    # 2. Ambil Deskripsi Saat Ini
    current_alert = await iris_client.get_alert(target_alert_id)
    if not current_alert:
        log.error("❌ Gagal mengambil detail alert %s.", target_alert_id)
        return False
        
    current_desc = current_alert.get("alert_description", "")
    if not isinstance(current_desc, str):
        current_desc = ""

    # 3. Cek Duplikasi (apakah laporan sudah pernah disisipkan?)
    first_line_report = incident_report.split('\n')[0].strip()
    if first_line_report and first_line_report in current_desc:
        log.info("ℹ️ Laporan insiden sudah ada di alert %s. Melewati update.", target_alert_id)
        return True

    # 4. SISIPKAN (INJECT) ke Tengah (setelah baris "Faktor:")
    lines = current_desc.split('\n')
    injected = False
    
    for i, line in enumerate(lines):
        if "Faktor:" in line and "kritikalitas aset" in line:
            lines.insert(i + 1, f"\n{incident_report}\n")
            injected = True
            log.info("📝 Laporan disisipkan setelah baris 'Faktor:' pada alert %s.", target_alert_id)
            break

    # Fallback jika struktur "Faktor:" tidak ditemukan
    if not injected:
        log.warning("⚠️ Struktur 'Faktor:' tidak ditemukan. Menambahkan di bagian bawah deskripsi.")
        lines.append(f"\n\n## Analisis AI (Incident Report)\n{incident_report}")

    new_desc = '\n'.join(lines)

    # 5. Update ke IRIS
    success = await iris_client.update_alert_description(target_alert_id, new_desc)
    return success


async def run_receiver():
    log.info("🎧 Receiver aktif (Mode: Inject Incident Report to Middle).")
    
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
                            await inject_incident_report(iris_client, raw_data)
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
        log.info("🚀 Stream Receiver (Inject Mode) dimulai.")
        asyncio.run(run_receiver())
    except KeyboardInterrupt:
        log.info("🛑 Receiver dihentikan.")