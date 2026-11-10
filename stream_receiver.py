import asyncio
import json
import logging
import os
import httpx
import markdown

from iris_client import IrisClient

logging.basicConfig(
    level="INFO",
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("stream-receiver")

TARGET_STREAM_URL = os.getenv("TARGET_STREAM_URL", "http://38.47.66.253:17772/stream")

async def inject_incident_report(iris_client: IrisClient, raw_data: dict) -> bool:
    log_uuid = str(raw_data.get("log_uuid") or raw_data.get("id", "")).strip()
    incident_report = raw_data.get("incident_report")
    
    if not incident_report:
        log.debug("ℹ️ Tidak ada incident_report. Melewati.")
        return False
    if not log_uuid:
        log.warning("⚠️ Ada incident_report tapi Tidak ada UUID. Melewati.")
        return False

    log.info("🔍 Mencari Alert dan Case dengan UUID: %s...", log_uuid)
    
    # ==========================================================
    # 1. UPDATE ALERT
    # ==========================================================
    target_alert_id = None
    try:
        resp = await iris_client._client.get("/api/v2/alerts", params={"per_page": 50, "page": 1, "sort": "alert_source_event_time:desc"})
        resp.raise_for_status()
        resp_json = resp.json()
        alerts = resp_json.get("data", []) if isinstance(resp_json, dict) else resp_json
        
        for alert in alerts:
            if not isinstance(alert, dict): continue
            a_id = alert.get("id") or alert.get("alert_id")
            if a_id is None and isinstance(alert.get("data"), dict):
                a_id = alert["data"].get("id") or alert["data"].get("alert_id")
            
            source_ref = str(alert.get("alert_source_ref", ""))
            desc = str(alert.get("alert_description", ""))
            
            if str(log_uuid) == source_ref or str(log_uuid) in desc:
                target_alert_id = a_id
                break
    except Exception as e:
        log.error("❌ Gagal mencari alert: %s", e)

    if target_alert_id:
        log.info("✅ Alert DITEMUKAN! ID: %s", target_alert_id)
        current_alert = await iris_client.get_alert(target_alert_id)
        if current_alert:
            current_desc = current_alert.get("alert_description", "")
            if isinstance(current_desc, str):
                first_line_report = incident_report.split('\n')[0].strip()
                if first_line_report and first_line_report not in current_desc:
                    lines = current_desc.split('\n')
                    injected = False
                    for i, line in enumerate(lines):
                        if line.strip().startswith('# Source') or line.strip() == 'Source':
                            lines.insert(i, f"\n{incident_report}\n")
                            injected = True
                            break
                    if not injected:
                        lines.append(f"\n\n## Analisis AI (Incident Report)\n{incident_report}")
                    
                    await iris_client.update_alert_description(target_alert_id, '\n'.join(lines))
                    log.info("📝 Deskripsi Alert %s berhasil diupdate.", target_alert_id)
                else:
                    log.info("ℹ️ Laporan sudah ada di Alert %s.", target_alert_id)

    # ==========================================================
    # 2. UPDATE CASE (JIKA SUDAH ADA) - VERSI ROBUST
    # ==========================================================
    target_case_id = None
    try:
        resp_case = await iris_client._client.get("/api/v2/cases", params={"per_page": 50, "page": 1, "sort": "open_date:desc"})
        resp_case.raise_for_status()
        cases_data = resp_case.json()
        cases = cases_data.get("data", []) if isinstance(cases_data, dict) else cases_data
        
        for case in cases:
            if not isinstance(case, dict): continue
            c_id = case.get("case_id") or case.get("id")
            soc_id = str(case.get("case_soc_id") or case.get("soc_id") or "")
            
            if str(log_uuid) == soc_id:
                target_case_id = c_id
                break
    except Exception as e:
        log.error("❌ Gagal mencari case: %s", e)

    if target_case_id:
        log.info("✅ Case DITEMUKAN! ID: %s. Mengupdate deskripsi Case...", target_case_id)
        try:
            current_case = await iris_client._get(f"/api/v2/cases/{target_case_id}")
            if not current_case:
                log.warning("⚠️ Gagal mengambil detail Case %s", target_case_id)
            else:
                old_desc = current_case.get("case_description") or current_case.get("description") or ""
                
                # 1. KONVERSI MARKDOWN KE HTML DI SINI
                # Ekstensi 'extra', 'fenced_code', dan 'tables' memastikan format AI rapi
                html_report = markdown.markdown(
                    incident_report, 
                    extensions=['extra', 'fenced_code', 'tables']
                )
                
                # 2. Gabungkan dengan deskripsi lama (yang juga sebaiknya di-HTML-kan jika perlu, 
                # tapi untuk amannya kita append HTML baru di bawah)
                combined_desc = f"{old_desc}<hr><h3>🤖 Update Analisis AI</h3>{html_report}"
                
                if incident_report.strip() not in old_desc: # Cek sederhana
                    update_payload = {
                        "case_description": combined_desc[:16000],
                        "case_name": current_case.get("case_name") or "Unnamed Case",
                        "case_customer": current_case.get("case_customer_id") or current_case.get("case_customer") or 1,
                        "case_soc_id": current_case.get("case_soc_id") or current_case.get("soc_id") or log_uuid,
                        "case_tags": current_case.get("case_tags") or "",
                        "state_id": current_case.get("state_id") or 3,
                        "severity_id": current_case.get("severity_id") or 4,
                        "status_id": current_case.get("status_id") or 0,
                        "owner_id": current_case.get("owner_id") or current_case.get("user_id") or 1,
                    }
                    
                    await iris_client._put(f"/api/v2/cases/{target_case_id}", update_payload)
                    log.info("📝 Deskripsi Case %s berhasil diupdate dengan HTML Laporan AI.", target_case_id)
                else:
                    log.info("ℹ️ Laporan AI sudah ada di Case %s.", target_case_id)
                    
        except Exception as e:
            log.error("❌ Gagal mengupdate Case %s: %s", target_case_id, e)
    # ==========================================================
    # 3. TAMBAHKAN KE NOTES (FALLBACK YANG PASTI MUNCUL) <--- INI BAGIAN BARUNYA
    # ==========================================================
    if target_case_id:
        try:
            note_payload = {
                "note_title": f"🤖 Laporan Analisis AI - {log_uuid[:8]}",
                "note_content": incident_report,
            }
            # Kirim ke endpoint Notes API v2
            await iris_client._post(f"/api/v2/cases/{target_case_id}/notes", note_payload)
            log.info("✅ Laporan AI berhasil ditambahkan ke tab NOTES Case %s", target_case_id)
        except Exception as e:
            log.warning("⚠️ Gagal menambah ke Notes: %s", e)    
                
    return True


async def run_receiver():
    log.info("🎧 Receiver aktif (Mode: Inject IR ke Alert & Case).")
    
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
                        if not line: continue
                        
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
            
            log.info("🔄 Reconnect dalam5 detik...")
            await asyncio.sleep(5)

if __name__ == "__main__":
    try:
        log.info("🚀 Stream Receiver (Inject Mode) dimulai.")
        asyncio.run(run_receiver())
    except KeyboardInterrupt:
        log.info("🛑 Receiver dihentikan.")