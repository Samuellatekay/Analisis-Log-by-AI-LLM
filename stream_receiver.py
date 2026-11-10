import asyncio
import json
import logging
import os
import httpx

from iris_client import IrisClient, upsert_ai_section

logging.basicConfig(
    level="INFO",
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("stream-receiver")

TARGET_STREAM_URL = os.getenv("TARGET_STREAM_URL", "http://38.47.66.253:17772/stream")


def log_incident_report(log_uuid: str, report: str) -> None:
    """Tampilkan seluruh laporan AI di log tanpa mengubah isi atau line ending."""
    log.info("===== BEGIN LLM REPORT uuid=%s chars=%s =====", log_uuid, len(report))
    log.info("%s", report)
    log.info("===== END LLM REPORT uuid=%s =====", log_uuid)


async def inject_incident_report(iris_client: IrisClient, raw_data: dict) -> bool:
    log_uuid = str(raw_data.get("log_uuid") or raw_data.get("id", "")).strip()
    source_alert_id = raw_data.get("alert_id")
    incident_report = raw_data.get("incident_report")
    
    if not isinstance(incident_report, str) or not incident_report.strip():
        log.debug("ℹ️ Tidak ada incident_report. Melewati.")
        return False
    if not log_uuid:
        log.warning("⚠️ Ada incident_report tapi Tidak ada UUID. Melewati.")
        return False

    log.info("incident_report diterima untuk %s: %s karakter.", log_uuid, len(incident_report))
    log_incident_report(log_uuid, incident_report)
    log.info(
        "🔍 Mencari Alert untuk UUID %s%s...",
        log_uuid,
        f" dan ID {source_alert_id}" if source_alert_id is not None else "",
    )
    
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
            
            if (
                source_alert_id is not None and str(source_alert_id) == str(a_id)
            ) or str(log_uuid) == source_ref or str(log_uuid) in desc:
                target_alert_id = a_id
                break
    except Exception as e:
        log.error("❌ Gagal mencari alert: %s", e)

    if target_alert_id:
        log.info("✅ Alert DITEMUKAN! ID: %s", target_alert_id)
        current_alert = await iris_client.get_alert(target_alert_id)
        if current_alert:
            alert_source_ref = str(current_alert.get("alert_source_ref") or "").strip()
            if alert_source_ref and alert_source_ref != log_uuid:
                if source_alert_id is not None and str(source_alert_id) == str(target_alert_id):
                    log.warning(
                        "UUID laporan %s berbeda dari UUID Alert %s; menggunakan UUID Alert.",
                        log_uuid,
                        alert_source_ref,
                    )
                    log_uuid = alert_source_ref
                else:
                    log.error(
                        "UUID Alert %s (%s) tidak cocok dengan laporan (%s); "
                        "laporan tidak ditulis untuk menghindari salah Alert.",
                        target_alert_id,
                        alert_source_ref,
                        log_uuid,
                    )
                    target_alert_id = None

        if target_alert_id and current_alert:
            current_desc = current_alert.get("alert_description", "")
            if isinstance(current_desc, str):
                updated_desc = upsert_ai_section(current_desc, log_uuid, incident_report)
                current_note = current_alert.get("alert_note") or ""
                if isinstance(current_note, str):
                    updated_note = upsert_ai_section(current_note, log_uuid, incident_report)
                else:
                    updated_note = upsert_ai_section("", log_uuid, incident_report)

                if updated_desc != current_desc or updated_note != current_note:
                    if await iris_client.update_alert_description(
                        target_alert_id, updated_desc, alert_note=updated_note
                    ):
                        saved_alert = await iris_client.get_alert(target_alert_id)
                        saved_note = saved_alert.get("alert_note") if saved_alert else None
                        if isinstance(saved_note, str) and incident_report in saved_note:
                            log.info(
                                "📝 Deskripsi dan Alert Note %s diupdate; laporan utuh tersimpan (%s karakter).",
                                target_alert_id,
                                len(incident_report),
                            )
                        else:
                            saved_note_len = len(saved_note) if isinstance(saved_note, str) else 0
                            log.warning(
                                "⚠️ Verifikasi Alert Note %s gagal: laporan masuk %s karakter, "
                                "Note terbaca %s karakter.",
                                target_alert_id,
                                len(incident_report),
                                saved_note_len,
                            )
                    else:
                        log.warning("⚠️ Gagal mengupdate deskripsi Alert %s.", target_alert_id)
                else:
                    log.info("ℹ️ Laporan sudah ada di Alert %s.", target_alert_id)

    # ==========================================================
    # 2. UPDATE CASE (JIKA SUDAH ADA) - VERSI ROBUST
    # ==========================================================
    target_case_id = None
    try:
        for page in range(1, 11):
            resp_case = await iris_client._client.get(
                "/api/v2/cases",
                params={"per_page": 100, "page": page, "sort": "open_date:desc"},
            )
            resp_case.raise_for_status()
            cases_data = resp_case.json()
            cases = cases_data.get("data", []) if isinstance(cases_data, dict) else cases_data
            if isinstance(cases, dict):
                cases = cases.get("data", [])
            if not isinstance(cases, list):
                log.warning("⚠️ Format daftar Case IRIS tidak dikenali.")
                break

            for case in cases:
                if not isinstance(case, dict):
                    continue
                c_id = case.get("case_id") or case.get("id")
                soc_id = str(case.get("case_soc_id") or case.get("soc_id") or "")
                description = case.get("case_description") or case.get("description") or ""
                has_log_uuid = (
                    isinstance(description, str)
                    and f"log_uuid: {log_uuid}" in description.splitlines()
                )

                if str(log_uuid) == soc_id or has_log_uuid:
                    target_case_id = c_id
                    break

            if target_case_id or len(cases) < 100:
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
                updated_desc = upsert_ai_section(old_desc, log_uuid, incident_report)

                if updated_desc != old_desc:
                    await iris_client._put(
                        f"/api/v2/cases/{target_case_id}",
                        {"case_description": updated_desc},
                    )
                    log.info("📝 Summary Case %s berhasil diupdate dengan analisis AI.", target_case_id)
                else:
                    log.info("ℹ️ Laporan AI sudah ada di Case %s.", target_case_id)
                    
        except Exception as e:
            log.error("❌ Gagal mengupdate Case %s: %s", target_case_id, e)
    else:
        log.warning("⚠️ Case untuk log_uuid %s tidak ditemukan; laporan hanya diproses untuk Alert.", log_uuid)

    # ==========================================================
    # 3. TAMBAHKAN KE NOTES (DENGAN LOGIKA DIRECTORY OTOMATIS)
    # ==========================================================
    if target_case_id:
        try:
            # A. Cek apakah sudah ada directory/folder notes di Case ini
            dirs_resp = await iris_client._get(f"/api/v2/cases/{target_case_id}/notes-directories")
            dirs_data = dirs_resp.get("data", [])
            
            directory_id = None
            
            # Jika sudah ada folder, ambil ID folder pertama
            if isinstance(dirs_data, list) and len(dirs_data) > 0:
                directory_id = dirs_data[0].get("id")
            else:
                # Jika BELUM ADA folder, BUAT folder baru terlebih dahulu!
                log.info("📁 Belum ada folder notes, membuat folder 'Laporan AI'...")
                new_dir = await iris_client._post(
                    f"/api/v2/cases/{target_case_id}/notes-directories", 
                    {"name": "Laporan AI"}
                )
                directory_id = new_dir.get("id")

            # Sekarang buat Notenya
            if directory_id:
                note_payload = {
                    "note_title": f"🤖 Laporan Analisis AI - {log_uuid[:8]}",
                    "note_content": incident_report,
                    "directory_id": int(directory_id)
                }
                
                await iris_client._post(f"/api/v2/cases/{target_case_id}/notes", note_payload)
                log.info("✅ Laporan AI berhasil ditambahkan ke tab NOTES Case %s", target_case_id)
            else:
                log.error("❌ Gagal mendapatkan ID directory untuk Case %s", target_case_id)
                
        except Exception as e:
            log.error("❌ Gagal menambah Note ke Case %s: %s", target_case_id, e)

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
                        if not line.strip():
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
            
            log.info("🔄 Reconnect dalam5 detik...")
            await asyncio.sleep(5)

if __name__ == "__main__":
    try:
        log.info("🚀 Stream Receiver (Inject Mode) dimulai.")
        asyncio.run(run_receiver())
    except KeyboardInterrupt:
        log.info("🛑 Receiver dihentikan.")