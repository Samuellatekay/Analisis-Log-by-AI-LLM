import asyncio
import json
import logging
import os
import re
import httpx

from iris_client import IrisClient, upsert_ai_section

logging.basicConfig(
    level="INFO",
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("stream-receiver")

TARGET_STREAM_URL = os.getenv("TARGET_STREAM_URL", "http://38.47.66.253:17772/stream")


def linked_case_ids(alert: dict) -> list[int]:
    cases = alert.get("cases")
    if not isinstance(cases, list):
        return []

    case_ids = []
    for case in cases:
        if isinstance(case, dict):
            value = case.get("case_id") or case.get("id")
        else:
            value = case
        try:
            case_id = int(value)
        except (TypeError, ValueError):
            continue
        if case_id not in case_ids:
            case_ids.append(case_id)
    return case_ids


def upsert_alert_description(summary: str, alert_id: int, description: str) -> str:
    start = f"<!-- iris-alert-description:{alert_id}:start -->"
    end = f"<!-- iris-alert-description:{alert_id}:end -->"
    block = f"{start}\n{description}\n{end}"
    pattern = re.compile(
        rf"{re.escape(start)}.*?{re.escape(end)}",
        re.DOTALL,
    )
    if pattern.search(summary):
        return pattern.sub(lambda _: block, summary, count=1)
    if description and description in summary:
        return summary.replace(description, block, 1)
    return f"{summary.rstrip()}\n\n{block}" if summary.strip() else block


async def sync_alert_description_to_case(
    iris_client: IrisClient,
    alert_id: int,
    alert: dict | None = None,
) -> int:
    if alert is None:
        alert = await iris_client.get_alert(alert_id)
    if not isinstance(alert, dict):
        return 0

    description = alert.get("alert_description")
    if not isinstance(description, str) or not description.strip():
        log.warning(
            "Description Alert %s kosong atau tidak dikembalikan API (field alert_description).",
            alert_id,
        )
        return 0

    synced = 0
    for case_id in linked_case_ids(alert):
        try:
            case = await iris_client._get(f"/api/v2/cases/{case_id}")
            if not case:
                log.warning("Case %s terkait Alert %s tidak ditemukan.", case_id, alert_id)
                continue

            old_summary = next(
                (
                    case[field]
                    for field in ("case_description", "description", "summary", "case_summary")
                    if isinstance(case.get(field), str) and case[field]
                ),
                "",
            )
            updated_summary = upsert_alert_description(old_summary, alert_id, description)
            if updated_summary == old_summary:
                log.info(
                    "Summary Case %s sudah tersinkron dengan Alert %s (summary=%s, description=%s karakter).",
                    case_id,
                    alert_id,
                    len(old_summary),
                    len(description),
                )
                continue

            summary_fields = ["case_description"]
            summary_fields.extend(
                field for field in ("description", "summary", "case_summary")
                if field in case
            )
            configured_field = getattr(iris_client, "case_summary_field", "")
            if configured_field and configured_field not in summary_fields:
                summary_fields.append(configured_field)

            await iris_client._put(
                f"/api/v2/cases/{case_id}",
                {field: updated_summary for field in summary_fields},
            )
            saved_case = await iris_client._get(f"/api/v2/cases/{case_id}")
            if isinstance(saved_case, dict) and any(
                saved_case.get(field) == updated_summary for field in summary_fields
            ):
                log.info(
                    "Description Alert %s tersinkron ke Summary Case %s.",
                    alert_id,
                    case_id,
                )
                synced += 1
            else:
                log.error(
                    "Description Alert %s belum terverifikasi di Summary Case %s.",
                    alert_id,
                    case_id,
                )
        except Exception as e:
            log.error(
                "Gagal menyinkronkan Description Alert %s ke Case %s: %s",
                alert_id,
                case_id,
                e,
            )
    return synced


async def sync_escalated_alerts(iris_client: IrisClient, interval: int) -> None:
    while True:
        try:
            scanned_alerts = 0
            linked_alerts = 0
            synced_cases = 0
            for page in range(1, 11):
                response = await iris_client._client.get(
                    "/api/v2/alerts",
                    params={
                        "per_page": 100,
                        "page": page,
                        "sort": "alert_source_event_time:desc",
                        "observables": "summary",
                        "fields": "alert_id,alert_description,cases",
                    },
                )
                response.raise_for_status()
                payload = response.json()
                alerts = payload.get("data", []) if isinstance(payload, dict) else payload
                if isinstance(alerts, dict):
                    alerts = alerts.get("data", [])
                if not isinstance(alerts, list):
                    raise ValueError("Format daftar Alert IRIS tidak dikenali.")

                for item in alerts:
                    if not isinstance(item, dict):
                        continue
                    scanned_alerts += 1
                    case_ids = linked_case_ids(item)
                    if not case_ids:
                        continue
                    linked_alerts += 1
                    alert_id = item.get("alert_id") or item.get("id")
                    try:
                        alert_id = int(alert_id)
                    except (TypeError, ValueError):
                        log.warning("ID Alert tidak valid pada daftar IRIS: %r", alert_id)
                        continue
                    synced_cases += await sync_alert_description_to_case(iris_client, alert_id)

                if len(alerts) < 100:
                    break
            log.info(
                "Pemeriksaan eskalasi IRIS selesai: %s Alert dipindai, "
                "%s Alert terkait Case, %s Summary diperbarui.",
                scanned_alerts,
                linked_alerts,
                synced_cases,
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.error("Gagal memeriksa Alert yang sudah dieskalasi: %s", e)
        await asyncio.sleep(interval)


def log_incident_report(reference: str, report: str) -> None:
    """Tampilkan seluruh laporan AI di log tanpa mengubah isi atau line ending."""
    log.info("===== BEGIN LLM REPORT ref=%s chars=%s =====", reference, len(report))
    log.info("%s", report)
    log.info("===== END LLM REPORT ref=%s =====", reference)


async def inject_incident_report(iris_client: IrisClient, raw_data: dict) -> bool:
    log_uuid = str(raw_data.get("log_uuid") or raw_data.get("id", "")).strip()
    source_alert_id = raw_data.get("alert_id")
    if source_alert_id is None and log_uuid.isdecimal():
        source_alert_id = log_uuid
    try:
        source_alert_id = int(source_alert_id) if source_alert_id is not None else None
    except (TypeError, ValueError):
        log.warning("ID Alert tidak valid: %r.", source_alert_id)
        source_alert_id = None
    incident_report = raw_data.get("incident_report")
    
    if not isinstance(incident_report, str) or not incident_report.strip():
        log.debug("ℹ️ Tidak ada incident_report. Melewati.")
        return False
    if not log_uuid and source_alert_id is None:
        log.warning("⚠️ Ada incident_report tapi tidak ada UUID atau ID Alert. Melewati.")
        return False

    log.info(
        "incident_report diterima untuk reference=%s alert_id=%s: %s karakter.",
        log_uuid or "(none)",
        source_alert_id if source_alert_id is not None else "(none)",
        len(incident_report),
    )
    log_incident_report(log_uuid, incident_report)
    log.info(
        "🔍 Mencari Alert untuk reference %s%s...",
        log_uuid,
        f" dan ID {source_alert_id}" if source_alert_id is not None else "",
    )
    
    # ==========================================================
    # 1. UPDATE ALERT
    # ==========================================================
    target_alert_id = source_alert_id
    current_alert = None
    if target_alert_id is not None:
        current_alert = await iris_client.get_alert(target_alert_id)
        if not current_alert:
            log.warning("Alert ID %s tidak ditemukan saat mengambil detail.", target_alert_id)
            target_alert_id = None

    if target_alert_id is None and log_uuid and not log_uuid.isdecimal():
        try:
            resp = await iris_client._client.get(
                "/api/v2/alerts",
                params={"per_page": 50, "page": 1, "sort": "alert_source_event_time:desc"},
            )
            resp.raise_for_status()
            resp_json = resp.json()
            alerts = resp_json.get("data", []) if isinstance(resp_json, dict) else resp_json

            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                alert_id = alert.get("id") or alert.get("alert_id")
                if alert_id is None and isinstance(alert.get("data"), dict):
                    alert_id = alert["data"].get("id") or alert["data"].get("alert_id")

                source_ref = str(alert.get("alert_source_ref", ""))
                description = str(alert.get("alert_description", ""))
                if log_uuid == source_ref or log_uuid in description:
                    target_alert_id = int(alert_id) if alert_id is not None else None
                    break
        except Exception as e:
            log.error("❌ Gagal mencari alert: %s", e)

        if target_alert_id is not None:
            current_alert = await iris_client.get_alert(target_alert_id)

    if target_alert_id and current_alert:
        log.info("✅ Alert DITEMUKAN! ID: %s", target_alert_id)
        alert_source_ref = str(current_alert.get("alert_source_ref") or "").strip()
        if alert_source_ref and alert_source_ref != log_uuid:
            if source_alert_id == target_alert_id:
                log.info(
                    "ID Alert %s terverifikasi; menggunakan UUID kanonis %s (UUID payload: %s).",
                    target_alert_id,
                    alert_source_ref,
                    log_uuid or "(tidak dikirim)",
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
                        if isinstance(saved_alert, dict):
                            current_alert = saved_alert
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

    if target_alert_id and current_alert:
        refreshed_alert = await iris_client.get_alert(target_alert_id)
        if refreshed_alert:
            current_alert = refreshed_alert
    related_case_ids = (
        linked_case_ids(current_alert)
        if target_alert_id and current_alert
        else []
    )

    # ==========================================================
    # 2. UPDATE CASE (JIKA SUDAH ADA) - VERSI ROBUST
    # ==========================================================
    target_case_id = related_case_ids[0] if related_case_ids else None
    try:
        if target_case_id is None:
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
                alert_description = current_alert.get("alert_description") if current_alert else None
                if target_alert_id and isinstance(alert_description, str):
                    updated_desc = upsert_alert_description(
                        updated_desc,
                        target_alert_id,
                        alert_description,
                    )

                if updated_desc != old_desc:
                    summary_fields = ["case_description"]
                    summary_fields.extend(
                        field for field in ("description", "summary", "case_summary")
                        if field in current_case
                    )
                    configured_field = getattr(iris_client, "case_summary_field", "")
                    if configured_field and configured_field not in summary_fields:
                        summary_fields.append(configured_field)

                    update_payload = {field: updated_desc for field in summary_fields}
                    await iris_client._put(
                        f"/api/v2/cases/{target_case_id}",
                        update_payload,
                    )
                    saved_case = await iris_client._get(f"/api/v2/cases/{target_case_id}")
                    saved_values = {
                        field: saved_case.get(field)
                        for field in summary_fields
                        if isinstance(saved_case.get(field), str)
                    }
                    if any(value == updated_desc for value in saved_values.values()):
                        log.info(
                            "📝 Summary Case %s terverifikasi tersimpan di field %s.",
                            target_case_id,
                            [field for field, value in saved_values.items() if value == updated_desc],
                        )
                    else:
                        log.error(
                            "❌ PUT Case %s mendapat respons tetapi Summary tidak terverifikasi. "
                            "Field dikirim=%s; panjang yang terbaca=%s.",
                            target_case_id,
                            summary_fields,
                            {field: len(value) for field, value in saved_values.items()},
                        )
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
        "IRIS_CASE_SUMMARY_FIELD": os.getenv("IRIS_CASE_SUMMARY_FIELD", ""),
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
    try:
        sync_interval = max(5, int(os.getenv("IRIS_CASE_SUMMARY_SYNC_INTERVAL_S", "30")))
    except ValueError:
        log.error("IRIS_CASE_SUMMARY_SYNC_INTERVAL_S harus berupa bilangan bulat.")
        return
    log.info(
        "Sinkronisasi Alert–Case native IRIS aktif (interval %s detik).",
        sync_interval,
    )
    sync_task = asyncio.create_task(sync_escalated_alerts(iris_client, sync_interval))
    
    async with httpx.AsyncClient(timeout=None) as client:
        try:
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

                log.info("🔄 Reconnect dalam 5 detik...")
                await asyncio.sleep(5)
        finally:
            sync_task.cancel()
            try:
                await sync_task
            except asyncio.CancelledError:
                pass

if __name__ == "__main__":
    try:
        log.info("🚀 Stream Receiver (Inject Mode) dimulai.")
        asyncio.run(run_receiver())
    except KeyboardInterrupt:
        log.info("🛑 Receiver dihentikan.")