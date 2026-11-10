"""
stream_receiver.py - Menerima stream incident_report (analisis LLM) dan memasukkannya ke DFIR-IRIS.

Tujuan:
  - Deskripsi alert : section "## Analisis AI (LLM) - <id>" di akhir deskripsi
  - Summary case    : section yang sama di case_description (maks 6000 karakter)
  - Notes case      : note lengkap di folder "Laporan AI"

Case dicari lewat alert (alert -> case yang terhubung), bukan lewat teks, jadi tetap ketemu
walaupun beberapa alert digabung ke satu case. Section diganti per log_uuid (tidak dobel), dan
iris_client.py mempertahankannya saat deskripsi alert/case ditulis ulang oleh aplikasi utama.
"""
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
CASE_RETRIES = int(os.getenv("RECEIVER_CASE_RETRIES", "3"))       # coba cari case N kali
CASE_RETRY_DELAY = float(os.getenv("RECEIVER_CASE_RETRY_DELAY", "5"))
NOTES_DIRECTORY = os.getenv("RECEIVER_NOTES_DIRECTORY", "Laporan AI")

_notes_done: set[tuple[int, str]] = set()   # (case_id, log_uuid) yang sudah dibuatkan note


def _report_text(value) -> str:
    if isinstance(value, str):
        return value.strip()
    return "```json\n" + json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n```"


# ------------------------------------------------------------------ pencarian
async def find_alert_id(iris: IrisClient, log_uuid: str):
    try:
        resp = await iris._client.get("/api/v2/alerts", params={
            "per_page": 100, "page": 1, "sort": "alert_source_event_time:desc"})
        resp.raise_for_status()
        body = resp.json()
        alerts = body.get("data", []) if isinstance(body, dict) else body
    except Exception as e:
        log.error("❌ Gagal mencari alert: %s", e)
        return None
    for alert in alerts if isinstance(alerts, list) else []:
        if not isinstance(alert, dict):
            continue
        if log_uuid == str(alert.get("alert_source_ref", "")) or log_uuid in str(alert.get("alert_description", "")):
            return alert.get("id") or alert.get("alert_id")
    return None


def case_ids_from_alert(alert: dict) -> list[int]:
    ids: list[int] = []
    for c in (alert or {}).get("cases") or []:
        cid = c if isinstance(c, int) else (c.get("case_id") or c.get("id")) if isinstance(c, dict) else None
        if isinstance(cid, int) and cid not in ids:
            ids.append(cid)
    return ids


async def find_cases_by_search(iris: IrisClient, log_uuid: str) -> list[int]:
    """Cadangan: cari case yang soc_id/nama/deskripsinya memuat log_uuid."""
    try:
        resp = await iris._client.get("/api/v2/cases", params={"per_page": 100, "page": 1, "sort": "open_date:desc"})
        resp.raise_for_status()
        body = resp.json()
        cases = body.get("data", []) if isinstance(body, dict) else body
    except Exception as e:
        log.error("❌ Gagal mencari case: %s", e)
        return []
    found = []
    for case in cases if isinstance(cases, list) else []:
        if not isinstance(case, dict):
            continue
        blob = " ".join(str(case.get(k) or "") for k in ("case_soc_id", "soc_id", "case_name", "case_description"))
        cid = case.get("case_id") or case.get("id")
        if log_uuid in blob and isinstance(cid, int):
            found.append(cid)
    return found


# ------------------------------------------------------------------ penulisan
async def update_alert_report(iris: IrisClient, alert_id, log_uuid: str, report: str) -> None:
    current = await iris.get_alert(alert_id)
    desc = (current or {}).get("alert_description")
    if not isinstance(desc, str):
        log.warning("⚠️ Deskripsi alert %s tidak terbaca; dilewati.", alert_id)
        return
    new = upsert_ai_section(desc, log_uuid, report)
    if new.strip() == desc.strip():
        log.info("ℹ️ Analisis AI sudah ada di Alert %s.", alert_id)
        return
    if await iris.update_alert_description(alert_id, new):
        log.info("📝 Deskripsi Alert %s diperbarui dengan Analisis AI.", alert_id)


async def update_case_summary(iris: IrisClient, case_id: int, log_uuid: str, report: str) -> bool:
    try:
        current = await iris._get(f"/api/v2/cases/{case_id}")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            log.warning("⚠️ Case %s tidak ada di IRIS (404). Dilewati.", case_id)
        else:
            log.error("❌ Gagal membaca Case %s: HTTP %s", case_id, e.response.status_code)
        return False
    desc = current.get("case_description") or current.get("description") or ""
    new = upsert_ai_section(desc, log_uuid, report)
    if new.strip() == desc.strip():
        log.info("ℹ️ Analisis AI sudah ada di Summary Case %s.", case_id)
        return True
    # Sama seperti UI IRIS saat menyimpan Summary: hanya case_description (tag/atribut tidak disentuh).
    await iris._put(f"/api/v2/cases/{case_id}", {"case_description": new[:16000]})
    log.info("📝 Summary Case %s diperbarui dengan Analisis AI.", case_id)
    return True


async def _notes_directory_id(iris: IrisClient, case_id: int):
    path = f"/api/v2/cases/{case_id}/notes-directories"
    resp = await iris._get(path, {"per_page": 100, "page": 1})
    dirs = resp.get("data")
    if isinstance(dirs, dict):
        dirs = dirs.get("data")
    dirs = [d for d in dirs if isinstance(d, dict) and isinstance(d.get("id"), int)] if isinstance(dirs, list) else []
    wanted = next((d for d in dirs if str(d.get("name", "")).strip().lower() == NOTES_DIRECTORY.lower()), None)
    if wanted:
        return wanted["id"]
    try:
        created = await iris._post(path, {"name": NOTES_DIRECTORY})
        if isinstance(created.get("id"), int):
            log.info("📁 Folder '%s' dibuat di Notes Case %s.", NOTES_DIRECTORY, case_id)
            return created["id"]
    except Exception as e:
        log.warning("⚠️ Gagal membuat folder Notes (%s); memakai folder yang ada.", e)
    root = next((d for d in dirs if d.get("parent_id") is None), dirs[0] if dirs else None)
    return root["id"] if root else None


async def add_case_note(iris: IrisClient, case_id: int, log_uuid: str, report: str) -> bool:
    if (case_id, log_uuid) in _notes_done:
        log.info("ℹ️ Note Analisis AI untuk Case %s sudah dibuat.", case_id)
        return True
    directory_id = await _notes_directory_id(iris, case_id)
    if directory_id is None:
        log.error("❌ Tidak ada folder Notes yang bisa dipakai di Case %s.", case_id)
        return False
        
    # PERBAIKAN: Ganti "note_content" menjadi "note_text"
    await iris._post(f"/api/v2/cases/{case_id}/notes", {
        "note_title": f"Analisis AI - {log_uuid[:8]}"[:154],
        "note_text": report,  # <-- Diubah di sini
        "directory_id": int(directory_id),
    })
    
    _notes_done.add((case_id, log_uuid))
    log.info("✅ Analisis AI ditambahkan ke tab NOTES Case %s.", case_id)
    return True



# ------------------------------------------------------------------ alur utama
async def inject_incident_report(iris: IrisClient, raw_data: dict) -> bool:
    log_uuid = str(raw_data.get("log_uuid") or raw_data.get("id", "")).strip()
    incident_report = raw_data.get("incident_report")
    if not incident_report:
        log.debug("ℹ️ Tidak ada incident_report. Melewati.")
        return False
    if not log_uuid:
        log.warning("⚠️ Ada incident_report tapi tidak ada UUID. Melewati.")
        return False
    report = _report_text(incident_report)

    log.info("🔍 Mencari Alert dan Case dengan UUID: %s...", log_uuid)
    alert_id = await find_alert_id(iris, log_uuid)
    if alert_id:
        log.info("✅ Alert ditemukan. ID: %s", alert_id)
        try:
            await update_alert_report(iris, alert_id, log_uuid, report)
        except Exception as e:
            log.error("❌ Gagal mengupdate Alert %s: %s", alert_id, e)
    else:
        log.info("ℹ️ Alert untuk UUID ini tidak ditemukan di 100 alert terbaru.")

    # Case: lewat alert (paling andal), cadangan pencarian teks. Dicoba beberapa kali karena
    # case dibuat sesaat setelah alert.
    case_ids: list[int] = []
    for attempt in range(1, CASE_RETRIES + 1):
        if alert_id:
            alert = await iris.get_alert(alert_id)
            case_ids = case_ids_from_alert(alert or {})
        if not case_ids:
            case_ids = await find_cases_by_search(iris, log_uuid)
        if case_ids:
            break
        if attempt < CASE_RETRIES:
            log.info("⏳ Case belum ada (percobaan %s/%s), tunggu %.0f dtk...", attempt, CASE_RETRIES, CASE_RETRY_DELAY)
            await asyncio.sleep(CASE_RETRY_DELAY)
    if not case_ids:
        log.info("ℹ️ Alert ini belum menjadi/digabung ke case. Analisis AI hanya masuk ke alert.")
        return True

    for case_id in case_ids:
        log.info("🔄 Memproses Case ID: %s...", case_id)
        try:
            await update_case_summary(iris, case_id, log_uuid, report)
        except Exception as e:
            log.error("❌ Gagal mengupdate Summary Case %s: %s", case_id, e)
        try:
            await add_case_note(iris, case_id, log_uuid, report)
        except Exception as e:
            log.error("❌ Gagal menambah Note di Case %s: %s", case_id, e)
    return True


async def run_receiver():
    log.info("🎧 Receiver aktif (Mode: Inject Analisis AI ke Alert, Summary & Notes Case).")

    env = {
        "IRIS_ENABLED": "true",
        "IRIS_URL": os.getenv("IRIS_URL", "https://192.168.51.40"),
        "IRIS_API_KEY": os.getenv("IRIS_API_KEY", ""),
        "IRIS_CA_CERT": os.getenv("IRIS_CA_CERT", ""),
        "IRIS_VERIFY_SSL": os.getenv("IRIS_VERIFY_SSL", "false"),
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
                        log.info("📩 TERIMA DATA DARI STREAM: %s...", line[:100])
                        try:
                            raw_data = json.loads(line)
                            if not raw_data.get("incident_report"):
                                log.warning("⚠️ Data diterima, tapi TIDAK ADA 'incident_report'. Melewati.")
                                continue
                            await inject_incident_report(iris_client, raw_data)
                        except json.JSONDecodeError as e:
                            log.error("❌ Data BUKAN JSON valid: %s | Error: %s", line[:100], e)
                        except Exception as e:
                            log.error("❌ Error fatal saat memproses data: %s", e, exc_info=True)

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