import asyncio
import json
import logging
import os
import httpx

# ============================================================
# CONFIGURATION
# ============================================================

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("IRIS_STREAM_PORT", "17771"))

BASE_IRIS_URL = os.getenv("IRIS_URL", "https://iris.example.local").rstrip("/")
IRIS_LIST_ENDPOINT = f"{BASE_IRIS_URL}/api/v2/alerts"
IRIS_API_KEY = os.getenv("IRIS_API_KEY", "")

POLL_INTERVAL = float(os.getenv("IRIS_POLL_INTERVAL", "5.0"))
REQUEST_TIMEOUT = float(os.getenv("IRIS_REQUEST_TIMEOUT", "10.0"))
MUX_TIMEOUT = float(os.getenv("MUX_TIMEOUT", "1.0"))

clients = set()
seen_alerts = set()
MAX_SEEN_ALERTS = 100000

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("iris-stream")

if not IRIS_API_KEY:
    log.warning("[!] PERINGATAN: IRIS_API_KEY kosong.")


# ============================================================
# IRIS API REQUESTS
# ============================================================

async def fetch_alert_list():
    """Mengambil daftar alert (ringan) untuk mendeteksi ID baru."""
    headers = {"Authorization": f"Bearer {IRIS_API_KEY}", "Accept": "application/json"}
    async with httpx.AsyncClient(verify=False, timeout=REQUEST_TIMEOUT) as client:
        try:
            response = await client.get(IRIS_LIST_ENDPOINT, headers=headers, params={"per_page": 10, "page": 1})
            response.raise_for_status()
            data = response.json()
            if isinstance(data, list): return data
            if isinstance(data, dict) and "data" in data: return data["data"]
            return []
        except Exception as e:
            log.error("Gagal fetch list: %s", e)
            return []

async def fetch_alert_detail(alert_id):
    """Mengambil detail lengkap 1 alert untuk mendapatkan 'original' dan '@timestamp'."""
    url = f"{BASE_IRIS_URL}/api/v2/alerts/{alert_id}"
    headers = {"Authorization": f"Bearer {IRIS_API_KEY}", "Accept": "application/json"}
    async with httpx.AsyncClient(verify=False, timeout=REQUEST_TIMEOUT) as client:
        try:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            log.error("Gagal fetch detail alert %s: %s", alert_id, e)
            return None


# ============================================================
# PAYLOAD BUILDER (DIPAKAI DI SEMUA TEMPAT)
# ============================================================

def build_minimal_payload(detail_data):
    """Membangun payload HANYA dengan 3 field dari data DETAIL yang lengkap."""
    if not detail_data or not isinstance(detail_data, dict):
        return {"alert_description": "Gagal mengambil detail"}

    payload = {
        "alert_description": detail_data.get("alert_description", "")
    }
    
    # 1. Ambil 'original' (bisa string di root, atau string di dalam dict 'original')
    if "original" in detail_data:
        if isinstance(detail_data["original"], str):
            payload["original"] = detail_data["original"]
        elif isinstance(detail_data["original"], dict) and "original" in detail_data["original"]:
            payload["original"] = detail_data["original"]["original"]
            
    # 2. Ambil '@timestamp'
    ts = detail_data.get("@timestamp")
    if not ts and isinstance(detail_data.get("original"), dict):
        ts = detail_data["original"].get("@timestamp")
    if ts:
        payload["@timestamp"] = ts
        
    return payload


# ============================================================
# STREAMING & HTTP
# ============================================================

async def send_to_client(writer, payload):
    writer.write((json.dumps(payload, ensure_ascii=False, default=str) + "\n").encode("utf-8"))
    await writer.drain()

async def broadcast_alert(payload):
    disconnected = []
    for writer in list(clients):
        try:
            await send_to_client(writer, payload)
        except (ConnectionError, OSError, BrokenPipeError):
            disconnected.append(writer)
    for writer in disconnected:
        clients.discard(writer)
        writer.close()


async def handle_client(reader, writer):
    peer = writer.get_extra_info('peername')
    try:
        try:
            first_data = await asyncio.wait_for(reader.read(1024), timeout=MUX_TIMEOUT)
        except asyncio.TimeoutError:
            first_data = b""

        # ========================================================
        # 1. HTTP REQUEST (CURL / BROWSER) - DIPERBAIKI TOTAL
        # ========================================================
        if first_data.startswith((b"GET ", b"HEAD ")):
            log.info("HTTP request dari %s", peer)
            
            # Ambil daftar alert dulu
            alerts_list = await fetch_alert_list()
            formatted_alerts = []
            
            # PERBAIKAN: Loop untuk mengambil DETAIL LENGKAP setiap alert
            # agar field 'original' dan '@timestamp' pasti muncul di HTTP
            for alert_summary in alerts_list:
                alert_id = alert_summary.get("id") or alert_summary.get("alert_id")
                if alert_id:
                    detail_data = await fetch_alert_detail(alert_id)
                    if detail_data:
                        formatted_alerts.append(build_minimal_payload(detail_data))
                    else:
                        # Fallback jika detail gagal diambil
                        formatted_alerts.append({"alert_description": alert_summary.get("alert_description", "")})

            body = json.dumps(formatted_alerts, ensure_ascii=False, indent=2, default=str).encode("utf-8")
            
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "\r\n"
            ).encode("utf-8") + body
            
            writer.write(response)
            await writer.drain()
            writer.close()
            return

        # ========================================================
        # 2. TCP STREAMING CLIENT
        # ========================================================
        log.info("TCP client terhubung: %s", peer)
        clients.add(writer)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: keep-alive\r\n\r\n")
        await writer.drain()
        
        try:
            while True:
                await asyncio.wait_for(reader.read(4096), timeout=30.0)
        except asyncio.TimeoutError:
            pass
    except Exception as e:
        log.error("Error klien %s: %s", peer, e)
    finally:
        clients.discard(writer)
        writer.close()


# ============================================================
# IRIS POLLING MONITOR
# ============================================================

async def iris_monitor():
    log.info("Polling aktif (Mode: Fetch Detail untuk alert baru)...")
    while True:
        try:
            alerts_list = await fetch_alert_list()

            for alert_summary in alerts_list:
                alert_id = alert_summary.get("id") or alert_summary.get("alert_id")
                if not alert_id:
                    continue
                    
                dedup_key = str(alert_id)
                if dedup_key in seen_alerts:
                    continue
                
                # ALERT BARU DITEMUKAN!
                seen_alerts.add(dedup_key)
                log.info("🔍 Alert baru terdeteksi (ID: %s). Mengambil detail lengkap...", alert_id)
                
                detail_data = await fetch_alert_detail(alert_id)
                
                if detail_data:
                    payload = build_minimal_payload(detail_data)
                    log.info("✅ Berhasil mengirim alert %s. Field: %s", alert_id, list(payload.keys()))
                    await broadcast_alert(payload)
                else:
                    log.warning("⚠️ Gagal mengambil detail untuk alert %s", alert_id)

            if len(seen_alerts) > MAX_SEEN_ALERTS:
                log.warning("Batas seen_alerts tercapai. Reset memori...")
                seen_alerts.clear()

        except Exception as e:
            log.exception("Error polling: %s", e)

        await asyncio.sleep(POLL_INTERVAL)


# ============================================================
# MAIN
# ============================================================

async def main():
    server = await asyncio.start_server(handle_client, host=HOST, port=PORT)
    log.info("🚀 Server aktif di %s:%s", HOST, PORT)
    
    monitor_task = asyncio.create_task(iris_monitor())

    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        log.info("Menerima sinyal pembatalan...")
    finally:
        monitor_task.cancel()
        for writer in list(clients):
            writer.close()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Server dihentikan.")