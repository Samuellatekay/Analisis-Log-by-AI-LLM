import asyncio
import json
import logging
import os
import httpx

# ============================================================
# CONFIGURATION (Disesuaikan dengan docker-compose.yml)
# ============================================================

# Mendukung IRIS_STREAM_BIND (dari compose) atau fallback ke HOST / 0.0.0.0
HOST = os.getenv("IRIS_STREAM_BIND", os.getenv("HOST", "0.0.0.0"))
PORT = int(os.getenv("IRIS_STREAM_HTTP_PORT", os.getenv("IRIS_STREAM_PORT", "17771")))

BASE_IRIS_URL = os.getenv("IRIS_URL", "https://iris.local").rstrip("/")
IRIS_LIST_ENDPOINT = f"{BASE_IRIS_URL}/api/v2/alerts"
IRIS_API_KEY = os.getenv("IRIS_API_KEY", "")
IRIS_CA_CERT = os.getenv("IRIS_CA_CERT", "/app/iris-ca.crt")

POLL_INTERVAL = float(os.getenv("IRIS_POLL_INTERVAL", "5.0"))
REQUEST_TIMEOUT = float(os.getenv("IRIS_REQUEST_TIMEOUT", "10.0"))
MUX_TIMEOUT = float(os.getenv("MUX_TIMEOUT", "1.0"))

clients = set()
seen_alerts = set()
MAX_SEEN_ALERTS = 100000

logging.basicConfig(
    level="DEBUG", # Aktifkan DEBUG penuh untuk forensik
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
    headers = {"Authorization": f"Bearer {IRIS_API_KEY}", "Accept": "application/json"}
    # Gunakan verify=IRIS_CA_CERT jika file ada, else False
    ssl_verify = IRIS_CA_CERT if os.path.exists(IRIS_CA_CERT) else False
    
    async with httpx.AsyncClient(verify=ssl_verify, timeout=REQUEST_TIMEOUT) as client:
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
    url = f"{BASE_IRIS_URL}/api/v2/alerts/{alert_id}"
    headers = {"Authorization": f"Bearer {IRIS_API_KEY}", "Accept": "application/json"}
    ssl_verify = IRIS_CA_CERT if os.path.exists(IRIS_CA_CERT) else False
    
    async with httpx.AsyncClient(verify=ssl_verify, timeout=REQUEST_TIMEOUT) as client:
        try:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            log.error("Gagal fetch detail alert %s: %s", alert_id, e)
            return None


# ============================================================
# PAYLOAD BUILDER (FORENSIK TINGKAT TINGGI)
# ============================================================

def build_minimal_payload(detail_data):
    if not detail_data or not isinstance(detail_data, dict):
        return {"alert_description": "Gagal mengambil detail"}

    payload = {
        "alert_description": detail_data.get("alert_description", "")
    }
    
    # --- FORENSIK: Lihat struktur data sebenarnya ---
    log.debug("=== FORENSIK ALERT ID: %s ===", detail_data.get("id"))
    log.debug("Top-level keys: %s", list(detail_data.keys()))

    # 1. Ekstrak 'original'
    raw_original = None
    if "original" in detail_data:
        orig = detail_data["original"]
        log.debug("Key 'original' ditemukan. Tipe data: %s", type(orig))
        
        if isinstance(orig, str):
            raw_original = orig
            log.debug("✅ 'original' adalah string langsung.")
        elif isinstance(orig, dict):
            log.debug("Keys di dalam dict 'original': %s", list(orig.keys()))
            # Cari string yang merupakan log Wazuh
            for k, v in orig.items():
                if isinstance(v, str) and ("rule" in v or "full_log" in v):
                    raw_original = v
                    log.debug("✅ Ditemukan string Wazuh di dalam key: '%s'", k)
                    break
            
            # Fallback: jika ada key 'original' di dalam dict 'original'
            if not raw_original and "original" in orig:
                raw_original = orig["original"]
                log.debug("✅ Ditemukan di orig['original']")

    # Fallback: cek alert_source_content
    if not raw_original and "alert_source_content" in detail_data:
        asc = detail_data["alert_source_content"]
        if isinstance(asc, str) and "rule" in asc:
            raw_original = asc
        elif isinstance(asc, dict) and "original" in asc:
            raw_original = asc["original"]

    if raw_original:
        payload["original"] = raw_original
    else:
        log.warning("⚠️ GAGAL MENEMUKAN DATA 'original' WAZUH DI MANAPUN!")

    # 2. Ekstrak '@timestamp'
    ts = detail_data.get("@timestamp")
    if not ts and isinstance(detail_data.get("original"), dict):
        ts = detail_data["original"].get("@timestamp")
    
    if ts:
        payload["@timestamp"] = ts
        log.debug("✅ Ditemukan '@timestamp': %s", ts)
    else:
        log.debug("⚠️ '@timestamp' tidak ditemukan.")

    log.info("✅ Field yang berhasil dibuat: %s", list(payload.keys()))
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
            first_data = await asyncio.wait_for(reader.read1(1024), timeout=MUX_TIMEOUT) # read1 lebih aman untuk HTTP
        except asyncio.TimeoutError:
            first_data = b""
        except Exception:
            first_data = b""

        first_line = first_data.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore") if first_data else ""

        # --- ENDPOINT HEALTHCHECK (PENTING UNTUK DOCKER COMPOSE) ---
        if first_line.startswith("GET /health") or first_line.startswith("HEAD /health"):
            response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
            writer.write(response)
            await writer.drain()
            writer.close()
            return

        # --- HTTP REQUEST BIASA ---
        if first_line.startswith(("GET ", "HEAD ")):
            log.info("HTTP request dari %s", peer)
            alerts_list = await fetch_alert_list()
            formatted_alerts = []
            
            for alert_summary in alerts_list:
                alert_id = alert_summary.get("id") or alert_summary.get("alert_id")
                if alert_id:
                    detail_data = await fetch_alert_detail(alert_id)
                    if detail_data:
                        formatted_alerts.append(build_minimal_payload(detail_data))
                    else:
                        formatted_alerts.append({"alert_description": alert_summary.get("alert_description", "")})

            body = json.dumps(formatted_alerts, ensure_ascii=False, indent=2, default=str).encode("utf-8")
            
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n".encode() +
                b"Connection: close\r\n"
                b"Access-Control-Allow-Origin: *\r\n"
                b"\r\n" + body
            )
            
            writer.write(response)
            await writer.drain()
            writer.close()
            return

        # --- TCP STREAMING ---
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
    log.info("Polling aktif di %s:%s...", HOST, PORT)
    while True:
        try:
            alerts_list = await fetch_alert_list()

            for alert_summary in alerts_list:
                alert_id = alert_summary.get("id") or alert_summary.get("alert_id")
                if not alert_id: continue
                    
                dedup_key = str(alert_id)
                if dedup_key in seen_alerts: continue
                
                seen_alerts.add(dedup_key)
                log.info("🔍 Alert baru (ID: %s). Mengambil detail...", alert_id)
                
                detail_data = await fetch_alert_detail(alert_id)
                
                if detail_data:
                    payload = build_minimal_payload(detail_data)
                    await broadcast_alert(payload)
                else:
                    log.warning("⚠️ Gagal mengambil detail untuk alert %s", alert_id)

            if len(seen_alerts) > MAX_SEEN_ALERTS:
                seen_alerts.clear()

        except Exception as e:
            log.exception("Error polling: %s", e)

        await asyncio.sleep(POLL_INTERVAL)


# ============================================================
# MAIN
# ============================================================

async def main():
    try:
        server = await asyncio.start_server(handle_client, host=HOST, port=PORT)
        log.info("🚀 Server aktif dan mendengarkan di %s:%s", HOST, PORT)
        
        monitor_task = asyncio.create_task(iris_monitor())

        async with server:
            await server.serve_forever()
    except Exception as e:
        log.critical("GAGAL MEMULAI SERVER: %s", e)

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Server dihentikan.")