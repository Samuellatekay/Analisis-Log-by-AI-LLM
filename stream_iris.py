import asyncio
import json
import logging
import os
import httpx

# ============================================================
# CONFIGURATION
# ============================================================

HOST = "0.0.0.0"
PORT = int(os.getenv("IRIS_STREAM_HTTP_PORT", os.getenv("IRIS_STREAM_PORT", "17771")))

BASE_IRIS_URL = os.getenv("IRIS_URL", "https://iris.local").rstrip("/")
IRIS_LIST_ENDPOINT = f"{BASE_IRIS_URL}/api/v2/alerts"
IRIS_API_KEY = os.getenv("IRIS_API_KEY", "")
IRIS_CA_CERT = os.getenv("IRIS_CA_CERT", "/app/iris-ca.crt")

EXTERNAL_IP = os.getenv("EXTERNAL_IP", "38.47.67.117")
EXTERNAL_SEND_PATH = os.getenv("EXTERNAL_SEND_PATH", "/api/receive")
EXTERNAL_RECV_PATH = os.getenv("EXTERNAL_RECV_PATH", "/api/receive")
EXTERNAL_API_KEY = os.getenv("EXTERNAL_API_KEY", "")
EXTERNAL_VERIFY_SSL = os.getenv("EXTERNAL_VERIFY_SSL", "false").lower() == "true"

WEBHOOK_URL = os.getenv("WEBHOOK_URL", "").strip()
POLL_INTERVAL = float(os.getenv("IRIS_POLL_INTERVAL", "5.0"))
REQUEST_TIMEOUT = float(os.getenv("IRIS_REQUEST_TIMEOUT", "10.0"))
EXTERNAL_POLL_INTERVAL = float(os.getenv("EXTERNAL_POLL_INTERVAL", "10.0"))

clients = set()
sse_clients = set()
seen_alerts = set()
MAX_SEEN_ALERTS = 100000

logging.basicConfig(
    level="INFO", 
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
            log.error("Gagal fetch list IRIS: %s", e)
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
# EXTERNAL API FUNCTIONS
# ============================================================

async def send_to_external_server(payload: dict):
    if not EXTERNAL_API_KEY: return False
    url = f"https://{EXTERNAL_IP}{EXTERNAL_SEND_PATH}"
    headers = {"Authorization": f"Bearer {EXTERNAL_API_KEY}", "Content-Type": "application/json"}
    async with httpx.AsyncClient(verify=EXTERNAL_VERIFY_SSL, timeout=REQUEST_TIMEOUT) as client:
        try:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            log.info("✅ Data dikirim ke %s (Status: %s)", EXTERNAL_IP, response.status_code)
            return True
        except Exception as e:
            log.error("❌ Gagal kirim ke %s: %s", EXTERNAL_IP, e)
            return False

async def receive_from_external_server() -> list:
    if not EXTERNAL_API_KEY: return []
    url = f"https://{EXTERNAL_IP}{EXTERNAL_RECV_PATH}"
    headers = {"Authorization": f"Bearer {EXTERNAL_API_KEY}", "Accept": "application/json"}
    async with httpx.AsyncClient(verify=EXTERNAL_VERIFY_SSL, timeout=REQUEST_TIMEOUT) as client:
        try:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data if isinstance(data, list) else [data]
        except Exception as e:
            log.error("❌ Gagal ambil data dari %s: %s", EXTERNAL_IP, e)
            return []


# ============================================================
# PAYLOAD BUILDER
# ============================================================

def build_minimal_payload(detail_data):
    if isinstance(detail_data, dict) and "data" in detail_data:
        detail_data = detail_data["data"]
    if not detail_data or not isinstance(detail_data, dict):
        return {"alert_description": "Gagal mengambil detail"}

    payload = {"alert_description": detail_data.get("alert_description", "")}
    raw_original = None
    if "original" in detail_data:
        if isinstance(detail_data["original"], str): raw_original = detail_data["original"]
        elif isinstance(detail_data["original"], dict) and "original" in detail_data["original"]:
            raw_original = detail_data["original"]["original"]
    if not raw_original and "alert_source_content" in detail_data:
        asc = detail_data["alert_source_content"]
        if isinstance(asc, str): raw_original = asc
        elif isinstance(asc, dict) and "original" in asc: raw_original = asc["original"]

    if raw_original: payload["original"] = raw_original

    ts = detail_data.get("@timestamp")
    if not ts and isinstance(detail_data.get("original"), dict): ts = detail_data["original"].get("@timestamp")
    if not ts and isinstance(detail_data.get("alert_source_content"), dict): ts = detail_data["alert_source_content"].get("@timestamp")
    if ts: payload["@timestamp"] = ts
    return payload


# ============================================================
# STREAMING & HTTP HANDLER
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
        clients.discard(writer); writer.close()
    
    disconnected_sse = []
    for writer in list(sse_clients):
        try:
            sse_data = f"data: {json.dumps(payload, ensure_ascii=False, default=str)}\n\n"
            writer.write(sse_data.encode("utf-8"))
            await writer.drain()
        except (ConnectionError, OSError, BrokenPipeError):
            disconnected_sse.append(writer)
    for writer in disconnected_sse:
        sse_clients.discard(writer); writer.close()

    if WEBHOOK_URL:
        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
                await client.post(WEBHOOK_URL, json=payload)
        except Exception as e:
            log.error("❌ Gagal webhook lokal: %s", e)

async def handle_client(reader, writer):
    peer = writer.get_extra_info('peername')
    try:
        try:
            first_data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
        except asyncio.TimeoutError:
            first_data = b""
        except Exception:
            first_data = b""

        # Jika tidak ada data, anggap TCP streaming pasif
        if not first_data:
            clients.add(writer)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: keep-alive\r\n\r\n")
            await writer.drain()
            try:
                while True: await asyncio.wait_for(reader.read(4096), timeout=30.0)
            except (asyncio.TimeoutError, ConnectionError, OSError): pass
            finally:
                clients.discard(writer); writer.close()
            return

        try:
            request_text = first_data.decode("utf-8", errors="ignore")
            first_line = request_text.split("\r\n", 1)[0].split("\n", 1)[0].lower()
            path = first_line.split(" ")[1] if len(first_line.split(" ")) > 1 else "/"
        except Exception:
            first_line = ""; path = "/"

        # 1. HEALTHCHECK (Anti-Deadlock)
        if "/health" in first_line:
            log.debug("Healthcheck request diterima dari %s", peer)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            await writer.drain(); writer.close(); return

        # 2. RAW SSE STREAM (Untuk script/EventSource)
        if path == "/stream":
            log.info("SSE client terhubung (Raw Stream): %s", peer)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n")
            await writer.drain()
            sse_clients.add(writer)
            try:
                alerts_list = await fetch_alert_list()
                for alert_summary in alerts_list[:5]:
                    alert_id = alert_summary.get("id") or alert_summary.get("alert_id")
                    if alert_id:
                        detail_data = await fetch_alert_detail(alert_id)
                        if detail_data:
                            payload = build_minimal_payload(detail_data)
                            sse_data = f"data: {json.dumps(payload, ensure_ascii=False, default=str)}\n\n"
                            writer.write(sse_data.encode("utf-8")); await writer.drain()
                while True: await asyncio.wait_for(reader.read(4096), timeout=30.0)
            except (asyncio.TimeoutError, ConnectionError, OSError): pass
            finally:
                sse_clients.discard(writer); writer.close()
            return

        # 3. RAW JSON SNAPSHOT (Untuk Browser / curl) - MENAMPILKAN DATA TERBARU
        if first_line.startswith("get ") or first_line.startswith("head "):
            log.info("HTTP request (Snapshot JSON) dari %s", peer)
            alerts_list = await fetch_alert_list()
            formatted_alerts = []
            for alert_summary in alerts_list:
                alert_id = alert_summary.get("id") or alert_summary.get("alert_id")
                if alert_id:
                    detail_data = await fetch_alert_detail(alert_id)
                    if detail_data: formatted_alerts.append(build_minimal_payload(detail_data))
                    else: formatted_alerts.append({"alert_description": alert_summary.get("alert_description", "")})
            
            body = json.dumps(formatted_alerts, ensure_ascii=False, indent=2, default=str).encode("utf-8")
            response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("utf-8") + body
            writer.write(response); await writer.drain(); writer.close(); return

    except Exception as e:
        log.error("Error klien %s: %s", peer, e)
    finally:
        clients.discard(writer); sse_clients.discard(writer)
        try:
            if not writer.is_closing(): writer.close(); await writer.wait_closed()
        except Exception: pass


# ============================================================
# MONITORS
# ============================================================

async def iris_monitor():
    log.info("Polling IRIS aktif...")
    while True:
        try:
            alerts_list = await fetch_alert_list()
            for alert_summary in alerts_list:
                alert_id = alert_summary.get("id") or alert_summary.get("alert_id")
                if not alert_id: continue
                dedup_key = str(alert_id)
                if dedup_key in seen_alerts: continue
                seen_alerts.add(dedup_key)
                log.info("🔍 Alert BARU (ID: %s). Mengambil detail...", alert_id)
                
                detail_data = await fetch_alert_detail(alert_id)
                if detail_data:
                    payload = build_minimal_payload(detail_data)
                    await broadcast_alert(payload)
                    await send_to_external_server(payload)
                    log.info("✅ Alert %s diproses & dikirim.", alert_id)
            if len(seen_alerts) > MAX_SEEN_ALERTS: seen_alerts.clear()
        except Exception as e:
            log.exception("Error polling IRIS: %s", e)
        await asyncio.sleep(POLL_INTERVAL)

async def external_data_poller():
    log.info("🔄 External Poller aktif untuk %s", EXTERNAL_IP)
    while True:
        try:
            external_data = await receive_from_external_server()
            for item in external_data:
                log.info("📥 Data dari eksternal: %s", str(item)[:100])
        except Exception as e:
            log.error("Error external poller: %s", e)
        await asyncio.sleep(EXTERNAL_POLL_INTERVAL)


# ============================================================
# MAIN
# ============================================================

async def main():
    try:
        server = await asyncio.start_server(handle_client, host=HOST, port=PORT)
        log.info("🚀 Server aktif di %s:%s", HOST, PORT)
        log.info("💡 Buka http://%s:%s/ di Browser untuk melihat data JSON terbaru!", HOST.replace("0.0.0.0", "127.0.0.1"), PORT)
        
        asyncio.create_task(iris_monitor())
        asyncio.create_task(external_data_poller())
        async with server: await server.serve_forever()
    except Exception as e:
        log.critical("GAGAL MEMULAI SERVER: %s", e)

if __name__ == '__main__':
    try: asyncio.run(main())
    except KeyboardInterrupt: log.info("Server dihentikan.")