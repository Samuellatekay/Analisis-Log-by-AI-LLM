import asyncio
import json
import logging
import os
import httpx

# ============================================================
# CONFIGURATION
# ============================================================

# Di dalam container, kita HARUS bind ke 0.0.0.0
HOST = "0.0.0.0"
PORT = int(os.getenv("IRIS_STREAM_HTTP_PORT", os.getenv("IRIS_STREAM_PORT", "17771")))

BASE_IRIS_URL = os.getenv("IRIS_URL", "https://iris.local").rstrip("/")
IRIS_LIST_ENDPOINT = f"{BASE_IRIS_URL}/api/v2/alerts"
IRIS_API_KEY = os.getenv("IRIS_API_KEY", "")
IRIS_CA_CERT = os.getenv("IRIS_CA_CERT", "/app/iris-ca.crt")

# Opsional: Kirim otomatis ke Webhook eksternal (kosongkan jika tidak perlu)
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "").strip()

POLL_INTERVAL = float(os.getenv("IRIS_POLL_INTERVAL", "5.0"))
REQUEST_TIMEOUT = float(os.getenv("IRIS_REQUEST_TIMEOUT", "10.0"))
MUX_TIMEOUT = float(os.getenv("MUX_TIMEOUT", "1.0"))

# State global
clients = set()          # Untuk raw TCP streaming
sse_clients = set()      # 🆕 Untuk Server-Sent Events (Browser real-time)
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
# PAYLOAD BUILDER
# ============================================================

def build_minimal_payload(detail_data):
    # Handle IRIS quirk: response might be wrapped in {"data": {...}}
    if isinstance(detail_data, dict) and "data" in detail_data:
        detail_data = detail_data["data"]

    if not detail_data or not isinstance(detail_data, dict):
        return {"alert_description": "Gagal mengambil detail"}

    payload = {
        "alert_description": detail_data.get("alert_description", "")
    }
    
    # Aggressive search for 'original'
    raw_original = None
    if "original" in detail_data:
        if isinstance(detail_data["original"], str):
            raw_original = detail_data["original"]
        elif isinstance(detail_data["original"], dict) and "original" in detail_data["original"]:
            raw_original = detail_data["original"]["original"]
            
    if not raw_original and "alert_source_content" in detail_data:
        asc = detail_data["alert_source_content"]
        if isinstance(asc, str):
            raw_original = asc
        elif isinstance(asc, dict) and "original" in asc:
            raw_original = asc["original"]

    if raw_original:
        payload["original"] = raw_original
    else:
        log.warning("⚠️ Alert %s: Field 'original' TIDAK DITEMUKAN di respons API.", detail_data.get("id"))

    # Aggressive search for '@timestamp'
    ts = detail_data.get("@timestamp")
    if not ts and isinstance(detail_data.get("original"), dict):
        ts = detail_data["original"].get("@timestamp")
    if not ts and isinstance(detail_data.get("alert_source_content"), dict):
        ts = detail_data["alert_source_content"].get("@timestamp")
        
    if ts:
        payload["@timestamp"] = ts

    return payload


# ============================================================
# AUTO-SEND & STREAMING
# ============================================================

async def send_to_client(writer, payload):
    writer.write((json.dumps(payload, ensure_ascii=False, default=str) + "\n").encode("utf-8"))
    await writer.drain()

async def broadcast_alert(payload):
    """Kirim otomatis ke semua klien (TCP dan SSE) yang terhubung"""
    
    # 1. Kirim ke Raw TCP Clients
    disconnected = []
    for writer in list(clients):
        try:
            await send_to_client(writer, payload)
        except (ConnectionError, OSError, BrokenPipeError):
            disconnected.append(writer)
    for writer in disconnected:
        clients.discard(writer)
        writer.close()
    
    # 2. 🆕 Kirim ke SSE Clients (Browser Real-time)
    disconnected_sse = []
    for writer in list(sse_clients):
        try:
            # Format SSE: "data: {json}\n\n"
            sse_data = f"data: {json.dumps(payload, ensure_ascii=False, default=str)}\n\n"
            writer.write(sse_data.encode("utf-8"))
            await writer.drain()
        except (ConnectionError, OSError, BrokenPipeError):
            disconnected_sse.append(writer)
    for writer in disconnected_sse:
        sse_clients.discard(writer)
        writer.close()

    # 3. Opsional: Kirim ke Webhook Eksternal
    if WEBHOOK_URL:
        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
                await client.post(WEBHOOK_URL, json=payload)
        except Exception as e:
            log.error("❌ Gagal mengirim webhook: %s", e)


async def handle_client(reader, writer):
    peer = writer.get_extra_info('peername')
    try:
        try:
            first_data = await asyncio.wait_for(reader.read(1024), timeout=MUX_TIMEOUT)
        except Exception:
            first_data = b""

        first_line = first_data.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore") if first_data else ""

        # Healthcheck endpoint (untuk Docker)
        if first_line.startswith(("GET /health", "HEAD /health")):
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            await writer.drain()
            writer.close()
            return

        # 🆕 ENDPOINT SSE: Real-time streaming untuk Browser
        if first_line.startswith("GET /stream"):
            log.info("SSE client terhubung (Real-time Stream): %s", peer)
            
            headers_str = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/event-stream\r\n"
                "Cache-Control: no-cache\r\n"
                "Connection: keep-alive\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "\r\n"
            )
            writer.write(headers_str.encode("utf-8"))
            await writer.drain()
            
            sse_clients.add(writer)
            
            try:
                # Kirim 5 alert terakhir sebagai snapshot awal
                alerts_list = await fetch_alert_list()
                for alert_summary in alerts_list[:5]:
                    alert_id = alert_summary.get("id") or alert_summary.get("alert_id")
                    if alert_id:
                        detail_data = await fetch_alert_detail(alert_id)
                        if detail_data:
                            payload = build_minimal_payload(detail_data)
                            sse_data = f"data: {json.dumps(payload, ensure_ascii=False, default=str)}\n\n"
                            writer.write(sse_data.encode("utf-8"))
                            await writer.drain()
                
                # Tunggu sampai client menutup koneksi (browser ditutup)
                while True:
                    await asyncio.wait_for(reader.read(4096), timeout=30.0)
            except (asyncio.TimeoutError, ConnectionError, OSError):
                pass
            finally:
                sse_clients.discard(writer)
                writer.close()
            return

        # HTTP Request biasa (Snapshot JSON Array)
        if first_line.startswith(("GET ", "HEAD ")):
            log.info("HTTP request (Snapshot) dari %s", peer)
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
            
            headers_str = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "\r\n"
            )
            response = headers_str.encode("utf-8") + body
            
            writer.write(response)
            await writer.drain()
            writer.close()
            return

        # Fallback: Raw TCP Streaming
        log.info("TCP client terhubung (Raw Stream): %s", peer)
        clients.add(writer)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: keep-alive\r\n\r\n")
        await writer.drain()
        
        try:
            while True:
                await asyncio.wait_for(reader.read(4096), timeout=30.0)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
    except Exception as e:
        log.error("Error klien %s: %s", peer, e)
    finally:
        clients.discard(writer)
        sse_clients.discard(writer)
        writer.close()


# ============================================================
# IRIS POLLING MONITOR
# ============================================================

async def iris_monitor():
    log.info("Polling aktif di %s:%s...", HOST, PORT)
    if WEBHOOK_URL:
        log.info("🎯 Auto-send Webhook AKTIF menuju: %s", WEBHOOK_URL)

    while True:
        try:
            alerts_list = await fetch_alert_list()

            for alert_summary in alerts_list:
                alert_id = alert_summary.get("id") or alert_summary.get("alert_id")
                if not alert_id: continue
                    
                dedup_key = str(alert_id)
                if dedup_key in seen_alerts: continue
                
                seen_alerts.add(dedup_key)
                log.info("🔍 Alert BARU terdeteksi (ID: %s). Mengambil detail & mengirim...", alert_id)
                
                detail_data = await fetch_alert_detail(alert_id)
                
                if detail_data:
                    payload = build_minimal_payload(detail_data)
                    await broadcast_alert(payload)
                    log.info("✅ Alert %s berhasil diproses dan dikirim ke semua klien.", alert_id)

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
        log.info("💡 Buka http://localhost:%s/stream di browser untuk real-time auto-update!" % PORT)
        
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