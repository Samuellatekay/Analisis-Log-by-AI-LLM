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
IRIS_ALERTS_ENDPOINT = f"{BASE_IRIS_URL}/api/v2/alerts"
IRIS_API_KEY = os.getenv("IRIS_API_KEY", "")

POLL_INTERVAL = float(os.getenv("IRIS_POLL_INTERVAL", "5.0"))
REQUEST_TIMEOUT = float(os.getenv("IRIS_REQUEST_TIMEOUT", "10.0"))
MUX_TIMEOUT = float(os.getenv("MUX_TIMEOUT", "1.0"))

clients = set()
seen_alerts = set()
MAX_SEEN_ALERTS = 100000

logging.basicConfig(
    level="DEBUG", # <--- UBAH KE DEBUG AGAR KITA BISA MELIHAT SEMUANYA
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("iris-stream")

if not IRIS_API_KEY:
    log.warning("[!] PERINGATAN: IRIS_API_KEY kosong.")


# ============================================================
# IRIS API REQUEST
# ============================================================

async def fetch_latest_alerts():
    headers = {
        "Authorization": f"Bearer {IRIS_API_KEY}",
        "Accept": "application/json",
        "User-Agent": "IRIS-Alert-Stream-DIAGNOSTIC",
    }
    
    async with httpx.AsyncClient(verify=False, timeout=REQUEST_TIMEOUT) as client:
        try:
            response = await client.get(IRIS_ALERTS_ENDPOINT, headers=headers, params={"per_page": 10, "page": 1})
            response.raise_for_status()
            return response.json() # Kembalikan mentah dulu untuk di-debug
        except Exception as e:
            log.error("Gagal fetch: %s", e)
            return []


# ============================================================
# PAYLOAD BUILDER
# ============================================================

def build_minimal_payload(alert):
    payload = {"alert_description": alert.get("alert_description", "")}
    
    # 1. Ekstrak 'original' (bisa string di root, atau string di dalam dict 'original')
    if "original" in alert:
        if isinstance(alert["original"], str):
            payload["original"] = alert["original"]
        elif isinstance(alert["original"], dict) and "original" in alert["original"]:
            payload["original"] = alert["original"]["original"]
            
    # 2. Ekstrak '@timestamp' (bisa di root, atau di dalam dict 'original')
    ts = alert.get("@timestamp")
    if not ts and isinstance(alert.get("original"), dict):
        ts = alert["original"].get("@timestamp")
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
    for writer in list(clents): # typo fixed below in actual code, but keeping logic simple
        try:
            await send_to_client(writer, payload is not None and payload or {})
        except:
            clients.discard(writer); writer.close()

# Fix typo in broadcast
async def broadcast_alert_fixed(payload):
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

        if first_data.startswith((b"GET ", b"HEAD ")):
            alerts = await fetch_latest_alerts()
            # Pastikan alerts adalah list
            if isinstance(alerts, dict) and "data" in alerts:
                alerts = alerts["data"]
            if not isinstance(alerts, list):
                alerts = [alerts] if alerts else []

            formatted = [build_minimal_payload(a) for a in alerts]
            body = json.dumps(formatted, ensure_ascii=False, indent=2, default=str).encode("utf-8")
            
            response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
            writer.write(response)
            await writer.drain()
            writer.close()
            return

        # TCP Stream
        clients.add(writer)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: keep-alive\r\n\r\n")
        await writer.drain()
        
        # Snapshot
        alerts = await fetch_latest_alerts()
        if isinstance(alerts, dict) and "data" in alerts:
            alerts = alerts["data"]
        if isinstance(alerts, list):
            for a in alerts[:3]:
                await send_to_client(writer, build_minimal_payload(a))

        while True:
            await asyncio.wait_for(reader.read(4096), timeout=30.0)
    except:
        pass
    finally:
        clients.discard(writer)
        writer.close()


# ============================================================
# IRIS POLLING MONITOR (DENGAN DEBUG AGRESIF)
# ============================================================

async def iris_monitor():
    log.info("Polling aktif...")
    while True:
        try:
            raw_response = await fetch_latest_alerts()
            
            # Normalisasi ke list
            alerts_list = []
            if isinstance(raw_response, list):
                alerts_list = raw_response
            elif isinstance(raw_response, dict) and "data" in raw_response:
                alerts_list = raw_response["data"] if isinstance(raw_response["data"], list) else [raw_response["data"]]
            elif isinstance(raw_response, dict):
                alerts_list = [raw_response]

            for alert in alerts_list:
                alert_id = alert.get("id") or alert.get("alert_id") or "UNKNOWN"
                dedup_key = str(alert_id)

                if dedup_key in seen_alerts:
                    continue
                seen_alerts.add(dedup_key)

                # === MODE DEBUG AGRESIF ===
                log.info("=== DEBUG ALERT ID: %s ===", alert_id)
                log.info("1. Semua Keys di Root: %s", list(alert.keys()))
                
                if "original" in alert:
                    log.info("2. Tipe data 'original': %s", type(alert["original"]))
                    if isinstance(alert["original"], dict):
                        log.info("3. Keys di dalam 'original': %s", list(alert["original"].keys()))
                else:
                    log.warning("⚠️ TIDAK ADA KEY 'original' DI ROOT!")
                    
                if "alert_source_content" in alert:
                    log.info("4. alert_source_content ditemukan. Tipe: %s", type(alert["alert_source_content"]))
                # ==========================

                payload = build_minimal_payload(alert)
                log.info("✅ HASIL AKHIR PAYLOAD KEYS: %s", list(payload.keys()))
                
                await broadcast_alert_fixed(payload)

        except Exception as e:
            log.exception("Error polling: %s", e)

        await asyncio.sleep(POLL_INTERVAL)


async def main():
    server = await asyncio.start_server(handle_client, host=HOST, port=PORT)
    log.info("Server aktif di %s:%s", HOST, PORT)
    asyncio.create_task(iris_monitor())
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Stopped.")