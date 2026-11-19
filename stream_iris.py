import asyncio
import json
import logging
import os
import time
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

# Jeda sebelum alert baru dikirim, supaya enrichment (GLPI/OpenCTI) yang masuk setelah alert
# dibuat sudah ikut di deskripsi. 0 = kirim langsung saat pertama terlihat.
SETTLE_SECONDS = float(os.getenv("IRIS_SETTLE_SECONDS", "10"))

tcp_clients = set()
http_stream_clients = set()
seen_alerts = set()
pending_alerts = {}   # alert_id -> waktu pertama kali terlihat (monotonic)
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

def _source_content(detail_data):
    """alert_source_content sebagai dict (bisa berupa dict atau string JSON)."""
    asc = detail_data.get("alert_source_content")
    if isinstance(asc, str):
        try:
            asc = json.loads(asc)
        except ValueError:
            return {}
    return asc if isinstance(asc, dict) else {}


def build_minimal_payload(detail_data):
    if isinstance(detail_data, dict) and "data" in detail_data:
        detail_data = detail_data["data"]
    if not detail_data or not isinstance(detail_data, dict):
        return {"alert_description": "Gagal mengambil detail"}

    # Description di IRIS dibuat ringkas (Source/Destination ada di tab Assets, IOC di tab IOCs).
    # Deskripsi lengkap (Event, Source, Destination, Threat Intelligence, Geolokasi, IOC terkait)
    # disimpan oleh iris_client di alert_source_content["alert_description_full"].
    asc_dict = _source_content(detail_data)
    full_description = asc_dict.get("alert_description_full")
    payload = {
        "alert_id": detail_data.get("alert_id") or detail_data.get("id"),
        "log_uuid": detail_data.get("alert_source_ref"),
        "alert_description": full_description or detail_data.get("alert_description", ""),
    }

    raw_original = None
    if "original" in detail_data:
        if isinstance(detail_data["original"], str): raw_original = detail_data["original"]
        elif isinstance(detail_data["original"], dict) and "original" in detail_data["original"]:
            raw_original = detail_data["original"]["original"]
    if not raw_original and "alert_source_content" in detail_data:
        asc = detail_data["alert_source_content"]
        if isinstance(asc, str):
            raw_original = asc_dict.get("original") or asc   # string JSON -> ambil field original-nya
        elif isinstance(asc, dict) and "original" in asc: raw_original = asc["original"]

    if raw_original: payload["original"] = raw_original

    ts = detail_data.get("@timestamp")
    if not ts and isinstance(detail_data.get("original"), dict): ts = detail_data["original"].get("@timestamp")
    if not ts and isinstance(detail_data.get("alert_source_content"), dict): ts = detail_data["alert_source_content"].get("@timestamp")
    if ts: payload["@timestamp"] = ts
    return payload


# ============================================================
# HYBRID HANDLER (TCP + HTTP)
# ============================================================

async def broadcast_all(payload):
    data_bytes = (json.dumps(payload, ensure_ascii=False, default=str) + "\n").encode("utf-8")
    
    disconnected_tcp = []
    for writer in list(tcp_clients):
        try:
            writer.write(data_bytes)
            await writer.drain()
        except (ConnectionError, OSError, BrokenPipeError):
            disconnected_tcp.append(writer)
    for w in disconnected_tcp:
        tcp_clients.discard(w); w.close()

    disconnected_http = []
    for writer in list(http_stream_clients):
        try:
            writer.write(data_bytes)
            await writer.drain()
        except (ConnectionError, OSError, BrokenPipeError):
            disconnected_http.append(writer)
    for w in disconnected_http:
        http_stream_clients.discard(w); w.close()

async def handle_client(reader, writer):
    peer = writer.get_extra_info('peername')
    
    try:
        first_data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
    except asyncio.TimeoutError:
        first_data = b""
    except Exception:
        first_data = b""

    # --- SKENARIO 1: RAW TCP (Netcat / Socket mentah) ---
    if not first_data:
        log.info("🔌 Raw TCP client terhubung (pasif): %s", peer)
        tcp_clients.add(writer)
        try:
            while True:
                data = await reader.read(4096)
                if not data: break
        except Exception: pass
        finally:
            tcp_clients.discard(writer)
            writer.close()
        return

    try:
        request_text = first_data.decode('utf-8', errors='ignore')
        first_line = request_text.split('\r\n')[0].split('\n')[0].upper()
        path = request_text.split('\r\n')[0].split('\n')[0].split(' ')[1] if ' ' in request_text.split('\r\n')[0] else '/'
    except Exception:
        first_line = ""; path = "/"

    # --- SKENARIO 2: HTTP REQUEST ---
    if first_line.startswith(('GET ', 'POST ', 'HEAD ', 'PUT ', 'DELETE ')):
        
        # A. Healthcheck (Untuk Docker)
        if "/HEALTH" in first_line:
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            await writer.drain(); writer.close(); return

        # B. HTTP Stream Real-time (/stream)
        if path == "/stream":
            log.info("🌐 HTTP Stream client terhubung: %s", peer)
            http_stream_clients.add(writer)
            # Content-Type text/plain agar browser menampilkannya, bukan mendownload
            header = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: keep-alive\r\n\r\n"
            writer.write(header)
            await writer.drain()
            try:
                while True:
                    data = await reader.read(4096)
                    if not data: break
            except Exception: pass
            finally:
                http_stream_clients.discard(writer)
                writer.close()
            return

        # C. HTTP Snapshot JSON (/)
        if path == "/" or path.startswith("/?"):
            log.info("🌐 HTTP Snapshot request dari %s", peer)
            alerts_list = await fetch_alert_list()
            formatted = []
            for alert_summary in alerts_list:
                alert_id = alert_summary.get("id") or alert_summary.get("alert_id")
                if alert_id:
                    detail_data = await fetch_alert_detail(alert_id)
                    if detail_data: formatted.append(build_minimal_payload(detail_data))
                    else: formatted.append({"alert_description": alert_summary.get("alert_description", "")})
            
            body = json.dumps(formatted, ensure_ascii=False, indent=2, default=str).encode("utf-8")
            response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("utf-8") + body
            writer.write(response); await writer.drain(); writer.close(); return

    # --- SKENARIO 3: TCP DENGAN DATA AWAL (Non-HTTP) ---
    log.info("🔌 Raw TCP client terhubung (dengan data awal): %s", peer)
    tcp_clients.add(writer)
    try:
        while True:
            data = await reader.read(4096)
            if not data: break
    except Exception: pass
    finally:
        tcp_clients.discard(writer)
        writer.close()


# ============================================================
# MONITORS
# ============================================================

async def iris_monitor():
    log.info("Polling IRIS aktif (jeda enrichment: %.0f detik)...", SETTLE_SECONDS)
    while True:
        try:
            alerts_list = await fetch_alert_list()
            current = set()
            for alert_summary in alerts_list:
                alert_id = alert_summary.get("id") or alert_summary.get("alert_id")
                if not alert_id: continue
                dedup_key = str(alert_id)
                current.add(dedup_key)
                if dedup_key in seen_alerts: continue

                # Tunggu enrichment (GLPI/OpenCTI) selesai sebelum alert dikirim.
                first_seen = pending_alerts.setdefault(dedup_key, time.monotonic())
                if time.monotonic() - first_seen < SETTLE_SECONDS: continue
                pending_alerts.pop(dedup_key, None)

                seen_alerts.add(dedup_key)
                log.info("🔍 Alert BARU (ID: %s). Mengambil detail...", alert_id)
                
                detail_data = await fetch_alert_detail(alert_id)
                if detail_data:
                    payload = build_minimal_payload(detail_data)
                    await broadcast_all(payload)
                    await send_to_external_server(payload)
                    log.info("✅ Alert %s diproses & dikirim.", alert_id)
            for key in list(pending_alerts):
                if key not in current: del pending_alerts[key]
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
        log.info("🚀 Hybrid TCP/HTTP Server aktif di %s:%s", HOST, PORT)
        log.info("💡 TCP: nc 127.0.0.1 %s", PORT)
        log.info("💡 HTTP Snapshot: curl http://127.0.0.1:%s/", PORT)
        log.info("💡 HTTP Stream (Browser): http://127.0.0.1:%s/stream", PORT)
        
        asyncio.create_task(iris_monitor())
        asyncio.create_task(external_data_poller())
        async with server: await server.serve_forever()
    except Exception as e:
        log.critical("GAGAL MEMULAI SERVER: %s", e)

if __name__ == '__main__':
    try: asyncio.run(main())
    except KeyboardInterrupt: log.info("Server dihentikan.")