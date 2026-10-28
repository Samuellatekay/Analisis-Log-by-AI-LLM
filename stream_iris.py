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
    log.warning("[!] PERINGATAN: IRIS_API_KEY kosong. Pastikan sudah diisi di .env")


# ============================================================
# IRIS API REQUEST
# ============================================================

async def fetch_latest_alerts():
    """Mengambil alert terbaru dari IRIS menggunakan httpx."""
    headers = {
        "Authorization": f"Bearer {IRIS_API_KEY}",
        "Accept": "application/json",
        "User-Agent": "IRIS-Alert-Stream/2.1",
    }
    
    async with httpx.AsyncClient(verify=False, timeout=REQUEST_TIMEOUT) as client:
        try:
            response = await client.get(
                IRIS_ALERTS_ENDPOINT, 
                headers=headers,
                params={"per_page": 10, "page": 1} 
            )
            response.raise_for_status()
            data = response.json()
            
            alerts = []
            if isinstance(data, list):
                alerts = data
            elif isinstance(data, dict):
                inner_data = data.get("data")
                if isinstance(inner_data, list):
                    alerts = inner_data
                elif isinstance(inner_data, dict):
                    alerts = inner_data.get("data", [])
                    if not isinstance(alerts, list):
                        alerts = []
            
            return alerts

        except httpx.HTTPStatusError as e:
            log.error("HTTP Error dari IRIS: %s - %s", e.response.status_code, e.response.text[:200])
            return []
        except httpx.RequestError as e:
            log.error("Gagal menghubungi IRIS (Network Error): %s", str(e))
            return []
        except json.JSONDecodeError:
            log.error("Respons dari IRIS bukan JSON yang valid.")
            return []
        except Exception as e:
            log.error("Error tidak terduga saat menghubungi IRIS: %s", str(e))
            return []


# ============================================================
# TCP STREAMING & HTTP MULTIPLEXER
# ============================================================

async def send_to_client(writer, payload):
    data = (json.dumps(payload, ensure_ascii=False, default=str) + "\n").encode("utf-8")
    writer.write(data)
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
    """Menangani koneksi masuk: HTTP GET untuk dashboard, atau TCP Stream murni."""
    peer = writer.get_extra_info('peername')
    
    try:
        try:
            first_data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
        except asyncio.TimeoutError:
            first_data = b""

        # Jika diawali dengan GET/HEAD, perlakukan sebagai request HTTP biasa
        if first_data.startswith((b"GET ", b"HEAD ")):
            log.info("HTTP request dari %s", peer)
            alerts = await fetch_latest_alerts()
            
            # Format ulang alerts agar konsisten dengan format streaming
            formatted_alerts = []
            for alert in alerts:
                alert_id = alert.get("id") or alert.get("alert_id")
                original_log = alert.get("original") or alert.get("alert_source_content", "Tidak ada data original")
                
                formatted_alerts.append({
                    "iris_alert_id": alert_id,
                    "alert_title": alert.get("alert_title", "Tanpa Judul"),
                    "alert_description": alert.get("alert_description", ""),
                    "original": original_log
                })

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

        # Jika bukan HTTP, perlakukan sebagai TCP Streaming Client (persisten)
        log.info("TCP client terhubung (streaming): %s", peer)
        clients.add(writer)

        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: keep-alive\r\n\r\n")
        await writer.drain()

        try:
            while True:
                await asyncio.wait_for(reader.read(4096), timeout=30.0)
        except asyncio.TimeoutError:
            pass
        except (ConnectionResetError, BrokenPipeError):
            pass

    except Exception as e:
        log.error("Error pada koneksi klien %s: %s", peer, e)
    finally:
        clients.discard(writer)
        writer.close()
        log.info("Klien terputus: %s", peer)


# ============================================================
# IRIS POLLING MONITOR
# ============================================================

async def iris_monitor():
    log.info("IRIS polling aktif: %s (interval: %ss)", IRIS_ALERTS_ENDPOINT, POLL_INTERVAL)

    while True:
        try:
            alerts = await fetch_latest_alerts()

            for alert in alerts:
                alert_id = alert.get("id") or alert.get("alert_id")
                dedup_key = str(alert_id) if alert_id else json.dumps(alert, sort_keys=True, default=str)

                if dedup_key in seen_alerts:
                    continue

                seen_alerts.add(dedup_key)
                
                if len(seen_alerts) > MAX_SEEN_ALERTS:
                    log.warning("Batas seen_alerts tercapai. Mempertahankan ukuran maksimum.")

                # ============================================================
                # EKSTRAKSI DATA 'ORIGINAL' YANG FLEKSIBEL & AMAN
                # ============================================================
                original_log = alert.get("original")
                
                if original_log is None:
                    source_content = alert.get("alert_source_content")
                    if isinstance(source_content, str):
                        try:
                            source_content = json.loads(source_content)
                        except json.JSONDecodeError:
                            pass
                    
                    if isinstance(source_content, dict):
                        original_log = source_content.get("original", source_content)
                    else:
                        original_log = source_content

                if isinstance(original_log, str):
                    try:
                        parsed_json = json.loads(original_log)
                        if isinstance(parsed_json, (dict, list)):
                            original_log = parsed_json
                    except json.JSONDecodeError:
                        pass # Tetap pertahankan sebagai string teks biasa

                payload = {
                    "iris_alert_id": alert_id,
                    "alert_title": alert.get("alert_title", "Tanpa Judul"),
                    "alert_description": alert.get("alert_description", ""),
                    "original": original_log  # <-- Data lengkap akan masuk di sini
                }

                log.info("Alert baru: id=%s | title=%s", alert_id, alert.get("alert_title", "N/A"))
                await broadcast_alert(payload)

        except Exception as e:
            log.exception("Gagal polling IRIS: %s", e)

        await asyncio.sleep(POLL_INTERVAL)


# ============================================================
# MAIN
# ============================================================

async def main():
    server = await asyncio.start_server(handle_client, host=HOST, port=PORT)
    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    
    log.info("Server aktif di: %s", addrs)
    log.info("Endpoint IRIS Target: %s", IRIS_ALERTS_ENDPOINT)
    log.info("Tes HTTP: curl http://localhost:%s/" % PORT)
    log.info("Tes TCP: nc localhost %s" % PORT)

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
        log.info("Server streaming dihentikan secara manual.")