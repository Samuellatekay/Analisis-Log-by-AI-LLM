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
    headers = {
        "Authorization": f"Bearer {IRIS_API_KEY}",
        "Accept": "application/json",
        "User-Agent": "IRIS-Alert-Stream/5.0",
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
# PAYLOAD BUILDER (SANGAT SEDERHANA & LANGSUNG)
# ============================================================

def build_minimal_payload(alert):
    """
    Membangun payload HANYA dengan field yang diminta, 
    tanpa mengubah tipe data (string tetap string, dict tetap dict).
    """
    payload = {
        "alert_description": alert.get("alert_description", "")
    }
    
    # 1. Ambil 'original' apa adanya (langsung assign, tanpa cek tipe data)
    if "original" in alert:
        payload["original"] = alert["original"]
    elif "alert_source_content" in alert:
        payload["original"] = alert["alert_source_content"]
        
    # 2. Ambil '@timestamp' apa adanya
    if "@timestamp" in alert:
        payload["@timestamp"] = alert["@timestamp"]
    elif isinstance(alert.get("original"), dict) and "@timestamp" in alert["original"]:
        payload["@timestamp"] = alert["original"]["@timestamp"]
        
    return payload


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
    peer = writer.get_extra_info('peername')
    
    try:
        try:
            first_data = await asyncio.wait_for(reader.read(1024), timeout=MUX_TIMEOUT)
        except asyncio.TimeoutError:
            first_data = b""

        # 1. HTTP REQUEST
        if first_data.startswith((b"GET ", b"HEAD ")):
            log.info("HTTP request dari %s", peer)
            alerts = await fetch_latest_alerts()
            
            formatted_alerts = [build_minimal_payload(alert) for alert in alerts]
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

        # 2. TCP STREAMING CLIENT
        log.info("TCP client terhubung (streaming): %s", peer)
        clients.add(writer)

        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: keep-alive\r\n\r\n")
        await writer.drain()

        try:
            initial_alerts = await fetch_latest_alerts()
            if initial_alerts:
                log.info("📦 Mengirim %d alert snapshot awal ke %s", len(initial_alerts), peer)
                for alert in initial_alerts[:5]:
                    snapshot_payload = build_minimal_payload(alert)
                    # DEBUG: Cetak key yang berhasil diambil ke log
                    log.debug("Snapshot payload keys: %s", list(snapshot_payload.keys()))
                    await send_to_client(writer, snapshot_payload)
        except Exception as e:
            log.error("Gagal mengirim snapshot awal: %s", e)

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

                payload = build_minimal_payload(alert)
                
                # LOG PENTING: Ini akan membuktikan field apa saja yang berhasil diambil
                log.info("✅ Alert BARU dikirim (ID: %s). Field yang dikirim: %s", alert_id, list(payload.keys()))
                
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
    
    log.info("🚀 Server aktif di: %s", addrs)
    log.info("🎯 Endpoint IRIS Target: %s", IRIS_ALERTS_ENDPOINT)

    monitor_task = asyncio.create_task(iris_monitor())

    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        log.info("Menerima sinyal pembatalan...")
    finally:
        log.info("Menutup server dan membersihkan koneksi...")
        monitor_task.cancel()
        for writer in list(clients):
            writer.close()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Server streaming dihentikan secara manual.")