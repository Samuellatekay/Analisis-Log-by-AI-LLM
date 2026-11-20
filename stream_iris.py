import asyncio
import json
import logging
import os
import socket
import time
import uuid

import httpx
import redis.asyncio as aioredis
from redis.exceptions import ResponseError

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
REDIS_URL = os.getenv("IRIS_STREAM_REDIS_URL") or os.getenv(
    "REDIS_URL", "redis://localhost:6379/0"
)
ALERT_QUEUE_STREAM = os.getenv("IRIS_ALERT_QUEUE_STREAM", "iris:alerts:outbound")
ALERT_QUEUE_GROUP = os.getenv("IRIS_ALERT_QUEUE_GROUP", "iris-stream")
ALERT_PAGE_SIZE = max(1, int(os.getenv("IRIS_ALERT_PAGE_SIZE", "100")))
ALERT_WORKERS = max(1, int(os.getenv("IRIS_ALERT_WORKERS", "4")))
ALERT_MAX_ATTEMPTS = max(1, int(os.getenv("IRIS_ALERT_MAX_ATTEMPTS", "8")))
ALERT_RETRY_BASE_SECONDS = max(
    0.1, float(os.getenv("IRIS_ALERT_RETRY_BASE_SECONDS", "2"))
)
ALERT_CLAIM_IDLE_MS = max(
    1000, int(os.getenv("IRIS_ALERT_CLAIM_IDLE_MS", "900000"))
)
ALERT_SEEN_TTL_SECONDS = max(
    86400, int(os.getenv("IRIS_ALERT_SEEN_TTL_SECONDS", "7776000"))
)

# Jeda sebelum alert baru dikirim, supaya enrichment (GLPI/OpenCTI) yang masuk setelah alert
# dibuat sudah ikut di deskripsi. 0 = kirim langsung saat pertama terlihat.
SETTLE_SECONDS = float(os.getenv("IRIS_SETTLE_SECONDS", "10"))

tcp_clients = set()
http_stream_clients = set()
iris_http_client: httpx.AsyncClient | None = None
external_http_client: httpx.AsyncClient | None = None
enqueue_alert_script = """
if redis.call('EXISTS', KEYS[1]) == 1 then
    return '0:' .. redis.call('GET', KEYS[1])
end
local stream_id = redis.call(
    'XADD', KEYS[2], '*',
    'alert_id', ARGV[1],
    'available_at', ARGV[2]
)
redis.call('SET', KEYS[1], stream_id, 'EX', ARGV[3])
return '1:' .. stream_id
"""
ALERT_WATERMARK_KEY = f"{ALERT_QUEUE_STREAM}:watermark"
ALERT_DEAD_LETTER_STREAM = f"{ALERT_QUEUE_STREAM}:dead"

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

def _iris_tls_verify():
    return IRIS_CA_CERT if os.path.exists(IRIS_CA_CERT) else False


async def _iris_get(url: str, *, params: dict | None = None):
    headers = {"Authorization": f"Bearer {IRIS_API_KEY}", "Accept": "application/json"}
    if iris_http_client is not None:
        return await iris_http_client.get(url, headers=headers, params=params)
    async with httpx.AsyncClient(
        verify=_iris_tls_verify(), timeout=REQUEST_TIMEOUT
    ) as client:
        return await client.get(url, headers=headers, params=params)


async def fetch_alert_list(
    page: int = 1, per_page: int = ALERT_PAGE_SIZE
) -> list[dict] | None:
    try:
        response = await _iris_get(
            IRIS_LIST_ENDPOINT,
            params={"per_page": per_page, "page": page},
        )
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and isinstance(data.get("data"), list):
            return data["data"]
        log.error("Format respons daftar alert IRIS tidak dikenali.")
        return None
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log.error("Gagal fetch daftar alert IRIS halaman %s: %s", page, exc)
        return None


async def fetch_alert_detail(alert_id):
    url = f"{BASE_IRIS_URL}/api/v2/alerts/{alert_id}"
    try:
        response = await _iris_get(url)
        response.raise_for_status()
        return response.json()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log.error("Gagal fetch detail alert %s: %s", alert_id, exc)
        return None

# ============================================================
# EXTERNAL API FUNCTIONS
# ============================================================

async def send_to_external_server(payload: dict):
    if not EXTERNAL_API_KEY: return False
    url = f"https://{EXTERNAL_IP}{EXTERNAL_SEND_PATH}"
    headers = {"Authorization": f"Bearer {EXTERNAL_API_KEY}", "Content-Type": "application/json"}
    try:
        if external_http_client is not None:
            response = await external_http_client.post(url, json=payload, headers=headers)
        else:
            async with httpx.AsyncClient(
                verify=EXTERNAL_VERIFY_SSL, timeout=REQUEST_TIMEOUT
            ) as client:
                response = await client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        log.info("✅ Data dikirim ke %s (Status: %s)", EXTERNAL_IP, response.status_code)
        return True
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log.error("❌ Gagal kirim ke %s: %s", EXTERNAL_IP, exc)
        return False

async def receive_from_external_server() -> list:
    if not EXTERNAL_API_KEY: return []
    url = f"https://{EXTERNAL_IP}{EXTERNAL_RECV_PATH}"
    headers = {"Authorization": f"Bearer {EXTERNAL_API_KEY}", "Accept": "application/json"}
    try:
        if external_http_client is not None:
            response = await external_http_client.get(url, headers=headers)
        else:
            async with httpx.AsyncClient(
                verify=EXTERNAL_VERIFY_SSL, timeout=REQUEST_TIMEOUT
            ) as client:
                response = await client.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, list) else [data]
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log.error("❌ Gagal ambil data dari %s: %s", EXTERNAL_IP, exc)
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
    if asc_dict:
        payload["alert_source_content"] = asc_dict
        related_events = asc_dict.get("related_events")
        if isinstance(related_events, list):
            payload["related_events"] = related_events

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
            await asyncio.wait_for(writer.drain(), timeout=2)
        except (ConnectionError, OSError, BrokenPipeError, asyncio.TimeoutError):
            disconnected_tcp.append(writer)
    for w in disconnected_tcp:
        tcp_clients.discard(w); w.close()

    disconnected_http = []
    for writer in list(http_stream_clients):
        try:
            writer.write(data_bytes)
            await asyncio.wait_for(writer.drain(), timeout=2)
        except (ConnectionError, OSError, BrokenPipeError, asyncio.TimeoutError):
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
            if alerts_list is None:
                alerts_list = []
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

async def enqueue_alert(redis, alert_id: str, available_at: float) -> bool:
    seen_key = f"{ALERT_QUEUE_STREAM}:seen:{alert_id}"
    result = await redis.eval(
        enqueue_alert_script,
        2,
        seen_key,
        ALERT_QUEUE_STREAM,
        alert_id,
        str(available_at),
        ALERT_SEEN_TTL_SECONDS,
    )
    return str(result).startswith("1:")


async def scan_iris_alerts(redis) -> int:
    watermark_raw = await redis.get(ALERT_WATERMARK_KEY)
    initial_scan = watermark_raw is None
    try:
        baseline_watermark = int(watermark_raw) if watermark_raw is not None else None
    except ValueError as exc:
        raise ValueError(f"Watermark alert IRIS tidak valid: {watermark_raw!r}") from exc

    next_watermark = baseline_watermark
    queued_count = 0
    page = 1
    scan_complete = True
    while True:
        alerts = await fetch_alert_list(page=page, per_page=ALERT_PAGE_SIZE)
        if alerts is None:
            scan_complete = False
            break
        if not alerts:
            break

        valid_alerts = []
        invalid_ids = False
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            alert_id = alert.get("id") or alert.get("alert_id")
            try:
                numeric_id = int(alert_id)
            except (TypeError, ValueError):
                log.warning("ID alert IRIS tidak valid; alert dilewati: %r", alert_id)
                invalid_ids = True
                continue
            if numeric_id <= 0:
                log.warning("ID alert IRIS harus positif; alert dilewati: %r", alert_id)
                invalid_ids = True
                continue
            valid_alerts.append((str(alert_id), numeric_id))
        if invalid_ids:
            scan_complete = False

        new_alerts = [
            (alert_id, numeric_id)
            for alert_id, numeric_id in valid_alerts
            if baseline_watermark is None or numeric_id > baseline_watermark
        ]
        if not new_alerts and not initial_scan:
            break

        available_at = time.time() + SETTLE_SECONDS
        for alert_id, numeric_id in new_alerts:
            if await enqueue_alert(redis, alert_id, available_at):
                queued_count += 1
            if next_watermark is None or numeric_id > next_watermark:
                next_watermark = numeric_id

        if initial_scan or len(alerts) < ALERT_PAGE_SIZE:
            break
        page += 1

    if (
        scan_complete
        and next_watermark is not None
        and next_watermark != baseline_watermark
    ):
        await redis.set(ALERT_WATERMARK_KEY, str(next_watermark))
    if queued_count:
        queue_depth = await redis.xlen(ALERT_QUEUE_STREAM)
        log.info(
            "Alert IRIS baru masuk antrean: %d (pending=%d, stream=%s, watermark=%s).",
            queued_count,
            queue_depth,
            ALERT_QUEUE_STREAM,
            next_watermark,
        )
    return queued_count


async def iris_monitor(redis):
    log.info(
        "IRIS polling aktif (page_size=%d, interval=%.1fs, settle=%.0fs).",
        ALERT_PAGE_SIZE,
        POLL_INTERVAL,
        SETTLE_SECONDS,
    )
    while True:
        try:
            await scan_iris_alerts(redis)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Gagal memindai/enqueue alert IRIS; akan dicoba lagi.")
        await asyncio.sleep(POLL_INTERVAL)


async def _read_alert_job(redis, consumer: str, claim_cursor: str):
    next_cursor = claim_cursor
    try:
        claimed = await redis.xautoclaim(
            ALERT_QUEUE_STREAM,
            ALERT_QUEUE_GROUP,
            consumer,
            min_idle_time=ALERT_CLAIM_IDLE_MS,
            start_id=claim_cursor,
            count=1,
        )
        if claimed:
            next_cursor = claimed[0]
        if len(claimed) > 1 and claimed[1]:
            return claimed[1][0], next_cursor
    except ResponseError as exc:
        log.error("Gagal mengambil alert pending dari Redis Stream: %s", exc)

    batches = await redis.xreadgroup(
        ALERT_QUEUE_GROUP,
        consumer,
        {ALERT_QUEUE_STREAM: ">"},
        count=1,
        block=1000,
    )
    for _, messages in batches:
        if messages:
            return messages[0], next_cursor
    return None, next_cursor


async def _ack_alert_job(redis, message_id: str) -> None:
    await redis.xack(ALERT_QUEUE_STREAM, ALERT_QUEUE_GROUP, message_id)
    await redis.xdel(ALERT_QUEUE_STREAM, message_id)


async def _dead_letter_alert(
    redis, message_id: str, fields: dict, error: str, attempts: int
) -> None:
    await redis.xadd(
        ALERT_DEAD_LETTER_STREAM,
        {
            **fields,
            "source_message_id": message_id,
            "error": error[:1000],
            "attempts": str(attempts),
            "failed_at": str(time.time()),
        },
        maxlen=10000,
        approximate=True,
    )
    await _ack_alert_job(redis, message_id)
    log.error(
        "Alert IRIS %s dipindahkan ke dead-letter setelah %d percobaan: %s",
        fields.get("alert_id"),
        attempts,
        error,
    )


async def _deliver_alert_job(redis, message_id: str, fields: dict) -> None:
    alert_id = fields.get("alert_id")
    try:
        available_at = float(fields.get("available_at") or 0)
    except (TypeError, ValueError):
        available_at = 0
    if available_at > time.time():
        await asyncio.sleep(available_at - time.time())

    last_error = "detail alert tidak tersedia"
    broadcasted = False
    for attempt in range(1, ALERT_MAX_ATTEMPTS + 1):
        try:
            detail_data = await fetch_alert_detail(alert_id)
            if not detail_data:
                raise RuntimeError(f"detail Alert {alert_id} tidak berhasil dibaca")
            payload = build_minimal_payload(detail_data)
            if not broadcasted:
                await broadcast_all(payload)
                broadcasted = True
            if EXTERNAL_API_KEY and not await send_to_external_server(payload):
                raise RuntimeError("pengiriman ke layanan eksternal gagal")
            await _ack_alert_job(redis, message_id)
            log.info("✅ Alert %s berhasil diproses dari antrean.", alert_id)
            return
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt == ALERT_MAX_ATTEMPTS:
                await _dead_letter_alert(redis, message_id, fields, last_error, attempt)
                return
            delay = min(ALERT_RETRY_BASE_SECONDS * (2 ** (attempt - 1)), 60)
            log.warning(
                "Alert %s gagal dikirim (percobaan %d/%d); retry %.1fs: %s",
                alert_id,
                attempt,
                ALERT_MAX_ATTEMPTS,
                delay,
                last_error,
            )
            await asyncio.sleep(delay)


async def alert_delivery_worker(redis, worker_index: int) -> None:
    consumer = f"{socket.gethostname()}-{os.getpid()}-{worker_index}-{uuid.uuid4().hex[:8]}"
    claim_cursor = "0-0"
    while True:
        try:
            job, claim_cursor = await _read_alert_job(redis, consumer, claim_cursor)
            if job is None:
                continue
            message_id, fields = job
            await _deliver_alert_job(redis, message_id, fields)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Worker pengiriman Alert IRIS %s gagal; melanjutkan.", consumer)
            await asyncio.sleep(1)

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
    global iris_http_client, external_http_client
    redis = aioredis.from_url(
        REDIS_URL,
        decode_responses=True,
        max_connections=max(20, ALERT_WORKERS * 4),
        socket_connect_timeout=5,
        socket_timeout=REQUEST_TIMEOUT,
    )
    while True:
        try:
            await redis.ping()
            break
        except asyncio.CancelledError:
            await redis.aclose()
            raise
        except Exception as exc:
            log.warning("Redis belum siap untuk antrean alert (%s); retry 2s.", exc)
            await asyncio.sleep(2)

    try:
        await redis.xgroup_create(
            ALERT_QUEUE_STREAM,
            ALERT_QUEUE_GROUP,
            id="0-0",
            mkstream=True,
        )
    except ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            await redis.aclose()
            raise

    iris_http_client = httpx.AsyncClient(
        verify=_iris_tls_verify(),
        timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=5),
        limits=httpx.Limits(
            max_connections=max(20, ALERT_WORKERS * 4),
            max_keepalive_connections=max(10, ALERT_WORKERS * 2),
        ),
    )
    external_http_client = httpx.AsyncClient(
        verify=EXTERNAL_VERIFY_SSL,
        timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=5),
        limits=httpx.Limits(
            max_connections=max(20, ALERT_WORKERS * 4),
            max_keepalive_connections=max(10, ALERT_WORKERS * 2),
        ),
    )
    tasks = []
    try:
        server = await asyncio.start_server(handle_client, host=HOST, port=PORT)
        log.info(
            "Hybrid TCP/HTTP aktif di %s:%s; antrean Redis=%s workers=%d.",
            HOST,
            PORT,
            ALERT_QUEUE_STREAM,
            ALERT_WORKERS,
        )
        tasks = [
            asyncio.create_task(iris_monitor(redis), name="iris-alert-poller"),
            asyncio.create_task(external_data_poller(), name="external-data-poller"),
            *[
                asyncio.create_task(
                    alert_delivery_worker(redis, index),
                    name=f"iris-alert-worker-{index}",
                )
                for index in range(ALERT_WORKERS)
            ],
        ]
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("Gagal menjalankan stream IRIS.")
        raise
    finally:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if iris_http_client is not None:
            await iris_http_client.aclose()
            iris_http_client = None
        if external_http_client is not None:
            await external_http_client.aclose()
            external_http_client = None
        await redis.aclose()

if __name__ == '__main__':
    try: asyncio.run(main())
    except KeyboardInterrupt: log.info("Server dihentikan.")