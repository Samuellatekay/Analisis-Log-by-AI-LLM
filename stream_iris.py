
import asyncio
import json
import logging
import os
import socket
import ssl
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlparse

# ============================================================
# CONFIGURATION
# ============================================================

HOST = "0.0.0.0"
PORT = int(os.getenv("IRIS_STREAM_PORT", "17771"))

IRIS_URL = os.getenv(
    "IRIS_URL",
    "https://iris.local/api/v2/alerts"
).rstrip("/")

IRIS_API_KEY = os.getenv("IRIS_API_KEY", "")

IRIS_VERIFY_SSL = os.getenv(
    "IRIS_VERIFY_SSL", "true"
).lower() in ("1", "true", "yes", "on")

IRIS_CA_CERT = os.getenv(
    "IRIS_CA_CERT", "/app/iris-ca.crt"
)

POLL_INTERVAL = float(os.getenv("IRIS_POLL_INTERVAL", "5"))
REQUEST_TIMEOUT = float(os.getenv("IRIS_REQUEST_TIMEOUT", "30"))

# Client TCP yang sedang terhubung
clients = set()

# Hindari mengirim alert yang sama berulang kali
seen_alerts = set()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s"
)

log = logging.getLogger("iris-stream")


# ============================================================
# TLS
# ============================================================

def get_tls_context():
    if not IRIS_VERIFY_SSL:
        log.warning("IRIS TLS certificate verification DISABLED")
        return ssl._create_unverified_context()

    if not os.path.isfile(IRIS_CA_CERT):
        raise FileNotFoundError(
            f"CA certificate tidak ditemukan: {IRIS_CA_CERT}"
        )

    return ssl.create_default_context(cafile=IRIS_CA_CERT)


# ============================================================
# JSON HELPERS
# ============================================================

def parse_json_if_string(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value

    return value


def extract_alerts(payload):
    """
    Mendukung respons IRIS berbentuk:
      - list alert
      - {"data": [...]}
      - {"alerts": [...]}
      - {"data": {"alerts": [...]}}
      - satu objek alert
    """
    payload = parse_json_if_string(payload)

    if isinstance(payload, list):
        return payload

    if not isinstance(payload, dict):
        return []

    for key in ("alerts", "data", "results", "items"):
        value = parse_json_if_string(payload.get(key))

        if isinstance(value, list):
            return value

        if isinstance(value, dict):
            for nested_key in ("alerts", "results", "items"):
                nested = parse_json_if_string(value.get(nested_key))
                if isinstance(nested, list):
                    return nested

    # Respons API mungkin membungkus satu alert di dalam data.
    data = parse_json_if_string(payload.get("data"))
    if isinstance(data, dict):
        payload = data

    if any(
        key in payload
        for key in ("alert_id", "id", "alert_title", "title")
    ):
        return [payload]

    return []


def normalize_alert(alert):
    """
    Normalisasi satu alert untuk HTTP dan TCP.
    Data asli tetap disimpan di field 'original'.
    """
    if not isinstance(alert, dict):
        alert = {"value": alert}

    alert_id = (
        alert.get("alert_id")
        or alert.get("id")
        or alert.get("alert_uuid")
    )

    title = (
        alert.get("alert_title")
        or alert.get("title")
        or alert.get("name")
        or "IRIS Alert"
    )

    description = (
        alert.get("alert_description")
        or alert.get("description")
        or alert.get("details")
        or ""
    )

    result = {
        "alert_title": title,
        "alert_description": description,
        "original": alert,
    }

    if alert_id is not None:
        try:
            result["iris_alert_id"] = int(alert_id)
        except (ValueError, TypeError):
            result["iris_alert_id"] = alert_id

    return result


# ============================================================
# IRIS API REQUEST
# ============================================================

def fetch_latest_alerts_sync():
    """
    Mengambil alert dari IRIS menggunakan urllib.
    Fungsi sinkron ini dijalankan melalui asyncio.to_thread().
    """
    if not IRIS_API_KEY:
        raise RuntimeError("IRIS_API_KEY belum diatur di .env")

    headers = {
        "Authorization": f"Bearer {IRIS_API_KEY}",
        "Accept": "application/json",
        "User-Agent": "IRIS-Alert-Stream/1.0",
    }

    request = Request(
        IRIS_URL,
        headers=headers,
        method="GET",
    )

    context = get_tls_context()

    with urlopen(
        request,
        timeout=REQUEST_TIMEOUT,
        context=context,
    ) as response:
        body = response.read().decode("utf-8")
        payload = json.loads(body)

    alerts = extract_alerts(payload)
    return [normalize_alert(alert) for alert in alerts]


async def fetch_latest_alerts():
    return await asyncio.to_thread(fetch_latest_alerts_sync)


# ============================================================
# HTTP RESPONSE
# ============================================================

async def send_http_response(
    writer,
    status_code,
    reason,
    body,
    content_type="application/json; charset=utf-8",
):
    if isinstance(body, str):
        body = body.encode("utf-8")

    headers = (
        f"HTTP/1.1 {status_code} {reason}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "\r\n"
    ).encode("ascii")

    writer.write(headers + body)
    await writer.drain()


async def handle_http_request(reader, writer, first_data):
    """
    Menangani HTTP di port yang sama dengan TCP streaming.
    Endpoint GET / mengembalikan array alert dalam JSON.
    """
    try:
        request_text = first_data.decode("iso-8859-1", errors="replace")
        request_line = request_text.splitlines()[0] if request_text else ""
        parts = request_line.split()

        if len(parts) < 2:
            await send_http_response(
                writer, 400, "Bad Request",
                json.dumps({"error": "Invalid HTTP request"})
            )
            return

        method, path = parts[0], urlparse(parts[1]).path

        # Baca sisa header jika belum diterima bersama data awal.
        while b"\r\n\r\n" not in first_data:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=2)
            if not chunk:
                break
            first_data += chunk
            if len(first_data) > 65536:
                raise ValueError("HTTP headers terlalu besar")

        if method == "OPTIONS":
            await send_http_response(
                writer,
                204,
                "No Content",
                b"",
            )
            return

        if method not in ("GET", "HEAD"):
            await send_http_response(
                writer, 405, "Method Not Allowed",
                json.dumps({"error": "Gunakan GET atau HEAD"})
            )
            return

        if path not in ("/", "/alerts", "/api/alerts"):
            await send_http_response(
                writer, 404, "Not Found",
                json.dumps({
                    "error": "Endpoint tidak ditemukan",
                    "available_endpoints": [
                        "/", "/alerts", "/api/alerts"
                    ]
                })
            )
            return

        alerts = await fetch_latest_alerts()
        body = json.dumps(
            alerts,
            ensure_ascii=False,
            indent=2,
            default=str,
        )

        if method == "HEAD":
            await send_http_response(
                writer, 200, "OK", b""
            )
        else:
            await send_http_response(
                writer, 200, "OK", body
            )

    except HTTPError as exc:
        body = json.dumps({
            "error": "IRIS API HTTP error",
            "status": exc.code,
            "detail": exc.read().decode("utf-8", errors="replace"),
        })
        await send_http_response(
            writer, 502, "Bad Gateway", body
        )

    except (URLError, ssl.SSLError, TimeoutError) as exc:
        log.exception("Gagal mengambil data IRIS melalui HTTP")
        await send_http_response(
            writer, 502, "Bad Gateway",
            json.dumps({
                "error": "Tidak dapat mengambil alert dari IRIS",
                "detail": str(exc),
            })
        )

    except Exception as exc:
        log.exception("HTTP handler error")
        try:
            await send_http_response(
                writer, 500, "Internal Server Error",
                json.dumps({
                    "error": "Internal server error",
                    "detail": str(exc),
                })
            )
        except Exception:
            pass


# ============================================================
# TCP STREAMING
# ============================================================

async def send_to_client(writer, payload):
    data = (
        json.dumps(payload, ensure_ascii=False, default=str) + "\n"
    ).encode("utf-8")

    writer.write(data)
    await writer.drain()


async def broadcast_alert(payload):
    disconnected = []

    for writer in list(clients):
        try:
            await send_to_client(writer, payload)
        except (ConnectionError, OSError):
            disconnected.append(writer)

    for writer in disconnected:
        clients.discard(writer)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def handle_tcp_client(reader, writer):
    """
    TCP client menerima JSON Lines untuk setiap alert baru.
    Koneksi tetap terbuka sampai client memutuskan koneksi.
    """
    peer = writer.get_extra_info("peername")
    log.info("TCP client terhubung: %s", peer)

    clients.add(writer)

    try:
        # Tunggu sampai client menutup koneksi.
        # Streaming tidak mensyaratkan client mengirim data.
        while await reader.read(4096):
            pass
    except (ConnectionError, OSError):
        pass
    finally:
        clients.discard(writer)
        writer.close()

        try:
            await writer.wait_closed()
        except Exception:
            pass

        log.info("TCP client terputus: %s", peer)


# ============================================================
# MULTIPLEXER: HTTP + TCP ON THE SAME PORT
# ============================================================

async def handle_client(reader, writer):
    """
    Membedakan HTTP browser dan TCP streaming pada port 17771.
    Browser mengirim GET/HEAD; TCP streaming biasanya menunggu
    data tanpa mengirim request.
    """
    peer = writer.get_extra_info("peername")

    try:
        try:
            first_data = await asyncio.wait_for(
                reader.read(4096),
                timeout=0.7,
            )
        except asyncio.TimeoutError:
            first_data = b""

        if not first_data:
            # TCP streaming client biasanya langsung menunggu alert.
            await handle_tcp_client(reader, writer)
            return

        first_line = first_data.split(b"\r\n", 1)[0]
        is_http = first_line.startswith((
            b"GET ",
            b"HEAD ",
            b"POST ",
            b"OPTIONS ",
        ))

        if is_http:
            log.info("HTTP request dari %s", peer)
            await handle_http_request(reader, writer, first_data)
        else:
            # Client TCP mengirim payload awal: pertahankan koneksi.
            # Data awal tidak diproses sebagai perintah aplikasi.
            log.info("TCP client mengirim data awal: %s", peer)
            clients.add(writer)

            try:
                while await reader.read(4096):
                    pass
            finally:
                clients.discard(writer)

    except Exception:
        log.exception("Client handler gagal: %s", peer)

    finally:
        if not writer.is_closing():
            writer.close()

        try:
            await writer.wait_closed()
        except Exception:
            pass


# ============================================================
# IRIS POLLING
# ============================================================

async def iris_monitor():
    log.info("IRIS polling aktif: %s", IRIS_URL)

    while True:
        try:
            alerts = await fetch_latest_alerts()

            for alert in alerts:
                alert_id = alert.get("iris_alert_id")

                # Gunakan ID IRIS jika tersedia. Jika tidak, gunakan
                # representasi JSON agar alert yang sama tidak terus
                # dikirim pada setiap polling.
                dedup_key = (
                    str(alert_id)
                    if alert_id is not None
                    else json.dumps(
                        alert, sort_keys=True, default=str
                    )
                )

                if dedup_key in seen_alerts:
                    continue

                seen_alerts.add(dedup_key)

                # Batasi memori jika API mengembalikan banyak alert.
                if len(seen_alerts) > 10000:
                    seen_alerts.clear()
                    seen_alerts.add(dedup_key)

                log.info(
                    "Alert baru: id=%s title=%s",
                    alert_id,
                    alert.get("alert_title"),
                )

                await broadcast_alert(alert)

        except Exception:
            log.exception("Gagal polling IRIS")

        await asyncio.sleep(POLL_INTERVAL)


# ============================================================
# MAIN
# ============================================================

async def main():
    if IRIS_VERIFY_SSL:
        get_tls_context()

    server = await asyncio.start_server(
        handle_client,
        host=HOST,
        port=PORT,
    )

    log.info(
        "HTTP JSON dan TCP streaming aktif di %s:%s",
        HOST,
        PORT,
    )
    log.info("HTTP URL: http://192.168.51.39:%s/", PORT)
    log.info("TCP endpoint: 192.168.51.39:%s", PORT)

    monitor_task = asyncio.create_task(iris_monitor())

    try:
        async with server:
            await server.serve_forever()
    finally:
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("IRIS stream dihentikan")
