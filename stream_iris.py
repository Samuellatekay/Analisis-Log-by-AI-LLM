
import asyncio
import json
import logging
import os
import ssl
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlparse

# ============================================================
# CONFIG
# ============================================================

HOST = "0.0.0.0"
PORT = int(os.getenv("IRIS_STREAM_PORT", "17771"))

# Harus berupa endpoint API JSON, bukan URL dashboard frontend.
IRIS_URL = os.getenv(
    "IRIS_URL",
    "https://iris.local/api/v2/alerts",
).strip().rstrip("/")

IRIS_API_KEY = os.getenv("IRIS_API_KEY", "").strip()

IRIS_VERIFY_SSL = os.getenv(
    "IRIS_VERIFY_SSL", "true"
).lower() in ("1", "true", "yes", "on")

IRIS_CA_CERT = os.getenv(
    "IRIS_CA_CERT", "/app/iris-ca.crt"
)

POLL_INTERVAL = max(
    1, float(os.getenv("IRIS_POLL_INTERVAL", "5"))
)

REQUEST_TIMEOUT = max(
    1, float(os.getenv("IRIS_REQUEST_TIMEOUT", "30"))
)

clients = set()
seen_alerts = set()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)

log = logging.getLogger("iris-stream")


# ============================================================
# CONFIG VALIDATION
# ============================================================

def validate_config():
    parsed = urlparse(IRIS_URL)

    if parsed.scheme not in ("https", "http") or not parsed.netloc:
        raise ValueError(
            f"IRIS_URL tidak valid: {IRIS_URL!r}"
        )

    # Mencegah dashboard HTML dianggap sebagai API JSON.
    if parsed.path in ("", "/"):
        raise ValueError(
            "IRIS_URL hanya menunjuk ke root/dashboard, bukan endpoint API. "
            "Atur IRIS_URL ke endpoint API JSON DFIR-IRIS di file .env."
        )

    if not IRIS_API_KEY:
        raise ValueError(
            "IRIS_API_KEY kosong. Periksa konfigurasi .env."
        )

    if IRIS_VERIFY_SSL and not os.path.isfile(IRIS_CA_CERT):
        raise FileNotFoundError(
            f"CA certificate tidak ditemukan: {IRIS_CA_CERT}"
        )


# ============================================================
# TLS
# ============================================================

def get_tls_context():
    if not IRIS_VERIFY_SSL:
        log.warning(
            "TLS verification dinonaktifkan. "
            "Jangan gunakan konfigurasi ini di produksi."
        )
        return ssl._create_unverified_context()

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
    payload = parse_json_if_string(payload)

    if isinstance(payload, list):
        return payload

    if not isinstance(payload, dict):
        return []

    # Format respons yang umum digunakan API.
    for key in ("alerts", "data", "results", "items"):
        value = parse_json_if_string(payload.get(key))

        if isinstance(value, list):
            return value

        if isinstance(value, dict):
            for nested_key in ("alerts", "results", "items"):
                nested = parse_json_if_string(value.get(nested_key))

                if isinstance(nested, list):
                    return nested

    # Respons berupa satu objek alert.
    if any(
        key in payload
        for key in ("alert_id", "id", "alert_title", "title")
    ):
        return [payload]

    return []


def normalize_alert(alert):
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
    context = get_tls_context()

    request = Request(
        IRIS_URL,
        headers={
            "Authorization": f"Bearer {IRIS_API_KEY}",
            "Accept": "application/json",
            "User-Agent": "IRIS-Alert-Stream/1.0",
        },
        method="GET",
    )

    try:
        with urlopen(
            request,
            timeout=REQUEST_TIMEOUT,
            context=context,
        ) as response:
            status = response.status
            content_type = response.headers.get("Content-Type", "")
            raw_body = response.read()

    except HTTPError as exc:
        error_body = exc.read().decode(
            "utf-8", errors="replace"
        )

        raise RuntimeError(
            f"IRIS API HTTP {exc.code}; URL={IRIS_URL}; "
            f"Content-Type={exc.headers.get('Content-Type', '')!r}; "
            f"body={error_body[:500]!r}"
        ) from exc

    except URLError as exc:
        raise RuntimeError(
            f"Tidak dapat menghubungi IRIS: {exc}; URL={IRIS_URL}"
        ) from exc

    body = raw_body.decode(
        "utf-8-sig", errors="replace"
    ).strip()

    if not body:
        raise RuntimeError(
            f"Respons IRIS kosong; HTTP={status}; "
            f"Content-Type={content_type!r}; URL={IRIS_URL}"
        )

    # Dashboard biasanya merespons HTML, bukan JSON.
    if (
        "text/html" in content_type.lower()
        or body[:100].lower().startswith(
            ("<!doctype html", "<html")
        )
    ):
        raise RuntimeError(
            "IRIS_URL mengembalikan HTML dashboard, bukan JSON API. "
            f"HTTP={status}; Content-Type={content_type!r}; "
            f"URL={IRIS_URL}; preview={body[:250]!r}. "
            "Periksa endpoint API DFIR-IRIS dan konfigurasi .env."
        )

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Respons IRIS bukan JSON valid; HTTP={status}; "
            f"Content-Type={content_type!r}; URL={IRIS_URL}; "
            f"body_preview={body[:500]!r}"
        ) from exc

    alerts = extract_alerts(payload)

    if not alerts and isinstance(payload, dict):
        log.warning(
            "JSON valid, tetapi struktur alert belum dikenali. "
            "Top-level keys=%s",
            list(payload.keys())[:30],
        )

    return [normalize_alert(alert) for alert in alerts]


async def fetch_latest_alerts():
    return await asyncio.to_thread(fetch_latest_alerts_sync)


# ============================================================
# HTTP JSON SERVER
# ============================================================

async def send_http_response(
    writer,
    status,
    reason,
    body,
    head_only=False,
):
    if isinstance(body, str):
        body = body.encode("utf-8")

    headers = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Cache-Control: no-store\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, HEAD, OPTIONS\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")

    writer.write(headers)

    if not head_only:
        writer.write(body)

    await writer.drain()


async def handle_http_request(reader, writer, initial_data):
    try:
        text = initial_data.decode(
            "iso-8859-1", errors="replace"
        )

        lines = text.splitlines()
        request_line = lines[0] if lines else ""
        parts = request_line.split()

        if len(parts) < 2:
            await send_http_response(
                writer, 400, "Bad Request",
                json.dumps({"error": "Invalid HTTP request"}),
            )
            return

        method, target = parts[0], parts[1]
        path = urlparse(target).path

        # Baca sisa HTTP headers.
        data = initial_data

        while b"\r\n\r\n" not in data:
            chunk = await asyncio.wait_for(
                reader.read(4096), timeout=3
            )

            if not chunk:
                break

            data += chunk

            if len(data) > 65536:
                raise ValueError("HTTP headers terlalu besar")

        if method == "OPTIONS":
            await send_http_response(
                writer, 204, "No Content", b""
            )
            return

        if method not in ("GET", "HEAD"):
            await send_http_response(
                writer, 405, "Method Not Allowed",
                json.dumps({"error": "Gunakan GET atau HEAD"}),
            )
            return

        if path not in ("/", "/alerts", "/api/alerts"):
            await send_http_response(
                writer, 404, "Not Found",
                json.dumps({
                    "error": "Endpoint lokal tidak ditemukan",
                    "available": ["/", "/alerts", "/api/alerts"],
                }),
                head_only=(method == "HEAD"),
            )
            return

        try:
            alerts = await fetch_latest_alerts()

            result = json.dumps(
                alerts,
                ensure_ascii=False,
                indent=2,
                default=str,
            )

            await send_http_response(
                writer, 200, "OK", result,
                head_only=(method == "HEAD"),
            )

        except Exception as exc:
            log.error("HTTP: gagal mengambil alert: %s", exc)

            await send_http_response(
                writer, 502, "Bad Gateway",
                json.dumps({
                    "error": "Gagal mengambil data dari IRIS API",
                    "detail": str(exc),
                }),
                head_only=(method == "HEAD"),
            )

    except Exception as exc:
        log.exception("HTTP handler error")

        try:
            await send_http_response(
                writer, 500, "Internal Server Error",
                json.dumps({
                    "error": "Internal server error",
                    "detail": str(exc),
                }),
            )
        except Exception:
            pass


# ============================================================
# TCP STREAMING
# ============================================================

async def send_to_client(writer, payload):
    message = json.dumps(
        payload,
        ensure_ascii=False,
        default=str,
    ) + "\n"

    writer.write(message.encode("utf-8"))
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
    peer = writer.get_extra_info("peername")
    clients.add(writer)

    log.info("TCP client terhubung: %s", peer)

    try:
        # Client TCP cukup terhubung untuk menerima alert.
        while await reader.read(4096):
            pass

    except (ConnectionError, OSError):
        pass

    finally:
        clients.discard(writer)

        if not writer.is_closing():
            writer.close()

        try:
            await writer.wait_closed()
        except Exception:
            pass

        log.info("TCP client terputus: %s", peer)


# ============================================================
# HTTP / TCP MULTIPLEXER - ONE PORT
# ============================================================

async def handle_client(reader, writer):
    peer = writer.get_extra_info("peername")

    try:
        try:
            initial_data = await asyncio.wait_for(
                reader.read(4096),
                timeout=0.7,
            )
        except asyncio.TimeoutError:
            initial_data = b""

        # TCP stream client biasanya tidak mengirim request awal.
        if not initial_data:
            await handle_tcp_client(reader, writer)
            return

        first_line = initial_data.split(b"\r\n", 1)[0]

        is_http = first_line.startswith((
            b"GET ",
            b"HEAD ",
            b"POST ",
            b"OPTIONS ",
        ))

        if is_http:
            log.info("HTTP request dari %s", peer)
            await handle_http_request(
                reader, writer, initial_data
            )
        else:
            log.info("TCP client terhubung: %s", peer)
            await handle_tcp_client(reader, writer)

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
    log.info("Polling IRIS: %s", IRIS_URL)

    while True:
        try:
            alerts = await fetch_latest_alerts()

            for alert in alerts:
                alert_id = alert.get("iris_alert_id")

                if alert_id is not None:
                    dedup_key = str(alert_id)
                else:
                    dedup_key = json.dumps(
                        alert, sort_keys=True, default=str
                    )

                if dedup_key in seen_alerts:
                    continue

                seen_alerts.add(dedup_key)

                if len(seen_alerts) > 10000:
                    seen_alerts.clear()
                    seen_alerts.add(dedup_key)

                log.info(
                    "Alert baru: id=%s title=%s",
                    alert_id,
                    alert.get("alert_title"),
                )

                await broadcast_alert(alert)

        except Exception as exc:
            log.error(
                "Gagal polling IRIS: %s",
                exc,
                exc_info=True,
            )

        await asyncio.sleep(POLL_INTERVAL)


# ============================================================
# MAIN
# ============================================================

async def main():
    validate_config()

    server = await asyncio.start_server(
        handle_client,
        HOST,
        PORT,
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
