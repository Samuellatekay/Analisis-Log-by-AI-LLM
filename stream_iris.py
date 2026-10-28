
import asyncio
import json
import httpx
import os

IRIS_URL = os.getenv("IRIS_URL", "https://iris.example.local")
IRIS_API_KEY = os.getenv("IRIS_API_KEY", "")

HOST = "0.0.0.0"
PORT = 17771
POLL_INTERVAL = 1
PER_PAGE = 100

IRIS_ALERTS_ENDPOINT = f"{IRIS_URL.rstrip('/')}/api/v2/alerts"

# Kumpulan klien TCP yang sedang terhubung.
clients = set()

# ID alert yang sudah pernah dikirim selama proses berjalan.
sent_alert_ids = set()

# Lock untuk mencegah pengiriman bersamaan.
broadcast_lock = asyncio.Lock()


def parse_json_if_string(value):
    """Mengubah JSON string menjadi objek Python jika memungkinkan."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value
    return value


def extract_alerts(data):
    """Mendukung beberapa bentuk respons JSON IRIS."""
    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        inner = data.get("data")

        if isinstance(inner, list):
            return inner

        if isinstance(inner, dict):
            nested = inner.get("data")
            if isinstance(nested, list):
                return nested

    return []


async def fetch_latest_alerts(client):
    """Mengambil alert terbaru dari IRIS."""
    headers = {
        "Authorization": f"Bearer {IRIS_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    try:
        response = await client.get(
            IRIS_ALERTS_ENDPOINT,
            headers=headers,
            params={
                "per_page": PER_PAGE,
                "page": 1,
            },
        )
        response.raise_for_status()

        return extract_alerts(response.json())

    except httpx.HTTPStatusError as exc:
        print(
            f"[!] IRIS HTTP {exc.response.status_code}: "
            f"{exc.response.text[:300]}"
        )
    except (httpx.RequestError, json.JSONDecodeError) as exc:
        print(f"[!] Gagal mengambil alert IRIS: {exc}")
    except Exception as exc:
        print(f"[!] Kesalahan saat membaca IRIS: {exc}")

    return []


def normalize_alert(alert):
    """Mengambil field yang dibutuhkan dari alert IRIS."""
    if not isinstance(alert, dict):
        return None

    alert_id = alert.get("id")
    if alert_id is None:
        alert_id = alert.get("alert_id")

    if alert_id is None:
        # Tanpa ID stabil, deduplikasi tidak dapat dijamin.
        return None

    source_content = parse_json_if_string(
        alert.get("alert_source_content", {})
    )

    if not isinstance(source_content, dict):
        source_content = {}

    original_log = parse_json_if_string(
        source_content.get("original", {})
    )

    return {
        "alert_title": alert.get("alert_title"),
        "alert_description": alert.get("alert_description"),
        "original": original_log,
        "iris_alert_id": alert_id,
    }


async def send_to_client(writer, message):
    """Mengirim satu pesan JSON per baris."""
    writer.write(
        (json.dumps(message, ensure_ascii=False, default=str) + "\n").encode(
            "utf-8"
        )
    )
    await writer.drain()


async def broadcast_alert(payload):
    """Mengirim alert baru ke seluruh klien yang aktif."""
    disconnected = []

    async with broadcast_lock:
        for writer in list(clients):
            try:
                await send_to_client(writer, payload)
            except (ConnectionResetError, BrokenPipeError, OSError):
                disconnected.append(writer)
            except Exception as exc:
                print(f"[!] Gagal mengirim ke klien: {exc}")
                disconnected.append(writer)

        for writer in disconnected:
            clients.discard(writer)
            writer.close()


async def iris_monitor():
    """Polling IRIS dan menyiarkan hanya alert yang baru."""
    if not IRIS_API_KEY:
        print("[!] IRIS_API_KEY kosong. Periksa file .env.")

    timeout = httpx.Timeout(10.0)

    async with httpx.AsyncClient(
        verify=os.getenv("IRIS_VERIFY_TLS", "true").lower()
        in ("1", "true", "yes"),
        timeout=timeout,
    ) as client:
        while True:
            alerts = await fetch_latest_alerts(client)

            # Proses dari yang paling lama ke yang paling baru,
            # jika API mengembalikan data terbaru terlebih dahulu.
            for alert in reversed(alerts):
                payload = normalize_alert(alert)

                if payload is None:
                    continue

                alert_id = str(payload["iris_alert_id"])

                if alert_id in sent_alert_ids:
                    continue

                # Tandai hanya setelah pengiriman berhasil ke setidaknya
                # satu klien. Jika belum ada klien, alert akan dicoba lagi.
                if not clients:
                    continue

                await broadcast_alert(payload)
                sent_alert_ids.add(alert_id)

                print(
                    f"[+] Alert baru dikirim: "
                    f"ID={alert_id} | "
                    f"Judul={payload.get('alert_title')}"
                )

            await asyncio.sleep(POLL_INTERVAL)


async def handle_client(reader, writer):
    """Melayani koneksi TCP dan mengirim stream NDJSON."""
    addr = writer.get_extra_info("peername")
    print(f"[+] Klien terhubung: {addr}")

    try:
        # Protokol ini mengirim NDJSON melalui TCP, bukan HTTP.
        # Klien harus membaca satu baris JSON setiap pesan.
        clients.add(writer)

        while not reader.at_eof():
            # Menunggu klien menutup koneksi.
            data = await reader.read(1024)
            if not data:
                break

    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as exc:
        print(f"[!] Error klien {addr}: {exc}")
    finally:
        clients.discard(writer)
        writer.close()

        try:
            await writer.wait_closed()
        except Exception:
            pass

        print(f"[-] Klien terputus: {addr}")


async def main():
    if not IRIS_API_KEY:
        print("[!] Isi IRIS_API_KEY sebelum menjalankan server.")

    server = await asyncio.start_server(
        handle_client,
        HOST,
        PORT,
    )

    print(f"[*] TCP streaming aktif di {HOST}:{PORT}")
    print(f"[*] Interval polling IRIS: {POLL_INTERVAL} detik")
    print("[*] Hanya alert baru yang akan dikirim.")

    monitor_task = asyncio.create_task(iris_monitor())

    try:
        async with server:
            await server.serve_forever()
    finally:
        monitor_task.cancel()
        await asyncio.gather(monitor_task, return_exceptions=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Server streaming dihentikan.")
