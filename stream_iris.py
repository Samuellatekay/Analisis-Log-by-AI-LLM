
import asyncio
import json
import httpx
import os

# ============================================================
# KONFIGURASI IRIS
# ============================================================

IRIS_URL = os.getenv("IRIS_URL", "https://iris.local")
IRIS_API_KEY = os.getenv("IRIS_API_KEY", "")

# CA internal IRIS yang di-mount ke dalam container
IRIS_CA_CERT = os.getenv(
    "IRIS_CA_CERT",
    "/etc/ssl/custom/iris-ca.pem"
)

IRIS_ALERTS_ENDPOINT = (
    f"{IRIS_URL.rstrip('/')}/api/v2/alerts"
)

# ============================================================
# KONFIGURASI STREAMING
# ============================================================

HOST = "0.0.0.0"
PORT = 17771

POLL_INTERVAL = 1
PER_PAGE = 100

# Klien yang sedang terhubung
clients = set()

# ID alert yang sudah dikirim
sent_alert_ids = set()

# Mencegah pengiriman alert secara bersamaan
broadcast_lock = asyncio.Lock()


# ============================================================
# PARSING JSON
# ============================================================

def parse_json_if_string(value):
    """Parsing JSON jika input berupa string."""
    if not isinstance(value, str):
        return value

    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


def extract_alerts(data):
    """Mengambil daftar alert dari respons API IRIS."""
    if isinstance(data, list):
        return data

    if not isinstance(data, dict):
        return []

    inner_data = data.get("data")

    if isinstance(inner_data, list):
        return inner_data

    if isinstance(inner_data, dict):
        nested_data = inner_data.get("data")

        if isinstance(nested_data, list):
            return nested_data

    return []


# ============================================================
# NORMALISASI ALERT
# ============================================================

def normalize_alert(alert):
    """Mengambil informasi alert yang akan dikirim ke klien."""

    if not isinstance(alert, dict):
        return None

    alert_id = alert.get("id")

    if alert_id is None:
        alert_id = alert.get("alert_id")

    if alert_id is None:
        print("[!] Alert dilewati karena tidak memiliki ID.")
        return None

    source_content = parse_json_if_string(
        alert.get("alert_source_content", {})
    )

    if not isinstance(source_content, dict):
        source_content = {}

    original_log = parse_json_if_string(
        source_content.get(
            "original",
            "Data original tidak ditemukan di alert ini"
        )
    )

    return {
        "alert_title": alert.get("alert_title"),
        "alert_description": alert.get("alert_description"),
        "original": original_log,
        "iris_alert_id": alert_id
    }


# ============================================================
# FETCH ALERT DARI IRIS
# ============================================================

async def fetch_latest_alerts(client):
    """Mengambil alert terbaru dari API IRIS."""

    headers = {
        "Authorization": f"Bearer {IRIS_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        response = await client.get(
            IRIS_ALERTS_ENDPOINT,
            headers=headers,
            params={
                "per_page": PER_PAGE,
                "page": 1
            }
        )

        response.raise_for_status()

        data = response.json()

        return extract_alerts(data)

    except httpx.HTTPStatusError as exc:
        print(
            f"[!] HTTP Error IRIS: "
            f"{exc.response.status_code} - "
            f"{exc.response.text[:300]}"
        )

    except httpx.RequestError as exc:
        print(f"[!] Koneksi IRIS gagal: {exc}")

    except (json.JSONDecodeError, ValueError) as exc:
        print(f"[!] Respons JSON IRIS tidak valid: {exc}")

    except Exception as exc:
        print(f"[!] Error saat mengambil alert: {exc}")

    return []


# ============================================================
# KIRIM ALERT KE SATU KLIEN
# ============================================================

async def send_to_client(writer, payload):
    """Mengirim satu objek JSON dalam satu baris NDJSON."""

    message = json.dumps(
        payload,
        ensure_ascii=False,
        default=str
    ) + "\n"

    writer.write(message.encode("utf-8"))

    await writer.drain()


# ============================================================
# BROADCAST KE SELURUH KLIEN
# ============================================================

async def broadcast_alert(payload):
    """Mengirim alert baru ke semua klien yang terhubung."""

    disconnected = []
    success_count = 0

    async with broadcast_lock:
        for writer in list(clients):
            try:
                await send_to_client(writer, payload)
                success_count += 1

            except (
                ConnectionResetError,
                BrokenPipeError,
                OSError
            ) as exc:
                print(f"[!] Klien terputus saat pengiriman: {exc}")
                disconnected.append(writer)

            except Exception as exc:
                print(f"[!] Gagal mengirim alert: {exc}")
                disconnected.append(writer)

        for writer in disconnected:
            clients.discard(writer)
            writer.close()

    return success_count


# ============================================================
# MONITORING REAL-TIME IRIS
# ============================================================

async def iris_monitor():
    """Polling IRIS dan mengirim alert baru saja."""

    if not IRIS_API_KEY:
        print("[!] PERINGATAN: IRIS_API_KEY kosong.")

    # Verifikasi TLS tetap aktif menggunakan CA internal IRIS.
    if not os.path.isfile(IRIS_CA_CERT):
        print(
            f"[!] Sertifikat CA tidak ditemukan: {IRIS_CA_CERT}"
        )
        print(
            "[!] Pastikan CA di-mount ke container. "
            "Monitoring akan tetap berjalan dan mencoba kembali."
        )

    timeout = httpx.Timeout(10.0)

    while True:
        try:
            async with httpx.AsyncClient(
                verify=IRIS_CA_CERT,
                timeout=timeout
            ) as client:

                print("[*] Monitoring API IRIS dimulai.")

                while True:
                    alerts = await fetch_latest_alerts(client)

                    # Jika API mengembalikan alert terbaru lebih dahulu,
                    # proses secara terbalik agar alert lebih lama
                    # dikirim terlebih dahulu.
                    for alert in reversed(alerts):

                        payload = normalize_alert(alert)

                        if payload is None:
                            continue

                        alert_id = str(
                            payload["iris_alert_id"]
                        )

                        # Alert sudah pernah dikirim
                        if alert_id in sent_alert_ids:
                            continue

                        # Belum ada klien: jangan tandai sebagai terkirim.
                        if not clients:
                            continue

                        success_count = await broadcast_alert(payload)

                        # Tandai jika berhasil dikirim ke setidaknya
                        # satu klien yang terhubung.
                        if success_count > 0:
                            sent_alert_ids.add(alert_id)

                            print(
                                f"[+] Alert baru dikirim | "
                                f"ID={alert_id} | "
                                f"Judul={payload.get('alert_title')} | "
                                f"Klien={success_count}"
                            )

                    # Tidak ada alert baru berarti tidak ada data
                    # yang dikirim ke klien.
                    await asyncio.sleep(POLL_INTERVAL)

        except asyncio.CancelledError:
            raise

        except Exception as exc:
            print(f"[!] Monitoring IRIS error: {exc}")
            print("[*] Mencoba koneksi kembali dalam 5 detik.")
            await asyncio.sleep(5)


# ============================================================
# TCP CLIENT HANDLER
# ============================================================

async def handle_client(reader, writer):
    """Menangani koneksi TCP dari klien penerima."""

    addr = writer.get_extra_info("peername")

    print(f"[+] Klien terhubung: {addr}")

    clients.add(writer)

    try:
        # TCP streaming NDJSON.
        # Klien membaca data per baris, bukan HTTP.
        while True:
            data = await reader.read(1024)

            if not data:
                break

    except asyncio.CancelledError:
        raise

    except (
        ConnectionResetError,
        BrokenPipeError,
        OSError
    ):
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


# ============================================================
# MAIN SERVER
# ============================================================

async def main():

    server = await asyncio.start_server(
        handle_client,
        HOST,
        PORT
    )

    print("=" * 60)
    print("[*] IRIS ALERT STREAMING SERVER")
    print("=" * 60)
    print(f"[*] TCP Host       : {HOST}")
    print(f"[*] TCP Port       : {PORT}")
    print(f"[*] IRIS URL       : {IRIS_URL}")
    print(f"[*] IRIS Endpoint  : {IRIS_ALERTS_ENDPOINT}")
    print(f"[*] CA Certificate : {IRIS_CA_CERT}")
    print(f"[*] Poll Interval  : {POLL_INTERVAL} detik")
    print("[*] Mode           : Alert baru saja")
    print("[*] TLS Verify     : Aktif")
    print("=" * 60)

    monitor_task = asyncio.create_task(iris_monitor())

    try:
        async with server:
            await server.serve_forever()

    finally:
        monitor_task.cancel()

        await asyncio.gather(
            monitor_task,
            return_exceptions=True
        )

        for writer in list(clients):
            writer.close()

        await asyncio.gather(
            *[
                writer.wait_closed()
                for writer in list(clients)
            ],
            return_exceptions=True
        )

        print("[*] Server streaming dihentikan.")


if __name__ == "__main__":

    try:
        asyncio.run(main())

    except KeyboardInterrupt:
        print("\n[*] Server streaming dihentikan.")
