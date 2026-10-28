
import asyncio
import json
import httpx
import os

# ============================================================
# KONFIGURASI
# ============================================================

IRIS_URL = os.getenv("IRIS_URL", "https://iris.local")
IRIS_API_KEY = os.getenv("IRIS_API_KEY", "")

IRIS_VERIFY_SSL = os.getenv(
    "IRIS_VERIFY_SSL", "true"
).strip().lower() in ("1", "true", "yes", "on")

IRIS_CA_CERT = os.getenv(
    "IRIS_CA_CERT",
    "/etc/ssl/custom/iris-ca.pem"
)

HOST = "0.0.0.0"
PORT = 17771

POLL_INTERVAL = 1
PER_PAGE = 100

IRIS_ALERTS_ENDPOINT = (
    f"{IRIS_URL.rstrip('/')}/api/v2/alerts"
)

# Klien TCP aktif
clients = set()

# ID alert yang sudah berhasil dikirim selama proses berjalan
sent_alert_ids = set()

broadcast_lock = asyncio.Lock()


# ============================================================
# PARSING DATA
# ============================================================

def parse_json_if_string(value):
    if not isinstance(value, str):
        return value

    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


def extract_alerts(data):
    if isinstance(data, list):
        return data

    if not isinstance(data, dict):
        return []

    inner = data.get("data")

    if isinstance(inner, list):
        return inner

    if isinstance(inner, dict):
        nested = inner.get("data")
        if isinstance(nested, list):
            return nested

    return []


def normalize_alert(alert):
    if not isinstance(alert, dict):
        return None

    alert_id = alert.get("id")

    if alert_id is None:
        alert_id = alert.get("alert_id")

    if alert_id is None:
        print("[!] Alert dilewati: ID tidak tersedia.")
        return None

    source_content = parse_json_if_string(
        alert.get("alert_source_content", {})
    )

    if not isinstance(source_content, dict):
        source_content = {}

    original = parse_json_if_string(
        source_content.get(
            "original",
            "Data original tidak ditemukan di alert ini"
        )
    )

    return {
        "alert_title": alert.get("alert_title"),
        "alert_description": alert.get("alert_description"),
        "original": original,
        "iris_alert_id": alert_id
    }


# ============================================================
# KONFIGURASI TLS
# ============================================================

def get_tls_verify():
    """
    Verifikasi TLS selalu aktif.
    Jika CA internal disediakan, gunakan CA tersebut.
    Jika tidak, gunakan CA bawaan sistem.
    """

    if not IRIS_VERIFY_SSL:
        raise RuntimeError(
            "IRIS_VERIFY_SSL=false tidak diizinkan. "
            "Aktifkan verifikasi TLS."
        )

    if IRIS_CA_CERT:
        if not os.path.isfile(IRIS_CA_CERT):
            raise FileNotFoundError(
                f"CA IRIS tidak ditemukan: {IRIS_CA_CERT}. "
                "Pastikan file tersedia dan di-mount ke container."
            )

        return IRIS_CA_CERT

    return True


# ============================================================
# AMBIL ALERT DARI IRIS
# ============================================================

async def fetch_latest_alerts(client):
    headers = {
        "Authorization": f"Bearer {IRIS_API_KEY}",
        "Accept": "application/json",
        "Content-Type": "application/json"
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

        return extract_alerts(response.json())

    except httpx.HTTPStatusError as exc:
        print(
            f"[!] HTTP IRIS {exc.response.status_code}: "
            f"{exc.response.text[:300]}"
        )

    except httpx.RequestError as exc:
        print(f"[!] Koneksi IRIS gagal: {exc}")

    except (json.JSONDecodeError, ValueError) as exc:
        print(f"[!] Respons IRIS tidak valid: {exc}")

    except Exception as exc:
        print(f"[!] Gagal membaca alert IRIS: {exc}")

    return []


# ============================================================
# KIRIM DATA KE KLIEN
# ============================================================

async def send_to_client(writer, payload):
    message = json.dumps(
        payload,
        ensure_ascii=False,
        default=str
    ) + "\n"

    writer.write(message.encode("utf-8"))
    await writer.drain()


async def broadcast_alert(payload):
    """
    Broadcast alert ke seluruh klien yang aktif.
    Mengembalikan jumlah klien yang berhasil menerima data.
    """

    disconnected = []
    success_count = 0

    async with broadcast_lock:
        for writer in list(clients):
            try:
                await send_to_client(writer, payload)
                success_count += 1

            except (ConnectionResetError, BrokenPipeError, OSError) as exc:
                print(f"[!] Koneksi klien gagal: {exc}")
                disconnected.append(writer)

            except Exception as exc:
                print(f"[!] Pengiriman ke klien gagal: {exc}")
                disconnected.append(writer)

        for writer in disconnected:
            clients.discard(writer)
            writer.close()

    return success_count


# ============================================================
# MONITORING ALERT BARU
# ============================================================

async def iris_monitor():
    if not IRIS_API_KEY:
        print("[!] PERINGATAN: IRIS_API_KEY kosong.")

    while True:
        try:
            tls_verify = get_tls_verify()

            async with httpx.AsyncClient(
                verify=tls_verify,
                timeout=httpx.Timeout(10.0)
            ) as client:

                print("[*] Koneksi TLS IRIS berhasil dikonfigurasi.")

                while True:
                    alerts = await fetch_latest_alerts(client)

                    # Proses alert lama terlebih dahulu jika API
                    # mengembalikan data terbaru pada posisi pertama.
                    for alert in reversed(alerts):
                        payload = normalize_alert(alert)

                        if payload is None:
                            continue

                        alert_id = str(payload["iris_alert_id"])

                        # Tidak mengirim alert yang sudah pernah dikirim.
                        if alert_id in sent_alert_ids:
                            continue

                        # Jika tidak ada klien, jangan tandai terkirim.
                        if not clients:
                            continue

                        success_count = await broadcast_alert(payload)

                        if success_count > 0:
                            sent_alert_ids.add(alert_id)

                            print(
                                f"[+] Alert baru dikirim | "
                                f"ID={alert_id} | "
                                f"Judul={payload.get('alert_title')} | "
                                f"Klien={success_count}"
                            )

                    # Jika tidak ada alert baru, tidak ada pesan
                    # yang dikirim ke klien.
                    await asyncio.sleep(POLL_INTERVAL)

        except asyncio.CancelledError:
            raise

        except Exception as exc:
            print(f"[!] Monitoring IRIS error: {exc}")
            print("[*] Mencoba kembali dalam 5 detik.")
            await asyncio.sleep(5)


# ============================================================
# TCP SERVER
# ============================================================

async def handle_client(reader, writer):
    addr = writer.get_extra_info("peername")

    print(f"[+] Klien terhubung: {addr}")
    clients.add(writer)

    try:
        # TCP NDJSON: setiap pesan diakhiri newline.
        while True:
            data = await reader.read(1024)

            if not data:
                break

    except asyncio.CancelledError:
        raise

    except (ConnectionResetError, BrokenPipeError, OSError):
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
# MAIN
# ============================================================

async def main():
    if not IRIS_VERIFY_SSL:
        raise RuntimeError(
            "TLS verification wajib aktif. "
            "Periksa IRIS_VERIFY_SSL di .env."
        )

    print("=" * 60)
    print("[*] IRIS REAL-TIME ALERT STREAM")
    print("=" * 60)
    print(f"[*] IRIS URL       : {IRIS_URL}")
    print(f"[*] API Endpoint   : {IRIS_ALERTS_ENDPOINT}")
    print(f"[*] CA Certificate : {IRIS_CA_CERT}")
    print(f"[*] TLS Verify     : {IRIS_VERIFY_SSL}")
    print(f"[*] TCP Host       : {HOST}")
    print(f"[*] TCP Port       : {PORT}")
    print(f"[*] Poll Interval  : {POLL_INTERVAL}s")
    print("=" * 60)

    server = await asyncio.start_server(
        handle_client,
        HOST,
        PORT
    )

    monitor_task = asyncio.create_task(iris_monitor())

    try:
        async with server:
            print(f"[*] TCP streaming aktif di {HOST}:{PORT}")
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
