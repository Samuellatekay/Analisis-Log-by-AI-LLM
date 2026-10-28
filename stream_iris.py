import asyncio
import json
import httpx
import os

IRIS_URL = os.getenv("IRIS_URL", "https://iris.example.local")
IRIS_API_KEY = os.getenv("IRIS_API_KEY", "")

if not IRIS_API_KEY:
    print("[!] PERINGATAN: IRIS_API_KEY kosong. Pastikan sudah diisi di .env")

IRIS_ALERTS_ENDPOINT = f"{IRIS_URL.rstrip('/')}/api/v2/alerts"

async def fetch_latest_alerts_from_iris():
    """Mengambil alert terbaru langsung dari IRIS secara real-time."""
    headers = {
        "Authorization": f"Bearer {IRIS_API_KEY}",
        "Content-Type": "application/json"
    }
    
    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        try:
            response = await client.get(
                IRIS_ALERTS_ENDPOINT, 
                headers=headers,
                params={"per_page": 5, "page": 1} 
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
                        
            payloads = []
            for alert in alerts:
                alert_id = alert.get("id")
                
                source_content = alert.get("alert_source_content", {})
                if isinstance(source_content, str):
                    try:
                        source_content = json.loads(source_content)
                    except json.JSONDecodeError:
                        pass

                original_log = source_content.get("original", "Data original tidak ditemukan di alert ini")
                if isinstance(original_log, str):
                    try:
                        original_log = json.loads(original_log)
                    except json.JSONDecodeError:
                        pass
                
                payload = {
                    "alert_title": alert.get("alert_title"),
                    "alert_description": alert.get("alert_description"),
                    "original": original_log,
                    "iris_alert_id": alert_id
                }
                payloads.append(payload)
                
            return payloads
                
        except Exception:
            return []

async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    print(f"[+] Klien terkoneksi dari {addr}")
    
    try:
        try:
            await asyncio.wait_for(reader.read(1024), timeout=1.0)
        except Exception:
            pass
            
        http_header = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Connection: keep-alive\r\n"
            "Cache-Control: no-cache\r\n"
            "\r\n"
        )
        writer.write(http_header.encode('utf-8'))
        await writer.drain()

        while True:
            payloads = await fetch_latest_alerts_from_iris()
            
            # HANYA KIRIM JIKA DATA ADA
            if payloads:
                for payload in payloads:
                    data_to_send = json.dumps(payload) + "\n"
                    writer.write(data_to_send.encode('utf-8'))
                    await writer.drain()
            
            # Cek berkala setiap 5 detik tanpa mencetak apa pun jika kosong
            await asyncio.sleep(5)
            
    except (ConnectionResetError, BrokenPipeError):
        print(f"[-] Klien {addr} terputus.")
    except Exception as e:
        print(f"[!] Error koneksi pada klien {addr}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

async def main():
    server = await asyncio.start_server(handle_client, '0.0.0.0', 17771)
    print(f"[*] Server streaming aktif di port 17771")

    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer streaming dihentikan.")