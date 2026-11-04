import asyncio
import json
import logging
import os

# ============================================================
# KONFIGURASI
# ============================================================

HOST = "0.0.0.0"
PORT = 17772
MAX_CACHE = 100  # Menyimpan 100 data terakhir untuk endpoint Snapshot (/)

logging.basicConfig(
    level="INFO",
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("receiver-17772")

# State global untuk menyimpan koneksi dan data
tcp_listeners = set()
http_listeners = set()
received_cache = []


# ============================================================
# FUNGSI PEMROSES & BROADCAST
# ============================================================

async def process_and_broadcast(payload: dict):
    """Menyimpan data ke cache dan mengirim ke semua listener yang terhubung"""
    # Simpan ke cache
    received_cache.append(payload)
    if len(received_cache) > MAX_CACHE:
        received_cache.pop(0)
    
    log.info("📥 Data diterima & disimpan. Cache size: %d", len(received_cache))
    
    # Format data untuk dikirim (JSON + newline)
    data_bytes = (json.dumps(payload, ensure_ascii=False, default=str) + "\n").encode("utf-8")
    
    # 1. Broadcast ke Raw TCP Listeners
    disconnected_tcp = []
    for writer in list(tcp_listeners):
        try:
            writer.write(data_bytes)
            await writer.drain()
        except (ConnectionError, OSError, BrokenPipeError):
            disconnected_tcp.append(writer)
    for w in disconnected_tcp:
        tcp_listeners.discard(w)
        w.close()

    # 2. Broadcast ke HTTP Stream Listeners
    disconnected_http = []
    for writer in list(http_listeners):
        try:
            writer.write(data_bytes)
            await writer.drain()
        except (ConnectionError, OSError, BrokenPipeError):
            disconnected_http.append(writer)
    for w in disconnected_http:
        http_listeners.discard(w)
        w.close()


# ============================================================
# HYBRID HANDLER (ROBUST: HTTP + TCP)
# ============================================================

async def handle_client(reader, writer):
    peer = writer.get_extra_info('peername')
    
    # 1. Baca data awal untuk mendeteksi jenis koneksi
    try:
        first_data = await asyncio.wait_for(reader.read(8192), timeout=2.0)
    except asyncio.TimeoutError:
        first_data = b""
    except Exception:
        first_data = b""

    # --- SKENARIO A: TCP LISTENER PASIF (Tidak mengirim data awal, hanya ingin menerima) ---
    if not first_data:
        log.info("🔌 TCP Listener terhubung (pasif): %s", peer)
        tcp_listeners.add(writer)
        try:
            while True: 
                await reader.read(4096) # Tunggu data dari server
        except Exception: 
            pass
        finally:
            tcp_listeners.discard(writer)
            writer.close()
        return

    # Decode data awal
    text = first_data.decode('utf-8', errors='ignore')
    first_line = text.split('\r\n')[0].split('\n')[0]
    
    # Deteksi HTTP yang aman (case-insensitive)
    is_http = first_line.upper().startswith(('GET ', 'POST ', 'HEAD ', 'PUT ', 'DELETE '))

    if is_http:
        parts = first_line.split(' ')
        method = parts[0].upper() if len(parts) > 0 else ""
        path = parts[1] if len(parts) > 1 else "/"

        # 1. Healthcheck (Untuk Docker)
        if path.upper() == '/HEALTH':
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            await writer.drain()
            writer.close()
            return

        # 2. HTTP Stream Listener (Real-time: /stream)
        if path.upper() == '/STREAM':
            log.info("🌐 HTTP Stream Listener terhubung: %s", peer)
            http_listeners.add(writer)
            header = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: keep-alive\r\n\r\n"
            writer.write(header)
            await writer.drain()
            try:
                while True: 
                    await reader.read(4096) # Biarkan koneksi tetap terbuka
            except Exception: 
                pass
            finally:
                http_listeners.discard(writer)
                writer.close()
            return

        # 3. HTTP GET Snapshot (Browser / Curl GET /)
        if method == 'GET' and (path == '/' or path.startswith('/?')):
            log.info("🌐 HTTP Snapshot request (Browser) dari %s", peer)
            body = json.dumps(received_cache, ensure_ascii=False, indent=2, default=str).encode("utf-8")
            response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("utf-8") + body
            writer.write(response)
            await writer.drain()
            writer.close()
            return

        # 4. HTTP POST Ingestion (Webhook dari VM)
        if method == 'POST':
            log.info("📤 Menerima HTTP POST dari %s", peer)
            header_end = text.find('\r\n\r\n')
            if header_end == -1: 
                header_end = text.find('\n\n')
            
            if header_end != -1:
                headers_part = text[:header_end]
                body_part = text[header_end+4:]
                
                # Parse Content-Length
                content_length = 0
                for line in headers_part.split('\r\n' if '\r\n' in headers_part else '\n'):
                    if line.lower().startswith('content-length:'):
                        try: 
                            content_length = int(line.split(':')[1].strip())
                        except: 
                            pass
                
                # Baca sisa body jika terpotong
                while len(body_part.encode('utf-8')) < content_length:
                    chunk = await reader.read(content_length - len(body_part.encode('utf-8')))
                    if not chunk: 
                        break
                    body_part += chunk.decode('utf-8', errors='ignore')
                
                try:
                    payload = json.loads(body_part.strip())
                    await process_and_broadcast(payload)
                    response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"status\": \"received\"}"
                except Exception as e:
                    log.error("❌ Gagal parse JSON POST: %s", e)
                    response = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nInvalid JSON"
                
                writer.write(response)
                await writer.drain()
                writer.close()
                return
            else:
                writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                writer.close()
                return

    # --- SKENARIO B: RAW TCP INGESTION (VM mengirim data mentah via netcat/socket) ---
    log.info("📤 Menerima Raw TCP Ingestion dari %s", peer)
    buffer = text 
    
    try:
        while True:
            # Proses baris per baris yang lengkap
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                line = line.strip()
                if line:
                    try:
                        payload = json.loads(line)
                        await process_and_broadcast(payload)
                    except json.JSONDecodeError:
                        # Abaikan baris yang bukan JSON (misal sisa header HTTP yang salah route)
                        pass 
            
            # Baca chunk data berikutnya
            data = await reader.read(4096)
            if not data: 
                break
            buffer += data.decode('utf-8', errors='ignore')
            
    except Exception as e:
        log.error("❌ Error TCP Ingestion: %s", e)
    finally:
        writer.close()


# ============================================================
# MAIN SERVER
# ============================================================

async def main():
    try:
        server = await asyncio.start_server(handle_client, host=HOST, port=PORT)
        log.info("🚀 Hybrid Receiver Server aktif di %s:%d", HOST, PORT)
        log.info("💡 VM Ingestion (TCP)   : nc <IP_SERVER> %d", PORT)
        log.info("💡 VM Ingestion (HTTP)  : curl -X POST -d '{...}' http://<IP_SERVER>:%d/", PORT)
        log.info("💡 Browser Viewer       : http://<IP_SERVER>:%d/", PORT)
        log.info("💡 Real-time Stream     : curl -N http://<IP_SERVER>:%d/stream", PORT)
        log.info("💡 Docker Healthcheck   : http://<IP_SERVER>:%d/health", PORT)
        
        async with server:
            await server.serve_forever()
            
    except OSError as e:
        log.critical("❌ GAGAL MEMULAI SERVER (Port mungkin sudah dipakai): %s", e)
    except Exception as e:
        log.critical("❌ GAGAL MEMULAI SERVER: %s", e)

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("🛑 Receiver dihentikan secara manual.")