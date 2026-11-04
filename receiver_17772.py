import asyncio
import json
import logging
import os

# ============================================================
# KONFIGURASI
# ============================================================

HOST = "0.0.0.0"
PORT = 17772
MAX_CACHE = 100  # Menyimpan 100 data terakhir untuk ditampilkan di browser

logging.basicConfig(
    level="INFO",
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("receiver-17772")

# State global
tcp_listeners = set()
http_listeners = set()
received_cache = []


# ============================================================
# FUNGSI PEMROSES & BROADCAST
# ============================================================

async def process_and_broadcast(payload: dict):
    """Menyimpan data ke cache dan mengirim ke semua listener"""
    # Simpan ke cache (untuk browser GET /)
    received_cache.append(payload)
    if len(received_cache) > MAX_CACHE:
        received_cache.pop(0)
    
    log.info("📥 Data diterima & disimpan. Cache size: %d", len(received_cache))
    
    # Broadcast ke semua TCP & HTTP listeners
    data_bytes = (json.dumps(payload, ensure_ascii=False, default=str) + "\n").encode("utf-8")
    
    disconnected_tcp = []
    for writer in list(tcp_listeners):
        try:
            writer.write(data_bytes)
            await writer.drain()
        except (ConnectionError, OSError, BrokenPipeError):
            disconnected_tcp.append(writer)
    for w in disconnected_tcp:
        tcp_listeners.discard(w); w.close()

    disconnected_http = []
    for writer in list(http_listeners):
        try:
            writer.write(data_bytes)
            await writer.drain()
        except (ConnectionError, OSError, BrokenPipeError):
            disconnected_http.append(writer)
    for w in disconnected_http:
        http_listeners.discard(w); w.close()


# ============================================================
# HYBRID HANDLER
# ============================================================

async def handle_client(reader, writer):
    peer = writer.get_extra_info('peername')
    
    # 1. Baca data awal untuk deteksi jenis koneksi
    try:
        first_data = await asyncio.wait_for(reader.read(4096), timeout=2.0)
    except asyncio.TimeoutError:
        first_data = b""
    except Exception:
        first_data = b""

    # --- SKENARIO A: TCP LISTENER (Pasif, tidak kirim data awal) ---
    if not first_data:
        log.info("🔌 TCP Listener terhubung (pasif): %s", peer)
        tcp_listeners.add(writer)
        try:
            while True: await reader.read(4096)
        except Exception: pass
        finally:
            tcp_listeners.discard(writer); writer.close()
        return

    # Decode data awal
    try:
        text = first_data.decode('utf-8', errors='ignore')
        first_line = text.split('\r\n')[0].split('\n')[0].upper()
        path = text.split('\r\n')[0].split('\n')[0].split(' ')[1] if ' ' in text.split('\r\n')[0] else '/'
    except Exception:
        first_line = ""; path = "/"

    # --- SKENARIO B: HTTP REQUEST ---
    if first_line.startswith(('GET ', 'POST ', 'HEAD ')):
        
        # 1. Healthcheck (Docker)
        if "/HEALTH" in first_line:
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            await writer.drain(); writer.close(); return

        # 2. HTTP Stream Listener (Real-time)
        if path == "/STREAM":
            log.info("🌐 HTTP Stream Listener terhubung: %s", peer)
            http_listeners.add(writer)
            header = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: keep-alive\r\n\r\n"
            writer.write(header); await writer.drain()
            try:
                while True: await reader.read(4096)
            except Exception: pass
            finally:
                http_listeners.discard(writer); writer.close()
            return

        # 3. HTTP Snapshot (Browser / Curl GET /)
        if path == "/" or path.startswith("/?"):
            log.info("🌐 HTTP Snapshot request (Browser) dari %s", peer)
            body = json.dumps(received_cache, ensure_ascii=False, indent=2, default=str).encode("utf-8")
            response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("utf-8") + body
            writer.write(response); await writer.drain(); writer.close(); return

        # 4. HTTP POST (Ingestion dari VM via Webhook/curl)
        if first_line.startswith('POST '):
            log.info("📤 Menerima HTTP POST dari %s", peer)
            # Baca seluruh body HTTP
            raw_text = text
            while '\r\n\r\n' not in raw_text and '\n\n' not in raw_text:
                chunk = await reader.read(4096)
                if not chunk: break
                raw_text += chunk.decode('utf-8', errors='ignore')
            
            # Pisahkan Header dan Body
            if '\r\n\r\n' in raw_text:
                header_part, body = raw_text.split('\r\n\r\n', 1)
            elif '\n\n' in raw_text:
                header_part, body = raw_text.split('\n\n', 1)
            else:
                body = ""
            
            # Parse Content-Length
            content_length = 0
            for line in header_part.split('\r\n' if '\r\n' in header_part else '\n'):
                if line.lower().startswith('content-length:'):
                    try: content_length = int(line.split(':')[1].strip())
                    except: pass
            
            # Baca sisa body jika terpotong
            while len(body.encode('utf-8')) < content_length:
                chunk = await reader.read(content_length - len(body.encode('utf-8')))
                if not chunk: break
                body += chunk.decode('utf-8', errors='ignore')
            
            try:
                payload = json.loads(body.strip())
                await process_and_broadcast(payload)
                response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"status\": \"received\"}"
            except Exception as e:
                log.error("❌ Gagal parse JSON POST: %s", e)
                response = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nInvalid JSON"
            
            writer.write(response); await writer.drain(); writer.close(); return

    # --- SKENARIO C: RAW TCP INGESTION (VM mengirim data mentah) ---
    log.info("📤 Menerima Raw TCP Ingestion dari %s", peer)
    buffer = text # Masukkan first_data ke buffer
    
    try:
        while True:
            # Proses baris per baris
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                line = line.strip()
                if line:
                    try:
                        payload = json.loads(line)
                        await process_and_broadcast(payload)
                    except json.JSONDecodeError:
                        log.warning("⚠️ Bukan JSON valid: %s", line[:50])
            
            # Baca chunk berikutnya
            data = await reader.read(4096)
            if not data: break
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
        log.info("💡 VM Ingestion (TCP): nc 192.168.51.39 %d", PORT)
        log.info("💡 VM Ingestion (HTTP): curl -X POST -d '{...}' http://192.168.51.39:%d/receive", PORT)
        log.info("💡 Browser Viewer: http://192.168.51.39:%d/", PORT)
        log.info("💡 Real-time Stream: curl -N http://192.168.51.39:%d/stream", PORT)
        
        async with server:
            await server.serve_forever()
    except OSError as e:
        log.critical("❌ GAGAL MEMULAI SERVER: %s", e)
    except Exception as e:
        log.critical("❌ GAGAL MEMULAI SERVER: %s", e)

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("🛑 Receiver dihentikan.")