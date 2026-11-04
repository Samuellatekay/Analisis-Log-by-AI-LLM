import asyncio
import json
import logging
import os

# ============================================================
# KONFIGURASI
# ============================================================

HOST = "0.0.0.0"      # Mendengarkan dari semua interface (termasuk VM lain)
PORT = 17772          # Port yang akan didengarkan

logging.basicConfig(
    level="INFO",
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("receiver-17772")


# ============================================================
# FUNGSI PEMROSES DATA
# ============================================================

def process_received_data(payload: dict):
    """
    Fungsi ini dipanggil setiap kali JSON utuh berhasil diterima dari VM lain.
    Silakan modifikasi bagian ini sesuai kebutuhan (simpan ke DB, kirim ke AI, dll).
    """
    log.info("📥 Data JSON utuh diterima!")
    
    # Contoh: Ambil beberapa field (sesuaikan dengan struktur data VM Anda)
    # timestamp = payload.get("timestamp", "N/A")
    # message = payload.get("message", "N/A")
    
    # log.info("⏰ Waktu: %s", timestamp)
    # log.info("📝 Pesan: %s", message)
    
    # TODO: Tambahkan logika pemrosesan Anda di sini!
    # Contoh: Menyimpan ke file
    # with open("received_data.json", "a") as f:
    #     f.write(json.dumps(payload) + "\n")


# ============================================================
# TCP SERVER HANDLER
# ============================================================

async def handle_vm_client(reader, writer):
    peer = writer.get_extra_info('peername')
    log.info("🔌 VM terhubung dari: %s", peer)
    
    buffer = "" # Buffer untuk menyusun ulang paket TCP yang terpotong
    
    try:
        while True:
            # Baca data dari VM (maksimal 64KB per chunk)
            data = await reader.read(65536)
            if not data:
                log.info("🔌 VM %s menutup koneksi.", peer)
                break
            
            # Tambahkan data masuk ke buffer
            buffer += data.decode('utf-8', errors='ignore')
            
            # Pisahkan berdasarkan baris baru (\n) untuk mendapatkan JSON utuh
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                line = line.strip()
                
                if line:
                    try:
                        payload = json.loads(line)
                        process_received_data(payload)
                    except json.JSONDecodeError:
                        log.warning("⚠️ Data bukan JSON valid dari %s: %s", peer, line[:100])
                        
    except Exception as e:
        log.error("❌ Error saat menangani VM %s: %s", peer, e)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ============================================================
# MAIN SERVER
# ============================================================

async def main():
    try:
        server = await asyncio.start_server(handle_vm_client, host=HOST, port=PORT)
        log.info("🚀 Receiver Server aktif dan mendengarkan di %s:%d", HOST, PORT)
        log.info("⏳ Menunggu data dari VM lain...")
        
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        log.info("🌐 Serving on %s", addrs)
        
        async with server:
            await server.serve_forever()
            
    except OSError as e:
        log.critical("❌ GAGAL MEMULAI SERVER: Port %d mungkin sudah digunakan atau tidak diizinkan. Error: %s", PORT, e)
    except Exception as e:
        log.critical("❌ GAGAL MEMULAI SERVER: %s", e)

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("🛑 Receiver dihentikan secara manual.")