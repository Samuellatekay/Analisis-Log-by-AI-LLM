import asyncio
import json
import logging

# ============================================================
# KONFIGURASI
# ============================================================

HOST = "0.0.0.0"  # Ganti dengan IP server jika listener dijalankan di mesin lain
PORT = 17772        # Port yang digunakan oleh stream_iris.py

logging.basicConfig(
    level="INFO",
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("listener")


# ============================================================
# FUNGSI PEMROSES DATA
# ============================================================

def process_alert(payload: dict):
    """
    Fungsi ini akan dipanggil setiap kali ada data JSON baru yang masuk.
    Silakan modifikasi bagian ini sesuai kebutuhan Anda (misal: kirim ke AI, simpan ke DB, dll).
    """
    timestamp = payload.get("@timestamp", "Waktu tidak diketahui")
    description = payload.get("alert_description", "Tidak ada deskripsi")
    
    # Ambil log mentah jika ada
    original_log = payload.get("original", "")
    
    log.info("🚨 ALERT DITERIMA!")
    log.info("⏰ Waktu : %s", timestamp)
    log.info("📝 Deskripsi: %s...", description[:150]) # Hanya tampilkan 150 karakter pertama
    
    if original_log:
        log.info("📦 Log Mentah: Tersedia (Panjang: %d karakter)", len(str(original_log)))
    
    log.info("-" * 50)
    
    # TODO: Tambahkan logika Anda di sini!
    # Contoh: Mengirim ke AI LLM
    # response = my_ai_analyze(original_log)
    # log.info("🤖 Hasil AI: %s", response)


# ============================================================
# TCP CLIENT LISTENER
# ============================================================

async def start_listener():
    buffer = "" # Buffer untuk menampung data TCP yang mungkin terpotong
    
    while True:
        try:
            log.info("🔌 Mencoba terhubung ke %s:%d...", HOST, PORT)
            reader, writer = await asyncio.open_connection(HOST, PORT)
            log.info("✅ Terhubung! Menunggu data real-time...")
            
            while True:
                # Baca data dari server (maksimal 8KB per chunk)
                data = await reader.read(8192)
                if not data:
                    log.warning("⚠️ Koneksi ditutup oleh server.")
                    break
                
                # Tambahkan data baru ke buffer
                buffer += data.decode('utf-8', errors='ignore')
                
                # Proses setiap baris lengkap (dipisahkan oleh \n)
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    line = line.strip()
                    
                    if line:
                        try:
                            # Parse JSON
                            payload = json.loads(line)
                            process_alert(payload)
                        except json.JSONDecodeError:
                            log.warning("⚠️ Data bukan format JSON valid: %s", line[:50])

        except ConnectionRefusedError:
            log.error("❌ Koneksi ditolak. Server mungkin belum siap.")
        except OSError as e:
            log.error("❌ Error jaringan: %s", e)
        except Exception as e:
            log.error("❌ Error tidak terduga: %s", e)
        
        # Tunggu 5 detik sebelum mencoba reconnect
        log.info("🔄 Mencoba reconnect dalam 5 detik...")
        await asyncio.sleep(5)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    try:
        log.info("🚀 Program Listener dimulai.")
        asyncio.run(start_listener())
    except KeyboardInterrupt:
        log.info("🛑 Listener dihentikan secara manual.")