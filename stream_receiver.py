import asyncio
import json
import logging
import os
import httpx

logging.basicConfig(
    level="INFO",
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("stream-receiver")

# URL stream yang akan didengarkan
TARGET_STREAM_URL = os.getenv("TARGET_STREAM_URL", "http://38.47.66.253:17772/stream")

async def run_receiver():
    log.info("🎧 Receiver aktif (Mode: Listen Only).")
    log.info("🔌 Menghubungkan ke stream: %s", TARGET_STREAM_URL)
    
    async with httpx.AsyncClient(timeout=None) as client:
        while True:
            try:
                async with client.stream("GET", TARGET_STREAM_URL) as response:
                    response.raise_for_status()
                    log.info("✅ Terhubung ke /stream! Menunggu data real-time...")
                    
                    async for line in response.aiter_lines():
                        line = line.strip()
                        if not line:
                            continue
                        
                        try:
                            # Parse JSON dari stream
                            raw_data = json.loads(line)
                            
                            # HANYA CETAK LOG DATA YANG MASUK, TIDAK MENGIRIM KE IRIS
                            log.info("📥 DATA DITERIMA:")
                            log.info("%s", json.dumps(raw_data, indent=2, ensure_ascii=False))
                            log.info("-" * 60)
                            
                        except json.JSONDecodeError:
                            log.warning("⚠️ Data dari stream bukan format JSON valid: %s", line[:50])
                        except Exception as e:
                            log.error("❌ Error saat memproses data: %s", e)
                            
            except httpx.RequestError as e:
                log.error("❌ Koneksi ke stream terputus: %s", e)
            except Exception as e:
                log.error("❌ Error tidak terduga: %s", e)
            
            # Auto-reconnect jika putus
            log.info("🔄 Mencoba menghubungkan ulang dalam 5 detik...")
            await asyncio.sleep(5)

if __name__ == "__main__":
    try:
        log.info("🚀 Stream Receiver dimulai.")
        asyncio.run(run_receiver())
    except KeyboardInterrupt:
        log.info("🛑 Receiver dihentikan secara manual.")