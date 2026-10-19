# Analisis_Log

Layanan ini menerima event dari Redis, menormalisasi dan menghitung skor risiko
secara deterministik, menyimpan event sementara di PostgreSQL, meneruskan dokumen
ke Logstash, dan mengirim alert berisiko ke DFIR-IRIS.

## Alur event

1. Event masuk melalui list Redis pada `REDIS_LISTS`, atau Redis Stream jika
   `REDIS_MODE=stream`.
2. Aplikasi menormalkan event dan menghitung skor risiko menggunakan
   `risk_calculator.py`.
3. Dokumen disimpan di PostgreSQL, diteruskan ke Logstash, dan diproses untuk
   pengiriman ke IRIS sesuai ambang risiko dan level Wazuh.
4. Alert Wazuh meminta lookup GLPI melalui `outbound-glpi` berdasarkan IP sumber
   dan tujuan. Jika IP sumber tidak tersedia, nama host/agent dipakai sebagai
   fallback untuk mencari aset sensor yang melaporkan event. Collector menerbitkan
   hasilnya ke `enrichment-events`.
5. Data enrichment yang datang kemudian digabung ke record PostgreSQL dan
   Logstash. Alert atau case IRIS yang sudah ada diperbarui dengan konteks baru.

`enrichment-events` dikonsumsi otomatis pada mode Redis `list`. Pastikan aplikasi
dan collector memakai Redis DB yang sama dan tidak ada proses lain yang mengambil
list tersebut.

## GLPI dan OpenCTI

Lookup aset dijadwalkan untuk IP sumber dan tujuan pada event Wazuh. Jika IP
sumber tidak ada, collector mencoba pencarian Computer GLPI dengan nama host
yang sama persis dan hanya menerima hasil yang unik. Hasilnya dipasangkan ke
aset host/agent yang melaporkan event, bukan dianggap sebagai IP penyerang.
Informasi aset yang tersedia dapat mencakup nama, pemilik, serial, sistem operasi,
status, dan lokasi.

Lookup OpenCTI dijadwalkan untuk IP sumber/tujuan, domain, dan hash file yang
terekstrak dari alert Wazuh. GLPI dicari berdasarkan IP sumber/tujuan, dengan
fallback hostname untuk host pelapor bila IP sumber tidak ada. Hanya record yang
cocok dengan IOC/hostname alert yang digabungkan; daftar inventaris atau feed
OpenCTI yang tidak terkait tidak disalin ke alert. Reputasi, geolokasi, data
indicator/observable yang cocok, referensi intel, status connector, dan seluruh
aset GLPI yang cocok disimpan di konten sumber IRIS; ringkasan ditampilkan di
deskripsi alert. Lookup hanya dipicu alert yang masuk setelah fitur ini diaktifkan; tidak ada backfill
massal untuk alert lama.

## DFIR-IRIS

Atur `IRIS_ENABLED`, `IRIS_URL`, `IRIS_API_KEY`, dan `IRIS_CUSTOMER_ID` di `.env`.
Pilih `IRIS_MODE=alert`, `alert_case`, atau `case`. Gunakan `IRIS_MIN_RISK` dan
`IRIS_MIN_WAZUH_LEVEL` untuk mengatur ambang pengiriman. Skor risiko dihitung
terpisah dari level Wazuh.

Pengiriman alert dilakukan melalui antrean worker IRIS. Satu kombinasi sumber dan
aksi dideduplikasi selama `IRIS_DEDUP_WINDOW_S`. `IRIS_WORKERS` mengatur jumlah
worker; `IRIS_QUEUE_MAX` membatasi antrean.

## Konfigurasi dan menjalankan

Salin `.env.example` menjadi `.env`, lalu isi nilai konfigurasi Redis, PostgreSQL,
Logstash, dan IRIS:

```sh
docker compose up -d --build
docker compose logs -f app
```

Gunakan pemeriksaan koneksi dari dalam jaringan Docker:

```sh
docker compose run --rm app python check_connections.py
docker compose run --rm app python check_connections.py --iris-ids
```

Opsi `--iris-test` dan `--iris-test-case` membuat objek uji sungguhan di IRIS;
hapus objek tersebut setelah pengujian.

`pipeline.conf` adalah contoh HTTP input Logstash dan indexing Elasticsearch.
Indeks contoh menggunakan pola `analisis-log-%{log_day}`. Sesuaikan pola indeks
Kibana yang sudah ada bila mengganti nama indeks.

## Retensi dan keandalan

`RETENTION_MINUTES` mengatur umur maksimum record sementara di PostgreSQL.
Event malformed atau gagal diteruskan dicatat pada stream dead-letter yang
ditentukan `REDIS_DLQ_STREAM`. Pemrosesan batch dan UUID deterministik menjaga
event yang dikirim ulang tetap idempoten.
