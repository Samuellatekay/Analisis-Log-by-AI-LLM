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
4. Alert Wazuh yang memiliki IP sumber atau tujuan meminta lookup GLPI melalui
   `outbound-glpi`. Collector menerbitkan hasilnya ke `enrichment-events`.
5. Data enrichment yang datang kemudian digabung ke record PostgreSQL dan
   Logstash. Alert atau case IRIS yang sudah ada diperbarui dengan konteks baru.

`enrichment-events` dikonsumsi otomatis pada mode Redis `list`. Pastikan aplikasi
dan collector memakai Redis DB yang sama dan tidak ada proses lain yang mengambil
list tersebut.

## GLPI dan OpenCTI

Lookup aset dijadwalkan untuk IP sumber dan tujuan pada event Wazuh. Collector
mencari aset GLPI berdasarkan IP di Computer atau NetworkPort, lalu menerbitkan
hasil pencarian ke Redis. Informasi aset yang tersedia dapat mencakup nama,
pemilik, serial, sistem operasi, status, dan lokasi.

Lookup OpenCTI juga dijadwalkan untuk IP sumber dan tujuan. Hasil reputasi,
geolokasi, indikator, dan status connector yang tersedia disimpan sebagai konteks
enrichment. Data tersebut ditampilkan pada deskripsi alert IRIS; layanan ini tidak
membuat objek aset native baru di IRIS.

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
