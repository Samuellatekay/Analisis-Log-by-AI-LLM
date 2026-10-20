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
4. Alert Wazuh meminta lookup GLPI melalui `outbound-glpi` berdasarkan IP sumber,
   IP tujuan, dan hostname agent untuk mengenali aset sensor yang melaporkan event.
   Hasilnya diterbitkan ke `enrichment-events`.
5. Data enrichment yang datang kemudian digabung ke record PostgreSQL dan
   Logstash. Alert atau case IRIS yang sudah ada diperbarui dengan konteks baru.

`enrichment-events` dikonsumsi otomatis pada mode Redis `list`. Pastikan aplikasi
dan collector memakai Redis DB yang sama dan tidak ada proses lain yang mengambil
list tersebut.

## GLPI dan OpenCTI

Lookup aset dijadwalkan untuk IP sumber dan tujuan pada event Wazuh serta nama
Computer GLPI yang sama persis dengan hostname agent. Hasil hostname hanya
ditampilkan sebagai aset host pelapor/sensor (atau host tujuan bila IP sumber
tidak ada), bukan dianggap sebagai IP penyerang. Hasil hostname ambigu ditolak.
Jika pencarian hostname sensor gagal tetapi hostname dan IP agent sama persis
dengan aset GLPI yang sudah cocok melalui IP sumber/tujuan, alert merujuk ke aset
tersebut alih-alih melaporkannya sebagai tidak ditemukan.
Informasi aset yang tersedia dapat mencakup nama, semua alamat IP terkait, pemilik,
serial, nomor inventaris, sistem operasi, status, lokasi, tipe, produsen, model,
entity/grup, kontak, catatan, dan tanggal inventaris, selama kolom tersebut terisi
di GLPI. Alamat IP aset dipisahkan menjadi IP privat (RFC1918/IPv6 ULA), IP publik
yang dapat dirutekan global, dan IP lainnya yang tidak termasuk dua kategori tersebut.

Lookup OpenCTI dijadwalkan untuk IP sumber/tujuan, domain, dan hash file yang
terekstrak dari alert Wazuh. GLPI dicari berdasarkan IP sumber/tujuan dan hostname
agent yang cocok persis. Hasil hostname dilaporkan sebagai aset sensor, bukan
sebagai IP sumber atau penyerang. Hanya record yang cocok dengan IOC/hostname alert
yang digabungkan; daftar inventaris atau feed
OpenCTI yang tidak terkait tidak disalin ke alert. Reputasi, geolokasi, data
indicator/observable yang cocok, referensi intel, status connector, dan seluruh
aset GLPI yang cocok disimpan di konten sumber IRIS; ringkasan ditampilkan di
deskripsi alert. Lookup hanya dipicu alert yang masuk setelah fitur ini diaktifkan; tidak ada backfill
massal untuk alert lama.
Jika relasi OpenCTI `based-on` tidak memberikan Indicator, collector mencari pattern
Indicator berdasarkan nilai IOC persis. Deskripsi IRIS membedakan observable yang
ditemukan tanpa Indicator terkait dari IOC yang tidak ditemukan.
Hasil OpenCTI dan GLPI untuk IOC yang sama digabungkan, bukan saling menimpa, sehingga
event lookup GLPI yang datang belakangan tidak menghapus detail indicator OpenCTI.
Data aset GLPI di-cache untuk membatasi panggilan API. Saat ada alert Wazuh berikutnya
dengan IP atau hostname yang sama, lookup GLPI dijalankan ulang jika hasil terakhir
lebih lama dari 1 detik. Lookup IOC OpenCTI mengikuti batas deduplikasi yang sama.
Hasil baru memperbarui alert IRIS terkait yang masih berada dalam masa retensi.
GLPI dan OpenCTI tidak dipantau secara live oleh jalur ini, sehingga perubahan tanpa
event Wazuh baru tidak langsung tercermin. Timestamp `Terakhir diperbarui` adalah tanggal
perubahan objek Computer (`date_mod`) dan tidak selalu berubah saat relasi NetworkName
atau IPAddress yang diubah.
Jika alert sudah dieskalasi ke case, enrichment terbaru mengganti deskripsi case di menu
Case dengan satu laporan alert terbaru. Laporan lama tidak ditambahkan sebagai blok kedua,
sehingga detail GLPI/OpenCTI dan IOC tidak berulang. Riwayat alert/escalation IRIS tetap ada.

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
