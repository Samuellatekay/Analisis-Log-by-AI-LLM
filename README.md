# Analisis_Log

Layanan ini menerima event dari Redis, menormalisasi dan menghitung skor risiko
melalui `soc-risk-engine`, menyimpan event sementara di PostgreSQL, meneruskan dokumen
ke Logstash, dan mengirim alert berisiko ke DFIR-IRIS.

## Alur event

1. Event masuk melalui list Redis pada `REDIS_LISTS`, atau Redis Stream jika
   `REDIS_MODE=stream`.
2. Aplikasi menormalkan event dan menghitung skor risiko melalui Risk Engine
   eksternal (`RISK_ENGINE_URL`).
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

## CrowdStrike Falcon
Log CrowdStrike Falcon dalam format CEF dinormalisasi otomatis, baik dikirim
sebagai string `message`/`full_log` maupun pada field `data`. Header CEF menjadi
event dan severity internal; extension seperti `dhost`, user, process ID,
command line, hash file, waktu deteksi, serta tactic/technique dipetakan ke
field `host`, `user`, `process`, `file`, `@timestamp`, dan `threat`. Untuk alert
CrowdStrike yang dibungkus Wazuh, `host.name` mengikuti `dhost` (endpoint yang
terdeteksi), `user.name` mengikuti `duser`, sedangkan `agent.name` tetap
menunjukkan agent/collector Wazuh. Hash file CEF dikirim sebagai IOC alert agar
tersedia di tab IOCs sejak alert dibuat. Setiap pesan Redis sebaiknya memuat satu
baris CEF. Alert Wazuh yang berasal dari CEF
CrowdStrike digabungkan di integrasi IRIS berdasarkan `CompositeId` yang sama;
`MitreAttack` yang tiba lebih dulu ditahan selama `IRIS_DEDUP_WINDOW_S` agar
`DetectionSummary` yang membawa hash dapat digabung sebelum Alert dibuat. Jika
pasangannya datang, hash dikirim sebagai IOC saat pembuatan Alert. Jika tidak ada
pasangan, event tetap tersimpan di PostgreSQL tetapi tidak membuat Alert IRIS
mandiri. Penggabungan ini tidak mencegah Wazuh sendiri mencatat dua Alert dan
tidak menghapus event individual dari PostgreSQL atau Logstash. Jika Alert sudah
dibuat dari event yang hanya memuat hostname collector, event terkait yang
menyertakan `dhost` akan memperbarui nama aset tujuan di tab Assets IRIS. Update
CrowdStrike yang tidak membawa `dhost` dan hanya memiliki hostname collector tidak
akan menimpa nama endpoint yang sudah tersimpan di tab Assets.

## GLPI dan OpenCTI

Lookup aset dijadwalkan untuk IP sumber dan tujuan pada event Wazuh serta nama
Computer GLPI yang sama persis dengan hostname endpoint (`dhost`) atau host pelapor.
Hasil hostname hanya
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
Untuk scoring AHP, Risk Engine membaca `business_value` dan `data_sensitivity` dari
field aset GLPI jika tersedia, atau dari format `business_value=support
data_sensitivity=internal` di Catatan/Description. Aset GLPI tujuan diprioritaskan
sebagai host yang diserang. Nilai yang diterima adalah `core`/`support`/`test` dan
`top_secret`/`confidential`/`internal`/`public`; jika tidak valid atau tidak tersedia,
nilai bawaan adalah `support` dan `internal`.

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
Indicator berdasarkan nilai IOC persis melalui pencarian OpenCTI dan filter field
`pattern`. Deskripsi IRIS membedakan observable yang ditemukan tanpa Indicator
terkait dari IOC yang tidak ditemukan.
Untuk observable dan indicator yang cocok, collector juga mengambil entitas STIX
serta relasi yang terhubung langsung (misalnya malware, threat actor, campaign,
attack pattern, dan hubungan `uses`/`indicates`), Event OpenCTI, serta Sightings
yang terhubung langsung dengan IOC cocok; bukan seluruh isi OpenCTI.
Detail Observable, Indicator, Events, Sightings, entitas, dan relasi yang diambil
disimpan di konten sumber IRIS. Ringkasan deskripsi dibatasi agar bagian alert lain
tidak terpotong.
Hasil OpenCTI dan GLPI untuk IOC yang sama digabungkan, bukan saling menimpa, sehingga
event lookup GLPI yang datang belakangan tidak menghapus detail indicator OpenCTI.
Hasil OpenCTI dapat digunakan dari cache untuk mempercepat alert baru. Hasil aset GLPI
yang tersimpan di cache tidak diterapkan ke alert baru agar alamat IP inventaris lama
tidak terbawa; alert baru meminta lookup GLPI, dengan deduplikasi satu detik untuk IP
atau hostname yang sama. Lookup IOC OpenCTI mengikuti batas deduplikasi yang sama.
Hasil GLPI terbaru memperbarui alert IRIS terkait yang masih berada dalam masa retensi.
GLPI dan OpenCTI tidak dipantau secara live oleh jalur ini, sehingga perubahan tanpa
event Wazuh baru tidak langsung tercermin. Timestamp `Terakhir diperbarui` adalah tanggal
perubahan objek Computer (`date_mod`) dan tidak selalu berubah saat relasi NetworkName
atau IPAddress yang diubah.
Jika alert sudah dieskalasi ke case, enrichment terbaru mengganti deskripsi case di menu
Case dengan satu laporan alert terbaru. Laporan lama tidak ditambahkan sebagai blok kedua,
sehingga detail GLPI/OpenCTI dan IOC tidak berulang. Riwayat alert/escalation IRIS tetap ada.

## DFIR-IRIS

Atur `IRIS_ENABLED`, `IRIS_URL`, `IRIS_API_KEY`, dan `IRIS_CUSTOMER_ID` di `.env`.
Untuk instalasi multi-customer, `IRIS_CUSTOMER_ROUTING_MAP` dapat memilih
customer alert/case dari hostname manager, hostname agent/endpoint, atau keyword
pada action event. Formatnya `ID:pola1|pola2,ID:pola3`; contoh
`1:customer-a|hids-a,2:customer-b|hids-b`. Pencocokan tidak peka huruf besar/kecil.
Jika tidak ada pola yang cocok atau beberapa customer cocok, aplikasi memakai
`IRIS_CUSTOMER_ID` sebagai fallback dan mencatat warning. Entri map yang salah
format atau pola duplikat lintas customer menghentikan startup agar routing tidak
diam-diam salah. Pastikan ID dan pola sesuai dengan customer/manager di IRIS/Wazuh.
Pilih `IRIS_MODE=alert`, `alert_case`, atau `case`. Gunakan `IRIS_MIN_RISK` dan
`IRIS_MIN_WAZUH_LEVEL` untuk mengatur ambang pengiriman. Skor risiko dihitung
terpisah dari level Wazuh.

### Risk level dan severity IRIS

Risk Engine mengembalikan skor `0`–`100` dan level berdasarkan skor akhir:

| Skor | Risk level |
| --- | --- |
| `< 40` | `low` |
| `40`–`< 60` | `medium` |
| `60`–`< 80` | `high` |
| `80`–`100` | `critical` |

`RISK_ENVIRONMENT_MULTIPLIER` dikonfigurasi pada `.env` milik Risk Engine.
Nilai `1.0` mempertahankan skor; `1.2` menaikkan skor akhir 20%, lalu level
dihitung ulang. Skor dibatasi maksimum `100`.

Judul alert seperti `[MEDIUM]` memakai risk level dari Risk Engine. Badge severity
IRIS memakai ID numerik dari `IRIS_SEVERITY_MAP`; ID dapat berbeda pada tiap
instalasi IRIS. Jadi, judul `[MEDIUM]` dengan badge `LOW` biasanya berarti ID
`medium` dipetakan ke severity `LOW` di IRIS, bukan skor kalkulator yang berbeda.

Periksa nama dan ID severity pada instalasi IRIS:

```sh
docker compose run --rm app python check_connections.py --iris-ids
```

Isi `IRIS_SEVERITY_MAP` di `.env` dengan ID yang sesuai, misalnya
`low:<id_low>,medium:<id_medium>,high:<id_high>,critical:<id_critical>`.
ID pada `.env.example` bukan nilai universal. Jika map diisi, auto-discovery
berdasarkan nama severity tidak dijalankan; jika kosong, aplikasi mencoba
mencocokkan nama severity dari IRIS. Setelah mengubah `.env`, buat ulang container
`app`. Perubahan berlaku untuk alert yang dibuat atau diperbarui berikutnya;
severity alert lama tidak otomatis berubah.

Untuk tetap membuat Alert tetapi mematikan eskalasi otomatis ke Case, atur
`IRIS_AUTO_ESCALATE=false` (berlaku saat `IRIS_MODE=alert_case`). Alert tetap
dapat dieskalasi manual dari UI IRIS. Mode `IRIS_MODE=case` tetap membuat Case
secara langsung dan tidak dipengaruhi sakelar ini.

Pengiriman alert dilakukan melalui antrean worker IRIS. Satu kombinasi sumber dan
aksi dideduplikasi selama `IRIS_DEDUP_WINDOW_S`. `IRIS_WORKERS` mengatur jumlah
worker; `IRIS_QUEUE_MAX` membatasi antrean.

Saat alert dieskalasi menjadi case, deskripsi alert disalin ke Case Summary.
Eskalasi otomatis ditangani langsung; `stream-receiver` juga memeriksa relasi
Alert–Case IRIS secara berkala agar eskalasi melalui tombol UI ikut tersinkron,
termasuk bila dilakukan setelah laporan AI diterima. Konten Summary yang sudah
ada tetap dipertahankan; bagian awal deskripsi Alert yang sama dengan akhir
Summary tidak disalin ulang. Untuk `log_uuid` yang sama, bagian Risiko diganti
dengan nilai terbaru, bukan ditambahkan sebagai salinan baru. Section AI yang
sudah ada juga tidak diduplikasi. Hasil update dibaca ulang dari IRIS untuk
memastikan Summary benar-benar tersimpan. Interval pemeriksaan diatur melalui
`IRIS_CASE_SUMMARY_SYNC_INTERVAL_S` (default 30 detik, minimum 5 detik).

Layanan `stream-receiver` menerima laporan dari `TARGET_STREAM_URL` dalam JSON
yang memuat `log_uuid` dan `incident_report`. Laporan ditambahkan sebagai section
Markdown di Description alert/case dan disimpan juga sebagai Alert Note serta
Note case. Salinan Alert Note menjaga laporan lengkap tetap tersedia di Alert
jika Description dibatasi saat ditampilkan. Case eskalasi dicocokkan melalui
relasi Alert–Case IRIS, dengan pencocokan `log_uuid` sebagai fallback. Jika
`.env` sudah dibuat sebelumnya, buat ulang container setelah memperbarui image.
Pembaruan Case Summary diverifikasi dengan membaca ulang Case dari IRIS; status
HTTP 200 saja tidak dianggap bukti bahwa Summary sudah tersimpan.
`stream_iris.py` menyertakan `alert_id` dan `log_uuid` (`alert_source_ref`) pada
payload ke layanan eksternal agar laporan dapat dikaitkan ke alert asal. Payload
juga memuat `original`, seluruh `alert_source_content`, dan `related_events`
tanpa pemotongan di normalizer atau pembentuk payload. Receiver mengutamakan
kecocokan ID alert yang eksplisit dan menggunakan UUID dari IRIS sebagai UUID
kanonis bila kedua nilai berbeda.
Receiver meneruskan seluruh teks `incident_report` yang diterima tanpa batas
karakter atau trim whitespace. Jika log jumlah karakter menunjukkan laporan
sudah tidak lengkap saat diterima, teks yang hilang harus diperbaiki pada
layanan pengirim; receiver tidak dapat memulihkan teks yang tidak dikirim.
Untuk lonjakan alert, `stream_iris.py` memindai halaman IRIS ke Redis Stream,
lalu memproses antrean dengan worker paralel. Konfigurasi utamanya:
`IRIS_ALERT_PAGE_SIZE` (default 100), `IRIS_ALERT_WORKERS` (4), dan
`IRIS_ALERT_MAX_ATTEMPTS` (8). Alert gagal setelah percobaan maksimum disimpan
di stream dead-letter `<IRIS_ALERT_QUEUE_STREAM>:dead` untuk pemeriksaan manual.
Antrean bertahan saat proses `iris-stream` restart selama Redis menyimpan datanya.
Pengiriman menggunakan semantik at-least-once: jika proses berhenti setelah server
eksternal menerima alert tetapi sebelum ACK Redis tersimpan, alert dapat terkirim
ulang; penerima sebaiknya menduplikasi berdasarkan `alert_id`.

## Konfigurasi dan menjalankan

Salin `.env.example` menjadi `.env`, lalu isi nilai konfigurasi Redis, PostgreSQL,
Logstash, dan IRIS:

`RISK_ENGINE_URL` harus menunjuk ke Risk Engine yang dapat dijangkau dari container
`app`; `RISK_STRATEGY` menerima `linear` atau `ahp_2026`. `RISK_ENGINE_MAX_CONCURRENCY`
membatasi permintaan bersamaan dari aplikasi ke Risk Engine (default 16); sesuaikan
berdasarkan hasil uji beban layanan Risk Engine. Kegagalan sementara saat menghubungi
Risk Engine akan membuat batch dicoba ulang, sedangkan respons HTTP 4xx selain 429
dikirim ke dead-letter stream.

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
