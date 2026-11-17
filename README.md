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
Pilih `IRIS_MODE=alert`, `alert_case`, atau `case`. Gunakan `IRIS_MIN_RISK` dan
`IRIS_MIN_WAZUH_LEVEL` untuk mengatur ambang pengiriman. Skor risiko dihitung
terpisah dari level Wazuh.

### Risk level dan severity IRIS

Strategi `ahp_2026` menerapkan enam bobot kriteria dari Table 5 jurnal Guo et al.,
“Intelligent priority awareness method for alert data in SOC threat response”
(2026, DOI: `10.1007/s44443-026-01172-w`):
target `0.16`, attack-stage `0.31`, intelligence `0.18`, feasibility `0.22`,
persistence `0.07`, dan environment `0.06`. Tiap kriteria mengagregasi
sub-indikator Table 4 sesuai bobotnya; skor dasar `Rb = 100 × Σ(Wi × Ci)`,
lalu skor akhir mengikuti Eq. (10): `R = min(100, Rb × Eext × Eint)`.

Sub-indikator yang belum dikirim oleh sumber log memakai fallback eksplisit:

- Target: business value `support` (0.6), sensitivitas `internal` (0.5), dan
  attack surface `internal` (0.6).
- Attack-stage: hazard memakai pemetaan kategori event sebagai fallback;
  stage policy memakai 0.5.
- Intelligence: confidence memakai skor reputasi / 100, atau IOC match (1/0)
  jika tidak ada skor; vulnerability, APT association, dan freshness memakai 0.
- Feasibility: exploitability `none` (0.3), reachability `unknown` (0.5),
  dan bypass tanpa bukti (0.8).
- Persistence: korelasi `min(1, 0.5 + 0.1 × repeat_count)`, progression tanpa
  bukti (0.5), dan lateral movement `unknown` (0.7).
- Environment criterion: rata-rata intensitas eksternal dan internal yang
  dinormalisasi. Jurnal tidak memberi sub-bobot untuk dua indikator ini, jadi
  implementasi memakai bobot sama (0.5 masing-masing).

`RISK_EXTERNAL_MULTIPLIER` dan `RISK_INTERNAL_MULTIPLIER` di `.env` milik
Risk Engine mengatur `Eext` dan `Eint` (normal `1.0`; kampanye industri `1.2`;
anomali internal `1.1`). Nilai environment yang dikirim langsung pada payload
Risk Engine meng-override nilai konfigurasi. Field baru dapat dikirim melalui
`asset.attack_surface_exposure`, `event.phase_hazard`,
`event.stage_policy_weight`, dan `threat` sub-indikator terkait. `domain_age_days`
dipertahankan untuk kompatibilitas payload lama, tetapi tidak digunakan oleh
strategi AHP jurnal.

Jika `.env` lama masih memakai `RISK_ENVIRONMENT_MULTIPLIER`, ganti dengan
`RISK_EXTERNAL_MULTIPLIER=<nilai_lama>` dan `RISK_INTERNAL_MULTIPLIER=1.0`
untuk mempertahankan efek pengali skor global sebelumnya. Untuk konfigurasi jurnal,
gunakan nilai external dan internal secara terpisah seperti di atas.

Jurnal tidak menetapkan batas label level; batas aplikasi tetap:
`<40` low, `40–<60` medium, `60–<80` high, dan `80–100` critical. Implementasi
ini juga memvalidasi graph event/OpenCTI sebelum evidence graph dipakai:
identifier IP/domain/CVE/CWE dinormalisasi, node dan edge diperiksa tipe serta
endpoint-nya, dan fakta eksternal harus punya source/provenance, waktu pengambilan,
waktu pembaruan, serta confidence yang valid. Fakta revoked, belum berlaku, atau
sudah melewati `valid_until` dikarantina. Jurnal tidak menentukan freshness limit
berupa angka hari, jadi implementasi hanya memakai metadata validitas yang tersedia;
fakta tanpa metadata wajib tidak mengaktifkan gate dan skor kembali ke fallback.
Graph snapshot ID, status, evidence gate, jumlah fakta tervalidasi/dikarantina, dan
kode pelanggaran tercantum di `risk.graph_validation`.

OpenCTI lookup berjalan asynchronous. Skor awal hanya dapat memakai enrichment
yang sudah tersedia di cache saat alert diproses; enrichment yang baru datang
setelah kalkulasi memperbarui konteks alert tetapi tidak menghitung ulang skor
lama. Karena itu, alert tanpa cache memakai fallback, dan event berikutnya dapat
memakai graph setelah enrichment tersedia. Deploy ulang collector agar hasil
lookup baru menyimpan `acquired_at`; cache lama yang belum memiliki waktu tersebut
akan dikarantina sampai enrichment baru diterima.

Gate mengeluarkan `retain` jika ada bukti IOC OpenCTI tervalidasi, kerentanan
exploitable atau attack-pattern dari relasi graph yang valid, atau indikator risiko
tinggi dari event (aset criticality >= 4 pada skala 1–5, phase hazard > 0, atau
kill-chain progression). Jurnal tidak menetapkan batas numerik untuk aset
“high-criticality”, jadi nilai 4 adalah kebijakan lokal. IOC dianggap terkonfirmasi
jika ada relasi exact-match aktif dengan confidence positif; jurnal juga tidak
menetapkan batas confidence numerik. APT association yang tervalidasi ikut menjadi
bukti scoring, tetapi tidak sendirian mengaktifkan retain.
Selain itu keputusan `fallback` dan kalkulator tetap memproses event memakai nilai
fallback yang terdokumentasi. Gate ini belum menghapus alert: pipeline FFT-PCC
jurnal tidak ada dalam implementasi. Graph sekarang terbatas ke event dan enrichment
OpenCTI; graph asosiasi aset-vulnerability internal, validasi ontology lengkap,
perbaikan deterministik, pemeriksaan konflik lintas sumber, FFT-PCC, dan BERT
multi-agent belum diimplementasikan.

Risk level dihitung dari skor akhir `0`–`100`:

| Skor | Risk level |
| --- | --- |
| `< 40` | `low` |
| `40`–`< 60` | `medium` |
| `60`–`< 80` | `high` |
| `80`–`100` | `critical` |

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
payload ke layanan eksternal agar laporan dapat dikaitkan ke alert asal. Receiver
mengutamakan kecocokan ID alert yang eksplisit dan menggunakan UUID dari IRIS
sebagai UUID kanonis bila kedua nilai berbeda.
Receiver meneruskan seluruh teks `incident_report` yang diterima tanpa batas
karakter atau trim whitespace. Jika log jumlah karakter menunjukkan laporan
sudah tidak lengkap saat diterima, teks yang hilang harus diperbaiki pada
layanan pengirim; receiver tidak dapat memulihkan teks yang tidak dikirim.

## Konfigurasi dan menjalankan

Salin `.env.example` menjadi `.env`, lalu isi nilai konfigurasi Redis, PostgreSQL,
Logstash, dan IRIS:

`RISK_ENGINE_URL` harus menunjuk ke Risk Engine yang dapat dijangkau dari container
`app`; `RISK_STRATEGY` menerima `linear` atau `ahp_2026`. Kegagalan sementara saat
menghubungi Risk Engine akan membuat batch dicoba ulang, sedangkan respons HTTP 4xx
selain 429 dikirim ke dead-letter stream.

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
