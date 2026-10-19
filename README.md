# Analisis Log by AI/LLM

## Korelasi enrichment Collector

Dalam mode Redis `list`, aplikasi mengonsumsi `enrichment-events` otomatis selain
list yang tercantum pada `REDIS_LISTS`. Event dicocokkan ke alert Wazuh yang masih ada
di PostgreSQL berdasarkan IP sumber atau hash file MD5/SHA-1/SHA-256/SHA-512.

Untuk setiap alert Wazuh dengan IP sumber dan/atau tujuan, aplikasi meminta lookup aset melalui Redis
`outbound-glpi` (aksi `lookup_asset`). Collector yang memiliki kredensial GLPI mencari
Computer berdasarkan IP dan menerbitkan hasilnya ke `enrichment-events`. Pastikan collector
mendukung aksi tersebut dan memakai Redis DB yang sama. Lookup dibatasi satu kali per IP
selama 5 menit; bila aset tidak ditemukan, hasil lookup berikutnya dapat mencoba lagi setelahnya.

Jika alert sudah tersimpan, enrichment ditambahkan ke `payload.enrichment.observables`,
record diperbarui di PostgreSQL dan Logstash, lalu analisis AI dijadwalkan ulang dengan
alert beserta konteks OpenCTI/GLPI. Untuk IP, metadata aset GLPI (nama, IP, pemilik,
serial, OS, dan status) diproyeksikan ke `asset`; skor/verdict OpenCTI dan data reputasi
diproyeksikan ke `reputation`, dan geolokasi ke `geolocation`. IOC lengkap tetap disimpan
di `payload.enrichment.observables`.

IRIS menampilkan metadata enrichment sebagai ringkasan berlabel pada deskripsi alert
(reputasi, geolokasi, aset, dan IOC), bukan sebagai JSON mentah berulang. Payload lengkap
tetap tersedia di `alert_source_content` untuk pemeriksaan detail. Untuk alert Wazuh,
bagian intelijen ancaman mencantumkan Author dari `createdBy` indicator OpenCTI jika ada;
jika OpenCTI tidak mengirim metadata itu, IRIS menyebutkannya tanpa menebak author.
IRIS juga mencantumkan level Wazuh (`rule.level`), nama/ID/IP agent, dan nama/IP manager
jika ada di payload. Wazuh umumnya menyertakan `agent.ip` tetapi hanya `manager.name`;
untuk menampilkan IP manager, isi `WAZUH_MANAGER_IP` pada `.env` aplikasi. IP tujuan
ditampilkan bila alert memuat `data.dstip`, `data.dst_ip`, `destination.ip`, atau field
tujuan umum yang didukung. Tidak semua jenis alert Wazuh memiliki IP tujuan (misalnya
alert file-integrity atau uji sintetis tanpa field tujuan). Sumber
Untuk setiap IP sumber/tujuan, collector memanggil semua connector OpenCTI bertipe
`INTERNAL_ENRICHMENT` yang aktif dan memiliki scope cocok, lalu mencantumkan status tiap
job di IRIS. Connector `EXTERNAL_IMPORT` dicari melalui indicator/external reference yang
sudah tersimpan di OpenCTI; feed tidak dijalankan sebagai API lookup per IP. Hasil yang
sudah diketahui OpenCTI ditampilkan beserta nama sumber jika tersedia. Connector aktif
saja tidak menjamin feed sudah selesai sinkronisasi atau punya data untuk IOC tersebut.

AbuseIPDB/VirusTotal direct API dari collector juga menjelaskan statusnya: key belum
dikonfigurasi, IP tidak didukung, data ditemukan, atau tidak ada record/API gagal (cek log
collector). `ABUSEIPDB_KEY` dan `VT_API_KEY` di `.env` collector berbeda dari connector
OpenCTI dan harus diatur terpisah. IP private seperti `192.168.x.x` tidak memiliki
reputasi AbuseIPDB publik yang bermakna.
Jika alert/case IRIS sudah pernah dibuat, alert diperbarui dan case terkait menerima catatan
enrichment (dideduplikasi). Saat alert baru langsung dieskalasi, catatan case juga menyertakan
ringkasan alert beserta enrichment. Pengayaan ini merupakan konteks pada alert/catatan; belum
membuat objek Asset/IOC native baru di IRIS. Jika alert belum datang, enrichment disimpan
sementara di Redis dan digabungkan saat alert yang cocok diproses. Data korelasi mengikuti
masa retensi database (`RETENTION_MINUTES`); cache Redis bertahan setidaknya 24 jam.

Record dari `opencti-events` dan `glpi-logs` tidak dikirim sebagai alert IRIS mandiri.
OpenCTI adalah sumber intelijen ancaman dan GLPI berisi umpan balik tiket collector;
keduanya tetap bisa dipakai sebagai konteks, sedangkan alert deteksi Wazuh yang dikorelasikan
yang dikirim ke IRIS.

Alert IRIS dikirim segera setelah lolos filter risiko dan level Wazuh, tanpa menunggu LLM
atau jendela agregasi AI. Status awal menyatakan bahwa analisis sedang berjalan. Saat LLM selesai,
alert yang sama diperbarui dengan hasilnya; jika alert sudah menjadi case, case juga menerima
catatan pembaruan. Untuk alert yang dianalisis secara agregat, hasil yang sama dipasang ke setiap
alert sumber yang termasuk agregasi.

Contoh isi yang diteruskan ke LLM:

```json
{
  "source": {"ip": "192.168.51.143"},
  "enrichment": {
    "observables": [{
      "entity_type": "IPv4-Addr",
      "value": "192.168.51.143",
      "reputation": {},
      "geolocation": {},
      "asset": {}
    }]
  }
}
```

Hash file dicocokkan terhadap hash pada alert Wazuh, bukan terhadap IP. Event enrichment
yang tidak memiliki alert cocok tetap dicache untuk alert yang datang kemudian dan tidak
dibuat sebagai analisis LLM terpisah.

Kegagalan pengiriman ke Logstash dicatat ke DLQ dan log aplikasi, tetapi tidak lagi
menghentikan analisis AI atau pengiriman ke IRIS. PostgreSQL tetap menjadi penyimpanan
untuk analisis; Logstash hanya tujuan penerusan/indexing.
