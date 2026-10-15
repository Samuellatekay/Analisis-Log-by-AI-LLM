# Analisis Log by AI/LLM

## Korelasi enrichment Collector

Dalam mode Redis `list`, aplikasi mengonsumsi `enrichment-events` otomatis selain
list yang tercantum pada `REDIS_LISTS`. Event dicocokkan ke alert Wazuh yang masih ada
di PostgreSQL berdasarkan IP sumber atau hash file MD5/SHA-1/SHA-256/SHA-512.

Jika alert sudah tersimpan, enrichment ditambahkan ke `payload.enrichment.observables`,
record diperbarui di PostgreSQL dan Logstash, lalu analisis AI dijadwalkan ulang dengan
alert beserta konteks OpenCTI/GLPI. Untuk IP, metadata aset GLPI (nama, IP, pemilik,
serial, OS, dan status) diproyeksikan ke `asset`; skor/verdict OpenCTI dan data reputasi
diproyeksikan ke `reputation`, dan geolokasi ke `geolocation`. IOC lengkap tetap disimpan
di `payload.enrichment.observables`.

IRIS menampilkan metadata tersebut pada deskripsi alert dan `alert_source_content`.
Jika alert/case IRIS sudah pernah dibuat, alert diperbarui dan case terkait menerima catatan
enrichment (dideduplikasi). Saat alert baru langsung dieskalasi, catatan case juga menyertakan
ringkasan alert beserta enrichment. Pengayaan ini merupakan konteks pada alert/catatan; belum
membuat objek Asset/IOC native baru di IRIS. Jika alert belum datang, enrichment disimpan
sementara di Redis dan digabungkan saat alert yang cocok diproses. Data korelasi mengikuti
masa retensi database (`RETENTION_MINUTES`); cache Redis bertahan setidaknya 24 jam.

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
