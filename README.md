# Analisis Log by AI/LLM

## Korelasi enrichment Collector

Dalam mode Redis `list`, aplikasi mengonsumsi `enrichment-events` otomatis selain
list yang tercantum pada `REDIS_LISTS`. Event dicocokkan ke alert Wazuh yang masih ada
di PostgreSQL berdasarkan IP sumber atau hash file MD5/SHA-1/SHA-256/SHA-512.

Jika alert sudah tersimpan, enrichment ditambahkan ke `payload.enrichment.observables`,
record diperbarui di PostgreSQL dan Logstash, lalu analisis AI dijadwalkan ulang dengan
alert beserta konteks OpenCTI/GLPI. Hasil tersebut juga dikirim ke IRIS: deskripsi alert
memuat ringkasan reputasi, geolokasi, aset GLPI, umur domain, dan konteks OpenCTI, sementara
`alert_source_content` menyertakan dokumen alert lengkap. Jika alert IRIS sudah pernah dibuat,
alert yang sama diperbarui; untuk mode case langsung, konteks terbaru ditambahkan sebagai catatan
case. Jika alert belum datang, enrichment disimpan sementara di Redis dan digabungkan saat alert
yang cocok diproses. Data korelasi mengikuti masa retensi database (`RETENTION_MINUTES`); cache
Redis bertahan setidaknya 24 jam.

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
