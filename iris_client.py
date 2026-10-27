"""
iris_client.py
Klien untuk mengirim log terdeteksi/kritis ke DFIR-IRIS.
"""
from __future__ import annotations

import os
import json
import logging
import urllib.request
import urllib.error
import traceback
from typing import Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

def _d(value: Any) -> dict:
    """Helper untuk memastikan tipe kembalian adalah dictionary."""
    return value if isinstance(value, dict) else {}

def _display(value: Any, max_len: int = 100) -> str:
    """Helper untuk membatasi panjang string yang akan ditampilkan."""
    if value is None or value == "":
        return ""
    s = str(value).strip()
    return s[:max_len] + ("..." if len(s) > max_len else "")

def _md_escape(value: Any, max_len: int = 100) -> str:
    """Helper untuk melakukan escape pada karakter Markdown."""
    s = _display(value, max_len)
    for char in ("*", "_", "`", "[", "]"):
        s = s.replace(char, f"\\{char}")
    return s

def _join_list(val: Any) -> str:
    """Helper kebal-error untuk menggabungkan list menjadi string."""
    if isinstance(val, list):
        return ", ".join(str(v) for v in val if v)
    return str(val) if val else ""

def _format_asset(asset: dict, source_ip: Any, host_name: Any = None) -> list[str]:
    """Format tampilan aset ke list Markdown."""
    is_glpi_asset = (asset.get("inventory_source") == "GLPI" or asset.get("found") is True)
    if not is_glpi_asset:
        searched_ip = _display(asset.get("ip") or source_ip, 80)
        return [f"- Tidak ada aset GLPI yang cocok dengan IP {searched_ip}."]
    
    assets = asset.get("items")
    if not isinstance(assets, list) or not assets:
        assets = [asset]
    
    lines = []
    for index, item in enumerate(assets[:10], start=1):
        if not isinstance(item, dict): continue
        asset_id = _display(item.get("id"), 80)
        lines.append(f"- Aset GLPI #{asset_id or index}:")
        
        fields = (
            ("Nama", item.get("name")),
            ("IP privat", _join_list(item.get("private_ip_addresses"))),
            ("IP publik", _join_list(item.get("public_ip_addresses"))),
            ("Pemilik", item.get("owner") or item.get("user")),
            ("Sistem operasi", item.get("operating_system")),
            ("Status", item.get("status")),
            ("Lokasi", item.get("location")),
            ("Tipe", item.get("type")),
            ("Model", item.get("model")),
            ("Kontak", item.get("contact")),
            ("Catatan GLPI", item.get("description")),
        )
        for label, value in fields:
            display_val = _display(value, 180)
            if display_val:
                lines.append(f"- {label}: {display_val}")
    return lines

def _format_reputation(value: Any, observables: list | None = None) -> list[str]:
    """Format tampilan data reputasi dan label dari OpenCTI."""
    reputation = _d(value)
    if not reputation:
        return ["- Data reputasi belum tersedia."]
    
    lines = []
    score = _display(reputation.get("opencti_score"), 30)
    verdict = _display(reputation.get("verdict"), 40)
    if score or verdict:
        lines.append(f"- Skor OpenCTI: {score or 0}/100 - Verdict: {verdict or 'unknown'}.")
        
    labels = reputation.get("labels")
    if isinstance(labels, list) and labels:
        shown = [_display(label, 80) for label in labels[:8] if label]
        if shown:
            lines.append(f"- Label: {', '.join(shown)}.")
            
    authors = []
    if isinstance(observables, list):
        for obs in observables:
            if not isinstance(obs, dict): continue
            inds = _d(obs.get("opencti")).get("indicators", [])
            for ind in inds if isinstance(inds, list) else []:
                if isinstance(ind, dict):
                    author = ind.get("created_by") or ind.get("author")
                    if isinstance(author, dict): author = author.get("name")
                    if author and author not in authors: authors.append(str(author))
    
    lines.append("- Author: " + ("; ".join(authors[:5]) + "." if authors else "Tidak tersedia."))
    return lines

def _format_geolocation(value: Any) -> list[str]:
    """Format tampilan data geolokasi."""
    geo = _d(value)
    if not geo or geo.get("available") is False:
        return ["- Data geolokasi belum tersedia."]
        
    fields = (
        ("Lokasi", ", ".join(str(p) for p in (geo.get("city"), geo.get("region"), geo.get("country_name")) if p)),
        ("ISP", geo.get("isp") or geo.get("org")),
        ("ASN", geo.get("asn")),
        ("Hosting", "Ya" if geo.get("hosting") is True else "Tidak" if geo.get("hosting") is False else None),
        ("Proxy", "Ya" if geo.get("proxy") is True else "Tidak" if geo.get("proxy") is False else None),
    )
    return [f"- {label}: {_md_escape(val, 180)}" for label, val in fields if _display(val, 180)]


class IrisClient:
    """Class untuk berinteraksi dengan API DFIR-IRIS."""
    
    @classmethod
    def from_env(cls, env: dict) -> IrisClient | None:
        """Instansiasi klien berdasarkan environment variables."""
        if str(env.get("IRIS_ENABLED", "false")).strip().lower() != "true":
            return None
        return cls()

    def __init__(self):
        self.url = os.getenv("IRIS_URL", "").rstrip("/")
        self.api_key = os.getenv("IRIS_API_KEY", "")
        self.customer_id = int(os.getenv("IRIS_CUSTOMER_ID", 1))
        
        status = os.getenv("IRIS_STATUS_ID")
        self.status_id = int(status) if status else None
        
        self.source_link_tpl = os.getenv("IRIS_SOURCE_LINK_TEMPLATE", "")
        
        # Mapping tingkat keparahan risiko ke ID di IRIS
        self.severity_map = {
            "critical": 6,
            "high": 5,
            "medium": 4,
            "low": 3
        }
        
    def allows(self, doc: dict) -> bool:
        """Mengecek apakah log ini valid dan diizinkan untuk dikirim ke IRIS."""
        if not self.url or not self.api_key:
            return False
        return True

    def build_payload(self, doc: dict) -> dict:
        """Merakit dictionary payload yang siap dikirim via POST JSON ke IRIS."""
        # PENGAMANAN: Jika yang dikirim adalah object (LogRecord), ambil dictionary-nya
        if hasattr(doc, "doc") and isinstance(doc.doc, dict):
            doc = doc.doc
        if not isinstance(doc, dict):
            doc = {}

        risk = _d(doc.get("risk"))
        ev = _d(doc.get("event"))
        src = _d(doc.get("source"))
        asset = _d(doc.get("asset"))
        
        level = str(risk.get("level", "medium")).lower()
        what = _md_escape(ev.get("action") or ev.get("category") or "event", 80)
        
        destination = _d(doc.get("destination"))
        source_asset = _d(src.get("asset")) or (asset if src.get("ip") else {})
        destination_asset = _d(destination.get("asset"))
        observables = _d(doc.get("enrichment")).get("observables") or []
        is_wazuh = doc.get("data_source") == "wazuh" or "wazuh_level" in ev
        
        destination_ip = _display(destination.get("ip"), 80)
        source_ip = _display(src.get("ip"), 80)
        source_label = source_ip or "Tidak tersedia di event"
        destination_label = destination_ip or "Tidak tersedia di event"

        lines = [
            "Risiko",
            f"- Skor: {risk.get('score')} ({level})",
            f"- Faktor: kritikalitas aset {risk.get('asset_criticality')}, severity {risk.get('event_severity')}, outcome {risk.get('event_outcome')}, ancaman {risk.get('threat_weight')}, pengulangan {risk.get('repeat_count')}",
            "Event",
            f"- Deteksi: {what}",
            f"- Hasil: {_display(ev.get('outcome'), 60) or 'Tidak tersedia'}",
            f"- IP sumber (kemungkinan penyerang): {source_label}",
            *([f"- Wazuh Level: {_display(ev.get('wazuh_level'), 30)}"] if is_wazuh else []),
            f"- IP tujuan (host yang diserang): {destination_label}",
            "Source",
            *_format_asset(source_asset, src.get("ip")),
            "Destination",
            *_format_asset(destination_asset, destination.get("ip")),
            "Threat Intelligence Enrichment",
            *([f"- IP : {source_ip}"] if source_ip else []),
            *_format_reputation(doc.get("reputation"), observables),
            "Geolokasi",
            *_format_geolocation(doc.get("geolocation")),
            "IOC terkait"
        ]
        
        shown_ioc = False
        if isinstance(observables, list) and observables:
            for obs in observables[:20]:
                if not isinstance(obs, dict): continue
                e_type = _display(obs.get("entity_type"), 40)
                e_val = _display(obs.get("value"), 180)
                if e_type and e_val:
                    lines.append(f"- {e_type}: {e_val}")
                    shown_ioc = True
                    
        if not shown_ioc:
            lines.append("- Detail IOC tidak tersedia.")
            
        lines.append(f"log_uuid: {doc.get('log_uuid')}")

        tags = ["analisis_log", f"risk:{level}"]
        
        payload: dict[str, Any] = {
            "alert_title": f"[{level.upper()}] {what}"[:250],
            "alert_description": "\n".join(lines)[:8000],
            "alert_source": "Analisis_Log",
            "alert_source_ref": str(doc.get("log_uuid")),
            "alert_source_content": doc,
            "alert_severity_id": self.severity_map.get(level, 4),
            "alert_customer_id": self.customer_id,
            "alert_source_event_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
            "alert_tags": ",".join(tags),
        }
        
        if self.source_link_tpl:
            payload["alert_source_link"] = self.source_link_tpl.format(log_uuid=doc.get("log_uuid"))
        if self.status_id is not None:
            payload["alert_status_id"] = self.status_id
            
        return payload

    def send_alert(self, doc: dict) -> dict:
        """Kirim payload alert ke IRIS via HTTP API."""
        try:
            if not self.url or not self.api_key:
                logger.warning("IRIS_URL atau IRIS_API_KEY tidak diatur. Melewati pengiriman ke IRIS.")
                return {"status": "skipped", "reason": "iris_not_configured"}

            payload = self.build_payload(doc)
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            endpoint = f"{self.url}/alerts/add"
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(endpoint, data=data, headers=headers, method="POST")
            
            with urllib.request.urlopen(req, timeout=10) as response:
                resp_data = response.read().decode("utf-8")
                logger.info(f"Berhasil mengirim alert ke IRIS untuk log: {payload.get('alert_source_ref')}")
                return json.loads(resp_data)
                
        except urllib.error.HTTPError as e:
            logger.error(f"Gagal mengirim alert ke IRIS (HTTP Error): {e.code} - {e.reason}")
            error_body = e.read().decode("utf-8")
            logger.error(f"Response body: {error_body}")
            return {"status": "error", "error": f"HTTP {e.code}: {error_body}"}
        except Exception as e:
            # Jika masih terjadi error, ini akan mencetak baris penyebab utamanya di terminal!
            logger.error(f"Gagal mengirim alert ke IRIS: {e}\n{traceback.format_exc()}")
            raise e