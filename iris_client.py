"""
iris_client.py - Integrasi DFIR-IRIS (REST API: POST {IRIS_URL}/alerts/add, auth Bearer API key).


Alert dibuat dari log berisiko tinggi dan konteks enrichment. Severity IRIS ditentukan
secara deterministik dari risk score.

Source dan Destination tidak lagi ditulis di Description, tetapi dikirim sebagai
`alert_assets` (tab "Assets" alert IRIS) saat alert dibuat. IRIS v3 mengabaikan
`alert_assets` pada update alert, jadi data GLPI yang datang belakangan disinkronkan lewat:
  - PUT /api/v2/alerts/{alert}/assets/{asset}  -> aset di tab Assets alert (`sync_alert_assets`)
  - PUT /api/v2/manage/managed-assets/{id}     -> aset bersama (`sync_assets`)

Threat Intelligence, Geolokasi, dan IOC terkait tidak lagi ditulis di Description, tetapi
dikirim sebagai `alert_iocs` (tab "IOCs"): satu IOC per observable, dengan reputasi OpenCTI dan
geolokasi di deskripsi/enrichment IOC. Pembaruan belakangan lewat `sync_alert_iocs`.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import re
import ssl
from datetime import datetime, timezone
from typing import Any, Mapping

import httpx
import orjson

log = logging.getLogger("iris")
RETRY_STATUS = {429, 500, 502, 503, 504}

PATHS = {
    "legacy": {
        "alert": "/alerts/add", "alert_update": "/alerts/update/{id}",
        "alert_delete": "/alerts/delete/{id}",
        "escalate": "/alerts/escalate/{id}", "merge": "/alerts/merge/{id}",
        "case": "/manage/cases/add", "case_read": "/manage/cases/{id}",
        "case_update": "/manage/cases/update/{id}", "case_delete": "/manage/cases/delete/{id}",
        "case_note": "/case/notes/add",
        "probe": "/manage/cases/list",
        "severity_list": ["/manage/severities/list"], "status_list": ["/manage/alert-status/list"],
        "ioc_type_list": ["/manage/ioc-types/list"], "tlp_list": ["/manage/tlp/list"],
    },
    "v2": {
        "alert": "/api/v2/alerts", "alert_update": "/api/v2/alerts/{id}",
        "alert_delete": "/api/v2/alerts/{id}",
        "escalate": "/api/v2/alerts/escalate/{id}",
        "merge": "/api/v2/alerts/merge/{id}", "case": "/api/v2/cases",
        "case_read": "/api/v2/cases/{id}", "case_update": "/api/v2/cases/{id}",
        "case_delete": "/api/v2/cases/{id}",
        "case_note": "/api/v2/cases/{id}/notes",
        "case_note_directories": "/api/v2/cases/{id}/notes-directories",
        "probe": "/api/v2/cases",
        "managed_assets": "/api/v2/manage/managed-assets",
        "alert_asset": "/api/v2/alerts/{alert_id}/assets/{id}",
        "alert_ioc": "/api/v2/alerts/{alert_id}/iocs/{id}",
        "ioc_type_list": ["/api/v2/manage/case-objects/ioc-types"], "tlp_list": ["/api/v2/manage/tlp"],
        "severity_list": ["/api/v2/manage/severities"],
        "status_list": ["/api/v2/manage/alert-statuses", "/api/v2/manage/alert-status"]
    },
}


class IrisError(Exception):
    def __init__(self, msg: str):
        super().__init__(msg)
        self.public_message = msg


def _unwrap(j) -> dict:
    if not isinstance(j, dict):
        return {}
    d = j.get("data")
    return d if isinstance(d, dict) else j


DEFAULT_SEVERITY_MAP = {"low": 3, "medium": 4, "high": 5, "critical": 6}


def _d(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _short(v: Any, n: int = 300) -> str:
    return orjson.dumps(v).decode()[:n] if isinstance(v, (dict, list)) else str(v)[:n]


def _md_escape(v: Any, n: int = 300) -> str:
    s = _short(v, n)
    for ch in ("<", ">", "`", "|", "*", "[", "]"):
        s = s.replace(ch, " ")
    return s.replace("\r", " ").replace("\n", " ")


def _display(v: Any, n: int = 300) -> str | None:
    if v is None or v == "" or v == [] or v == {}:
        return None
    text = str(v).strip()
    if text.lower() in {
        "none", "null", "n/a", "not available", "tidak tersedia",
        "belum tersedia", "tidak ditemukan di glpi",
    }:
        return None
    return _md_escape(text, n)


def _join_list(val: Any) -> str:
    if isinstance(val, list):
        return ", ".join(str(v) for v in val if v)
    return str(val) if val else ""


def _format_reputation(value: Any, observables: list | None = None) -> list[str]:
    """Format reputasi dengan fallback ke observables jika doc.reputation kosong."""
    reputation = _d(value)

    if not reputation and isinstance(observables, list):
        for obs in observables:
            if not isinstance(obs, dict):
                continue
            opencti = obs.get("opencti")
            if isinstance(opencti, dict) and (opencti.get("score") or opencti.get("verdict") or opencti.get("indicators") or opencti.get("labels")):
                reputation = {
                    "opencti_score": opencti.get("score"),
                    "verdict": opencti.get("verdict"),
                    "labels": opencti.get("labels", []),
                    "indicators": opencti.get("indicators", []),
                }
                break
            if obs.get("opencti_score") or obs.get("verdict"):
                reputation = {
                    "opencti_score": obs.get("opencti_score"),
                    "verdict": obs.get("verdict"),
                    "labels": obs.get("labels", []),
                    "indicators": [],
                }
                break

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
    inds = reputation.get("indicators") or []
    if isinstance(inds, list):
        for ind in inds:
            if isinstance(ind, dict):
                author = ind.get("created_by") or ind.get("author")
                if isinstance(author, dict): author = author.get("name")
                if author and author not in authors: authors.append(str(author))

    if not authors and isinstance(observables, list):
        for obs in observables:
            if not isinstance(obs, dict): continue
            inds_obs = _d(obs.get("opencti")).get("indicators", [])
            for ind in inds_obs if isinstance(inds_obs, list) else []:
                if isinstance(ind, dict):
                    author = ind.get("created_by") or ind.get("author")
                    if isinstance(author, dict): author = author.get("name")
                    if author and author not in authors: authors.append(str(author))

    author_str = " | ".join(authors[:5]) if authors else "Tidak tersedia"
    lines.append(f"- Author: {author_str}.")
    return lines


def _format_geolocation(value: Any) -> list[str]:
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


def _format_asset(asset: dict, source_ip: Any, host_name: Any = None) -> list[str]:
    # Deteksi aset GLPI lebih fleksibel
    is_glpi_asset = (
        asset.get("inventory_source") == "GLPI" or
        asset.get("found") is True or
        isinstance(asset.get("id"), int) or
        bool(asset.get("glpi_id")) or
        isinstance(asset.get("items"), list)
    )

    if not is_glpi_asset:
        searched_ip = _display(asset.get("ip") or source_ip, 80)
        searched_host = _display(asset.get("host_name") or host_name, 80)

        if searched_ip and searched_host:
            lines = [f"- Tidak ada aset GLPI yang cocok dengan IP {searched_ip} maupun hostname {searched_host}."]
        elif searched_ip:
            lines = [f"- Tidak ada aset GLPI yang cocok dengan IP {searched_ip}."]
        elif searched_host:
            lines = [f"- Tidak ada aset GLPI yang cocok dengan hostname {searched_host}."]
        else:
            lines = ["- Tidak ada aset GLPI yang cocok: event tidak memuat IP maupun hostname."]

        error = _display(asset.get("error"), 160)
        if error:
            lines.append(f"- Catatan pencarian GLPI: {error}")
        return lines

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


def _make_alert_assets(role: str, tag: str, ip: Any, asset: dict, host_name: Any,
                       desc_lines: list[str], asset_type_id: int) -> list[dict]:
    """Ubah data aset GLPI (atau IP saja) menjadi entri alert_assets IRIS (tab Assets)."""
    ip_s = _display(ip, 80)
    items = asset.get("items")
    if isinstance(items, list) and items:
        glpi_items = [i for i in items if isinstance(i, dict)]
    else:
        glpi_items = [asset]

    out: list[dict] = []
    for item in glpi_items[:10]:
        priv_raw = _join_list(item.get("private_ip_addresses"))
        priv = priv_raw.split(", ")[0] if priv_raw else ""
        name = _display(item.get("name"), 150) or _display(host_name, 150) or ip_s
        if not name:
            continue
        lines = desc_lines if len(glpi_items) == 1 else _format_asset(item, ip, host_name)
        out.append({
            "asset_name": name,
            "asset_description": f"{role}\n" + "\n".join(lines),
            "asset_type_id": asset_type_id,
            "asset_ip": ip_s or priv or "",
            "asset_domain": "",
            "asset_tags": tag,
        })
    return out

_MANAGED_EDITABLE = ("name", "description", "owner", "location", "tags", "ip",
                     "domain", "criticality", "environment", "is_active", "custom_attributes")


def _glpi_items(asset: dict) -> list[dict]:
    """Kembalikan daftar item GLPI jika asset hasil lookup GLPI, selain itu list kosong."""
    items = asset.get("items")
    is_glpi = (
        asset.get("inventory_source") == "GLPI" or asset.get("found") is True
        or isinstance(asset.get("id"), int) or bool(asset.get("glpi_id"))
        or isinstance(items, list)
    )
    if not is_glpi:
        return []
    if isinstance(items, list) and items:
        return [i for i in items if isinstance(i, dict)]
    return [asset]


def _asset_targets(doc: dict) -> list[dict]:
    """Susun daftar {candidates, fields}: nama yang mungkin dipakai aset di IRIS + data GLPI."""
    src, dst = _d(doc.get("source")), _d(doc.get("destination"))
    agent = _d(doc.get("agent"))
    agent_host = _display(_d(doc.get("host")).get("name") or agent.get("name"), 80)
    agent_ip = _display(agent.get("ip"), 80)
    dst_ip = _display(dst.get("ip"), 80)

    if not src.get("ip") and not dst.get("ip"):
        sides = [(dst.get("ip"), _d(dst.get("asset")) or _d(doc.get("asset")), agent_host)]
    else:
        sides = [
            (src.get("ip"), _d(src.get("asset")), None if src.get("ip") else agent_host),
            (dst.get("ip"), _d(dst.get("asset")),
             agent_host if (not dst_ip or dst_ip == agent_ip) else None),
        ]

    targets: list[dict] = []
    for side_ip, side_asset, host_hint in sides:
        items = _glpi_items(side_asset)
        for item in items[:10]:
            cands: list[str] = []

            def add(v: Any) -> None:
                t = str(v).strip() if v else ""
                if t and t.lower() not in [c.lower() for c in cands]:
                    cands.append(t)

            if len(items) == 1:
                add(side_ip)
                add(host_hint)
            priv = item.get("private_ip_addresses")
            for v in (priv if isinstance(priv, list) else []):
                add(v)
            add(item.get("ip"))
            add(item.get("name"))
            if not cands:
                continue

            lines = _format_asset({"items": [item]}, side_ip, host_hint)
            fields = {
                "description": ("Sumber: GLPI (disinkronkan otomatis oleh Analisis_Log)\n"
                                + "\n".join(lines))[:3500],
                "owner": _display(item.get("owner") or item.get("user"), 150),
                "location": _display(item.get("location"), 150),
                "ip": (str(priv[0]) if isinstance(priv, list) and priv else None) or _display(item.get("ip"), 80),
            }
            targets.append({"candidates": cands, "glpi_lines": lines,
                            "fields": {k: v for k, v in fields.items() if v}})
    return targets


def _ioc_kind(entity_type: Any, value: Any) -> str | None:
    """Petakan observable ke jenis IOC IRIS: ip | domain | url | sha256 | sha1 | md5 | filename."""
    t, v = str(entity_type or "").lower(), str(value or "").strip()
    if not v or t in ("host-name", "hostname", "host"):
        return None
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if "ipv4" in t or "ipv6" in t:
        return "ip"
    if "domain" in t:
        return "domain"
    if "url" in t:
        return "url"
    for kind, n in (("sha256", 64), ("sha1", 40), ("md5", 32)):
        if len(v) == n and re.fullmatch(r"[0-9a-fA-F]+", v):
            return kind
    if "file" in t:
        return "filename"
    return None


class IrisClient:
    def __init__(self, url: str, api_key: str, customer_id: int, verify: bool | ssl.SSLContext,
                 timeout_s: float, severity_map: dict[str, int], status_id: int | None,
                 source_link_tpl: str, api_version: str = "v2"):
        if api_version not in PATHS:
            raise ValueError("IRIS_API_VERSION harus: v2 | legacy")
        self.api_version = api_version
        self.paths = PATHS[api_version]
        self.customer_id = customer_id
        self._severity_explicit = False
        self.min_wazuh_level = 0
        self.max_wazuh_level = 0
        self.asset_type_id = 1
        self.assets_in_description = False
        self.sync_assets_enabled = True
        self.iocs_in_description = False
        self.show_event = True
        self.case_full_description = False
        self.case_import_assets = True
        self.case_summary_field = ""
        self.ioc_type_ids: dict[str, int] = {}
        self._ioc_type_override: dict[str, int] = {}
        self.tlp_id: int | None = None
        self._asset_sync_done: set[str] = set()
        self._asset_sync_lock = asyncio.Lock()
        self._ids_ready = False
        self._ids_lock = asyncio.Lock()
        self.severity_map = severity_map
        self.status_id = status_id
        self.source_link_tpl = source_link_tpl
        self._client = httpx.AsyncClient(
            base_url=url.rstrip("/"), verify=verify,
            timeout=httpx.Timeout(timeout_s, connect=5.0),
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "IrisClient | None":
        if env.get("IRIS_ENABLED", "false").lower() != "true":
            return None
        url, key = env.get("IRIS_URL", ""), env.get("IRIS_API_KEY", "")
        if not url or not key:
            raise ValueError("IRIS_URL dan IRIS_API_KEY wajib diisi jika IRIS_ENABLED=true")
        ca = env.get("IRIS_CA_CERT", "")
        verify: bool | ssl.SSLContext = (ssl.create_default_context(cafile=ca) if ca
                                         else env.get("IRIS_VERIFY_SSL", "true").lower() == "true")
        smap = dict(DEFAULT_SEVERITY_MAP)
        for pair in filter(None, env.get("IRIS_SEVERITY_MAP", "").split(",")):
            k, _, v = pair.partition(":")
            smap[k.strip().lower()] = int(v)
        status = env.get("IRIS_STATUS_ID", "").strip()
        obj = cls(url, key, int(env.get("IRIS_CUSTOMER_ID", "1")), verify,
                  float(env.get("IRIS_TIMEOUT_S", "30")), smap,
                  int(status) if status else None, env.get("IRIS_SOURCE_LINK_TEMPLATE", ""),
                  env.get("IRIS_API_VERSION", "v2").lower())
        obj._severity_explicit = bool(env.get("IRIS_SEVERITY_MAP", "").strip())
        obj.min_wazuh_level = int(env.get("IRIS_MIN_WAZUH_LEVEL", "0") or 0)
        obj.max_wazuh_level = int(env.get("IRIS_MAX_WAZUH_LEVEL", "0") or 0)
        obj.asset_type_id = int(env.get("IRIS_ASSET_TYPE_ID", "1") or 1)
        obj.assets_in_description = env.get("IRIS_ASSETS_IN_DESCRIPTION", "false").lower() == "true"
        obj.sync_assets_enabled = env.get("IRIS_SYNC_ASSETS", "true").lower() == "true"
        obj.iocs_in_description = env.get("IRIS_IOCS_IN_DESCRIPTION", "false").lower() == "true"
        obj.show_event = env.get("IRIS_SHOW_EVENT", "true").lower() == "true"
        obj.case_full_description = env.get("IRIS_CASE_FULL_DESCRIPTION", "false").lower() == "true"
        obj.case_import_assets = env.get("IRIS_CASE_IMPORT_ASSETS", "true").lower() == "true"
        obj.case_summary_field = env.get("IRIS_CASE_SUMMARY_FIELD", "").strip()
        for pair in filter(None, env.get("IRIS_IOC_TYPE_MAP", "").split(",")):
            k, _, v = pair.partition(":")
            obj._ioc_type_override[k.strip().lower()] = int(v)
        tlp = env.get("IRIS_IOC_TLP_ID", "").strip()
        obj.tlp_id = int(tlp) if tlp else None
        return obj

    def allows(self, doc: dict) -> bool:
        lvl = _d(doc.get("event")).get("wazuh_level")
        try:
            lvl = int(lvl)
        except (TypeError, ValueError):
            return True
        if lvl < self.min_wazuh_level:
            return False
        return not (self.max_wazuh_level and lvl > self.max_wazuh_level)

    def build_payload(self, doc: dict) -> dict:
        if hasattr(doc, "doc") and isinstance(doc.doc, dict):
            doc = doc.doc
        if not isinstance(doc, dict):
            doc = {}

        risk = _d(doc.get("risk"))
        ev = _d(doc.get("event"))
        src = _d(doc.get("source"))
        asset = _d(doc.get("asset"))
        agent_info = _d(doc.get("agent"))
        agent_host = _display(_d(doc.get("host")).get("name") or agent_info.get("name"), 80)
        agent_ip = _display(agent_info.get("ip"), 80)

        level = str(risk.get("level", "medium")).lower()
        what = _md_escape(ev.get("action") or ev.get("category") or "event", 80)
        who = _md_escape(src.get("ip") or asset.get("name") or "unknown", 80)

        destination = _d(doc.get("destination"))
        observables = _d(doc.get("enrichment")).get("observables") or []
        is_wazuh = doc.get("data_source") == "wazuh" or "wazuh_level" in ev

        destination_ip = _display(destination.get("ip"), 80)
        source_ip = _display(src.get("ip"), 80)
        source_label = source_ip or "Tidak tersedia di event"
        destination_label = destination_ip or "Tidak tersedia di event"

        is_local_event = not src.get("ip") and not destination.get("ip")

        if is_local_event:
            source_asset = {}
            destination_asset = _d(destination.get("asset")) or asset
        else:
            source_asset = _d(src.get("asset"))
            destination_asset = _d(destination.get("asset"))

        src_host = None if src.get("ip") else agent_host
        dst_host = agent_host if (not destination_ip or destination_ip == agent_ip) else None
        src_lines = _format_asset(source_asset, src.get("ip"), src_host)
        dst_lines = _format_asset(destination_asset, destination.get("ip"), dst_host)

        lines = [
            "# Risiko",
            f"- Skor: {risk.get('score')} ({level})",
            f"- Faktor: kritikalitas aset {risk.get('asset_criticality')}, severity {risk.get('event_severity')}, outcome {risk.get('event_outcome')}, ancaman {risk.get('threat_weight')}, pengulangan {risk.get('repeat_count')}",
        ]
        risk_lines = list(lines)
        event_block = [
            "# Event",
            f"- Deteksi: {what}",
            f"- Hasil: {_display(ev.get('outcome'), 60) or 'Tidak tersedia'}",
            f"- IP sumber (kemungkinan penyerang): {source_label}",
            *([f"- Wazuh Level: {_display(ev.get('wazuh_level'), 30)}"] if is_wazuh else []),
            f"- IP tujuan (host yang diserang): {destination_label}",
        ]
        asset_block = ["# Source", *src_lines, "# Destination", *dst_lines]
        # Bagian "# Event" bisa disembunyikan lewat IRIS_SHOW_EVENT=false.
        if self.show_event:
            lines += event_block
        # Source/Destination hanya ditulis di Description jika toggle dinyalakan.
        if self.assets_in_description:
            lines += asset_block
        ti: list[str] = ["# Threat Intelligence Enrichment"]

        # Source/Destination dikirim sebagai asset -> tab "Assets" di IRIS.
        alert_assets: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for a in (
            *_make_alert_assets("Source (kemungkinan penyerang)", "source", src.get("ip"),
                                source_asset, None, src_lines, self.asset_type_id),
            *_make_alert_assets("Destination (host yang diserang)", "destination", destination.get("ip"),
                                destination_asset, dst_host, dst_lines, self.asset_type_id),
        ):
            key = (a["asset_name"].lower(), a["asset_ip"])
            if key not in seen:
                seen.add(key)
                alert_assets.append(a)

        enriched_iocs = {"IP": [], "Domain": [], "Hash/File": []}
        reputation_data = _d(doc.get("reputation"))
        rep_ip = reputation_data.get("ip") or reputation_data.get("value")

        if isinstance(observables, list):
            for obs in observables:
                if not isinstance(obs, dict):
                    continue
                val = str(obs.get("value", ""))
                e_type = str(obs.get("entity_type", ""))

                has_opencti = False
                if rep_ip and val == rep_ip:
                    has_opencti = True
                elif isinstance(obs.get("opencti"), dict) and (obs["opencti"].get("indicators") or obs["opencti"].get("score")):
                    has_opencti = True
                elif obs.get("opencti_score") or obs.get("verdict"):
                    has_opencti = True

                if has_opencti:
                    if e_type in ("IPv4", "IPv6", "Ip") or (val and val.replace(".", "").replace(":", "").isdigit()):
                        if val not in enriched_iocs["IP"]:
                            enriched_iocs["IP"].append(val)
                    elif e_type in ("Domain", "Url", "Hostname"):
                        if val not in enriched_iocs["Domain"]:
                            enriched_iocs["Domain"].append(val)
                    elif e_type in ("StixFile", "File", "SHA-256", "SHA-1", "MD5"):
                        if val not in enriched_iocs["Hash/File"]:
                            enriched_iocs["Hash/File"].append(val)

        summary_parts = []
        if enriched_iocs["IP"]:
            summary_parts.append(f"IP: {', '.join(enriched_iocs['IP'])}")
        if enriched_iocs["Domain"]:
            summary_parts.append(f"Domain: {', '.join(enriched_iocs['Domain'])}")
        if enriched_iocs["Hash/File"]:
            summary_parts.append(f"Hash/File: {', '.join(enriched_iocs['Hash/File'][:3])}")

        if summary_parts:
            ti.append(f"- IOC : {' | '.join(summary_parts)}")
        elif source_ip:
            ti.append(f"- IP Sumber: {source_ip} (Tidak ditemukan dalam database OpenCTI)")

        ti.extend(_format_reputation(doc.get("reputation"), observables))
        ti.append("# Geolokasi")
        ti.extend(_format_geolocation(doc.get("geolocation")))
        ti.append("# IOC terkait")

        shown_ioc = False
        if isinstance(observables, list) and observables:
            for obs in observables[:20]:
                if not isinstance(obs, dict): continue
                e_type = _display(obs.get("entity_type"), 40)
                e_val = _display(obs.get("value"), 180)
                if e_type and e_val and e_type.lower() not in ("host-name", "hostname", "host"):
                    ti.append(f"- {e_type}: {e_val}")
                    shown_ioc = True

        if not shown_ioc:
            ti.append("- Detail IOC tidak tersedia.")

        if self.iocs_in_description:
            lines.extend(ti)
        uuid_line = f"log_uuid: {doc.get('log_uuid')}"
        lines.append(uuid_line)
        # Deskripsi lengkap (semua bagian, tanpa memedulikan toggle) disimpan di dalam
        # alert_source_content supaya konsumen lain (mis. iris_stream) tetap menerima isi
        # yang utuh walaupun tampilan Description di IRIS dibuat ringkas.
        full_description = "\n".join([*risk_lines, *event_block, *asset_block, *ti, uuid_line])[:16000]

        tags = ["analisis_log", f"risk:{level}"]

        doc_json_str = orjson.dumps(doc).decode('utf-8')
        if len(doc_json_str) > 500_000:
            safe_doc = {"error": "Payload terlalu besar (>500KB), dipangkas untuk keamanan IRIS", "log_uuid": doc.get("log_uuid")}
        else:
            safe_doc = doc
        safe_doc = {**safe_doc, "alert_description_full": full_description}

        payload: dict[str, Any] = {
            "alert_title": f"[{level.upper()}] {what} - {who}"[:250],
            "alert_description": "\n".join(lines)[:8000],
            "alert_source": "Analisis_Log",
            "alert_source_ref": str(doc.get("log_uuid")),
            "alert_source_content": safe_doc,
            "alert_severity_id": self.severity_map.get(level, 4),
            "alert_customer_id": self.customer_id,
            "alert_source_event_time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "alert_tags": ",".join(tags),
            "alert_assets": alert_assets,
        }
        alert_iocs = self._build_alert_iocs(doc)
        if alert_iocs:
            payload["alert_iocs"] = alert_iocs
        if self.source_link_tpl:
            payload["alert_source_link"] = self.source_link_tpl.format(log_uuid=doc.get("log_uuid"))
        if self.status_id is not None:
            payload["alert_status_id"] = self.status_id
        return payload

    def _ioc_type_id(self, kind: str, is_source: bool = False) -> int | None:
        ids = self.ioc_type_ids
        order = {
            "ip": ["ip-src", "ip-dst"] if is_source else ["ip-dst", "ip-src"],
            "domain": ["domain", "hostname"], "url": ["url"], "sha256": ["sha256"],
            "sha1": ["sha1"], "md5": ["md5"], "filename": ["filename"],
        }.get(kind, [])
        return next((ids[n] for n in order if n in ids), None)

    def _build_alert_iocs(self, doc: dict) -> list[dict]:
        """Satu IOC per observable, dengan reputasi OpenCTI + geolokasi di deskripsi/enrichment."""
        if not self.ioc_type_ids or self.tlp_id is None:
            return []
        doc = doc if isinstance(doc, dict) else {}
        observables = _d(doc.get("enrichment")).get("observables") or []
        if not isinstance(observables, list):
            observables = []
        src_ip = str(_d(doc.get("source")).get("ip") or "")
        # IP sumber/tujuan selalu jadi IOC, walau enrichment (observables) belum datang,
        # supaya update berikutnya punya IOC yang bisa diisi data OpenCTI/geolokasi.
        known = {str(o.get("value") or "").strip().lower() for o in observables if isinstance(o, dict)}
        base = [{"entity_type": "IPv4-Addr", "value": str(ip)}
                for ip in (src_ip, _d(doc.get("destination")).get("ip"))
                if ip and str(ip).strip().lower() not in known]
        observables = [*base, *observables]
        rep = _d(doc.get("reputation"))
        rep_ip = str(rep.get("ip") or rep.get("value") or "")
        geo = doc.get("geolocation")
        geo_ok = isinstance(geo, dict) and bool(geo) and geo.get("available") is not False

        out: list[dict] = []
        seen: set[str] = set()
        geo_done = False
        for obs in observables[:50]:
            if not isinstance(obs, dict):
                continue
            value = str(obs.get("value") or "").strip()
            kind = _ioc_kind(obs.get("entity_type"), value)
            if not kind or value.lower() in seen:
                continue
            is_src = bool(src_ip) and value == src_ip
            type_id = self._ioc_type_id(kind, is_src)
            if type_id is None:
                continue
            seen.add(value.lower())

            rep_here = rep if (rep and rep_ip and rep_ip == value) else {}
            rep_lines = _format_reputation(rep_here, [obs])
            if rep_lines == ["- Data reputasi belum tersedia."]:
                rep_lines = ["- Belum ada data OpenCTI untuk IOC ini."]
            lines = ["Threat Intelligence (OpenCTI):", *rep_lines]

            enr: dict[str, Any] = {}
            opencti = obs.get("opencti")
            if isinstance(opencti, dict) and opencti:
                enr["opencti"] = opencti
            elif rep_here:
                enr["opencti"] = rep_here

            use_geo = geo_ok and kind == "ip" and not geo_done and (is_src or not src_ip)
            if use_geo:
                geo_done = True
                lines += ["Geolokasi:", *_format_geolocation(geo)]
                enr["geolocation"] = geo
            if enr:
                enr = orjson.loads(orjson.dumps(enr, default=str))
                if len(orjson.dumps(enr)) > 20_000:
                    enr = {}

            ioc = {
                "ioc_value": value[:1000],
                "ioc_type_id": type_id,
                "ioc_tlp_id": self.tlp_id,
                "ioc_description": "\n".join(lines)[:3000],
                "ioc_tags": "analisis_log",
            }
            if enr:
                ioc["ioc_enrichment"] = enr
            out.append(ioc)
        return out

    def _parse(self, r: httpx.Response, path: str) -> dict:
        if r.status_code >= 400:
            log.warning("IRIS %s -> HTTP %s: %s", path, r.status_code, r.text[:300].replace("\n", " "))
            r.raise_for_status()
        try:
            return _unwrap(r.json())
        except ValueError:
            raise IrisError("Respons IRIS bukan JSON (path API salah? IRIS v3 butuh IRIS_API_VERSION=v2)") from None

    async def _post(self, path: str, body: dict) -> dict:
        for attempt in range(3):
            try:
                r = await self._client.post(path, json=body)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                if attempt == 2:
                    raise
                await asyncio.sleep(1 + attempt)
                continue
            if r.status_code in RETRY_STATUS and attempt < 2:
                await asyncio.sleep(1 + attempt)
                continue
            return self._parse(r, path)
        return {}

    async def _put(self, path: str, body: dict) -> dict:
        for attempt in range(3):
            try:
                r = await self._client.put(path, json=body)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                if attempt == 2:
                    raise
                await asyncio.sleep(1 + attempt)
                continue
            if r.status_code in RETRY_STATUS and attempt < 2:
                await asyncio.sleep(1 + attempt)
                continue
            return self._parse(r, path)
        return {}

    async def _get(self, path: str, params: dict | None = None) -> dict:
        for attempt in range(3):
            try:
                r = await self._client.get(path, params=params)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                if attempt == 2:
                    raise
                await asyncio.sleep(1 + attempt)
                continue
            if r.status_code in RETRY_STATUS and attempt < 2:
                await asyncio.sleep(1 + attempt)
                continue
            return self._parse(r, path)
        return {}

    async def _delete(self, path: str) -> dict | bool:
        for attempt in range(3):
            try:
                r = await self._client.delete(path)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                if attempt == 2:
                    raise
                await asyncio.sleep(1 + attempt)
                continue
            if r.status_code in RETRY_STATUS and attempt < 2:
                await asyncio.sleep(1 + attempt)
                continue
            if r.status_code in (200, 204):
                return True
            return self._parse(r, path)
        return False

    async def create_alert(self, doc: dict) -> int | None:
        await self._ensure_ids()
        payload = self.build_payload(doc)
        if payload.get("alert_iocs"):
            log.info("IRIS: membuat alert dengan %d IOC", len(payload["alert_iocs"]))
        else:
            log.warning("IRIS: alert dibuat TANPA alert_iocs (tipe IOC dikenali=%s, tlp_id=%s)",
                        sorted(self.ioc_type_ids), self.tlp_id)
        try:
            d = await self._post(self.paths["alert"], payload)
        except httpx.HTTPStatusError as exc:
            if not payload.get("alert_iocs") or exc.response.status_code not in (400, 422):
                raise
            log.warning("IRIS: alert ditolak dengan alert_iocs (HTTP %s); diulang tanpa IOC. "
                        "Cek IRIS_IOC_TYPE_MAP / IRIS_IOC_TLP_ID.", exc.response.status_code)
            payload.pop("alert_iocs")
            d = await self._post(self.paths["alert"], payload)
        await self._safe_sync_assets(doc)
        return d.get("alert_id") or d.get("id")

    async def update_alert(self, alert_id: int, doc: dict) -> None:
        payload = self.build_payload(doc)
        update = {
            key: payload[key]
            for key in (
                "alert_title", "alert_description", "alert_source_content",
                "alert_severity_id", "alert_tags",
            )
        }
        # alert_assets diabaikan IRIS saat update; aset diperbarui lewat _safe_sync_assets().
        path = self.paths["alert_update"].format(id=alert_id)
        if self.api_version == "legacy":
            await self._post(path, update)
        else:
            await self._put(path, update)
        await self._safe_sync_assets(doc, alert_id)

    # ============================================================
    # SINKRONISASI MANAGED ASSET (data GLPI -> aset IRIS)
    # ============================================================
    async def _safe_sync_assets(self, doc: dict, alert_id: int | None = None) -> None:
        # sinkronisasi aset tidak boleh menggagalkan alert
        try:
            await self.sync_assets(doc)
        except Exception as exc:
            log.warning("IRIS: sinkronisasi managed asset gagal (%s): %s", type(exc).__name__, exc)
        if alert_id is not None:
            try:
                await self.sync_alert_assets(alert_id, doc)
            except Exception as exc:
                log.warning("IRIS: sinkronisasi aset alert %s gagal (%s): %s", alert_id, type(exc).__name__, exc)
            try:
                await self.sync_alert_iocs(alert_id, doc)
            except Exception as exc:
                log.warning("IRIS: sinkronisasi IOC alert %s gagal (%s): %s", alert_id, type(exc).__name__, exc)

    async def sync_alert_iocs(self, alert_id: int, doc: dict) -> int:
        """Perbarui IOC alert yang sudah ada (deskripsi/enrichment) lewat PUT /alerts/{id}/iocs/{id}."""
        tpl = self.paths.get("alert_ioc")
        if not (self.sync_assets_enabled and tpl):
            return 0
        if hasattr(doc, "doc") and isinstance(doc.doc, dict):
            doc = doc.doc
        await self._ensure_ids()
        desired = self._build_alert_iocs(doc if isinstance(doc, dict) else {})
        if not desired:
            return 0
        sig = f"alert-ioc:{alert_id}:" + hashlib.sha1(orjson.dumps(desired, option=orjson.OPT_SORT_KEYS)).hexdigest()
        if sig in self._asset_sync_done:
            return 0

        async with self._asset_sync_lock:
            if sig in self._asset_sync_done:
                return 0
            alert = await self.get_alert(alert_id) or {}
            existing = {
                str(i.get("ioc_value") or i.get("value") or "").lower(): i
                for i in (alert.get("iocs") or []) if isinstance(i, dict)
            }
            updated, complete = 0, True
            for want in desired:
                cur = existing.get(want["ioc_value"].lower())
                ioc_id = (cur or {}).get("ioc_id") or (cur or {}).get("id")
                if ioc_id is None:
                    complete = False
                    log.info("IRIS: alert %s: IOC %s belum ada di alert (tidak bisa ditambah lewat update)",
                             alert_id, want["ioc_value"])
                    continue
                if ((cur.get("ioc_description") or "") == want["ioc_description"]
                        and (cur.get("ioc_enrichment") or None) == want.get("ioc_enrichment")):
                    continue
                body = {
                    "ioc_value": want["ioc_value"],
                    "ioc_type_id": cur.get("ioc_type_id") or want["ioc_type_id"],
                    "ioc_tlp_id": cur.get("ioc_tlp_id") or want["ioc_tlp_id"],
                    "ioc_description": want["ioc_description"],
                    "ioc_tags": cur.get("ioc_tags") or want["ioc_tags"],
                }
                if want.get("ioc_enrichment"):
                    body["ioc_enrichment"] = want["ioc_enrichment"]
                path = tpl.format(alert_id=alert_id, id=ioc_id)
                r = await self._client.put(path, json=body)
                if r.status_code >= 400:
                    log.warning("IRIS %s -> HTTP %s: %s", path, r.status_code, r.text[:300].replace("\n", " "))
                    r.raise_for_status()
                updated += 1
                log.info("IRIS: alert %s: IOC %s diperbarui", alert_id, want["ioc_value"])
            if complete:
                if len(self._asset_sync_done) > 5000:
                    self._asset_sync_done.clear()
                self._asset_sync_done.add(sig)
            return updated

    async def sync_alert_assets(self, alert_id: int, doc: dict) -> int:
        """Perbarui aset di tab Assets alert (deskripsi GLPI) lewat PUT /alerts/{id}/assets/{id}."""
        tpl = self.paths.get("alert_asset")
        if not (self.sync_assets_enabled and tpl):
            return 0
        if hasattr(doc, "doc") and isinstance(doc.doc, dict):
            doc = doc.doc
        targets = _asset_targets(doc if isinstance(doc, dict) else {})
        if not targets:
            return 0
        sig = f"alert:{alert_id}:" + hashlib.sha1(orjson.dumps(targets, option=orjson.OPT_SORT_KEYS)).hexdigest()
        if sig in self._asset_sync_done:
            return 0

        async with self._asset_sync_lock:
            if sig in self._asset_sync_done:
                return 0
            alert = await self.get_alert(alert_id) or {}
            assets = [a for a in (alert.get("assets") or []) if isinstance(a, dict) and a.get("asset_id") is not None]
            updated, complete, used = 0, True, set()
            for t in targets:
                cands = {c.lower() for c in t["candidates"]}
                a = next((x for x in assets if x["asset_id"] not in used and (
                    str(x.get("asset_name") or "").lower() in cands
                    or str(x.get("asset_ip") or "").lower() in cands)), None)
                if a is None:
                    complete = False
                    log.info("IRIS: alert %s: aset untuk %s belum ditemukan", alert_id, t["candidates"][:3])
                    continue
                used.add(a["asset_id"])
                tag = str(a.get("asset_tags") or "").lower()
                role = ("Source (kemungkinan penyerang)" if "source" in tag
                        else "Destination (host yang diserang)" if "destination" in tag else "")
                new_desc = ((role + "\n") if role else "") + "\n".join(t["glpi_lines"])
                if (a.get("asset_description") or "") == new_desc:
                    continue
                body = {
                    "asset_name": a.get("asset_name"),
                    "asset_type_id": a.get("asset_type_id"),
                    "asset_description": new_desc,
                    "asset_ip": a.get("asset_ip") or t["fields"].get("ip") or "",
                    "asset_domain": a.get("asset_domain") or "",
                    "asset_tags": a.get("asset_tags") or "",
                }
                if a.get("asset_enrichment") is not None:
                    body["asset_enrichment"] = a["asset_enrichment"]
                path = tpl.format(alert_id=alert_id, id=a["asset_id"])
                r = await self._client.put(path, json=body)
                if r.status_code >= 400:
                    log.warning("IRIS %s -> HTTP %s: %s", path, r.status_code, r.text[:300].replace("\n", " "))
                    r.raise_for_status()
                updated += 1
                log.info("IRIS: alert %s: aset %s (%s) diperbarui dengan data GLPI", alert_id, a["asset_id"], a.get("asset_name"))
            if complete:
                if len(self._asset_sync_done) > 5000:
                    self._asset_sync_done.clear()
                self._asset_sync_done.add(sig)
            return updated

    async def _save_managed_asset(self, path: str, body: dict) -> dict:
        try:
            return await self._put(path, body)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 405:
                raise
        r = await self._client.patch(path, json=body)
        return self._parse(r, path)

    async def sync_assets(self, doc: dict) -> int:
        """Isi managed asset yang sudah ada (owner, lokasi, IP, deskripsi) dengan data GLPI.

        Nama/tipe/customer tidak diubah karena itu identitas aset. Mengembalikan jumlah aset
        yang diperbarui.
        """
        base = self.paths.get("managed_assets")
        if not (self.sync_assets_enabled and base):
            return 0
        if hasattr(doc, "doc") and isinstance(doc.doc, dict):
            doc = doc.doc
        targets = _asset_targets(doc if isinstance(doc, dict) else {})
        if not targets:
            return 0
        sig = hashlib.sha1(orjson.dumps(targets, option=orjson.OPT_SORT_KEYS)).hexdigest()
        if sig in self._asset_sync_done:
            return 0

        async with self._asset_sync_lock:
            if sig in self._asset_sync_done:
                return 0
            listing = await self._get(base)
            rows = listing.get("data") if isinstance(listing.get("data"), list) else []
            if isinstance(listing.get("total"), int) and listing["total"] > len(rows):
                log.warning("IRIS: daftar managed asset terpotong (%s dari %s)", len(rows), listing["total"])
            index = {
                str(r.get("normalized_name") or r.get("name") or "").lower(): r
                for r in rows
                if isinstance(r, dict) and r.get("client_id") in (None, self.customer_id)
            }

            updated, complete, used = 0, True, set()
            for t in targets:
                row = next((index[c.lower()] for c in t["candidates"] if c.lower() in index), None)
                mid = row.get("managed_asset_id") if row else None
                if mid is None:
                    complete = False
                    log.info("IRIS: managed asset untuk %s belum ditemukan, dicoba lagi nanti", t["candidates"][:3])
                    continue
                if mid in used:
                    continue
                used.add(mid)
                fields = t["fields"]
                if all(row.get(k) == v for k, v in fields.items()):
                    continue
                body = {k: row.get(k) for k in _MANAGED_EDITABLE}
                if body.get("custom_attributes") is None:
                    body["custom_attributes"] = {}
                body.update(fields)
                await self._save_managed_asset(f"{base}/{mid}", body)
                updated += 1
                log.info("IRIS: managed asset %s (%s) diperbarui dari GLPI: %s",
                         mid, row.get("name"), sorted(fields))
            if complete:
                if len(self._asset_sync_done) > 5000:
                    self._asset_sync_done.clear()
                self._asset_sync_done.add(sig)
            return updated

    # ============================================================
    # GET & UPDATE ALERT DESCRIPTION
    # ============================================================
    async def get_alert(self, alert_id: int) -> dict | None:
        """Mengambil detail alert berdasarkan ID."""
        path = self.paths["alert_update"].format(id=alert_id)
        try:
            return await self._get(path)
        except Exception as e:
            log.error("Gagal mengambil detail alert %s: %s", alert_id, e)
            return None

    async def update_alert_description(self, alert_id: int, new_description: str) -> bool:
        """
        Mengupdate seluruh deskripsi alert dengan string baru.
        Digunakan untuk menyisipkan incident_report di tengah deskripsi.
        """
        path = self.paths["alert_update"].format(id=alert_id)
        # Batasi panjang maksimal sesuai batas IRIS
        update_payload = {"alert_description": new_description[:16000]}

        try:
            if self.api_version == "legacy":
                await self._post(path, update_payload)
            else:
                await self._put(path, update_payload)
            log.info("✅ Berhasil mengupdate deskripsi alert %s.", alert_id)
            return True
        except Exception as e:
            log.error("❌ Gagal mengupdate deskripsi alert %s: %s", alert_id, e)
            return False
    # ============================================================

    async def delete_alert(self, alert_id: int) -> bool:
        path = self.paths["alert_delete"].format(id=alert_id)
        if self.api_version == "v2":
            return await self._delete(path) is True
        else:
            res = await self._post(path, {})
            return bool(res)

    def _case_text(self, payload: dict) -> str:
        """Teks untuk case/note: lengkap (Event, Source, Destination, TI, Geolokasi, IOC) atau ringkas."""
        if self.case_full_description:
            full = _d(payload.get("alert_source_content")).get("alert_description_full")
            if isinstance(full, str) and full:
                return full
        return payload["alert_description"]

    async def create_case(self, doc: dict) -> int | None:
        p = self.build_payload(doc)
        body = {"case_name": p["alert_title"][:250], "case_description": self._case_text(p),
                "case_customer": self.customer_id, "case_soc_id": str(doc.get("log_uuid"))}
        if self.case_summary_field:
            body[self.case_summary_field] = body["case_description"]
        d = await self._post(self.paths["case"], body)
        return d.get("case_id") or d.get("id")

    async def update_case_description(self, case_id: int, doc: dict) -> bool:
        current = await self._get(self.paths["case_read"].format(id=case_id))
        current_description = current.get("case_description") or current.get("description", "")
        if not isinstance(current_description, str):
            current_description = ""

        updated_description = self._case_text(self.build_payload(doc))

        summary_same = (not self.case_summary_field
                        or str(current.get(self.case_summary_field) or "").strip() == updated_description.strip())
        if updated_description.strip() == current_description.strip() and summary_same:
            log.info("Case %s: Deskripsi tidak berubah, skip update untuk menghemat resource.", case_id)
            return False

        log.info("Case %s: Memulai pembaruan deskripsi...", case_id)

        if self.api_version == "v2":
            update_payload = {
                "case_description": updated_description,
                "case_name": current.get("case_name") or current.get("name", "Unnamed Case"),
                "case_customer": current.get("case_customer") or self.customer_id,
                "case_soc_id": current.get("case_soc_id") or current.get("soc_id") or "",
                "case_tags": current.get("case_tags") or "",
            }
            if self.case_summary_field:
                update_payload[self.case_summary_field] = updated_description
            if "classification_id" in current:
                update_payload["classification_id"] = current["classification_id"]
            if "owner_id" in current:
                update_payload["owner_id"] = current["owner_id"]

            await self._put(self.paths["case_update"].format(id=case_id), update_payload)
        else:
            legacy_body = {
                "case_name": current.get("case_name") or current.get("name", "Unnamed Case"),
                "case_soc_id": current.get("case_soc_id") or current.get("soc_id") or "",
                "case_description": updated_description,
                "classification_id": current.get("classification_id") or current.get("case_classification_id"),
                "custom_attributes": current.get("custom_attributes") or {},
                "owner_id": current.get("owner_id") or current.get("case_owner_id"),
                "case_tags": current.get("case_tags") or "",
            }
            if self.case_summary_field:
                legacy_body[self.case_summary_field] = updated_description
            await self._post(self.paths["case_update"].format(id=case_id), legacy_body)

        log.info("✅ Case %s: Deskripsi berhasil diperbarui.", case_id)
        return True

    async def delete_case(self, case_id: int) -> bool:
        path = self.paths["case_delete"].format(id=case_id)
        if self.api_version == "v2":
            return await self._delete(path) is True
        else:
            res = await self._post(path, {})
            return bool(res)

    async def add_case_note(self, case_id: int, doc: dict) -> None:
        payload = self.build_payload(doc)
        if self.api_version == "v2":
            directories_path = self.paths["case_note_directories"].format(id=case_id)
            response = await self._get(directories_path, {"per_page": 100, "page": 1})
            directories = response.get("data")
            if isinstance(directories, dict):
                directories = directories.get("data")
            if not isinstance(directories, list):
                raise IrisError("IRIS tidak mengembalikan daftar direktori catatan case")
            valid_directories = [directory for directory in directories if isinstance(directory, dict) and isinstance(directory.get("id"), int)]
            directory = next((item for item in valid_directories if item.get("parent_id") is None), valid_directories[0] if valid_directories else None)
            if directory is None:
                created = await self._post(directories_path, {"name": "Analisis_Log Updates"})
                directory = created
                if not isinstance(directory, dict) or not isinstance(directory.get("id"), int):
                    raise IrisError(f"IRIS gagal membuat direktori catatan untuk case {case_id}")
            directory_id = directory["id"]
        else:
            directory_id = None

        body: dict[str, Any] = {
            "note_title": f"Enrichment update - {doc.get('log_uuid')}"[:154],
            "note_content": self._case_text(payload),
        }
        if directory_id is not None:
            body["directory_id"] = directory_id
        path = self.paths["case_note"].format(id=case_id)
        await self._post(path, body)

    async def _import_lists(self, alert_id: int) -> tuple[list[str], list[str]]:
        """UUID IOC dan aset milik alert, untuk diimpor ke case saat escalate/merge."""
        if not self.case_import_assets:
            return [], []
        alert = await self.get_alert(alert_id) or {}
        iocs = [i["ioc_uuid"] for i in alert.get("iocs") or [] if isinstance(i, dict) and i.get("ioc_uuid")]
        assets = [a["asset_uuid"] for a in alert.get("assets") or [] if isinstance(a, dict) and a.get("asset_uuid")]
        return iocs, assets

    async def _post_with_import(self, path: str, body: dict) -> dict:
        try:
            return await self._post(path, body)
        except httpx.HTTPStatusError as exc:
            if not (body.get("iocs_import_list") or body.get("assets_import_list")) \
                    or exc.response.status_code not in (400, 422, 500):
                raise
            log.warning("IRIS: %s ditolak dengan import aset/IOC (HTTP %s); diulang tanpa import.",
                        path, exc.response.status_code)
            body = {**body, "iocs_import_list": [], "assets_import_list": []}
            return await self._post(path, body)

    async def escalate_alert(self, alert_id: int, doc: dict) -> int | None:
        p = self.build_payload(doc)
        iocs, assets = await self._import_lists(alert_id)
        body = {"iocs_import_list": iocs, "assets_import_list": assets, "import_as_event": False,
                "note": "Diekskalasi otomatis oleh Analisis_Log (risk tinggi).",
                "case_title": p["alert_title"][:250], "case_tags": p["alert_tags"]}
        d = await self._post_with_import(self.paths["escalate"].format(id=alert_id), body)
        return d.get("case_id") or d.get("id")

    async def merge_alert(self, alert_id: int, case_id: int, doc: dict) -> None:
        risk = _d(doc.get("risk"))
        iocs, assets = await self._import_lists(alert_id)
        body = {"target_case_id": case_id, "iocs_import_list": iocs, "assets_import_list": assets,
                "import_as_event": False,
                "note": f"Alert terkait dari sumber yang sama (risk {risk.get('score')}, {risk.get('level')}) digabung otomatis. log_uuid={doc.get('log_uuid')}"}
        await self._post_with_import(self.paths["merge"].format(id=alert_id), body)

    async def _list(self, paths: list[str]) -> list[tuple[int, str]]:
        for p in paths:
            try:
                r = await self._client.get(p)
                if r.status_code != 200 or "json" not in r.headers.get("content-type", ""):
                    continue
                j = r.json()
            except (httpx.HTTPError, ValueError):
                continue
            items = j if isinstance(j, list) else None
            if items is None and isinstance(j, dict):
                for v in j.values():
                    if isinstance(v, list):
                        items = v
                        break
                    if isinstance(v, dict):
                        items = next((x for x in v.values() if isinstance(x, list)), None)
                        if items is not None:
                            break
            out = []
            for it in items or []:
                if not isinstance(it, dict):
                    continue
                _id = it.get("id") if isinstance(it.get("id"), int) else next((v for k, v in it.items() if k.endswith("_id") and isinstance(v, int)), None)
                name = next((str(v) for k, v in it.items() if k == "name" or k.endswith("_name")), "")
                if _id is not None:
                    out.append((int(_id), name))
            if out:
                return out
        return []

    async def list_ids(self) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
        return (await self._list(self.paths["severity_list"]), await self._list(self.paths["status_list"]))

    async def _ensure_ids(self) -> None:
        if self._ids_ready:
            return
        async with self._ids_lock:
            if self._ids_ready:
                return
            try:
                if self.status_id is None:
                    sts = await self._list(self.paths["status_list"])
                    pick = next((i for i, n in sts if n.strip().lower() == "new"), None) or next((i for i, n in sts if "new" in n.lower()), None)
                    if pick is not None:
                        self.status_id = pick
                        log.info("IRIS: alert_status_id otomatis = %s", pick)
                    else:
                        log.warning("IRIS: status alert 'New' tidak ditemukan otomatis; set IRIS_STATUS_ID di .env")
                if self.paths.get("ioc_type_list") and not self.ioc_type_ids:
                    types = await self._list(self.paths["ioc_type_list"])
                    self.ioc_type_ids = {n.strip().lower(): i for i, n in types if n}
                if self._ioc_type_override:
                    self.ioc_type_ids.update(self._ioc_type_override)
                if self.tlp_id is None and self.paths.get("tlp_list"):
                    tl = await self._list(self.paths["tlp_list"])
                    self.tlp_id = next((i for i, n in tl if n.strip().lower() == "amber"), tl[0][0] if tl else None)
                if self.ioc_type_ids:
                    log.info("IRIS: tipe IOC dikenali = %s, tlp_id = %s", sorted(self.ioc_type_ids)[:12], self.tlp_id)
                else:
                    log.warning("IRIS: tipe IOC tidak ditemukan otomatis; isi IRIS_IOC_TYPE_MAP di .env (alert_iocs dinonaktifkan)")
                if not self._severity_explicit:
                    by_name = {n.strip().lower(): i for i, n in await self._list(self.paths["severity_list"])}
                    found = {lvl: by_name[lvl] for lvl in ("low", "medium", "high", "critical") if lvl in by_name}
                    if found:
                        self.severity_map.update(found)
                        log.info("IRIS: severity otomatis = %s", self.severity_map)
            except Exception as exc:
                log.warning("IRIS: gagal mengambil master data (%s)", type(exc).__name__)
            self._ids_ready = True

    async def check(self) -> tuple[str, str]:
        probe = self.paths["probe"]
        r = await self._client.get(probe)
        if "html" in r.headers.get("content-type", ""):
            hint = ("server ini IRIS v3: set IRIS_API_VERSION=v2" if self.api_version == "legacy" else "IRIS_URL salah / path API tidak dilayani (proxy lain?)")
            return "GAGAL", f"{probe} mengembalikan HTML: {hint}"
        if r.status_code in (401, 403):
            return "GAGAL", f"HTTP {r.status_code} di {probe}: API key salah / user tanpa izin"
        if r.status_code >= 400:
            return "CEK", f"{probe} HTTP {r.status_code}"
        ver = ""
        try:
            v = await self._client.get("/api/versions")
            if "json" in v.headers.get("content-type", ""):
                d = _unwrap(v.json())
                ver = f", IRIS {d.get('iris_current')} (API {d.get('api_current')})"
        except Exception:
            pass
        await self._ensure_ids()
        info = f"API key valid{ver}, api_version={self.api_version}, customer_id={self.customer_id}, status_id={self.status_id}"
        if self.min_wazuh_level or self.max_wazuh_level:
            info += f", level_wazuh={self.min_wazuh_level or 0}-{self.max_wazuh_level or 'maks'}"
        if self.api_version == "v2" and self.status_id is None:
            return "CEK", info + " | alert_status_id belum diketahui: set IRIS_STATUS_ID (lihat --iris-ids)"
        return "OK", info

    async def aclose(self) -> None:
        await self._client.aclose()