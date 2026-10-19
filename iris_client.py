"""
iris_client.py - Integrasi DFIR-IRIS (REST API: POST {IRIS_URL}/alerts/add, auth Bearer API key).

Alert dibuat dari log berisiko tinggi, diperkaya hasil analisis AI. Severity IRIS ditentukan
dari risk score (deterministik), BUKAN dari output AI. AI hanya memberi konteks untuk analis.
"""
from __future__ import annotations

import asyncio
import logging
import ssl
from datetime import datetime, timezone
from typing import Any, Mapping

import httpx
import orjson

log = logging.getLogger("iris")
RETRY_STATUS = {429, 500, 502, 503, 504}

# IRIS v2.4.x memakai path legacy; IRIS v3 hanya melayani /api/v2 (path legacy -> HTML frontend)
PATHS = {
    "legacy": {"alert": "/alerts/add", "alert_update": "/alerts/update/{id}",
               "escalate": "/alerts/escalate/{id}", "merge": "/alerts/merge/{id}",
               "case": "/manage/cases/add", "case_note": "/case/notes/add",
               "probe": "/manage/cases/list",
               "severity_list": ["/manage/severities/list"], "status_list": ["/manage/alert-status/list"]},
    "v2": {"alert": "/api/v2/alerts", "alert_update": "/api/v2/alerts/{id}",
           "escalate": "/api/v2/alerts/escalate/{id}",
           "merge": "/api/v2/alerts/merge/{id}", "case": "/api/v2/cases",
           "case_note": "/api/v2/cases/{id}/notes",
           "case_note_directories": "/api/v2/cases/{id}/notes-directories",
           "probe": "/api/v2/cases",
           "severity_list": ["/api/v2/manage/severities"],
           "status_list": ["/api/v2/manage/alert-statuses", "/api/v2/manage/alert-status"]},
}


class IrisError(Exception):
    def __init__(self, msg: str):
        super().__init__(msg)
        self.public_message = msg


def _unwrap(j) -> dict:
    """Legacy membungkus hasil di {"data": {...}}; v2 bisa mengembalikan objek langsung."""
    if not isinstance(j, dict):
        return {}
    d = j.get("data")
    return d if isinstance(d, dict) else j
DEFAULT_SEVERITY_MAP = {"low": 3, "medium": 4, "high": 5, "critical": 6}  # default severity IRIS


def _d(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _short(v: Any, n: int = 300) -> str:
    return orjson.dumps(v).decode()[:n] if isinstance(v, (dict, list)) else str(v)[:n]


def _md_escape(v: Any, n: int = 300) -> str:
    """Teks dari log/AI tidak tepercaya: netralkan karakter markdown/HTML."""
    s = _short(v, n)
    for ch in ("<", ">", "`", "|"):
        s = s.replace(ch, " ")
    return s.replace("\n", " ")


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


def _format_reputation(value: Any, observables: list | None = None) -> list[str]:
    reputation = _d(value)
    if not reputation:
        return ["- Data reputasi belum tersedia."]

    lines = []
    score = _display(reputation.get("opencti_score"), 30)
    verdict = _display(reputation.get("verdict"), 40)
    if score or verdict:
        summary = " - ".join(part for part in (
            f"Skor OpenCTI: {score}/100" if score else None,
            f"Verdict: {verdict}" if verdict else None,
        ) if part)
        lines.append(f"- {summary}.")

    labels = reputation.get("labels")
    if isinstance(labels, list) and labels:
        shown = [_display(label, 80) for label in labels[:8]]
        shown = [label for label in shown if label]
        suffix = f"; +{len(labels) - 8} label lainnya" if len(labels) > 8 else ""
        if shown:
            lines.append(f"- Label: {', '.join(shown)}{suffix}.")

    authors = []

    def add_authors(value: Any) -> None:
        if isinstance(value, list):
            for item in value:
                add_authors(item)
            return
        if isinstance(value, dict):
            author = value.get("name") or value.get("id")
            if author is None:
                for key in ("edges", "nodes", "items", "data"):
                    if key in value:
                        add_authors(value[key])
                        return
        else:
            author = value
        author = _display(author, 160)
        if author and author not in authors:
            authors.append(author)

    for observable in observables or []:
        if not isinstance(observable, dict):
            continue
        opencti = _d(observable.get("opencti"))
        indicators = opencti.get("indicators")
        if isinstance(indicators, list):
            for indicator in indicators:
                if isinstance(indicator, dict):
                    add_authors(
                        indicator.get("created_by")
                        or indicator.get("createdBy")
                        or indicator.get("creator")
                        or indicator.get("author")
                    )
        sources = opencti.get("sources")
        if isinstance(sources, list):
            for source in sources:
                if isinstance(source, dict):
                    add_authors(source)
    lines.append(
        "- Author: " + "; ".join(authors[:12]) + "."
        if authors else
        "- Author: Tidak dicantumkan pada indicator OpenCTI."
    )

    provider_status = _d(reputation.get("provider_status"))
    abuse = reputation.get("abuseipdb")
    if isinstance(abuse, dict):
        confidence = _display(abuse.get("confidence_score"), 20)
        reports = _display(abuse.get("total_reports"), 20)
        details = []
        if confidence:
            details.append(f"confidence {confidence}%")
        if reports:
            details.append(f"{reports} laporan")
        provider = _display(abuse.get("source"), 100) or "AbuseIPDB"
        status = _display(abuse.get("status"), 80)
        suffix = f"; status {status}" if status else ""
        if details:
            lines.append(f"- **AbuseIPDB:** {', '.join(details)} (sumber: {provider}{suffix}).")
        else:
            lines.append(f"- **AbuseIPDB:** tidak ada temuan{suffix} (sumber: {provider}).")
    elif "abuseipdb" in reputation:
        status = _display(provider_status.get("abuseipdb"), 120)
        if status and not any(
            message in status.lower()
            for message in ("hasil lookup tidak disertakan", "api key belum dikonfigurasi")
        ):
            lines.append(f"- **AbuseIPDB:** {status}.")

    vt = reputation.get("virustotal")
    if isinstance(vt, dict):
        stats = _d(vt.get("stats") or vt.get("last_analysis_stats"))
        counts = [f"{key} {stats[key]}" for key in ("malicious", "suspicious", "harmless")
                  if stats.get(key) is not None]
        provider = _display(vt.get("source"), 100) or "VirusTotal"
        status = _display(vt.get("status"), 80)
        suffix = f"; status {status}" if status else ""
        if counts:
            lines.append(f"- **VirusTotal:** {', '.join(counts)} (sumber: {provider}{suffix}).")
        elif vt:
            lines.append(f"- **VirusTotal:** data tersedia, ringkasan deteksi tidak tersedia (sumber: {provider}{suffix}).")
    elif "virustotal" in reputation:
        status = _display(provider_status.get("virustotal"), 120)
        if status and not any(
            message in status.lower()
            for message in ("hasil lookup tidak disertakan", "api key belum dikonfigurasi")
        ):
            lines.append(f"- **VirusTotal:** {status}.")

    return lines or ["- Data reputasi belum tersedia."]


def _format_intel_sources(doc: dict, observables: list) -> list[str]:
    contexts = [_d(doc.get("opencti"))]
    contexts.extend(
        _d(item.get("opencti")) for item in observables if isinstance(item, dict)
    )
    reputation = _d(doc.get("reputation"))
    candidates = reputation.get("sources", []) if isinstance(reputation.get("sources"), list) else []
    connector_lines = []
    external_match_count = 0
    lookup_statuses = []
    connector_inventory_included = False
    lookup_connector_reported = False

    for context in contexts:
        try:
            match_count = int(context.get("external_import_match_count") or 0)
        except (TypeError, ValueError):
            log.warning("Invalid OpenCTI external indicator match count: %r",
                        context.get("external_import_match_count"))
            match_count = 0
        external_match_count = max(external_match_count, match_count)
        lookup_status = _display(context.get("lookup_status"), 80)
        if lookup_status:
            lookup_statuses.append(lookup_status)
        connectors = context.get("connectors")
        if isinstance(connectors, list):
            connector_inventory_included = True
            for connector in connectors:
                if not isinstance(connector, dict):
                    continue
                name = _display(connector.get("name"), 120) or "Connector tanpa nama"
                kind = str(connector.get("type") or "").upper()
                if kind in {"INTERNAL_ENRICHMENT", "EXTERNAL_IMPORT"}:
                    lookup_connector_reported = True
                status = str(connector.get("status") or "unknown").lower()
                details = _display(connector.get("details"), 180)
                if kind == "INTERNAL_ENRICHMENT":
                    descriptions = {
                        "completed": "lookup selesai; hasil OpenCTI diperiksa pada ringkasan intel di atas",
                        "failed": f"lookup gagal{': ' + details if details else ''}",
                        "error": f"lookup error{': ' + details if details else ''}",
                        "timeout": f"lookup belum selesai{': ' + details if details else ''}",
                        "queued": "lookup masuk antrean OpenCTI",
                        "inactive": "connector tidak aktif; tidak dijalankan",
                        "out_of_scope": "tidak dijalankan karena scope IOC tidak sesuai",
                    }
                    description = descriptions.get(status, details or f"status {status}")
                    if connector.get("cached"):
                        description += " (status dari cache)"
                    connector_lines.append(f"- **{name} (Internal Enrichment):** {description}.")
                elif kind == "EXTERNAL_IMPORT":
                    if status == "indexed_lookup":
                        description = (
                            "feed aktif; IOC match ditemukan pada data OpenCTI terindeks (sumber per-feed tidak dapat ditentukan)"
                            if external_match_count else
                            "feed aktif; tidak ada indicator match pada data OpenCTI terindeks"
                        )
                    else:
                        description = details or f"status {status}"
                    connector_lines.append(f"- **{name} (External Import):** {description}.")
                elif status in {"error", "failed", "timeout"}:
                    connector_lines.append(
                        f"- **{name}:** {details or status}."
                    )

        sources = context.get("sources")
        if isinstance(sources, list):
            candidates.extend(sources)
        indicators = context.get("indicators")
        if not isinstance(indicators, list):
            continue
        for indicator in indicators:
            if not isinstance(indicator, dict):
                continue
            creator = indicator.get("created_by") or indicator.get("createdBy") or indicator.get("creator")
            if isinstance(creator, dict):
                creator = creator.get("name") or creator.get("id")
            source = indicator.get("connector") or creator or indicator.get("source")
            if isinstance(source, str) and source.lower() == "opencti":
                source = "OpenCTI (connector tidak dicantumkan)"
            elif isinstance(source, str) and source.lower() == "collector":
                source = "Collector (indicator internal)"
            name = indicator.get("name")
            if source or name:
                candidates.append({"source": source, "name": name})
            references = indicator.get("external_references") or indicator.get("externalReferences") or []
            for reference in references:
                if isinstance(reference, dict) and reference.get("source_name"):
                    candidates.append(reference["source_name"])

    evidence = []
    for candidate in candidates:
        if isinstance(candidate, dict):
            name = (candidate.get("connector") or candidate.get("agent") or
                    candidate.get("created_by") or candidate.get("source") or candidate.get("name"))
            if isinstance(name, dict):
                name = name.get("name") or name.get("id")
            detail = candidate.get("name")
            value = f"{name}: {detail}" if name and detail and name != detail else name or detail
        else:
            value = candidate
        value = _display(value, 160)
        if value and value not in evidence:
            evidence.append(value)

    lines = list(dict.fromkeys(connector_lines))
    if not lines:
        if not connector_inventory_included:
            lines.append(
                "- Status connector tidak disertakan pada data enrichment event ini; "
                "ini bukan bukti bahwa connector tidak tersedia di OpenCTI."
            )
        elif not lookup_connector_reported:
            lines.append(
                "- Inventory connector yang disertakan tidak memuat tipe "
                "Internal Enrichment atau External Import."
            )
    if lookup_statuses and "observable_not_found" in lookup_statuses:
        lines.append("- Observable belum ada di OpenCTI; feed eksternal diperiksa melalui pencarian indicator.")
    if evidence:
        lines.append("- **Sumber intel yang tercatat pada indicator:** " + "; ".join(evidence[:12]) + ".")
    else:
        lines.append("- Tidak ada nama sumber spesifik pada indicator yang cocok di OpenCTI.")
    return lines


def _format_geolocation(value: Any) -> list[str]:
    geo = _d(value)
    if not geo or geo.get("available") is False:
        return ["- Data geolokasi belum tersedia."]

    fields = (
        ("Lokasi", ", ".join(str(part) for part in
                              (geo.get("city"), geo.get("region"),
                               geo.get("country_name") or geo.get("country")) if part)),
        ("ISP", geo.get("isp") or geo.get("org")),
        ("ASN", geo.get("asn")),
        ("Hosting", "Ya" if geo.get("hosting") is True else
         "Tidak" if geo.get("hosting") is False else None),
        ("Proxy", "Ya" if geo.get("proxy") is True else
         "Tidak" if geo.get("proxy") is False else None),
    )
    lines = [f"- **{label}:** {_md_escape(value, 180)}"
             for label, value in fields if _display(value, 180)]
    return lines or ["- Data geolokasi tersedia, tetapi rinciannya kosong."]


def _format_asset(asset: dict, source_ip: Any, host_name: Any) -> list[str]:
    glpi_fields = ("owner", "user", "serial_number", "operating_system", "status", "location", "type")
    has_glpi_details = any(_display(asset.get(field), 180) for field in glpi_fields)
    is_glpi_asset = (
        asset.get("inventory_source") == "GLPI"
        or asset.get("found") is True
        or has_glpi_details
    )
    if not is_glpi_asset:
        error = _display(asset.get("error"), 180)
        if error:
            message = f"Pencarian aset GLPI gagal: {error}."
        elif asset.get("found") is False:
            searched_ip = _display(asset.get("ip"), 80)
            message = (
                f"Tidak ada aset GLPI yang cocok dengan IP {searched_ip}."
                if searched_ip else
                "Tidak ada aset GLPI yang cocok dengan IP ini."
            )
        else:
            message = "Data aset GLPI belum tersedia."
        lines = [f"- {message}"]
    else:
        fields = (
            ("Nama", asset.get("name")),
            ("IP", asset.get("ip") or source_ip),
            ("Pemilik", asset.get("owner") or asset.get("user")),
            ("Serial", asset.get("serial_number")),
            ("Sistem operasi", asset.get("operating_system")),
            ("Status", asset.get("status")),
            ("Lokasi", asset.get("location")),
            ("Tipe", asset.get("type")),
        )
        lines = [f"- **{label}:** {_md_escape(value, 180)}"
                 for label, value in fields if _display(value, 180)]
        if not lines:
            lines = ["- Data aset ditemukan, tetapi detailnya kosong."]

    if host_name and _display(host_name, 160):
        lines.append(f"- **Hostname Wazuh:** {_md_escape(host_name, 160)}")
    return lines


class IrisClient:
    def __init__(self, url: str, api_key: str, customer_id: int, verify: bool | ssl.SSLContext,
                 timeout_s: float, severity_map: dict[str, int], status_id: int | None,
                 source_link_tpl: str, api_version: str = "v2"):
        if api_version not in PATHS:
            raise ValueError("IRIS_API_VERSION harus: v2 | legacy")
        self.api_version = api_version
        self.paths = PATHS[api_version]
        self.customer_id = customer_id
        self._severity_explicit = False  # True jika IRIS_SEVERITY_MAP diisi manual
        self.min_wazuh_level = 0  # 0 = filter level Wazuh nonaktif
        self.max_wazuh_level = 0  # 0 = tanpa batas atas
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
        return obj

    # ------------------------------------------------------------ filter
    def allows(self, doc: dict) -> bool:
        """Filter level alert Wazuh (event.wazuh_level). Event tanpa level (bukan Wazuh) tidak difilter."""
        lvl = _d(doc.get("event")).get("wazuh_level")
        try:
            lvl = int(lvl)
        except (TypeError, ValueError):
            return True
        if lvl < self.min_wazuh_level:
            return False
        return not (self.max_wazuh_level and lvl > self.max_wazuh_level)

    # ------------------------------------------------------------ payload
    def build_payload(self, doc: dict, ai: dict | None) -> dict:
        risk, ev, src, asset = _d(doc.get("risk")), _d(doc.get("event")), _d(doc.get("source")), _d(doc.get("asset"))
        level = str(risk.get("level", "medium")).lower()
        analysis = _d(_d(ai).get("analysis")) if ai and ai.get("status") == "done" else {}
        what = _md_escape(ev.get("action") or ev.get("category") or "event", 80)
        who = _md_escape(src.get("ip") or asset.get("name") or "unknown", 80)
        verdict = analysis.get("verdict", "no-ai")
        host = _d(doc.get("host"))
        agent = _d(doc.get("agent"))
        agent_name = agent.get("name") or asset.get("agent_name") or host.get("name")

        lines = []
        if analysis:
            lines += ["## Ringkasan AI", _md_escape(analysis.get("summary", ""), 1500), "",
                      f"**Verdict:** {verdict} (confidence {analysis.get('confidence', 0)})  "
                      f"| **Model:** {_md_escape(_d(ai).get('provider', ''), 30)}/{_md_escape(_d(ai).get('model', ''), 60)}", ""]
        elif _d(ai).get("status") in ("running", "pending"):
            lines += ["_Analisis AI sedang berjalan; hasilnya akan ditambahkan ke alert ini._", ""]
        else:
            lines += [f"_Analisis AI tidak tersedia (status: {_md_escape(_d(ai).get('status', 'not_run'), 30)})._", ""]
        destination = _d(doc.get("destination"))
        source_asset = _d(src.get("asset")) or asset
        destination_asset = _d(destination.get("asset"))
        observables = _d(doc.get("enrichment")).get("observables") or []
        is_wazuh = doc.get("data_source") == "wazuh" or "wazuh_level" in ev
        destination_ip = _display(destination.get("ip"), 80)
        destination_label = (
            "Tidak ditemukan di field alert Wazuh"
            if is_wazuh else "Tidak tersedia di event"
        )
        lines += [
            "## Risiko",
            f"- **Skor:** {risk.get('score')} ({level})",
            f"- **Faktor:** kritikalitas aset {risk.get('asset_criticality')}, "
            f"severity {risk.get('event_severity')}, outcome {risk.get('event_outcome')}, "
            f"ancaman {risk.get('threat_weight')}, pengulangan {risk.get('repeat_count')}",
            "",
            "## Event",
            f"- **Deteksi:** {what}",
            f"- **Hasil:** {_display(ev.get('outcome'), 60) or 'Tidak tersedia'}",
            f"- **IP sumber (kemungkinan penyerang):** {who}",
            *([f"- **Wazuh Level:** {_display(ev.get('wazuh_level'), 30) or 'Tidak tersedia di event'}"]
              if is_wazuh else []),
            f"- **IP tujuan (host yang diserang):** {destination_ip or destination_label}",
            "",
            "## Aset sumber / penyerang",
            *_format_asset(source_asset, src.get("ip"), None),
            "",
            "## Aset tujuan / penerima serangan",
            *_format_asset(destination_asset, destination.get("ip"), None),
            "",
            "## Agent Wazuh (sensor yang melaporkan event)",
            f"- **Nama:** {_display(agent_name, 160) or 'Tidak tersedia'}",
            f"- **ID:** {_display(agent.get('id'), 80) or 'Tidak tersedia'}",
            f"- **IP agent:** {_display(agent.get('ip'), 80) or ('Tidak dikirim di event Wazuh' if is_wazuh else 'Tidak tersedia')}",
            f"- **Manager:** {_display(agent.get('manager'), 160) or 'Tidak tersedia'}",
            f"- **IP manager:** {_display(agent.get('manager_ip'), 80) or ('Tidak dikirim di event Wazuh' if is_wazuh else 'Tidak tersedia')}",
            "",
            "## Intelijen ancaman",
            *_format_reputation(doc.get("reputation"), observables),
            "",
            "## Sumber intel / connector OpenCTI",
            *_format_intel_sources(doc, _d(doc.get("enrichment")).get("observables") or []),
            "",
            "## Geolokasi",
            *_format_geolocation(doc.get("geolocation")),
        ]
        domain = _d(doc.get("domain"))
        domain_name = _display(domain.get("name"), 180)
        if domain_name:
            lines += ["", "## Domain", f"- **Nama:** {domain_name}"]
            age_days = _display(domain.get("age_days"), 40)
            if age_days:
                lines.append(f"- **Usia:** {age_days} hari")
        elif not domain:
            domain_name = _display(doc.get("domain"), 180)
            if domain_name:
                lines += ["", "## Domain", f"- {domain_name}"]

        if isinstance(observables, list) and observables:
            lines += ["", "## IOC terkait"]
            shown = 0
            for observable in observables[:20]:
                if not isinstance(observable, dict):
                    continue
                entity_type = _display(observable.get("entity_type"), 40)
                value = _display(observable.get("value"), 180)
                if not entity_type or not value:
                    continue
                lines.append(f"- **{entity_type}:** `{value}`")
                shown += 1
            if len(observables) > 20:
                lines.append(f"- {len(observables) - 20} IOC lainnya tersedia pada konten sumber alert.")
            if shown == 0:
                lines.append("- Detail IOC tidak tersedia.")
        if analysis.get("recommended_actions"):
            lines += ["## Rekomendasi tindakan"] + [f"- {_md_escape(a)}" for a in analysis["recommended_actions"]] + [""]
        if analysis.get("mitre_techniques"):
            lines += ["## MITRE ATT&CK"] + [f"- {_md_escape(t, 100)}" for t in analysis["mitre_techniques"]] + [""]
        lines += ["", f"`log_uuid: {doc.get('log_uuid')}`"]

        tags = ["ai-log-analyzer", f"risk:{level}", f"verdict:{verdict}"]
        tags += [f"mitre:{str(t).split(' ')[0]}" for t in analysis.get("mitre_techniques", [])[:5]]
        payload: dict[str, Any] = {
            "alert_title": f"[{level.upper()}] {what} - {who}"[:250],
            "alert_description": "\n".join(lines)[:8000],
            "alert_source": "Analisis-Log-AI",
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

    # --------------------------------------------------------------- kirim
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
                # Retry HANYA jika koneksi belum terbentuk (permintaan pasti belum diproses).
                # ReadTimeout dll. TIDAK diulang: IRIS mungkin sudah membuat alert -> duplikat.
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

    async def create_alert(self, doc: dict, ai: dict | None) -> int | None:
        await self._ensure_ids()
        d = await self._post(self.paths["alert"], self.build_payload(doc, ai))
        return d.get("alert_id") or d.get("id")

    async def update_alert(self, alert_id: int, doc: dict, ai: dict | None) -> None:
        payload = self.build_payload(doc, ai)
        update = {
            key: payload[key]
            for key in (
                "alert_title", "alert_description", "alert_source_content",
                "alert_severity_id", "alert_tags",
            )
        }
        path = self.paths["alert_update"].format(id=alert_id)
        if self.api_version == "legacy":
            await self._post(path, update)
        else:
            await self._put(path, update)

    async def create_case(self, doc: dict, ai: dict | None) -> int | None:
        """Buat case langsung, tanpa alert."""
        p = self.build_payload(doc, ai)
        body = {"case_name": p["alert_title"][:250], "case_description": p["alert_description"],
                "case_customer": self.customer_id, "case_soc_id": str(doc.get("log_uuid"))}
        d = await self._post(self.paths["case"], body)
        return d.get("case_id") or d.get("id")

    async def add_case_note(self, case_id: int, doc: dict, ai: dict | None) -> None:
        """Add newly correlated enrichment to an existing IRIS case."""
        payload = self.build_payload(doc, ai)
        if self.api_version == "v2":
            directories_path = self.paths["case_note_directories"].format(id=case_id)
            response = await self._get(directories_path, {"per_page": 100, "page": 1})
            directories = response.get("data")
            if isinstance(directories, dict):
                directories = directories.get("data")
            if not isinstance(directories, list):
                raise IrisError("IRIS tidak mengembalikan daftar direktori catatan case")
            valid_directories = [
                directory for directory in directories
                if isinstance(directory, dict) and isinstance(directory.get("id"), int)
            ]
            directory = next(
                (item for item in valid_directories if item.get("parent_id") is None),
                valid_directories[0] if valid_directories else None,
            )
            if directory is None:
                created = await self._post(directories_path, {
                    "name": "Analisis-Log-AI Updates",
                })
                directory = created.get("data", created)
                if not isinstance(directory, dict) or not isinstance(directory.get("id"), int):
                    raise IrisError(
                        f"IRIS gagal membuat direktori catatan untuk case {case_id}"
                    )
            directory_id = directory["id"]
        else:
            directory_id = None
        body: dict[str, Any] = {
            "note_title": f"Enrichment update - {doc.get('log_uuid')}"[:154],
            "note_content": payload["alert_description"],
        }
        if directory_id is not None:
            body["directory_id"] = directory_id
        path = self.paths["case_note"].format(id=case_id)
        await self._post(path, body)

    async def escalate_alert(self, alert_id: int, doc: dict, ai: dict | None) -> int | None:
        """Eskalasi alert menjadi case baru."""
        p = self.build_payload(doc, ai)
        body = {"iocs_import_list": [], "assets_import_list": [], "import_as_event": False,
                "note": "Dieskalasi otomatis oleh Analisis-Log-AI (risk tinggi).",
                "case_title": p["alert_title"][:250], "case_tags": p["alert_tags"]}
        d = await self._post(self.paths["escalate"].format(id=alert_id), body)
        return d.get("case_id") or d.get("id")

    async def merge_alert(self, alert_id: int, case_id: int, doc: dict) -> None:
        """Gabungkan alert ke case yang sudah ada."""
        risk = _d(doc.get("risk"))
        body = {"target_case_id": case_id, "iocs_import_list": [], "assets_import_list": [],
                "import_as_event": False,
                "note": f"Alert terkait dari sumber yang sama (risk {risk.get('score')}, "
                        f"{risk.get('level')}) digabung otomatis. log_uuid={doc.get('log_uuid')}"}
        await self._post(self.paths["merge"].format(id=alert_id), body)

    async def _list(self, paths: list[str]) -> list[tuple[int, str]]:
        """Baca daftar (id, nama) dari endpoint master data; toleran terhadap bentuk respons."""
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
                _id = it.get("id") if isinstance(it.get("id"), int) else next(
                    (v for k, v in it.items() if k.endswith("_id") and isinstance(v, int)), None)
                name = next((str(v) for k, v in it.items() if k == "name" or k.endswith("_name")), "")
                if _id is not None:
                    out.append((int(_id), name))
            if out:
                return out
        return []

    async def list_ids(self) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
        return (await self._list(self.paths["severity_list"]), await self._list(self.paths["status_list"]))

    async def _ensure_ids(self) -> None:
        """IRIS v3 mewajibkan alert_status_id. Jika tidak diset, cari status 'New' dan ID severity
        berdasarkan nama (sekali saja, best-effort)."""
        if self._ids_ready:
            return
        async with self._ids_lock:
            if self._ids_ready:
                return
            try:
                if self.status_id is None:
                    sts = await self._list(self.paths["status_list"])
                    pick = next((i for i, n in sts if n.strip().lower() == "new"), None) \
                        or next((i for i, n in sts if "new" in n.lower()), None)
                    if pick is not None:
                        self.status_id = pick
                        log.info("IRIS: alert_status_id otomatis = %s", pick)
                    else:
                        log.warning("IRIS: status alert 'New' tidak ditemukan otomatis; set IRIS_STATUS_ID di .env")
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
        """Cek koneksi + API key + kecocokan versi API. Mengembalikan (OK|GAGAL|CEK, detail)."""
        probe = self.paths["probe"]
        r = await self._client.get(probe)
        if "html" in r.headers.get("content-type", ""):
            hint = ("server ini IRIS v3: set IRIS_API_VERSION=v2" if self.api_version == "legacy"
                    else "IRIS_URL salah / path API tidak dilayani (proxy lain?)")
            return "GAGAL", f"{probe} mengembalikan HTML: {hint}"
        if r.status_code in (401, 403):
            return "GAGAL", f"HTTP {r.status_code} di {probe}: API key salah / user tanpa izin"
        if r.status_code >= 400:
            return "CEK", f"{probe} HTTP {r.status_code}"
        ver = ""
        try:  # opsional: /api/versions tidak selalu dilayani
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
