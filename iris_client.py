"""

iris_client.py - Integrasi DFIR-IRIS (REST API: POST {IRIS_URL}/alerts/add, auth Bearer API key).

Alert dibuat dari log berisiko tinggi dan konteks enrichment. Severity IRIS ditentukan
secara deterministik dari risk score.
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

PATHS = {
    "legacy": {"alert": "/alerts/add", "alert_update": "/alerts/update/{id}",
               "escalate": "/alerts/escalate/{id}", "merge": "/alerts/merge/{id}",
               "case": "/manage/cases/add", "case_read": "/manage/cases/{id}",
               "case_update": "/manage/cases/update/{id}", "case_note": "/case/notes/add",
               "probe": "/manage/cases/list",
               "severity_list": ["/manage/severities/list"], "status_list": ["/manage/alert-status/list"]},
    "v2": {"alert": "/api/v2/alerts", "alert_update": "/api/v2/alerts/{id}",
           "escalate": "/api/v2/alerts/escalate/{id}",
           "merge": "/api/v2/alerts/merge/{id}", "case": "/api/v2/cases",
           "case_read": "/api/v2/cases/{id}", "case_update": "/api/v2/cases/{id}",
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


def _join_list(val: Any) -> str:
    if isinstance(val, list):
        return ", ".join(str(v) for v in val if v)
    return str(val) if val else ""


def _format_reputation(value: Any, observables: list | None = None) -> list[str]:
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
    is_glpi_asset = (asset.get("inventory_source") == "GLPI" or asset.get("found") is True)
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
        if error:  # bedakan "tidak ada" dari "pencarian bermasalah"
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
        if index == 1 and asset.get("matched_by") == "hostname":
            matched_host = _display(asset.get("matched_value"), 120)
            if matched_host:
                lines.append(f"- Dicocokkan melalui hostname agent: {matched_host}")
        
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

    def allows(self, doc: dict) -> bool:
        """Filter level alert Wazuh (event.wazuh_level)."""
        lvl = _d(doc.get("event")).get("wazuh_level")
        try:
            lvl = int(lvl)
        except (TypeError, ValueError):
            return True
        if lvl < self.min_wazuh_level:
            return False
        return not (self.max_wazuh_level and lvl > self.max_wazuh_level)

    def build_payload(self, doc: dict) -> dict:
        """Merakit dictionary payload sesuai desain bersih yang diinginkan."""
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
        source_asset = _d(src.get("asset")) or (asset if src.get("ip") else {})
        destination_asset = _d(destination.get("asset"))
        observables = _d(doc.get("enrichment")).get("observables") or []
        is_wazuh = doc.get("data_source") == "wazuh" or "wazuh_level" in ev
        
        destination_ip = _display(destination.get("ip"), 80)
        source_ip = _display(src.get("ip"), 80)
        source_label = source_ip or "Tidak tersedia di event"
        destination_label = destination_ip or "Tidak tersedia di event"

        lines = [
            "# Risiko",
            f"- Skor: {risk.get('score')} ({level})",
            f"- Faktor: kritikalitas aset {risk.get('asset_criticality')}, severity {risk.get('event_severity')}, outcome {risk.get('event_outcome')}, ancaman {risk.get('threat_weight')}, pengulangan {risk.get('repeat_count')}",
            "# Event",
            f"- Deteksi: {what}",
            f"- Hasil: {_display(ev.get('outcome'), 60) or 'Tidak tersedia'}",
            f"- IP sumber (kemungkinan penyerang): {source_label}",
            *([f"- Wazuh Level: {_display(ev.get('wazuh_level'), 30)}"] if is_wazuh else []),
            f"- IP tujuan (host yang diserang): {destination_label}",
            "# Source",
            # tanpa IP sumber -> hostname agent; tanpa hostname -> hanya IP
            *_format_asset(source_asset, src.get("ip"), None if src.get("ip") else agent_host),
            "# Destination",
            *_format_asset(destination_asset, destination.get("ip"),
                           agent_host if (not destination_ip or destination_ip == agent_ip) else None),
            "# Threat Intelligence Enrichment",
            *([f"- IP : {source_ip}"] if source_ip else []),
            *_format_reputation(doc.get("reputation"), observables),
            "# Geolokasi",
            *_format_geolocation(doc.get("geolocation")),
            "# IOC terkait"
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
            "alert_title": f"[{level.upper()}] {what} - {who}"[:250],
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

    async def create_alert(self, doc: dict) -> int | None:
        await self._ensure_ids()
        d = await self._post(self.paths["alert"], self.build_payload(doc))
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
        path = self.paths["alert_update"].format(id=alert_id)
        if self.api_version == "legacy":
            await self._post(path, update)
        else:
            await self._put(path, update)

    async def create_case(self, doc: dict) -> int | None:
        p = self.build_payload(doc)
        body = {"case_name": p["alert_title"][:250], "case_description": p["alert_description"],
                "case_customer": self.customer_id, "case_soc_id": str(doc.get("log_uuid"))}
        d = await self._post(self.paths["case"], body)
        return d.get("case_id") or d.get("id")

    async def update_case_description(self, case_id: int, doc: dict) -> bool:
        current = await self._get(self.paths["case_read"].format(id=case_id))
        current_description = current.get("case_description")
        if not isinstance(current_description, str):
            current_description = current.get("description")
        if not isinstance(current_description, str):
            raise IrisError(
                f"IRIS tidak mengembalikan deskripsi case {case_id}; pembaruan dibatalkan"
            )

        updated_description = self.build_payload(doc)["alert_description"]
        if updated_description == current_description:
            return False

        if self.api_version == "v2":
            await self._put(
                self.paths["case_update"].format(id=case_id),
                {"case_description": updated_description},
            )
        else:
            await self._post(
                self.paths["case_update"].format(id=case_id),
                {
                    "case_name": current.get("case_name") or current.get("name"),
                    "case_soc_id": current.get("case_soc_id") or current.get("soc_id") or "",
                    "case_description": updated_description,
                    "classification_id": (
                        current.get("classification_id")
                        or current.get("case_classification_id")
                    ),
                    "custom_attributes": current.get("custom_attributes") or {},
                    "owner_id": current.get("owner_id") or current.get("case_owner_id"),
                    "case_tags": current.get("case_tags") or "",
                },
            )
        return True

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
                    "name": "Analisis_Log Updates",
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

    async def escalate_alert(self, alert_id: int, doc: dict) -> int | None:
        p = self.build_payload(doc)
        body = {"iocs_import_list": [], "assets_import_list": [], "import_as_event": False,
                "note": "Dieskalasi otomatis oleh Analisis_Log (risk tinggi).",
                "case_title": p["alert_title"][:250], "case_tags": p["alert_tags"]}
        d = await self._post(self.paths["escalate"].format(id=alert_id), body)
        return d.get("case_id") or d.get("id")

    async def merge_alert(self, alert_id: int, case_id: int, doc: dict) -> None:
        risk = _d(doc.get("risk"))
        body = {"target_case_id": case_id, "iocs_import_list": [], "assets_import_list": [],
                "import_as_event": False,
                "note": f"Alert terkait dari sumber yang sama (risk {risk.get('score')}, "
                        f"{risk.get('level')}) digabung otomatis. log_uuid={doc.get('log_uuid')}"}
        await self._post(self.paths["merge"].format(id=alert_id), body)

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