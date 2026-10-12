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
    "legacy": {"alert": "/alerts/add", "escalate": "/alerts/escalate/{id}", "merge": "/alerts/merge/{id}",
               "case": "/manage/cases/add", "probe": "/manage/cases/list",
               "severity_list": ["/manage/severities/list"], "status_list": ["/manage/alert-status/list"]},
    "v2": {"alert": "/api/v2/alerts", "escalate": "/api/v2/alerts/escalate/{id}",
           "merge": "/api/v2/alerts/merge/{id}", "case": "/api/v2/cases", "probe": "/api/v2/cases",
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
        return obj

    # ------------------------------------------------------------ payload
    def build_payload(self, doc: dict, ai: dict | None) -> dict:
        risk, ev, src, asset = _d(doc.get("risk")), _d(doc.get("event")), _d(doc.get("source")), _d(doc.get("asset"))
        level = str(risk.get("level", "medium")).lower()
        analysis = _d(_d(ai).get("analysis")) if ai and ai.get("status") == "done" else {}
        what = _md_escape(ev.get("action") or ev.get("category") or "event", 80)
        who = _md_escape(src.get("ip") or asset.get("name") or "unknown", 80)
        verdict = analysis.get("verdict", "no-ai")

        lines = []
        if analysis:
            lines += ["## Ringkasan AI", _md_escape(analysis.get("summary", ""), 1500), "",
                      f"**Verdict:** {verdict} (confidence {analysis.get('confidence', 0)})  "
                      f"| **Model:** {_md_escape(_d(ai).get('provider', ''), 30)}/{_md_escape(_d(ai).get('model', ''), 60)}", ""]
        else:
            lines += [f"_Analisis AI tidak tersedia (status: {_md_escape(_d(ai).get('status', 'not_run'), 30)})._", ""]
        lines += [
            "## Risk",
            f"- **Score:** {risk.get('score')} ({level}) - asset {risk.get('asset_criticality')}, "
            f"severity {risk.get('event_severity')}, outcome {risk.get('event_outcome')}, "
            f"threat {risk.get('threat_weight')}, repeat {risk.get('repeat_count')}",
            "## Konteks",
            f"- **Event:** {what} / outcome {_md_escape(ev.get('outcome'), 40)}",
            f"- **Source:** {who}",
            f"- **Asset:** {_md_escape(asset, 200)}",
            f"- **Reputation:** {_md_escape(doc.get('reputation'), 200)}",
            f"- **Geolocation:** {_md_escape(doc.get('geolocation'), 200)}",
            f"- **Domain:** {_md_escape(doc.get('domain'), 200)}", ""]
        if analysis.get("recommended_actions"):
            lines += ["## Rekomendasi tindakan"] + [f"- {_md_escape(a)}" for a in analysis["recommended_actions"]] + [""]
        if analysis.get("mitre_techniques"):
            lines += ["## MITRE ATT&CK"] + [f"- {_md_escape(t, 100)}" for t in analysis["mitre_techniques"]] + [""]
        lines.append(f"`log_uuid: {doc.get('log_uuid')}`")

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

    async def create_alert(self, doc: dict, ai: dict | None) -> int | None:
        await self._ensure_ids()
        d = await self._post(self.paths["alert"], self.build_payload(doc, ai))
        return d.get("alert_id") or d.get("id")

    async def create_case(self, doc: dict, ai: dict | None) -> int | None:
        """Buat case langsung, tanpa alert."""
        p = self.build_payload(doc, ai)
        body = {"case_name": p["alert_title"][:250], "case_description": p["alert_description"],
                "case_customer": self.customer_id, "case_soc_id": str(doc.get("log_uuid"))}
        d = await self._post(self.paths["case"], body)
        return d.get("case_id") or d.get("id")

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
        if self.api_version == "v2" and self.status_id is None:
            return "CEK", info + " | alert_status_id belum diketahui: set IRIS_STATUS_ID (lihat --iris-ids)"
        return "OK", info

    async def aclose(self) -> None:
        await self._client.aclose()