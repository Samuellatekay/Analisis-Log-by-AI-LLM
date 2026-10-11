"""
iris_client.py - Integrasi DFIR-IRIS (REST API: POST {IRIS_URL}/alerts/add, auth Bearer API key).

Alert dibuat dari log berisiko tinggi, diperkaya hasil analisis AI. Severity IRIS ditentukan
dari risk score (deterministik), BUKAN dari output AI. AI hanya memberi konteks untuk analis.
"""
from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timezone
from typing import Any, Mapping

import httpx
import orjson

RETRY_STATUS = {429, 500, 502, 503, 504}
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
                 source_link_tpl: str):
        self.customer_id = customer_id
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
        return cls(url, key, int(env.get("IRIS_CUSTOMER_ID", "1")), verify,
                   float(env.get("IRIS_TIMEOUT_S", "10")), smap,
                   int(status) if status else None, env.get("IRIS_SOURCE_LINK_TEMPLATE", ""))

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
    async def _post(self, path: str, body: dict) -> dict:
        for attempt in range(3):
            try:
                r = await self._client.post(path, json=body)
            except httpx.TransportError:
                if attempt == 2:
                    raise
                await asyncio.sleep(1 + attempt)
                continue
            if r.status_code in RETRY_STATUS and attempt < 2:
                await asyncio.sleep(1 + attempt)
                continue
            r.raise_for_status()
            return _d(r.json().get("data"))
        return {}

    async def create_alert(self, doc: dict, ai: dict | None) -> int | None:
        return (await self._post("/alerts/add", self.build_payload(doc, ai))).get("alert_id")

    async def create_case(self, doc: dict, ai: dict | None) -> int | None:
        """Buat case langsung (POST /manage/cases/add), tanpa alert."""
        p = self.build_payload(doc, ai)
        body = {"case_name": p["alert_title"][:250], "case_description": p["alert_description"],
                "case_customer": self.customer_id, "case_soc_id": str(doc.get("log_uuid"))}
        return (await self._post("/manage/cases/add", body)).get("case_id")

    async def escalate_alert(self, alert_id: int, doc: dict, ai: dict | None) -> int | None:
        """Eskalasi alert menjadi case baru (POST /alerts/escalate/{id})."""
        p = self.build_payload(doc, ai)
        body = {"iocs_import_list": [], "assets_import_list": [], "import_as_event": False,
                "note": "Dieskalasi otomatis oleh Analisis-Log-AI (risk tinggi).",
                "case_title": p["alert_title"][:250], "case_tags": p["alert_tags"]}
        data = await self._post(f"/alerts/escalate/{alert_id}", body)
        return data.get("case_id")

    async def merge_alert(self, alert_id: int, case_id: int, doc: dict) -> None:
        """Gabungkan alert ke case yang sudah ada (POST /alerts/merge/{id})."""
        risk = _d(doc.get("risk"))
        body = {"target_case_id": case_id, "iocs_import_list": [], "assets_import_list": [],
                "import_as_event": False,
                "note": f"Alert terkait dari sumber yang sama (risk {risk.get('score')}, "
                        f"{risk.get('level')}) digabung otomatis. log_uuid={doc.get('log_uuid')}"}
        await self._post(f"/alerts/merge/{alert_id}", body)

    async def aclose(self) -> None:
        await self._client.aclose()
