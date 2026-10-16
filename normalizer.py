"""
normalizer.py - Adaptor skema per sumber -> skema internal.

Skema internal (dibaca risk_calculator, iris_client, llm):
  event.{severity,outcome,category,action}, source.ip, host.name, asset.{criticality,name},
  reputation.{score,ioc_match}, geolocation, domain.{name,age_days}, threat.base_weight

* Alert Wazuh terdeteksi OTOMATIS dari isinya (ada `rule` + `agent`/`manager`), jadi aman
  walau list yang sama juga berisi data lain (GLPI/OpenCTI/enrichment).
* Skema lain: daftarkan fungsi di NORMALIZERS[nama_list] = fungsi.
* WAZUH_OUTCOME_INFER=false -> outcome Wazuh selalu "alert" (=1), seperti versi awal.
"""
from __future__ import annotations

import ipaddress
import os
from typing import Any, Callable

import orjson

MAX_ORIGINAL_CHARS = 6000
KNOWN_KEYS = ("event", "asset", "reputation", "geolocation", "domain")
WAZUH_OUTCOME_INFER = os.environ.get("WAZUH_OUTCOME_INFER", "true").lower() == "true"

NORMALIZERS: dict[str, Callable[[dict], dict]] = {}


def _dict(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


# ------------------------------------------------------------------- Wazuh
def wazuh_severity(level: int) -> int:
    """Level Wazuh -> severity 1-5 (ambang milik pengguna)."""
    if level >= 12:
        return 5
    if level >= 8:
        return 4
    if level >= 5:
        return 3
    if level >= 1:
        return 2
    return 1


_MALWARE = ("malware", "virus", "ransomware", "backdoor", "rootkit", "rootcheck", "trojan", "webshell")
_THREAT_EXACT = {"attack", "intrusion_detection", "authentication_failed"}  # pilihan pengguna


def _wazuh_category(groups: list[str]) -> str:
    sub = lambda keys: any(k in g for g in groups for k in keys)          # mengandung kata kunci
    pre = lambda keys: any(g == k or g.startswith(k) for g in groups for k in keys)  # persis/awalan
    if sub(_MALWARE):
        return "malware"
    if any(g in _THREAT_EXACT for g in groups):
        return "intrusion_detection"
    if sub(("authentication",)) or pre(("sshd", "pam", "sudo")):
        return "authentication"
    if pre(("web", "sql_injection", "xss")):
        return "web"
    if pre(("firewall", "ids", "suricata", "network", "dns")):
        return "network"
    if pre(("syscheck", "fim")):
        return "file"
    return "security"


def _wazuh_outcome(data: dict, groups: list[str]) -> str:
    if not WAZUH_OUTCOME_INFER:
        return "alert"
    if str(_dict(data.get("audit")).get("res", "")).lower() in ("failed", "fail", "failure", "no"):
        return "failure"
    if any(k in g for g in groups for k in ("authentication_fail", "invalid_login", "login_denied")):
        return "failure"
    if str(data.get("action", "")).lower() in ("drop", "deny", "denied", "block", "blocked", "reject"):
        return "denied"
    return "alert"


def _valid_ip(v: Any) -> str | None:
    """Hanya IP sungguhan. Auditd sering menulis addr=? / '-' ; loopback & 0.0.0.0 bukan sumber serangan."""
    try:
        ip = ipaddress.ip_address(str(v).strip())
    except ValueError:
        return None
    return None if (ip.is_loopback or ip.is_unspecified) else str(ip)


def _srcip(data: dict) -> str | None:
    cand = (data.get("srcip"), data.get("src_ip"), data.get("source_ip"),
            _dict(_dict(data.get("win")).get("eventdata")).get("ipAddress"),
            _dict(data.get("audit")).get("addr"))
    return next((ip for ip in (_valid_ip(c) for c in cand if c) if ip), None)


def is_wazuh(p: dict) -> bool:
    return isinstance(p.get("rule"), dict) and (
        "agent" in p or "manager" in p or _dict(p.get("event")).get("dataset") == "wazuh.alerts")


def norm_wazuh(p: dict) -> dict:
    """Alert Wazuh -> skema internal. Field kosong tidak disertakan."""
    rule, agent, data = _dict(p.get("rule")), _dict(p.get("agent")), _dict(p.get("data"))
    syscheck = _dict(data.get("syscheck"))
    try:
        level = int(float(rule.get("level", 0)))
    except (TypeError, ValueError):
        level = 0
    groups = [str(g).lower() for g in rule["groups"]] if isinstance(rule.get("groups"), list) else []
    host = agent.get("name") or _dict(p.get("host")).get("name")
    manager = _dict(p.get("manager"))
    agent_info = {
        key: value for key, value in {
            "id": agent.get("id"),
            "name": host,
            "ip": agent.get("ip"),
            "manager": manager.get("name"),
        }.items() if value not in (None, "")
    }

    out: dict[str, Any] = {
        "@timestamp": p.get("@timestamp") or p.get("timestamp"),
        "event": {"severity": wazuh_severity(level), "outcome": _wazuh_outcome(data, groups),
                  "category": [_wazuh_category(groups)],
                  "action": str(rule.get("description", "Wazuh alert"))[:200],
                  "wazuh_level": level, "rule_id": rule.get("id")},
        "host": {"name": host}, "asset": {"name": host},  # criticality dicari di Redis asset:<nama>
        "agent": agent_info,
        "data_source": "wazuh",
        # Disimpan sebagai STRING (bukan objek) agar tidak merusak mapping Elasticsearch
        "original": orjson.dumps({
            "rule": {"id": rule.get("id"), "level": level, "description": rule.get("description"), "groups": groups},
            "agent": agent_info, "decoder": _dict(p.get("decoder")).get("name"),
            "location": p.get("location"), "full_log": str(p.get("full_log", ""))[:1500], "data": data,
        }, default=str).decode()[:MAX_ORIGINAL_CHARS],
    }
    if _srcip(data):
        out["source"] = {"ip": _srcip(data)}
    if data.get("dstip"):
        out["destination"] = {"ip": data["dstip"]}
    hashes = {}
    for algorithm in ("sha512", "sha256", "sha1", "md5"):
        value = syscheck.get(f"{algorithm}_after") or syscheck.get(f"{algorithm}_before")
        if isinstance(value, str) and value.strip():
            hashes[algorithm] = value.strip().lower()
    if hashes:
        out["file"] = {"hash": hashes}
    return out


# ------------------------------------------------------------ OpenCTI / GLPI
def _merged_payload(p: dict) -> dict:
    """Support common connector envelopes while retaining fields from the envelope."""
    data = _dict(p.get("data"))
    return {**p, **data} if data else p


def _first(*values: Any) -> Any:
    return next((v for v in values if v not in (None, "")), None)


def _severity(value: Any, default: int = 1) -> int:
    levels = {
        "informational": 1, "info": 1, "debug": 1,
        "low": 2, "warning": 2, "medium": 3, "moderate": 3,
        "high": 4, "error": 4, "critical": 5, "very high": 5,
    }
    if isinstance(value, str) and value.strip().lower() in levels:
        return levels[value.strip().lower()]
    try:
        return max(1, min(5, int(float(value) + 0.5)))
    except (TypeError, ValueError):
        return default


def _opencti_indicator_ip(pattern: Any) -> str | None:
    """Extract only an IP literal from a common STIX indicator pattern."""
    if not isinstance(pattern, str):
        return None
    import re

    match = re.search(r"(?:ipv4-addr|ipv6-addr):value\s*=\s*['\"]([^'\"]+)", pattern, re.I)
    return _valid_ip(match.group(1)) if match else None


def norm_opencti(payload: dict) -> dict:
    """Map OpenCTI/STIX records and connector envelopes to the internal event schema."""
    p = _merged_payload(payload)
    existing_event = _dict(p.get("event"))
    entity_type = str(_first(p.get("entity_type"), p.get("type"), p.get("x_opencti_type"), ""))
    entity_type = entity_type.lower()
    pattern = p.get("pattern")
    is_indicator = entity_type in {"indicator", "ipv4-addr", "ipv6-addr", "domain-name", "url"} or bool(pattern)
    score = _first(p.get("x_opencti_score"), p.get("score"))
    try:
        score = max(0, min(100, float(score))) if score is not None else None
    except (TypeError, ValueError):
        score = None

    event = dict(existing_event)
    event.setdefault("action", _first(p.get("name"), p.get("description"), entity_type, "OpenCTI threat intelligence"))
    event.setdefault("category", ["threat"])
    event.setdefault("outcome", "alert")
    if "severity" not in event:
        event["severity"] = _severity(score / 20 if score is not None else None, 4 if is_indicator else 1)

    out = dict(p)
    out["event"] = event
    out["data_source"] = "opencti"
    out["threat"] = {**_dict(p.get("threat")), "base_weight": _dict(p.get("threat")).get("base_weight", 4)}
    if score is not None or is_indicator:
        out["reputation"] = {
            **_dict(p.get("reputation")),
            **({"score": score} if score is not None else {}),
            "ioc_match": bool(_dict(p.get("reputation")).get("ioc_match")) or is_indicator,
        }

    ip = _first(_dict(p.get("source")).get("ip"), p.get("srcip"), p.get("ip"), _opencti_indicator_ip(pattern))
    if ip and _valid_ip(ip):
        out["source"] = {**_dict(p.get("source")), "ip": _valid_ip(ip)}
    domain = _first(_dict(p.get("domain")).get("name"), p.get("domain_name"))
    if domain:
        out["domain"] = {**_dict(p.get("domain")), "name": domain}
    out.setdefault("original", orjson.dumps(payload, default=str).decode()[:MAX_ORIGINAL_CHARS])
    return out


def norm_glpi(payload: dict) -> dict:
    """Map GLPI ticket/log/asset records to the internal event schema."""
    p = _merged_payload(payload)
    existing_event = _dict(p.get("event"))
    priority = _first(p.get("priority"), p.get("urgency"), p.get("severity"))
    event = dict(existing_event)
    event.setdefault("action", _first(
        p.get("name"), p.get("message"), p.get("content"), p.get("title"),
        p.get("itemtype"), "GLPI event",
    ))
    event.setdefault("category", ["configuration"])
    event.setdefault("outcome", "alert")
    event.setdefault("severity", _severity(priority))

    out = dict(p)
    out["event"] = event
    out["data_source"] = "glpi"
    item_name = _first(p.get("item_name"), p.get("asset_name"), p.get("name"))
    item_type = _first(p.get("itemtype"), p.get("item_type"), p.get("asset_type"))
    asset = dict(_dict(p.get("asset")))
    if item_name:
        asset.setdefault("name", item_name)
    if item_type:
        asset.setdefault("type", item_type)
    if asset:
        out["asset"] = asset
    source_ip = _first(_dict(p.get("source")).get("ip"), p.get("source_ip"), p.get("ip"))
    if source_ip and _valid_ip(source_ip):
        out["source"] = {**_dict(p.get("source")), "ip": _valid_ip(source_ip)}
    out.setdefault("original", orjson.dumps(payload, default=str).decode()[:MAX_ORIGINAL_CHARS])
    return out


NORMALIZERS.update({
    "opencti-events": norm_opencti,
    "opencti": norm_opencti,
    "glpi-logs": norm_glpi,
    "glpi": norm_glpi,
})


# ------------------------------------------------------------------- entry
def normalize(source: str, payload: dict) -> dict:
    source_key = source.strip().lower().replace("_", "-")
    fn = NORMALIZERS.get(source_key)
    if fn is None and is_wazuh(payload):
        fn = norm_wazuh
    data = fn(payload) if fn else dict(payload)
    data.setdefault("data_source", source)
    # Skema tidak dikenali: sertakan payload asli agar tetap terlihat di Logstash/AI/IRIS
    if "original" not in data and not any(k in data for k in KNOWN_KEYS):
        data["original"] = orjson.dumps(payload, default=str).decode()[:MAX_ORIGINAL_CHARS]
    return data