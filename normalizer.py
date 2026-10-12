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

    out: dict[str, Any] = {
        "@timestamp": p.get("@timestamp") or p.get("timestamp"),
        "event": {"severity": wazuh_severity(level), "outcome": _wazuh_outcome(data, groups),
                  "category": [_wazuh_category(groups)],
                  "action": str(rule.get("description", "Wazuh alert"))[:200],
                  "wazuh_level": level, "rule_id": rule.get("id")},
        "host": {"name": host}, "asset": {"name": host},  # criticality dicari di Redis asset:<nama>
        "data_source": "wazuh",
        # Disimpan sebagai STRING (bukan objek) agar tidak merusak mapping Elasticsearch
        "original": orjson.dumps({
            "rule": {"id": rule.get("id"), "level": level, "description": rule.get("description"), "groups": groups},
            "agent": {"name": host}, "decoder": _dict(p.get("decoder")).get("name"),
            "location": p.get("location"), "full_log": str(p.get("full_log", ""))[:1500], "data": data,
        }, default=str).decode()[:MAX_ORIGINAL_CHARS],
    }
    if _srcip(data):
        out["source"] = {"ip": _srcip(data)}
    if data.get("dstip"):
        out["destination"] = {"ip": data["dstip"]}
    if syscheck.get("sha256_after"):
        out["file"] = {"hash": {"sha256": syscheck["sha256_after"]}}
    return out


# ------------------------------------------------------------------- entry
def normalize(source: str, payload: dict) -> dict:
    fn = NORMALIZERS.get(source)
    if fn is None and is_wazuh(payload):
        fn = norm_wazuh
    data = fn(payload) if fn else dict(payload)
    data.setdefault("data_source", source)
    # Skema tidak dikenali: sertakan payload asli agar tetap terlihat di Logstash/AI/IRIS
    if "original" not in data and not any(k in data for k in KNOWN_KEYS):
        data["original"] = orjson.dumps(payload, default=str).decode()[:MAX_ORIGINAL_CHARS]
    return data