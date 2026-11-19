"""
normalizer.py - Adaptor skema per sumber -> skema internal.

Skema internal (dibaca Risk Engine dan iris_client):
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
import re
from datetime import datetime, timezone
from typing import Any, Callable

import orjson

KNOWN_KEYS = ("event", "asset", "reputation", "geolocation", "domain")
WAZUH_OUTCOME_INFER = os.environ.get("WAZUH_OUTCOME_INFER", "true").lower() == "true"

NORMALIZERS: dict[str, Callable[[dict], dict]] = {}


def _dict(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _wazuh_domain(data: dict) -> str | None:
    dns = _dict(data.get("dns"))
    question = dns.get("question")
    question_name = question.get("name") if isinstance(question, dict) else question
    win = _dict(data.get("win"))
    eventdata = _dict(win.get("eventdata"))
    url = _dict(data.get("url"))
    domain_data = _dict(data.get("domain"))
    candidates = (
        question_name, dns.get("question_name"), dns.get("query"),
        eventdata.get("queryName"), data.get("queryName"),
        url.get("domain"), domain_data.get("name"),
        data.get("domain_name"), data.get("domain"),
    )
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        domain = candidate.strip().rstrip(".").casefold()
        if (
            not domain
            or len(domain) > 253
            or any(char.isspace() or char in "/:@?#" for char in domain)
        ):
            continue
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            return domain
    return None


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
_THREAT_EXACT = {"attack", "attacks", "intrusion_detection", "authentication_failed"}  # pilihan pengguna


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


def _dstip(payload: dict, data: dict) -> str | None:
    data_destination = _dict(data.get("destination"))
    data_network = _dict(data.get("network"))
    eventdata = _dict(_dict(data.get("win")).get("eventdata"))
    destination = _dict(payload.get("destination"))
    network = _dict(payload.get("network"))
    candidates = (
        data.get("dstip"), data.get("dst_ip"), data.get("destination_ip"), data.get("dest_ip"),
        data_destination.get("ip"), _dict(data_network.get("destination")).get("ip"),
        eventdata.get("destinationIp"), eventdata.get("destination_ip"),
        payload.get("dstip"), payload.get("dst_ip"), payload.get("destination_ip"),
        destination.get("ip"), _dict(network.get("destination")).get("ip"),
    )
    explicit_destination = next(
        (ip for ip in (_valid_ip(candidate) for candidate in candidates if candidate) if ip),
        None,
    )
    if explicit_destination:
        return explicit_destination
    return _valid_ip(_dict(payload.get("agent")).get("ip") or payload.get("agent_ip"))


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
    raw_manager = p.get("manager")
    manager = _dict(raw_manager)
    manager_name = manager.get("name") or (
        raw_manager if isinstance(raw_manager, str) else p.get("manager_name")
    )
    manager_ip = next(
        (
            ip for ip in (
                _valid_ip(candidate) for candidate in (
                    manager.get("ip"), manager.get("ip_address"), manager.get("address"),
                    p.get("manager_ip"), p.get("wazuh_manager_ip"),
                    os.environ.get("WAZUH_MANAGER_IP"),
                ) if candidate
            ) if ip
        ),
        None,
    )
    agent_info = {
        key: value for key, value in {
            "id": agent.get("id"),
            "name": host,
            "ip": _valid_ip(agent.get("ip") or p.get("agent_ip")),
            "manager": manager_name,
            "manager_ip": manager_ip,
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
        "original": orjson.dumps(p, default=str).decode(),
    }
    if _srcip(data):
        out["source"] = {"ip": _srcip(data)}
    destination_ip = _dstip(p, data)
    if destination_ip:
        out["destination"] = {"ip": destination_ip}
    hashes = {}
    for algorithm in ("sha512", "sha256", "sha1", "md5"):
        value = syscheck.get(f"{algorithm}_after") or syscheck.get(f"{algorithm}_before")
        if isinstance(value, str) and value.strip():
            hashes[algorithm] = value.strip().lower()
    if hashes:
        out["file"] = {"hash": hashes}
    domain = _wazuh_domain(data)
    if domain:
        out["domain"] = {"name": domain}
    cef_event = norm_crowdstrike({"full_log": p.get("full_log", "")})
    if "crowdstrike" in cef_event:
        cef_host = _dict(cef_event.get("host"))
        if cef_host.get("name"):
            out["host"] = {**_dict(out.get("host")), **cef_host}
            out["asset"] = {
                **_dict(out.get("asset")),
                **_dict(cef_event.get("asset")),
            }
        out["crowdstrike"] = cef_event["crowdstrike"]
        if cef_event.get("user"):
            out["user"] = {**_dict(out.get("user")), **cef_event["user"]}
        if cef_event.get("threat"):
            out["threat"] = cef_event["threat"]
        if cef_event.get("process"):
            out["process"] = cef_event["process"]
        if cef_event.get("file"):
            out["file"] = {
                **_dict(out.get("file")),
                **cef_event["file"],
                "hash": {
                    **_dict(_dict(out.get("file")).get("hash")),
                    **_dict(cef_event["file"].get("hash")),
                },
            }
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
    out.setdefault("original", orjson.dumps(payload, default=str).decode())
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
    out.setdefault("original", orjson.dumps(payload, default=str).decode())
    return out


_CEF_EXTENSION_KEYS = frozenset({
    "act", "app", "cat", "cn1", "cn1Label", "cn2", "cn2Label", "cn3", "cn3Label",
    "cs1", "cs1Label", "cs2", "cs2Label", "cs3", "cs3Label", "cs4", "cs4Label",
    "cs5", "cs5Label", "cs6", "cs6Label", "cnt", "destinationAddress",
    "destinationDnsDomain", "destinationHostName", "destinationNtDomain",
    "destinationPort", "destinationServiceName", "destinationTranslatedAddress",
    "destinationTranslatedPort", "deviceDirection", "deviceEventClassId",
    "deviceFacility", "deviceHostName", "deviceProduct", "deviceSeverity",
    "deviceVendor", "deviceVersion", "dhost", "dmac", "dntdom", "dpid", "dpriv",
    "dproc", "dpt", "dst", "duid", "duser", "dvchost", "end", "externalId",
    "fileHash", "filePath", "fileType", "fname", "fsize", "in", "msg",
    "oldFileId", "out", "outcome", "patternDisposition", "proto", "reason",
    "request", "requestClientApplication", "requestContext", "requestCookies",
    "requestMethod", "requestUrl", "rt", "sourceAddress", "sourceDnsDomain",
    "sourceHostName", "sourceNtDomain", "sourcePort", "sourceServiceName",
    "sourceTranslatedAddress", "sourceTranslatedPort", "sourceUserName", "sproc",
    "spt", "src", "start", "subject", "suid", "suser", "tactic", "target",
    "technique", "objective", "url", "userAgent", "CompositeId", "sourceProducts",
    "sourceProductsLabel", "sourceVendors", "sourceVendorsLabel", "dataDomains",
    "dataDomainsLabel", "FalconHostLink", "FalconHostLinkLabel", "ProcessId",
    "ParentProcessId", "Offset", "tacticId", "techniqueId", "patternId",
})
_CEF_EXTENSION_KEY_RE = re.compile(
    r"(?<!\\)(?:^|\s)([A-Za-z][A-Za-z0-9]*)="
)
_CEF_START_RE = re.compile(r"CEF:\d+\|")


def _extract_cef_from_string(value: Any) -> str | None:
    """Return the CEF payload starting at the first `CEF:<n>|` marker.

    Wazuh `full_log` may arrive with a syslog prefix (e.g.
    `Nov 19 12:00:00 host CEF:0|...`) or other noise before the CEF header.
    Search for the marker instead of requiring the string to start with `CEF:`.

    If the marker is embedded inside a JSON envelope (`{"full_log": "CEF:0|..."}`),
    return ``None`` so the caller can JSON-decode first; otherwise the trailing
    ``"}`` would be captured as part of the CEF payload.
    """
    if not isinstance(value, str):
        return None
    match = _CEF_START_RE.search(value)
    if match is None:
        return None
    prefix = value[:match.start()]
    # Syslog prefixes (timestamp/hostname) never contain JSON delimiters.
    if "{" in prefix or '"' in prefix:
        return None
    payload = value[match.start():].strip()
    if not payload:
        return None
    # CEF is line-based; drop anything after a newline (e.g. syslog multi-line).
    for delimiter in ("\n", "\r"):
        cut = payload.find(delimiter)
        if cut != -1:
            payload = payload[:cut].rstrip()
    return payload or None


def _extract_cef(payload: dict) -> str | None:
    candidates = [payload]
    for key in ("data", "event", "log", "raw"):
        nested = payload.get(key)
        if isinstance(nested, str):
            cef = _extract_cef_from_string(nested)
            if cef:
                return cef
        elif isinstance(nested, dict):
            candidates.append(nested)

    for candidate in candidates:
        for key in ("message", "full_log", "log", "raw", "cef", "original"):
            cef = _extract_cef_from_string(candidate.get(key))
            if cef:
                return cef
    return None


def _cef_unescape(value: str) -> str:
    return (
        value.replace(r"\=", "=")
        .replace(r"\|", "|")
        .replace(r"\n", "\n")
        .replace(r"\r", "\r")
        .replace(r"\\", "\\")
        .strip()
    )


def _cef_header(line: str) -> list[str] | None:
    fields: list[str] = []
    start = 0
    index = 0
    while index < len(line) and len(fields) < 7:
        if line[index] == "|":
            backslashes = 0
            cursor = index - 1
            while cursor >= start and line[cursor] == "\\":
                backslashes += 1
                cursor -= 1
            if backslashes % 2 == 0:
                fields.append(_cef_unescape(line[start:index]))
                start = index + 1
        index += 1
    if len(fields) != 7:
        return None
    fields.append(line[start:])
    if not fields[0].startswith("CEF:"):
        return None
    return fields


def _cef_extensions(value: str) -> dict[str, str]:
    matches = [
        match for match in _CEF_EXTENSION_KEY_RE.finditer(value)
        if match.group(1) in _CEF_EXTENSION_KEYS
        or match.group(1).endswith("Label")
    ]
    extensions: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(value)
        extensions[match.group(1)] = _cef_unescape(value[match.end():end])
    return extensions


def _cef_severity(value: str) -> int:
    try:
        severity = float(value)
    except (TypeError, ValueError):
        return 1
    if severity > 10:
        severity /= 10
    if severity <= 0:
        return 1
    if severity <= 3:
        return 2
    if severity <= 6:
        return 3
    if severity <= 8:
        return 4
    return 5


def _cef_timestamp(value: str) -> str | None:
    try:
        timestamp = datetime.fromtimestamp(float(value) / 1000, tz=timezone.utc)
    except (OverflowError, OSError, TypeError, ValueError):
        return None
    return timestamp.isoformat().replace("+00:00", "Z")


def _cef_label_value(extensions: dict[str, str], label: str) -> str | None:
    for key, value in extensions.items():
        if key.endswith("Label") and value.casefold() == label.casefold():
            field = key[:-5]
            return extensions.get(field)
    return None


def _cef_hash(value: str) -> dict[str, str]:
    normalized = value.strip().lower()
    for algorithm, length in (("md5", 32), ("sha1", 40), ("sha256", 64), ("sha512", 128)):
        if len(normalized) == length and re.fullmatch(r"[0-9a-f]+", normalized):
            return {algorithm: normalized}
    return {"value": normalized}


def norm_crowdstrike(payload: dict) -> dict:
    """Normalize CrowdStrike Falcon CEF events and common message envelopes."""
    cef = _extract_cef(payload)
    if cef is None:
        return dict(payload)

    parts = _cef_header(cef)
    if parts is None:
        return dict(payload)

    version, vendor, product, device_version, signature_id, name, severity, raw_ext = parts
    extensions = _cef_extensions(raw_ext)
    host_name = extensions.get("dhost") or extensions.get("deviceHostName")
    user_name = extensions.get("duser") or extensions.get("suser")
    action = extensions.get("msg") or name or signature_id
    event: dict[str, Any] = {
        "severity": _cef_severity(severity),
        "outcome": "alert",
        "category": ["intrusion_detection"],
        "action": action[:200],
        "code": signature_id,
        "kind": "alert",
        "provider": f"{vendor}/{product}",
    }
    if extensions.get("outcome"):
        event["outcome_code"] = extensions["outcome"]

    out = dict(payload)
    out["event"] = {**_dict(payload.get("event")), **event}
    out["data_source"] = "crowdstrike"
    out["message"] = extensions.get("msg") or name
    if host_name:
        out["host"] = {**_dict(payload.get("host")), "name": host_name}
        out["asset"] = {**_dict(payload.get("asset")), "name": host_name}
    if user_name:
        out["user"] = {**_dict(payload.get("user")), "name": user_name}

    process: dict[str, Any] = {}
    process_id = _cef_label_value(extensions, "ProcessId")
    parent_process_id = _cef_label_value(extensions, "ParentProcessId")
    command_line = _cef_label_value(extensions, "CommandLine")
    if process_id:
        process["pid"] = process_id
    if parent_process_id:
        process["parent"] = {"pid": parent_process_id}
    if command_line:
        process["command_line"] = command_line
    if extensions.get("fname"):
        process["name"] = extensions["fname"]
    if extensions.get("filePath"):
        process["executable"] = extensions["filePath"]
    if process:
        out["process"] = {**_dict(payload.get("process")), **process}

    file_hash = extensions.get("fileHash")
    if file_hash:
        out["file"] = {
            **_dict(payload.get("file")),
            "hash": {**_dict(_dict(payload.get("file")).get("hash")), **_cef_hash(file_hash)},
            **({"name": extensions["fname"]} if extensions.get("fname") else {}),
            **({"path": extensions["filePath"]} if extensions.get("filePath") else {}),
        }

    threat = {
        key: extensions[key]
        for key in (
            "tactic", "tacticId", "technique", "techniqueId",
            "objective", "patternDisposition", "patternId",
        )
        if extensions.get(key)
    }
    if threat:
        out["threat"] = {**_dict(payload.get("threat")), **threat}

    source_ip = _valid_ip(
        extensions.get("sourceAddress")
        or extensions.get("sourceTranslatedAddress")
        or extensions.get("src")
    )
    destination_ip = _valid_ip(
        extensions.get("destinationAddress")
        or extensions.get("destinationTranslatedAddress")
        or extensions.get("dst")
    )
    if source_ip:
        out["source"] = {**_dict(payload.get("source")), "ip": source_ip}
    if destination_ip:
        out["destination"] = {**_dict(payload.get("destination")), "ip": destination_ip}

    timestamp = _cef_timestamp(extensions.get("rt", ""))
    if timestamp:
        out["@timestamp"] = timestamp
    else:
        out.setdefault("@timestamp", payload.get("timestamp"))
    out["crowdstrike"] = {
        "cef_version": version.removeprefix("CEF:"),
        "device_version": device_version,
        "event_name": name,
        "signature_id": signature_id,
        "external_id": extensions.get("externalId"),
        "detection_id": extensions.get("CompositeId") or extensions.get("externalId"),
        "composite_id": extensions.get("CompositeId"),
        "host_name": host_name,
        "pattern_id": extensions.get("patternId"),
        "tactic_id": extensions.get("tacticId"),
        "technique_id": extensions.get("techniqueId"),
        "falcon_host_link": _cef_label_value(extensions, "FalconHostLink"),
        "source_products": extensions.get("sourceProducts"),
        "source_vendors": extensions.get("sourceVendors"),
        "data_domains": extensions.get("dataDomains"),
        "offset": _cef_label_value(extensions, "Offset"),
    }
    out["original"] = orjson.dumps(payload, default=str).decode()
    return out


def crowdstrike_detection_id(payload: dict) -> str | None:
    crowdstrike = _dict(payload.get("crowdstrike"))
    detection_id = crowdstrike.get("detection_id") or crowdstrike.get("composite_id")
    if isinstance(detection_id, str) and detection_id.strip():
        return detection_id.strip()

    cef = _extract_cef(payload)
    if cef is None:
        original = payload.get("original")
        if isinstance(original, str):
            try:
                original_payload = orjson.loads(original)
            except orjson.JSONDecodeError:
                original_payload = {}
            if isinstance(original_payload, dict):
                cef = _extract_cef(original_payload)
    if cef is None:
        return None

    parts = _cef_header(cef)
    if parts is None or parts[1].casefold() != "crowdstrike":
        return None
    extensions = _cef_extensions(parts[7])
    value = extensions.get("CompositeId") or extensions.get("externalId")
    return value.strip() if isinstance(value, str) and value.strip() else None


NORMALIZERS.update({
    "opencti-events": norm_opencti,
    "opencti": norm_opencti,
    "glpi-logs": norm_glpi,
    "glpi": norm_glpi,
    "crowdstrike": norm_crowdstrike,
    "crowdstrike-falcon": norm_crowdstrike,
    "crowdstrike-falconhost": norm_crowdstrike,
    "falcon": norm_crowdstrike,
})


# ------------------------------------------------------------------- entry
def normalize(source: str, payload: dict) -> dict:
    source_key = source.strip().lower().replace("_", "-")
    fn = NORMALIZERS.get(source_key)
    if is_wazuh(payload) and source_key not in {
        "opencti-events", "opencti", "glpi-logs", "glpi",
    }:
        fn = norm_wazuh
    elif fn is None and _extract_cef(payload):
        fn = norm_crowdstrike
    data = fn(payload) if fn else dict(payload)
    data.setdefault("data_source", source)
    # Skema tidak dikenali: sertakan payload asli agar tetap terlihat di Logstash/IRIS
    if "original" not in data and not any(k in data for k in KNOWN_KEYS):
        data["original"] = orjson.dumps(payload, default=str).decode()
    return data