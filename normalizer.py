"""
normalizer.py - Adaptor skema per sumber (nama list Redis) -> skema internal.

Skema internal (yang dibaca risk_calculator & iris_client):
  event.{severity,outcome,category,action}, source.ip, host.name, asset.{criticality,name},
  reputation.{score,ioc_match}, geolocation, domain.{name,age_days}, threat.base_weight

Jika payload sudah memakai skema itu, dibiarkan apa adanya (pass-through).
Untuk sumber dengan skema lain, daftarkan fungsi di NORMALIZERS:

    def norm_glpi(p: dict) -> dict:
        return {"event": {"severity": min(5, int(p.get("priority", 1))), "outcome": "alert",
                          "category": "ticket", "action": p.get("name")},
                "asset": {"name": p.get("computers_name")}, "original": p}

    NORMALIZERS["glpi-logs"] = norm_glpi
"""
from __future__ import annotations

from typing import Callable

import orjson

MAX_ORIGINAL_CHARS = 6000

KNOWN_KEYS = (
    "event",
    "asset",
    "reputation",
    "geolocation",
    "domain",
)

NORMALIZERS: dict[str, Callable[[dict], dict]] = {}


def norm_wazuh(p: dict) -> dict:
    """Konversi alert Wazuh ke skema internal analisis risiko."""

    rule = p.get("rule") or {}
    agent = p.get("agent") or {}
    data = p.get("data") or {}
    syscheck = data.get("syscheck") or {}

    try:
        wazuh_level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        wazuh_level = 0

    # Pemetaan level Wazuh ke severity internal 1–5.
    if wazuh_level >= 12:
        severity = 5
    elif wazuh_level >= 8:
        severity = 4
    elif wazuh_level >= 5:
        severity = 3
    elif wazuh_level >= 1:
        severity = 2
    else:
        severity = 1

    groups = rule.get("groups") or []
    threat_groups = {
        "attack",
        "malware",
        "intrusion_detection",
        "authentication_failed",
    }

    category = (
        "intrusion_detection"
        if any(str(g).lower() in threat_groups for g in groups)
        else "security"
    )

    return {
        "event": {
            "severity": severity,
            "outcome": "alert",
            "category": category,
            "action": rule.get("description", "Wazuh alert"),
            "wazuh_level": wazuh_level,
            "rule_id": rule.get("id"),
        },
        "source": {
            "ip": data.get("srcip"),
        },
        "destination": {
            "ip": data.get("dstip"),
        },
        "host": {
            "name": agent.get("name"),
        },
        "asset": {
            "name": agent.get("name"),
        },
        "file": {
            "hash": {
                "sha256": syscheck.get("sha256_after"),
            },
        },
        "original": p,
    }


def normalize(source: str, payload: dict) -> dict:
    """Normalisasi payload berdasarkan sumber Redis."""

    fn = NORMALIZERS.get(source)
    data = fn(payload) if fn else dict(payload)

    data.setdefault("data_source", source)

    # Payload yang belum dikenali tetap disimpan untuk pemeriksaan.
    if "original" not in data and not any(
        key in data for key in KNOWN_KEYS
    ):
        data["original"] = orjson.dumps(
            payload,
            default=str,
        ).decode()[:MAX_ORIGINAL_CHARS]

    return data


# Sesuaikan key ini dengan nama sumber Redis yang sebenarnya.
NORMALIZERS["analysis-in"] = norm_wazuh
