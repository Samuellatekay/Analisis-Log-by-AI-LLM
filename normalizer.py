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
KNOWN_KEYS = ("event", "asset", "reputation", "geolocation", "domain")

NORMALIZERS: dict[str, Callable[[dict], dict]] = {}


def normalize(source: str, payload: dict) -> dict:
    fn = NORMALIZERS.get(source)
    data = fn(payload) if fn else dict(payload)
    data.setdefault("data_source", source)
    # Skema tidak dikenali: sertakan payload asli agar tetap terlihat di Logstash/AI/IRIS
    if "original" not in data and not any(k in data for k in KNOWN_KEYS):
        data["original"] = orjson.dumps(payload).decode()[:MAX_ORIGINAL_CHARS]
    return data
