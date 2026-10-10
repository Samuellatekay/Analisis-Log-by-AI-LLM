"""
risk_calculator.py
Modul murni (tanpa I/O) untuk menghitung risk score per event log.

Rumus (sesuai spesifikasi):
    risk_score = ((asset_criticality*0.30) + (event_severity*0.25)
                  + (event_outcome*0.20) + (threat_weight*0.25)) * 20

CATATAN: karena event_outcome hanya 0/1, skor maksimum teoretis = 84, bukan 100.
Set normalize=True (env RISK_NORMALIZE=true) bila ingin skala 0-100 penuh.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, asdict
from typing import Any

W_ASSET, W_SEVERITY, W_OUTCOME, W_THREAT = 0.30, 0.25, 0.20, 0.25
MAX_RAW = 5 * W_ASSET + 5 * W_SEVERITY + 1 * W_OUTCOME + 5 * W_THREAT  # 4.2
SCALE = 20

DEFAULT_ASSET_CRITICALITY = 3.0  # aset tidak dikenal -> netral/menengah
DEFAULT_SEVERITY = 1.0

_DENY = {"deny", "denied", "block", "blocked", "drop", "dropped", "reject",
         "rejected", "failure", "fail", "failed", "0", "false"}

# Bobot dasar event per kategori ECS (event.category)
CATEGORY_BASE_WEIGHT = {
    "malware": 4, "intrusion_detection": 4, "threat": 4, "web": 3,
    "process": 3, "authentication": 2, "network": 2, "file": 2,
    "configuration": 2, "iam": 2,
}
DEFAULT_BASE_WEIGHT = 2


def _num(value: Any, default: float | None) -> float | None:
    try:
        f = float(value)
        return default if math.isnan(f) or math.isinf(f) else f
    except (TypeError, ValueError):
        return default


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def _dict(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def normalize_outcome(value: Any) -> int:
    """1 = allow/alert/success/unknown (konservatif), 0 = deny/blocked."""
    if isinstance(value, (bool, int, float)):
        return 1 if value else 0
    return 0 if str(value).strip().lower() in _DENY else 1


def compute_threat_weight(base_weight: float, reputation_score: float | None = None,
                          ioc_match: bool = False, domain_age_days: float | None = None,
                          repeat_count: int = 0) -> float:
    """Threat weight 1-5 = bobot dasar + bonus reputasi/IOC + domain baru + pengulangan."""
    w = _clamp(base_weight, 1, 5)
    bonus = 0.0
    if reputation_score is not None:  # 0-100, makin tinggi makin buruk
        bonus += 2.0 if reputation_score >= 80 else 1.0 if reputation_score >= 50 else 0.0
    if ioc_match:
        bonus += 1.0
    if domain_age_days is not None:
        bonus += 1.0 if domain_age_days < 30 else 0.5 if domain_age_days < 180 else 0.0
    if repeat_count >= 100:
        bonus += 1.5
    elif repeat_count >= 20:
        bonus += 1.0
    elif repeat_count >= 5:
        bonus += 0.5
    return round(_clamp(w + min(bonus, 4.0), 1, 5), 2)


def calculate_risk(asset_criticality: float, event_severity: float,
                   event_outcome: int, threat_weight: float,
                   normalize: bool = False) -> float:
    a = _clamp(asset_criticality, 1, 5)
    s = _clamp(event_severity, 1, 5)
    o = 1 if event_outcome else 0
    t = _clamp(threat_weight, 1, 5)
    raw = a * W_ASSET + s * W_SEVERITY + o * W_OUTCOME + t * W_THREAT
    score = raw * SCALE
    if normalize:
        score = raw / MAX_RAW * 100
    return round(score, 2)


def risk_level(score: float, normalized: bool = False) -> str:
    cut = (70, 50, 30) if normalized else (60, 45, 30)
    if score >= cut[0]:
        return "critical"
    if score >= cut[1]:
        return "high"
    if score >= cut[2]:
        return "medium"
    return "low"


@dataclass(slots=True)
class RiskResult:
    score: float
    level: str
    asset_criticality: float
    event_severity: float
    event_outcome: int
    threat_weight: float

    def as_dict(self) -> dict:
        return asdict(self)


def assess_event(data: dict, repeat_count: int = 0,
                 asset_criticality_fallback: float | None = None,
                 normalize: bool = False) -> RiskResult:
    """Ekstrak field dari event (skema ECS-like) lalu hitung risk."""
    ev, asset = _dict(data.get("event")), _dict(data.get("asset"))
    rep, dom, thr = _dict(data.get("reputation")), _dict(data.get("domain")), _dict(data.get("threat"))

    crit = _num(asset.get("criticality"), None)
    if crit is None:
        crit = asset_criticality_fallback if asset_criticality_fallback is not None else DEFAULT_ASSET_CRITICALITY
    severity = _num(ev.get("severity"), DEFAULT_SEVERITY)
    outcome = normalize_outcome(ev.get("outcome", 1))

    category = ev.get("category")
    if isinstance(category, list) and category:
        category = category[0]
    base = _num(thr.get("base_weight"), None)
    if base is None:
        base = CATEGORY_BASE_WEIGHT.get(str(category).lower(), DEFAULT_BASE_WEIGHT)

    tw = compute_threat_weight(base, _num(rep.get("score"), None), bool(rep.get("ioc_match")),
                               _num(dom.get("age_days"), None), repeat_count)
    score = calculate_risk(crit, severity, outcome, tw, normalize)
    return RiskResult(score, risk_level(score, normalize), _clamp(crit, 1, 5),
                      _clamp(severity, 1, 5), outcome, tw)
