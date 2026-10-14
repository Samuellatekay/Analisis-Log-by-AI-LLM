"""Optimalisasi serangan berulang sebelum dikirim ke analisis AI.

Tujuan:
- menggabungkan burst serangan yang berasal dari IP dan rule/aksi yang sama
- membatasi jumlah pekerjaan AI untuk serangan yang berulang dalam jendela waktu tertentu
- menjaga log original tetap tersimpan, sedangkan AI menerima payload agregat
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

UUID_NS = uuid.UUID("6f1c2f0e-8c1e-4e0a-9d52-3b1f7a5e9c11")


def _as_doc(value: Any) -> dict:
    if isinstance(value, dict):
        return value
    if hasattr(value, "doc") and isinstance(value.doc, dict):
        return value.doc
    return {}


def _risk_score(value: Any) -> float:
    doc = _as_doc(value)
    risk = doc.get("risk") if isinstance(doc.get("risk"), dict) else {}
    score = risk.get("score")
    try:
        return float(score)
    except (TypeError, ValueError):
        return 0.0


def _received_at(value: Any) -> datetime:
    doc = _as_doc(value)
    ts = doc.get("@timestamp") or doc.get("timestamp")
    if ts is None and hasattr(value, "received_at"):
        ts = getattr(value, "received_at")
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _log_uuid(value: Any) -> str:
    doc = _as_doc(value)
    if "log_uuid" in doc:
        return str(doc["log_uuid"])
    if hasattr(value, "log_uuid"):
        return str(value.log_uuid)
    return "unknown"


def attack_aggregation_key(value: Any) -> tuple[str, str] | None:
    """Kunci grouping burst: IP sumber + signature serangan."""
    doc = _as_doc(value)
    source = doc.get("source") if isinstance(doc.get("source"), dict) else {}
    event = doc.get("event") if isinstance(doc.get("event"), dict) else {}
    source_ip = source.get("ip")
    signature = event.get("rule_id") or event.get("action")
    if not source_ip or not signature:
        return None
    return str(source_ip), str(signature)


def aggregate_event(records: Iterable[Any], threshold: int, window_seconds: int,
                   representative: Any | None = None,
                   aggregate_uuid: uuid.UUID | None = None) -> tuple[dict, uuid.UUID]:
    """Buat payload agregat untuk satu burst attack.

    Return: (payload_aggregate, aggregate_uuid)
    """
    items = list(records)
    if not items:
        raise ValueError("records kosong untuk aggregate_event")

    ordered = sorted(items, key=_received_at)
    rep = representative or max(ordered, key=_risk_score)
    rep_doc = _as_doc(rep)
    first = _received_at(ordered[0])
    last = _received_at(ordered[-1])
    related_ids = [str(_log_uuid(r)) for r in ordered]
    agg_uuid = aggregate_uuid or uuid.uuid5(UUID_NS, "aggregate:" + ":".join(sorted(related_ids)))

    doc = dict(rep_doc)
    doc["event_type"] = "attack_aggregate"
    doc["log_uuid"] = str(agg_uuid)
    doc["attack_aggregation"] = {
        "count": len(ordered),
        "threshold": threshold,
        "window_seconds": window_seconds,
        "window_start": first.isoformat(),
        "window_end": last.isoformat(),
        "aggregate_log_uuid": str(agg_uuid),
        "representative_log_uuid": str(_log_uuid(rep)),
        "related_log_uuids": related_ids[:100],
        "samples": [
            {
                "log_uuid": str(_log_uuid(r)),
                "timestamp": _as_doc(r).get("@timestamp") or _as_doc(r).get("timestamp"),
                "event": _as_doc(r).get("event"),
                "risk_score": _risk_score(r),
            }
            for r in ordered[:10]
        ],
    }
    return doc, agg_uuid


def should_aggregate(records: Iterable[Any], threshold: int) -> bool:
    """True bila jumlah event melebihi threshold dan layak digabung."""
    return len(list(records)) > threshold
