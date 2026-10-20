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

# IRIS v2.4.x memakai path legacy; IRIS v3 hanya melayani /api/v2 (path legacy -> HTML frontend)
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
    """Teks dari log tidak tepercaya: netralkan karakter markdown/HTML."""
    s = _short(v, n)
    for ch in ("<", ">", "`", "|"):
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


def _format_reputation(value: Any, observables: list | None = None) -> list[str]:
    reputation = _d(value)
    if not reputation:
        return ["- Data reputasi belum tersedia."]

    lines = []
    score = _display(reputation.get("opencti_score"), 30)
    verdict = _display(reputation.get("verdict"), 40)
    if score or verdict:
        summary = " - ".join(part for part in (
            f"Skor OpenCTI: {score}/100" if score else None,
            f"Verdict: {verdict}" if verdict else None,
        ) if part)
        lines.append(f"- {summary}.")

    labels = reputation.get("labels")
    if isinstance(labels, list) and labels:
        shown = [_display(label, 80) for label in labels[:8]]
        shown = [label for label in shown if label]
        suffix = f"; +{len(labels) - 8} label lainnya" if len(labels) > 8 else ""
        if shown:
            lines.append(f"- Label: {', '.join(shown)}{suffix}.")

    authors = []

    def add_authors(value: Any) -> None:
        if isinstance(value, list):
            for item in value:
                add_authors(item)
            return
        if isinstance(value, dict):
            author = value.get("name") or value.get("id")
            if author is None:
                for key in ("edges", "nodes", "items", "data"):
                    if key in value:
                        add_authors(value[key])
                        return
        else:
            author = value
        author = _display(author, 160)
        if author and author not in authors:
            authors.append(author)

    for observable in observables or []:
        if not isinstance(observable, dict):
            continue
        opencti = _d(observable.get("opencti"))
        indicators = opencti.get("indicators")
        if isinstance(indicators, list):
            for indicator in indicators:
                if isinstance(indicator, dict):
                    add_authors(
                        indicator.get("created_by")
                        or indicator.get("createdBy")
                        or indicator.get("creator")
                        or indicator.get("author")
                    )
        sources = opencti.get("sources")
        if isinstance(sources, list):
            for source in sources:
                if isinstance(source, dict):
                    add_authors(source)
    lines.append(
        "- Author: " + "; ".join(authors[:12]) + "."
        if authors else
        "- Author: Tidak dicantumkan pada indicator OpenCTI."
    )

    provider_status = _d(reputation.get("provider_status"))
    abuse = reputation.get("abuseipdb")
    if isinstance(abuse, dict):
        confidence = _display(abuse.get("confidence_score"), 20)
        reports = _display(abuse.get("total_reports"), 20)
        details = []
        if confidence:
            details.append(f"confidence {confidence}%")
        if reports:
            details.append(f"{reports} laporan")
        provider = _display(abuse.get("source"), 100) or "AbuseIPDB"
        status = _display(abuse.get("status"), 80)
        suffix = f"; status {status}" if status else ""
        if details:
            lines.append(f"- **AbuseIPDB:** {', '.join(details)} (sumber: {provider}{suffix}).")
        else:
            lines.append(f"- **AbuseIPDB:** tidak ada temuan{suffix} (sumber: {provider}).")
    elif "abuseipdb" in reputation:
        status = _display(provider_status.get("abuseipdb"), 120)
        if status and not any(
            message in status.lower()
            for message in ("hasil lookup tidak disertakan", "api key belum dikonfigurasi")
        ):
            lines.append(f"- **AbuseIPDB:** {status}.")

    vt = reputation.get("virustotal")
    if isinstance(vt, dict):
        stats = _d(vt.get("stats") or vt.get("last_analysis_stats"))
        counts = [f"{key} {stats[key]}" for key in ("malicious", "suspicious", "harmless")
                  if stats.get(key) is not None]
        provider = _display(vt.get("source"), 100) or "VirusTotal"
        status = _display(vt.get("status"), 80)
        suffix = f"; status {status}" if status else ""
        if counts:
            lines.append(f"- **VirusTotal:** {', '.join(counts)} (sumber: {provider}{suffix}).")
        elif vt:
            lines.append(f"- **VirusTotal:** data tersedia, ringkasan deteksi tidak tersedia (sumber: {provider}{suffix}).")
    elif "virustotal" in reputation:
        status = _display(provider_status.get("virustotal"), 120)
        if status and not any(
            message in status.lower()
            for message in ("hasil lookup tidak disertakan", "api key belum dikonfigurasi")
        ):
            lines.append(f"- **VirusTotal:** {status}.")

    return lines or ["- Data reputasi belum tersedia."]


def _format_geolocation(value: Any) -> list[str]:
    geo = _d(value)
    if not geo or geo.get("available") is False:
        return ["- Data geolokasi belum tersedia."]

    fields = (
        ("Lokasi", ", ".join(str(part) for part in
                              (geo.get("city"), geo.get("region"),
                               geo.get("country_name") or geo.get("country")) if part)),
        ("ISP", geo.get("isp") or geo.get("org")),
        ("ASN", geo.get("asn")),
        ("Hosting", "Ya" if geo.get("hosting") is True else
         "Tidak" if geo.get("hosting") is False else None),
        ("Proxy", "Ya" if geo.get("proxy") is True else
         "Tidak" if geo.get("proxy") is False else None),
    )
    lines = [f"- **{label}:** {_md_escape(value, 180)}"
             for label, value in fields if _display(value, 180)]
    return lines or ["- Data geolokasi tersedia, tetapi rinciannya kosong."]


def _format_asset(asset: dict, source_ip: Any, host_name: Any) -> list[str]:
    glpi_fields = ("owner", "user", "serial_number", "operating_system", "status", "location", "type")
    has_glpi_details = any(_display(asset.get(field), 180) for field in glpi_fields)
    is_glpi_asset = (
        asset.get("inventory_source") == "GLPI"
        or asset.get("found") is True
        or has_glpi_details
    )
    if not is_glpi_asset:
        error = _display(asset.get("error"), 180)
        if error:
            message = f"Pencarian aset GLPI gagal: {error}."
        elif asset.get("found") is False:
            searched_ip = _display(asset.get("ip"), 80)
            searched_host = _display(asset.get("host_name"), 160)
            if searched_host:
                message = f"Tidak ada aset GLPI yang cocok dengan nama host {searched_host}."
            else:
                message = (
                    f"Tidak ada aset GLPI yang cocok dengan IP {searched_ip}."
                    if searched_ip else
                    "Tidak ada aset GLPI yang cocok dengan IP ini."
                )
        else:
            message = "Data aset GLPI belum tersedia."
        lines = [f"- {message}"]
    else:
        assets = asset.get("items")
        if not isinstance(assets, list) or not assets:
            assets = [asset]
        lines = []
        for index, item in enumerate(assets[:10], start=1):
            if not isinstance(item, dict):
                continue
            asset_id = _display(item.get("id"), 80)
            label = f"GLPI #{asset_id}" if asset_id else f"GLPI {index}"
            lines.append(f"- **Aset {label}:**")
            ip_addresses = item.get("ip_addresses")
            if isinstance(ip_addresses, list):
                ip_addresses = ", ".join(
                    str(value).strip() for value in ip_addresses
                    if isinstance(value, str) and value.strip()
                )
            classified_ip_fields = (
                ("IP privat", "private_ip_addresses"),
                ("IP publik", "public_ip_addresses"),
                ("IP lainnya", "other_ip_addresses"),
            )
            classified_ip_addresses = {
                key: item.get(key) if isinstance(item.get(key), list) else []
                for _, key in classified_ip_fields
            }
            has_classified_ip_addresses = any(classified_ip_addresses.values())
            fields = (
                ("Nama", item.get("name")),
                *(
                    (
                        label,
                        ", ".join(
                            str(value).strip()
                            for value in classified_ip_addresses[key]
                            if isinstance(value, str) and value.strip()
                        ),
                    )
                    for label, key in classified_ip_fields
                ),
                (
                    "Alamat IP",
                    (ip_addresses or item.get("ip") or source_ip)
                    if not has_classified_ip_addresses else None,
                ),
                ("Pemilik", item.get("owner") or item.get("user")),
                ("Serial", item.get("serial_number")),
                ("Nomor inventaris", item.get("asset_tag")),
                ("Sistem operasi", item.get("operating_system")),
                ("Status", item.get("status")),
                ("Lokasi", item.get("location")),
                ("Tipe", item.get("type")),
                ("Produsen", item.get("manufacturer")),
                ("Model", item.get("model")),
                ("Entitas GLPI", item.get("entity")),
                ("Grup", item.get("group")),
                ("Kontak", item.get("contact")),
                ("Nomor kontak", item.get("contact_number")),
                ("Dibuat", item.get("created_at")),
                ("Computer terakhir diperbarui (GLPI)", item.get("updated_at")),
                ("Tanggal pembelian", item.get("purchase_date")),
            )
            lines.extend(
                f"  - **{field}:** {_md_escape(value, 180)}"
                for field, value in fields if _display(value, 180)
            )
            description = _display(item.get("description"), 400)
            if description:
                lines.append(f"  - **Catatan GLPI:** {_md_escape(description, 400)}")
        if len(assets) > 10:
            lines.append(
                f"- {len(assets) - 10} aset GLPI lainnya tersedia di konten sumber alert."
            )
        if not lines:
            lines = ["- Data aset ditemukan, tetapi detailnya kosong."]
        matched_by = _display(asset.get("matched_by"), 40)
        matched_value = _display(asset.get("matched_value"), 180)
        if matched_by and matched_value:
            match_label = "IP" if matched_by == "ip" else "hostname"
            lines.insert(
                0,
                f"- **Cocok berdasarkan:** {match_label} `{_md_escape(matched_value, 180)}`",
            )

    if host_name and _display(host_name, 160):
        lines.append(f"- **Hostname Wazuh:** {_md_escape(host_name, 160)}")
    return lines


def _format_opencti_matches(doc: dict, observables: list) -> list[str]:
    contexts = [_d(doc.get("opencti"))]
    contexts.extend(
        _d(item.get("opencti")) for item in observables if isinstance(item, dict)
    )
    lookup_targets = []
    for item in observables:
        if not isinstance(item, dict):
            continue
        context = _d(item.get("opencti"))
        status = context.get("lookup_status")
        entity_type = _display(item.get("entity_type"), 40)
        value = _display(item.get("value"), 180)
        if status in {"observable_found", "observable_not_found"} and entity_type and value:
            target = (entity_type, value, status)
            if target not in lookup_targets:
                lookup_targets.append(target)

    seen_observables = set()
    seen_indicators = set()
    seen_locations = set()
    seen_related_entities = set()
    seen_relationships = set()
    matched_observables = []
    indicators = []
    locations = []
    related_entities = []
    relationships = []
    related_entity_count = 0
    relationship_count = 0
    related_data_truncated = False
    for context in contexts:
        if isinstance(context.get("related_entity_count"), int):
            related_entity_count = max(
                related_entity_count, context["related_entity_count"]
            )
        if isinstance(context.get("relationship_count"), int):
            relationship_count = max(
                relationship_count, context["relationship_count"]
            )
        related_data_truncated = (
            related_data_truncated
            or context.get("related_data_truncated") is True
        )
        observable = context.get("observable")
        if isinstance(observable, dict):
            key = (observable.get("entity_type"), observable.get("value"), observable.get("id"))
            if key not in seen_observables:
                seen_observables.add(key)
                matched_observables.append(observable)
        for indicator in context.get("indicators", []):
            if not isinstance(indicator, dict):
                continue
            key = indicator.get("id") or (
                indicator.get("name"), indicator.get("pattern")
            )
            if key not in seen_indicators:
                seen_indicators.add(key)
                indicators.append(indicator)
        for location in context.get("locations", []):
            if not isinstance(location, dict):
                continue
            key = (
                location.get("type"), location.get("name"),
                location.get("latitude"), location.get("longitude"),
            )
            if key not in seen_locations:
                seen_locations.add(key)
                locations.append(location)
        for entity in context.get("related_entities", []):
            if not isinstance(entity, dict):
                continue
            key = entity.get("id") or (
                entity.get("entity_type") or entity.get("type"),
                entity.get("name") or entity.get("value")
                or entity.get("observable_value"),
            )
            if key not in seen_related_entities:
                seen_related_entities.add(key)
                related_entities.append(entity)
        for relationship in context.get("relationships", []):
            if not isinstance(relationship, dict):
                continue
            from_entity = relationship.get("from")
            to_entity = relationship.get("to")
            key = relationship.get("id") or (
                relationship.get("relationship_type"),
                from_entity.get("id") if isinstance(from_entity, dict) else None,
                to_entity.get("id") if isinstance(to_entity, dict) else None,
            )
            if key not in seen_relationships:
                seen_relationships.add(key)
                relationships.append(relationship)

    lines = []
    for observable in matched_observables[:20]:
        entity_type = _display(observable.get("entity_type"), 40)
        value = _display(observable.get("value"), 180)
        if entity_type and value:
            lines.append(f"- **Observable:** {entity_type} `{_md_escape(value, 180)}`")
            if observable.get("id"):
                lines.append(f"  - **OpenCTI ID:** {_md_escape(observable['id'], 120)}")
            for label, field, limit in (
                ("Nama", "name", 120),
                ("Dibuat", "created_at", 80),
                ("Diubah", "updated_at", 80),
                ("Deskripsi", "description", 240),
                ("Confidence", "confidence", 40),
                ("Skor OpenCTI", "score", 40),
                ("Pertama terlihat", "first_seen", 80),
                ("Terakhir terlihat", "last_seen", 80),
                ("Pembuat/sumber", "created_by", 160),
            ):
                value = observable.get(field)
                if isinstance(value, dict):
                    value = value.get("name") or value.get("id")
                detail = _display(value, limit)
                if detail:
                    lines.append(f"  - **{label}:** {_md_escape(detail, limit)}")
            labels = observable.get("labels")
            if isinstance(labels, list) and labels:
                lines.append(
                    "  - **Label:** "
                    + ", ".join(_md_escape(label, 100) for label in labels[:20])
                )
    if len(matched_observables) > 20:
        lines.append(
            f"- {len(matched_observables) - 20} observable cocok lainnya tersedia di konten sumber alert."
        )
    for location in locations[:10]:
        details = [
            _display(location.get("type"), 80),
            _display(location.get("name"), 160),
            _display(location.get("latitude"), 40),
            _display(location.get("longitude"), 40),
        ]
        details = [value for value in details if value]
        if details:
            lines.append("- **Lokasi OpenCTI:** " + " | ".join(details))
    if len(locations) > 10:
        lines.append(
            f"- {len(locations) - 10} lokasi terkait lainnya tersedia di konten sumber alert."
        )

    for index, indicator in enumerate(indicators[:10], start=1):
        name = _display(indicator.get("name"), 180) or "Indicator tanpa nama"
        identifier = _display(indicator.get("id"), 120)
        lines.append(f"- **Indicator {index}:** {_md_escape(name, 180)}")
        if identifier:
            lines.append(f"  - **ID:** {_md_escape(identifier, 120)}")
        for label, field, limit in (
            ("Skor OpenCTI", "score", 40),
            ("Confidence", "confidence", 40),
            ("Status revoked", "revoked", 20),
            ("Valid dari", "valid_from", 80),
            ("Valid sampai", "valid_until", 80),
            ("Dibuat", "created", 80),
            ("Diubah", "modified", 80),
            ("Pertama terlihat", "first_seen", 80),
            ("Terakhir terlihat", "last_seen", 80),
            ("MITRE ID", "x_mitre_id", 80),
            ("Pembuat/sumber", "created_by", 160),
        ):
            value = indicator.get(field)
            if isinstance(value, dict):
                value = value.get("name") or value.get("id")
            display = _display(value, limit)
            if display:
                lines.append(f"  - **{label}:** {_md_escape(display, limit)}")
        for label, field in (("Deskripsi", "description"), ("Pattern", "pattern")):
            value = _display(indicator.get(field), 240)
            if value:
                lines.append(f"  - **{label}:** `{_md_escape(value, 240)}`")
        labels = indicator.get("labels")
        if isinstance(labels, list) and labels:
            lines.append(
                "  - **Label:** " + ", ".join(
                    _md_escape(label, 100) for label in labels[:20]
                )
            )
        indicator_types = indicator.get("indicator_types")
        if isinstance(indicator_types, list) and indicator_types:
            lines.append(
                "  - **Jenis:** "
                + ", ".join(_md_escape(value, 80) for value in indicator_types[:10])
            )
        kill_chain_phases = indicator.get("kill_chain_phases")
        if isinstance(kill_chain_phases, list) and kill_chain_phases:
            phases = []
            for phase in kill_chain_phases[:10]:
                if isinstance(phase, dict):
                    value = " / ".join(
                        str(phase[key]) for key in ("kill_chain_name", "phase_name")
                        if phase.get(key)
                    )
                else:
                    value = str(phase)
                if value:
                    phases.append(_md_escape(value, 120))
            if phases:
                lines.append("  - **Kill chain:** " + ", ".join(phases))
        references = indicator.get("external_references")
        if isinstance(references, list):
            for reference in references[:3]:
                if not isinstance(reference, dict):
                    continue
                details = [
                    _display(reference.get("source_name"), 120),
                    _display(reference.get("external_id"), 120),
                    _display(reference.get("url"), 240),
                    _display(reference.get("description"), 180),
                ]
                details = [value for value in details if value]
                if details:
                    lines.append(
                        "  - **Referensi:** "
                        + " | ".join(_md_escape(value, 240) for value in details)
                    )
    indicator_count = max(
        len(indicators),
        *(
            context.get("indicator_match_count")
            for context in contexts
            if isinstance(context.get("indicator_match_count"), int)
        ),
    )
    if indicator_count > 10:
        lines.append(
            f"- {indicator_count - 10} indicator cocok lainnya tersedia di konten sumber alert."
        )

    for entity in related_entities[:12]:
        entity_type = _display(
            entity.get("entity_type") or entity.get("type"), 60
        ) or "Entitas"
        name = _display(
            entity.get("name") or entity.get("value")
            or entity.get("observable_value"), 180
        ) or "Tanpa nama"
        lines.append(f"- **{_md_escape(entity_type, 60)} terkait:** {_md_escape(name, 180)}")
        identifier = _display(entity.get("id"), 120)
        if identifier:
            lines.append(f"  - **ID:** {_md_escape(identifier, 120)}")
        for label, field, limit in (
            ("Deskripsi", "description", 300),
            ("Aliases", "aliases", 180),
            ("MITRE ID", "x_mitre_id", 80),
            ("Skor OpenCTI", "score", 40),
            ("Confidence", "confidence", 40),
            ("Dibuat", "created", 80),
            ("Diubah", "modified", 80),
            ("Pertama terlihat", "first_seen", 80),
            ("Terakhir terlihat", "last_seen", 80),
        ):
            value = entity.get(field)
            if isinstance(value, list):
                value = ", ".join(str(item) for item in value[:10])
            display = _display(value, limit)
            if display:
                lines.append(f"  - **{label}:** {_md_escape(display, limit)}")
        labels = entity.get("labels")
        if isinstance(labels, list) and labels:
            lines.append(
                "  - **Label:** "
                + ", ".join(_md_escape(label, 100) for label in labels[:12])
            )
        references = entity.get("external_references")
        if isinstance(references, list):
            for reference in references[:2]:
                if not isinstance(reference, dict):
                    continue
                details = [
                    _display(reference.get("source_name"), 100),
                    _display(reference.get("external_id"), 100),
                    _display(reference.get("url"), 180),
                ]
                details = [value for value in details if value]
                if details:
                    lines.append(
                        "  - **Referensi:** "
                        + " | ".join(_md_escape(value, 180) for value in details)
                    )
    if related_entity_count > 12:
        lines.append(
            f"- {related_entity_count - 12} entitas terkait OpenCTI lainnya tersedia di konten sumber alert."
        )

    def relationship_endpoint(value):
        if not isinstance(value, dict):
            return "entitas tidak diketahui"
        entity_type = _display(value.get("entity_type") or value.get("type"), 50)
        name = _display(
            value.get("name") or value.get("value")
            or value.get("observable_value") or value.get("id"),
            120,
        )
        return " ".join(part for part in (entity_type, name) if part) or "entitas tidak diketahui"

    for relationship in relationships[:15]:
        relation_type = _display(
            relationship.get("relationship_type"), 80
        ) or "terkait"
        from_entity = relationship_endpoint(relationship.get("from"))
        to_entity = relationship_endpoint(relationship.get("to"))
        line = (
            f"- **Relasi:** {_md_escape(from_entity, 160)} "
            f"`{_md_escape(relation_type, 80)}` {_md_escape(to_entity, 160)}"
        )
        description = _display(relationship.get("description"), 180)
        if description:
            line += f" — {_md_escape(description, 180)}"
        lines.append(line)
    if relationship_count > 15:
        lines.append(
            f"- {relationship_count - 15} relasi OpenCTI lainnya tersedia di konten sumber alert."
        )
    if related_data_truncated:
        lines.append(
            "- Detail relasi dibatasi agar alert tetap ringkas; hasil OpenCTI yang diambil "
            "tersimpan pada konten sumber alert."
        )
    if matched_observables and not indicators:
        lines.append("- Observable ditemukan di OpenCTI, tetapi belum ada indicator terkait.")
    elif not matched_observables and not indicators:
        for entity_type, value, status in lookup_targets:
            if status == "observable_not_found":
                lines.append(
                    f"- Observable {entity_type} `{_md_escape(value, 180)}` tidak ditemukan "
                    "di OpenCTI; pencarian indicator berdasarkan IOC tetap dilakukan."
                )
            else:
                lines.append(
                    f"- OpenCTI melaporkan observable {entity_type} "
                    f"`{_md_escape(value, 180)}` ditemukan, tetapi detailnya tidak tersedia."
                )
    if not lines:
        return ["- Belum ada observable atau indicator OpenCTI yang cocok."]

    bounded_lines = []
    used_chars = 0
    omitted_lines = 0
    for line in lines:
        line_length = len(line) + (1 if bounded_lines else 0)
        if used_chars + line_length > 3600:
            omitted_lines += 1
            continue
        bounded_lines.append(line)
        used_chars += line_length
    if omitted_lines:
        bounded_lines.append(
            f"- {omitted_lines} baris detail OpenCTI lainnya disingkat; data lengkap yang diambil "
            "tetap ada di konten sumber alert."
        )
    return bounded_lines


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
        self.min_wazuh_level = 0  # 0 = filter level Wazuh nonaktif
        self.max_wazuh_level = 0  # 0 = tanpa batas atas
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

    # ------------------------------------------------------------ filter
    def allows(self, doc: dict) -> bool:
        """Filter level alert Wazuh (event.wazuh_level). Event tanpa level (bukan Wazuh) tidak difilter."""
        lvl = _d(doc.get("event")).get("wazuh_level")
        try:
            lvl = int(lvl)
        except (TypeError, ValueError):
            return True
        if lvl < self.min_wazuh_level:
            return False
        return not (self.max_wazuh_level and lvl > self.max_wazuh_level)

    # ------------------------------------------------------------ payload
    def build_payload(self, doc: dict) -> dict:
        risk, ev, src, asset = _d(doc.get("risk")), _d(doc.get("event")), _d(doc.get("source")), _d(doc.get("asset"))
        level = str(risk.get("level", "medium")).lower()
        what = _md_escape(ev.get("action") or ev.get("category") or "event", 80)
        who = _md_escape(src.get("ip") or asset.get("name") or "unknown", 80)
        host = _d(doc.get("host"))
        agent = _d(doc.get("agent"))
        agent_asset = _d(agent.get("asset"))
        agent_name = agent.get("name") or asset.get("agent_name") or host.get("name")

        lines = []
        destination = _d(doc.get("destination"))
        source_asset = _d(src.get("asset")) or (asset if src.get("ip") else {})
        destination_asset = _d(destination.get("asset"))
        observables = _d(doc.get("enrichment")).get("observables") or []
        is_wazuh = doc.get("data_source") == "wazuh" or "wazuh_level" in ev
        destination_ip = _display(destination.get("ip"), 80)
        source_ip = _display(src.get("ip"), 80)
        reporting_host = _display(agent_name or host.get("name"), 160)
        sensor_asset_match = None
        if agent.get("ip") and reporting_host and not agent_asset.get("found"):
            expected_name = reporting_host.casefold()
            expected_ip = str(agent["ip"]).strip()
            for section_name, candidate_asset in (
                ("tujuan", destination_asset),
                ("sumber", source_asset),
            ):
                if candidate_asset.get("found") is not True:
                    continue
                candidate_items = candidate_asset.get("items")
                if not isinstance(candidate_items, list) or not candidate_items:
                    candidate_items = [candidate_asset]
                for item in candidate_items:
                    if not isinstance(item, dict):
                        continue
                    item_name = str(item.get("name") or "").strip().casefold()
                    item_ips = item.get("ip_addresses")
                    item_ips = item_ips if isinstance(item_ips, list) else []
                    item_ips = {
                        str(value).strip()
                        for value in [*item_ips, item.get("ip")]
                        if value
                    }
                    if item_name == expected_name and expected_ip in item_ips:
                        sensor_asset_match = (section_name, item)
                        break
                if sensor_asset_match:
                    break
        source_label = source_ip or (
            f"Tidak tersedia di event (aktivitas dilaporkan oleh host {reporting_host})"
            if reporting_host else "Tidak tersedia di event"
        )
        destination_label = (
            "Tidak ditemukan di field alert Wazuh"
            if is_wazuh else "Tidak tersedia di event"
        )
        lines += [
            "## Risiko",
            f"- **Skor:** {risk.get('score')} ({level})",
            f"- **Faktor:** kritikalitas aset {risk.get('asset_criticality')}, "
            f"severity {risk.get('event_severity')}, outcome {risk.get('event_outcome')}, "
            f"ancaman {risk.get('threat_weight')}, pengulangan {risk.get('repeat_count')}",
            "",
            "## Event",
            f"- **Deteksi:** {what}",
            f"- **Hasil:** {_display(ev.get('outcome'), 60) or 'Tidak tersedia'}",
            f"- **IP sumber (kemungkinan penyerang):** {source_label}",
            *([f"- **Wazuh Level:** {_display(ev.get('wazuh_level'), 30) or 'Tidak tersedia di event'}"]
              if is_wazuh else []),
            f"- **IP tujuan (host yang diserang):** {destination_ip or destination_label}",
            "",
            "## Aset sumber / penyerang",
            *(
                ["- Event tidak memuat IP sumber; aset penyerang tidak dapat ditentukan dari event."]
                if is_wazuh and not source_ip else
                _format_asset(source_asset, src.get("ip"), None)
            ),
            "",
            "## Aset tujuan / penerima serangan",
            *(
                ["- Alert Wazuh tidak mencantumkan IP tujuan; aset tujuan belum dapat dicari di GLPI."]
                if is_wazuh and not destination_ip and not destination_asset else
                _format_asset(destination_asset, destination.get("ip"), None)
            ),
            "",
            "## Agent Wazuh (sensor yang melaporkan event)",
            f"- **Nama:** {_display(agent_name, 160) or 'Tidak tersedia'}",
            f"- **ID:** {_display(agent.get('id'), 80) or 'Tidak tersedia'}",
            f"- **IP agent:** {_display(agent.get('ip'), 80) or ('Tidak dikirim di event Wazuh' if is_wazuh else 'Tidak tersedia')}",
            f"- **Manager:** {_display(agent.get('manager'), 160) or 'Tidak tersedia'}",
            f"- **IP manager:** {_display(agent.get('manager_ip'), 80) or ('Tidak dikirim di event Wazuh' if is_wazuh else 'Tidak tersedia')}",
            *(
                [
                    "",
                    "## Aset host pelapor / sensor (GLPI)",
                    (
                        f"- Sama dengan aset GLPI #{_display(sensor_asset_match[1].get('id'), 80) or 'tanpa ID'} "
                        f"({_display(sensor_asset_match[1].get('name'), 160) or reporting_host}) "
                        f"pada bagian Aset {sensor_asset_match[0]}; cocok berdasarkan hostname "
                        f"dan IP agent {_display(agent.get('ip'), 80)}."
                    ),
                ]
                if sensor_asset_match else
                [
                    "",
                    "## Aset host pelapor / sensor (GLPI)",
                    *_format_asset(agent_asset, agent.get("ip"), None),
                ]
                if agent_asset else []
            ),
            "",
            "## Intelijen ancaman",
            *_format_reputation(doc.get("reputation"), observables),
            "",
            "## Data OpenCTI yang cocok dengan alert",
            *_format_opencti_matches(
                doc, _d(doc.get("enrichment")).get("observables") or []
            ),
            "",
            "## Geolokasi",
            *_format_geolocation(doc.get("geolocation")),
        ]
        domain = _d(doc.get("domain"))
        domain_name = _display(domain.get("name"), 180)
        if domain_name:
            lines += ["", "## Domain", f"- **Nama:** {domain_name}"]
            age_days = _display(domain.get("age_days"), 40)
            if age_days:
                lines.append(f"- **Usia:** {age_days} hari")
        elif not domain:
            domain_name = _display(doc.get("domain"), 180)
            if domain_name:
                lines += ["", "## Domain", f"- {domain_name}"]

        if isinstance(observables, list) and observables:
            lines += ["", "## IOC terkait"]
            shown = 0
            for observable in observables[:20]:
                if not isinstance(observable, dict):
                    continue
                entity_type = _display(observable.get("entity_type"), 40)
                value = _display(observable.get("value"), 180)
                if not entity_type or not value:
                    continue
                lines.append(f"- **{entity_type}:** `{value}`")
                shown += 1
            if len(observables) > 20:
                lines.append(f"- {len(observables) - 20} IOC lainnya tersedia pada konten sumber alert.")
            if shown == 0:
                lines.append("- Detail IOC tidak tersedia.")
        lines += ["", f"`log_uuid: {doc.get('log_uuid')}`"]

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
        """Buat case langsung, tanpa alert."""
        p = self.build_payload(doc)
        body = {"case_name": p["alert_title"][:250], "case_description": p["alert_description"],
                "case_customer": self.customer_id, "case_soc_id": str(doc.get("log_uuid"))}
        d = await self._post(self.paths["case"], body)
        return d.get("case_id") or d.get("id")

    async def update_case_description(self, case_id: int, doc: dict) -> bool:
        """Replace the case summary with the latest Analisis_Log alert description."""
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
        """Add newly correlated enrichment to an existing IRIS case."""
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
        """Eskalasi alert menjadi case baru."""
        p = self.build_payload(doc)
        body = {"iocs_import_list": [], "assets_import_list": [], "import_as_event": False,
                "note": "Dieskalasi otomatis oleh Analisis_Log (risk tinggi).",
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
        if self.min_wazuh_level or self.max_wazuh_level:
            info += f", level_wazuh={self.min_wazuh_level or 0}-{self.max_wazuh_level or 'maks'}"
        if self.api_version == "v2" and self.status_id is None:
            return "CEK", info + " | alert_status_id belum diketahui: set IRIS_STATUS_ID (lihat --iris-ids)"
        return "OK", info

    async def aclose(self) -> None:
        await self._client.aclose()
