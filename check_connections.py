#!/usr/bin/env python3
"""Check application dependencies from inside the Docker network."""
import argparse
import asyncio
import os
import socket
import ssl
import sys
import time
import uuid
from urllib.parse import urlparse

import asyncpg
import httpx
import redis.asyncio as aioredis

OK, FAIL, SKIP, WARN = "OK", "GAGAL", "LEWAT", "CEK"
PROD_LISTS = {"glpi-logs", "opencti-events", "enrichment-events"}
E = os.environ.get


def hostport(url: str) -> str:
    u = urlparse(url)
    return f"{u.hostname}:{u.port}" if u.port else str(u.hostname)


def explain(exc: Exception) -> str:
    n, m = type(exc).__name__, str(exc).lower()
    if isinstance(exc, ssl.SSLError) or "certificate" in m or "ssl" in m:
        hint = "sertifikat TLS tidak dipercaya -> set *_CA_CERT (jangan matikan verify)"
    elif isinstance(exc, socket.gaierror) or "name or service" in m or "name resolution" in m:
        hint = "nama host tidak ditemukan (DNS) -> pakai IP atau cek nama host"
    elif "wrongpass" in m or "noauth" in m or "password" in m or "authentication" in m or "401" in m:
        hint = "user/password/API key salah"
    elif "noperm" in m or "403" in m:
        hint = "tidak punya izin (ACL Redis / permission user)"
    elif getattr(exc, "errno", None) == 113 or "no route" in m:
        hint = "tidak ada rute ke host -> IP salah / beda jaringan"
    elif getattr(exc, "errno", None) == 111 or isinstance(exc, ConnectionRefusedError) or "refused" in m or "connecterror" in n.lower():
        hint = "port tertutup / service mati / Redis 'bind' hanya 127.0.0.1"
    elif "timeout" in n.lower() or "timed out" in m or getattr(exc, "errno", None) == 110 or isinstance(exc, asyncio.TimeoutError):
        hint = "tidak ada balasan -> IP/port salah atau firewall memblokir"
    else:
        hint = str(exc)[:120]
    return f"{n}: {hint}"


async def check_redis():
    url = E("REDIS_URL", "")
    if not url:
        return FAIL, "Redis", "-", "REDIS_URL kosong"
    tgt = f"{hostport(url)} db{urlparse(url).path.strip('/') or 0}"
    r = aioredis.from_url(url, decode_responses=True, socket_connect_timeout=5)
    try:
        t = time.perf_counter()
        await r.ping()
        ms = (time.perf_counter() - t) * 1000
        ver = (await r.info("server")).get("redis_version", "0")
        k = f"healthcheck:{uuid.uuid4().hex[:8]}"
        await r.rpush(f"{k}:src", "a")
        await r.lmove(f"{k}:src", f"{k}:proc", "LEFT", "RIGHT")
        await r.set(f"{k}:s", "1", ex=30)
        await r.incr(f"{k}:n")
        await r.expire(f"{k}:n", 30)
        await r.delete(f"{k}:src", f"{k}:proc", f"{k}:s", f"{k}:n")
        lists = [x.strip() for x in E("REDIS_LISTS", "analysis-in").split(",") if x.strip()]
        lens = ", ".join(f"{name}={await r.llen(name)}" for name in lists)
        old = tuple(int(x) for x in ver.split(".")[:2]) < (6, 2)
        detail = f"v{ver}, {ms:.0f}ms, izin perintah OK, isi list: {lens}"
        if old:
            detail += " | BUTUH >= 6.2 (BLMOVE)"
        return (WARN if old else OK), "Redis", tgt, detail
    except Exception as exc:
        return FAIL, "Redis", tgt, explain(exc)
    finally:
        await r.aclose()


async def check_postgres():
    dsn = E("POSTGRES_DSN", "")
    if not dsn:
        return FAIL, "PostgreSQL", "-", "POSTGRES_DSN kosong"
    tgt = f"{hostport(dsn)}{urlparse(dsn).path}"
    try:
        t = time.perf_counter()
        conn = await asyncpg.connect(dsn, timeout=5)
        try:
            await conn.fetchval("select 1")
            ms = (time.perf_counter() - t) * 1000
            has = await conn.fetchval("select to_regclass('log_events')")
            n = await conn.fetchval("select count(*) from log_events") if has else None
        finally:
            await conn.close()
        extra = f"tabel log_events: {n} baris" if has else "tabel log_events belum ada (dibuat otomatis saat aplikasi start)"
        return OK, "PostgreSQL", tgt, f"{ms:.0f}ms, {extra}"
    except Exception as exc:
        return FAIL, "PostgreSQL", tgt, explain(exc)


async def check_logstash():
    url = E("LOGSTASH_URL", "")
    if not url:
        return FAIL, "Logstash", "-", "LOGSTASH_URL kosong"
    auth = (E("LOGSTASH_USER", ""), E("LOGSTASH_PASSWORD", "")) if E("LOGSTASH_USER") else None
    try:
        async with httpx.AsyncClient(auth=auth, timeout=5) as client:
            t = time.perf_counter()
            response = await client.get(url)
        ms = (time.perf_counter() - t) * 1000
        if response.status_code in (401, 403):
            return FAIL, "Logstash", hostport(url), f"HTTP {response.status_code}: LOGSTASH_USER/PASSWORD salah"
        if response.status_code < 500:
            return OK, "Logstash", hostport(url), f"terjangkau (HTTP {response.status_code}, {ms:.0f}ms); tidak ada data dikirim"
        return WARN, "Logstash", hostport(url), f"HTTP {response.status_code}"
    except Exception as exc:
        return FAIL, "Logstash", hostport(url), explain(exc)


async def check_iris():
    if E("IRIS_ENABLED", "false").lower() != "true":
        return SKIP, "DFIR-IRIS", "-", "IRIS_ENABLED=false"
    tgt = hostport(E("IRIS_URL", ""))
    try:
        from iris_client import IrisClient
        client = IrisClient.from_env(os.environ)
        try:
            t = time.perf_counter()
            status, detail = await client.check()
            ms = (time.perf_counter() - t) * 1000
        finally:
            await client.aclose()
        mapped = {"OK": OK, "GAGAL": FAIL}.get(status, WARN)
        return mapped, "DFIR-IRIS", tgt, f"{detail} ({ms:.0f}ms), mode={E('IRIS_MODE', 'alert')}"
    except Exception as exc:
        return FAIL, "DFIR-IRIS", tgt, explain(exc)


async def iris_ids():
    """Show IRIS severity and alert-status IDs."""
    try:
        from iris_client import IrisClient
        client = IrisClient.from_env(os.environ)
        if client is None:
            return SKIP, "IRIS ID", "-", "IRIS_ENABLED=false"
        try:
            severities, statuses = await client.list_ids()
        finally:
            await client.aclose()
        fmt = lambda values: ", ".join(f"{i}={name}" for i, name in values) or "tidak terbaca otomatis (lihat UI IRIS: Advanced)"
        return OK, "IRIS ID", "-", f"severity: {fmt(severities)} | status alert: {fmt(statuses)}"
    except Exception as exc:
        return FAIL, "IRIS ID", "-", explain(exc)


async def iris_selftest(with_case: bool):
    """Create one real test alert and optionally escalate it to a case."""
    try:
        from iris_client import IrisClient
        client = IrisClient.from_env(os.environ)
        if client is None:
            return SKIP, "IRIS uji", "-", "IRIS_ENABLED=false"
        doc = {
            "log_uuid": "test-" + uuid.uuid4().hex[:8],
            "event": {"action": "koneksi-uji", "outcome": "success", "category": ["test"], "severity": 1},
            "source": {"ip": "203.0.113.1"},
            "risk": {"score": 30, "level": "low", "asset_criticality": 1,
                     "event_severity": 1, "event_outcome": 1, "threat_weight": 1, "repeat_count": 0},
        }
        try:
            alert_id = await client.create_alert(doc)
            msg = f"alert_id={alert_id}"
            if with_case:
                if alert_id is None:
                    return FAIL, "IRIS uji", "-", "alert dibuat tapi ID tak terbaca dari respons"
                msg += f", case_id={await client.escalate_alert(int(alert_id), doc)}"
        finally:
            await client.aclose()
        return OK, "IRIS uji", "-", msg + "  -> HAPUS objek uji ini di IRIS"
    except Exception as exc:
        return FAIL, "IRIS uji", "-", explain(exc) + " (lihat baris 'IRIS ... HTTP' di atas untuk alasan dari server)"


def config_warnings() -> list[str]:
    warnings = []
    lists = {x.strip() for x in E("REDIS_LISTS", "").split(",")}
    if E("REDIS_MODE", "list") == "list" and lists & PROD_LISTS:
        warnings.append(f"REDIS_LISTS memuat list produksi {sorted(lists & PROD_LISTS)}: pastikan Logstash TIDAK lagi BLPOP list itu.")
    if urlparse(E("POSTGRES_DSN", "")).hostname not in ("postgres", None):
        warnings.append("POSTGRES_DSN bukan host 'postgres' (service compose). Benar hanya jika memakai DB eksternal.")
    if urlparse(E("LOGSTASH_URL", "")).hostname in ("localhost", "127.0.0.1"):
        warnings.append("LOGSTASH_URL = localhost: di dalam container itu artinya container app sendiri. Pakai IP/host Logstash.")
    if urlparse(E("REDIS_URL", "")).hostname in ("localhost", "127.0.0.1"):
        warnings.append("REDIS_URL = localhost: di dalam container itu artinya container app sendiri. Pakai IP Redis.")
    return warnings


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iris-ids", action="store_true", help="tampilkan ID severity & status alert di IRIS")
    parser.add_argument("--iris-test", action="store_true", help="BUAT 1 alert uji di IRIS")
    parser.add_argument("--iris-test-case", action="store_true", help="BUAT 1 alert uji + eskalasi jadi case")
    args = parser.parse_args()
    tasks = [check_redis(), check_postgres(), check_logstash(), check_iris()]
    if args.iris_ids:
        tasks.append(iris_ids())
    if args.iris_test or args.iris_test_case:
        tasks.append(iris_selftest(args.iris_test_case))
    results = await asyncio.gather(
        *[asyncio.wait_for(task, 200) for task in tasks],
        return_exceptions=True,
    )
    print(f"\n{'STATUS':8} {'KOMPONEN':14} {'TARGET':28} DETAIL\n" + "-" * 100)
    failures = 0
    for result in results:
        if isinstance(result, Exception):
            result = (FAIL, "?", "-", explain(result))
        status, name, target, detail = result
        failures += status == FAIL
        print(f"[{status:^6}] {name:14} {target:28} {detail}")
    for warning in config_warnings():
        print(f"[ CEK  ] Konfigurasi: {warning}")
    print("-" * 100)
    print("SEMUA KONEKSI OK" if not failures else f"{failures} KOMPONEN GAGAL - perbaiki sesuai petunjuk di kolom DETAIL")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
