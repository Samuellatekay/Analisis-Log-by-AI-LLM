#!/usr/bin/env python3
"""
Cek semua koneksi dari DALAM container (jaringan yang sama dengan aplikasi):
  docker compose run --rm app python check_connections.py          # cek cepat (tanpa biaya)
  docker compose run --rm app python check_connections.py --live   # + uji analisis AI sungguhan

Tidak mengirim data ke Logstash/Elasticsearch/IRIS (hanya GET) dan tidak mencetak password/API key.
Exit code 0 = semua OK, 1 = ada yang GAGAL.
"""
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


# ------------------------------------------------------------------ pengecekan
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
        k = f"healthcheck:{uuid.uuid4().hex[:8]}"  # uji izin untuk perintah yang dipakai aplikasi
        await r.rpush(f"{k}:src", "a")
        await r.lmove(f"{k}:src", f"{k}:proc", "LEFT", "RIGHT")
        await r.set(f"{k}:s", "1", ex=30)
        await r.incr(f"{k}:n")
        await r.expire(f"{k}:n", 30)
        await r.delete(f"{k}:src", f"{k}:proc", f"{k}:s", f"{k}:n")
        lists = [x.strip() for x in E("REDIS_LISTS", "analysis-in").split(",") if x.strip()]
        parts = []
        for x in lists:
            parts.append(f"{x}={await r.llen(x)}")
        lens = ", ".join(parts)
        old = tuple(int(x) for x in ver.split(".")[:2]) < (6, 2)
        return (WARN if old else OK), "Redis", tgt, \
            f"v{ver}, {ms:.0f}ms, izin perintah OK, isi list: {lens}" + (" | BUTUH >= 6.2 (BLMOVE)" if old else "")
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
        async with httpx.AsyncClient(auth=auth, timeout=5) as c:
            t = time.perf_counter()
            r = await c.get(url)
        ms = (time.perf_counter() - t) * 1000
        if r.status_code in (401, 403):
            return FAIL, "Logstash", hostport(url), f"HTTP {r.status_code}: LOGSTASH_USER/PASSWORD salah"
        if r.status_code < 500:
            return OK, "Logstash", hostport(url), f"terjangkau (HTTP {r.status_code}, {ms:.0f}ms); tidak ada data dikirim"
        return WARN, "Logstash", hostport(url), f"HTTP {r.status_code}"
    except Exception as exc:
        return FAIL, "Logstash", hostport(url), explain(exc)


async def _get(url, headers=None, timeout=10):
    async with httpx.AsyncClient(timeout=timeout) as c:
        return await c.get(url, headers=headers)


async def check_llm(name: str):
    n = name.lower()
    try:
        if n == "ollama":
            base, model = E("OLLAMA_URL", "http://localhost:11434").rstrip("/"), E("OLLAMA_MODEL", "llama3.1:8b")
            r = await _get(f"{base}/api/tags")
            r.raise_for_status()
            names = [m.get("name", "") for m in r.json().get("models", [])]
            ok = model in names or f"{model}:latest" in names
            return (OK if ok else FAIL), "AI: Ollama", hostport(base), \
                f"model {model} " + ("tersedia" if ok else f"TIDAK ADA -> jalankan: ollama pull {model}")
        if n in ("gemini", "google"):
            key, model = E("GEMINI_API_KEY", ""), E("GEMINI_MODEL", "gemini-2.0-flash")
            if not key:
                return FAIL, "AI: Gemini", "-", "GEMINI_API_KEY kosong"
            base = E("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta")
            r = await _get(f"{base}/models/{model}", {"x-goog-api-key": key})
        elif n == "openai":
            key, model = E("OPENAI_API_KEY", ""), E("OPENAI_MODEL", "gpt-4o-mini")
            if not key:
                return FAIL, "AI: OpenAI", "-", "OPENAI_API_KEY kosong"
            base = E("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
            r = await _get(f"{base}/models/{model}", {"Authorization": f"Bearer {key}"})
        elif n in ("anthropic", "claude"):
            key, model = E("ANTHROPIC_API_KEY", ""), E("ANTHROPIC_MODEL", "claude-haiku-5-5")
            if not key:
                return FAIL, "AI: Claude", "-", "ANTHROPIC_API_KEY kosong"
            base = "https://api.anthropic.com"
            r = await _get(f"{base}/v1/models/{model}", {"x-api-key": key, "anthropic-version": "2023-06-01"})
        else:
            return FAIL, f"AI: {name}", "-", "provider tidak dikenal"
        label = {"google": "Gemini", "gemini": "Gemini", "openai": "OpenAI", "anthropic": "Claude", "claude": "Claude"}[n]
        if r.status_code == 200:
            return OK, f"AI: {label}", hostport(base), f"API key valid, model {model} tersedia"
        if r.status_code in (400, 401, 403):
            return FAIL, f"AI: {label}", hostport(base), f"HTTP {r.status_code}: API key salah / tidak punya akses"
        if r.status_code == 404:
            return FAIL, f"AI: {label}", hostport(base), f"model '{model}' tidak ditemukan -> cek nama model"
        return WARN, f"AI: {label}", hostport(base), f"HTTP {r.status_code}"
    except Exception as exc:
        return FAIL, f"AI: {name}", "-", explain(exc)


async def check_iris():
    if E("IRIS_ENABLED", "false").lower() != "true":
        return SKIP, "DFIR-IRIS", "-", "IRIS_ENABLED=false"
    try:
        from iris_client import IrisClient
        c = IrisClient.from_env(os.environ)
        t = time.perf_counter()
        r = await c._client.get("/manage/cases/list")
        ms = (time.perf_counter() - t) * 1000
        await c.aclose()
        tgt = hostport(E("IRIS_URL", ""))
        if r.status_code == 200:
            return OK, "DFIR-IRIS", tgt, f"API key valid ({ms:.0f}ms), customer_id={E('IRIS_CUSTOMER_ID', '1')}, mode={E('IRIS_MODE', 'alert')}"
        if r.status_code in (401, 403):
            return FAIL, "DFIR-IRIS", tgt, f"HTTP {r.status_code}: API key salah / user tanpa izin"
        return WARN, "DFIR-IRIS", tgt, f"HTTP {r.status_code}: terjangkau tapi respons tak terduga (versi IRIS?)"
    except Exception as exc:
        return FAIL, "DFIR-IRIS", hostport(E("IRIS_URL", "")), explain(exc)


async def check_live(name: str):
    """Analisis AI sungguhan (memakai token / waktu)."""
    try:
        from llm_analyzer import build_analyzer
        chain = build_analyzer({**os.environ, "LLM_PROVIDERS": name}, E("PERSONA_PATH", "soc_persona.md"))
        doc = {"event": {"action": "ssh-bruteforce", "outcome": "failure", "severity": 4},
               "source": {"ip": "198.51.100.77"}, "risk": {"score": 70, "level": "high"}}
        t = time.perf_counter()
        res, prov, model = await asyncio.wait_for(chain.analyze("test-" + uuid.uuid4().hex[:6], doc), 180)
        await chain.aclose()
        return OK, f"LIVE {prov}", model, f"{time.perf_counter() - t:.1f}s, verdict={res['verdict']}, parse_warning={res.get('parse_warning', False)}"
    except Exception as exc:
        return FAIL, f"LIVE {name}", "-", explain(exc)


def config_warnings() -> list[str]:
    w = []
    lists = {x.strip() for x in E("REDIS_LISTS", "").split(",")}
    if E("REDIS_MODE", "list") == "list" and lists & PROD_LISTS:
        w.append(f"REDIS_LISTS memuat list produksi {sorted(lists & PROD_LISTS)}: pastikan Logstash TIDAK lagi BLPOP list itu.")
    if urlparse(E("POSTGRES_DSN", "")).hostname not in ("postgres", None):
        w.append("POSTGRES_DSN bukan host 'postgres' (service compose). Benar hanya jika memakai DB eksternal.")
    if urlparse(E("LOGSTASH_URL", "")).hostname in ("localhost", "127.0.0.1"):
        w.append("LOGSTASH_URL = localhost: di dalam container itu artinya container app sendiri. Pakai IP/host Logstash.")
    if urlparse(E("REDIS_URL", "")).hostname in ("localhost", "127.0.0.1"):
        w.append("REDIS_URL = localhost: di dalam container itu artinya container app sendiri. Pakai IP Redis.")
    return w


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="uji analisis AI sungguhan (memakai token/waktu)")
    a = ap.parse_args()
    providers = [x.strip() for x in E("LLM_PROVIDERS", "ollama").split(",") if x.strip()]
    tasks = [check_redis(), check_postgres(), check_logstash(), check_iris()] + [check_llm(p) for p in providers]
    if a.live:
        tasks += [check_live(p) for p in providers]
    results = await asyncio.gather(*[asyncio.wait_for(t, 200) for t in tasks], return_exceptions=True)
    print(f"\n{'STATUS':8} {'KOMPONEN':14} {'TARGET':28} DETAIL\n" + "-" * 100)
    bad = 0
    for r in results:
        if isinstance(r, Exception):
            r = (FAIL, "?", "-", explain(r))
        st, name, tgt, detail = r
        bad += st == FAIL
        print(f"[{st:^6}] {name:14} {tgt:28} {detail}")
    for w in config_warnings():
        print(f"[ CEK  ] Konfigurasi: {w}")
    print("-" * 100)
    print("SEMUA KONEKSI OK" if not bad else f"{bad} KOMPONEN GAGAL - perbaiki sesuai petunjuk di kolom DETAIL")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))