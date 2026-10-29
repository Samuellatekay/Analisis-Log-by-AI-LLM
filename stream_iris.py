#!/usr/bin/env python3
"""
stream_iris.py - Polling alert DFIR-IRIS -> list Redis (dibaca Logstash).

Alert baru di IRIS diambil detailnya lalu di-RPUSH ke list Redis (default `iris-alerts-out`).
Logstash membaca list itu dengan input `redis` (lihat logstash-iris-input.conf). Tidak ada port
yang dibuka, tidak ada server TCP/HTTP; pesan tetap aman di Redis walau Logstash sedang mati.

Jaminan:
  * Kursor (ID alert terbesar yang sudah terkirim) disimpan di Redis -> restart tidak mengirim ulang.
  * Alert yang gagal diambil detailnya dicoba lagi pada siklus berikutnya (urutan ID terjaga).
  * Antrean dibatasi (IRIS_STREAM_MAXLEN) agar Redis (noeviction) tidak penuh bila Logstash mati.
  * Hanya satu instance yang aktif (lock di Redis), aman walau service di-scale.
  * TLS ke IRIS diverifikasi (IRIS_CA_CERT / IRIS_VERIFY_SSL), sama seperti iris_client.py.

Hanya mendukung IRIS v3 (IRIS_API_VERSION=v2, path /api/v2/alerts).

Variabel lingkungan (selain IRIS_URL, IRIS_API_KEY, REDIS_URL yang sudah ada di .env):
  IRIS_STREAM_LIST=iris-alerts-out      list Redis tujuan (JANGAN dimasukkan ke REDIS_LISTS aplikasi)
  IRIS_POLL_INTERVAL=5                  jeda antar polling (detik)
  IRIS_REQUEST_TIMEOUT=30               timeout request ke IRIS (detik)
  IRIS_STREAM_PER_PAGE=100              ukuran halaman daftar alert
  IRIS_STREAM_MAX_PAGES=20              batas halaman yang dibaca per siklus
  IRIS_STREAM_MAXLEN=50000              panjang maksimum list tujuan (yang terlama dibuang)
  IRIS_STREAM_BACKFILL=0                saat pertama jalan, kirim N alert terbaru (0 = hanya yang baru)
  IRIS_STREAM_DETAIL_MAX_FAILS=5        setelah N siklus gagal ambil detail, kirim ringkasan saja
  IRIS_STREAM_ORDER=auto                auto | asc | desc (urutan daftar alert dari API IRIS)
  IRIS_STREAM_LIST_PARAMS=              query tambahan untuk daftar alert, mis. "sort=desc"

Endpoint HTTP read-only (opsional, untuk dilihat/di-poll dari luar; TIDAK memanggil IRIS):
  IRIS_STREAM_HTTP_PORT=0               0 = nonaktif; mis. 17771 untuk mengaktifkan
  IRIS_STREAM_HTTP_HOST=0.0.0.0         alamat bind di dalam container
  IRIS_STREAM_TOKEN=                    WAJIB bila HTTP aktif (header "Authorization: Bearer <token>" atau ?token=)
  IRIS_STREAM_HTTP_ALLOW_ANON=false     true = tanpa token (tidak disarankan)
  IRIS_STREAM_RECENT=500                jumlah alert terbaru yang disimpan untuk endpoint HTTP
  Endpoint:  GET /  atau /alerts[?since_id=N&limit=100]  -> JSON array;   GET /health -> status
"""
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import math
import os
import signal
import ssl
import sys
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping
from urllib.parse import parse_qs, parse_qsl, urlsplit

import httpx
import redis.asyncio as aioredis

log = logging.getLogger("iris-stream")

LIST_PATH = "/api/v2/alerts"
DETAIL_PATH = "/api/v2/alerts/{id}"
CURSOR_KEY = "iris-stream:last_id"
LOCK_KEY = "iris-stream:leader"
RETRY_STATUS = {429, 500, 502, 503, 504}


class StreamError(Exception):
    pass


# --------------------------------------------------------------------- konfigurasi
def _verify(env: Mapping[str, str]) -> bool | ssl.SSLContext:
    ca = env.get("IRIS_CA_CERT", "").strip()
    if ca:
        return ssl.create_default_context(cafile=ca)
    return env.get("IRIS_VERIFY_SSL", "true").strip().lower() == "true"


@dataclass(frozen=True)
class Config:
    iris_url: str
    api_key: str
    redis_url: str
    list_key: str = "iris-alerts-out"
    poll_s: float = 5.0
    timeout_s: float = 30.0
    per_page: int = 100
    max_pages: int = 20
    maxlen: int = 50000
    backfill: int = 0
    max_fails: int = 5
    order: str = "auto"
    extra_params: dict = field(default_factory=dict)
    retry_base_s: float = 1.0
    http_port: int = 0
    http_host: str = "0.0.0.0"
    token: str = ""
    allow_anon: bool = False
    recent_key: str = "iris-alerts-recent"
    recent_len: int = 500
    http_timeout_s: float = 5.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> "Config":
        url, key = env.get("IRIS_URL", "").strip().rstrip("/"), env.get("IRIS_API_KEY", "").strip()
        if not url or not key:
            raise StreamError("IRIS_URL dan IRIS_API_KEY wajib diisi")
        if env.get("IRIS_API_VERSION", "v2").strip().lower() != "v2":
            raise StreamError("stream_iris.py hanya mendukung IRIS_API_VERSION=v2 (IRIS v3)")
        order = env.get("IRIS_STREAM_ORDER", "auto").strip().lower()
        if order not in {"auto", "asc", "desc"}:
            raise StreamError("IRIS_STREAM_ORDER harus: auto | asc | desc")
        http_port = int(env.get("IRIS_STREAM_HTTP_PORT", "0") or 0)
        token = env.get("IRIS_STREAM_TOKEN", "").strip()
        allow_anon = env.get("IRIS_STREAM_HTTP_ALLOW_ANON", "false").strip().lower() == "true"
        if http_port and not token and not allow_anon:
            raise StreamError("IRIS_STREAM_HTTP_PORT diisi tetapi IRIS_STREAM_TOKEN kosong. Isi token "
                              "(mis. openssl rand -hex 24), atau set IRIS_STREAM_HTTP_ALLOW_ANON=true (tidak disarankan)")
        return cls(
            iris_url=url, api_key=key,
            http_port=http_port, token=token, allow_anon=allow_anon,
            http_host=env.get("IRIS_STREAM_HTTP_HOST", "0.0.0.0").strip() or "0.0.0.0",
            recent_len=max(10, int(env.get("IRIS_STREAM_RECENT", "500") or 500)),
            redis_url=env.get("REDIS_URL", "redis://localhost:6379/0"),
            list_key=env.get("IRIS_STREAM_LIST", "iris-alerts-out").strip() or "iris-alerts-out",
            poll_s=max(0.5, float(env.get("IRIS_POLL_INTERVAL", "5") or 5)),
            timeout_s=float(env.get("IRIS_REQUEST_TIMEOUT", "30") or 30),
            per_page=max(1, int(env.get("IRIS_STREAM_PER_PAGE", "100") or 100)),
            max_pages=max(1, int(env.get("IRIS_STREAM_MAX_PAGES", "20") or 20)),
            maxlen=max(100, int(env.get("IRIS_STREAM_MAXLEN", "50000") or 50000)),
            backfill=max(0, int(env.get("IRIS_STREAM_BACKFILL", "0") or 0)),
            max_fails=max(1, int(env.get("IRIS_STREAM_DETAIL_MAX_FAILS", "5") or 5)),
            order=order,
            extra_params=dict(parse_qsl(env.get("IRIS_STREAM_LIST_PARAMS", ""))),
        )


def build_http(cfg: Config, env: Mapping[str, str] = os.environ,
               transport: httpx.AsyncBaseTransport | None = None) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=cfg.iris_url, verify=_verify(env), transport=transport,
        timeout=httpx.Timeout(cfg.timeout_s, connect=5.0),
        headers={"Authorization": f"Bearer {cfg.api_key}", "Accept": "application/json"},
    )


# ------------------------------------------------------------------------- parsing
def _unwrap(j: Any) -> dict:
    if not isinstance(j, dict):
        return {}
    d = j.get("data")
    return d if isinstance(d, dict) and not isinstance(d.get("data"), list) else j


def _alert_id(item: Any) -> int | None:
    if not isinstance(item, dict):
        return None
    for key in ("alert_id", "id"):
        try:
            value = int(item[key])
        except (KeyError, TypeError, ValueError):
            continue
        if value > 0:
            return value
    return None


def parse_list(payload: Any) -> tuple[list[dict], dict]:
    """Respons daftar alert -> (item, metadata paginasi). Menerima list polos atau {data:[...], total, ...}."""
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)], {}
    if not isinstance(payload, dict):
        return [], {}
    meta, data = payload, payload.get("data")
    if isinstance(data, dict):                      # {"data": {"data": [...], "last_page": n}}
        meta, data = data, data.get("data")
    items = [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []
    return items, meta


def _last_page(meta: dict, per_page: int) -> int | None:
    for key in ("last_page", "pages", "total_pages"):
        try:
            value = int(meta[key])
            if value > 0:
                return value
        except (KeyError, TypeError, ValueError):
            pass
    try:
        total = int(meta["total"])
        return max(1, math.ceil(total / per_page))
    except (KeyError, TypeError, ValueError):
        return None


def build_payload(alert_id: int, detail: dict | None, summary: dict) -> dict:
    """Payload ringkas untuk Logstash. Dokumen asli (original, @timestamp, log_uuid) ada di
    alert_source_content yang dibuat iris_client.py; akar respons dipakai sebagai cadangan."""
    d = _unwrap(detail) if detail else {}
    source = d.get("alert_source_content")
    if isinstance(source, str):
        try:
            source = json.loads(source)
        except ValueError:
            source = {}
    source = source if isinstance(source, dict) else {}

    payload: dict[str, Any] = {
        "iris_alert_id": alert_id,
        "alert_title": d.get("alert_title") or summary.get("alert_title") or "",
        "alert_description": d.get("alert_description") or summary.get("alert_description") or "",
    }
    original = source.get("original", d.get("original"))
    if isinstance(original, dict):
        original = original.get("original") if isinstance(original.get("original"), str) \
            else json.dumps(original, ensure_ascii=False, default=str)
    if isinstance(original, str) and original:
        payload["original"] = original
    timestamp = (source.get("@timestamp") or d.get("@timestamp")
                 or d.get("alert_source_event_time") or d.get("alert_creation_time"))
    if timestamp:
        payload["@timestamp"] = timestamp
    log_uuid = source.get("log_uuid") or d.get("alert_source_ref")
    if log_uuid:
        payload["log_uuid"] = str(log_uuid)
    return payload


# -------------------------------------------------------------------------- streamer
class Streamer:
    def __init__(self, cfg: Config, http: httpx.AsyncClient, redis: aioredis.Redis):
        self.cfg, self.http, self.redis = cfg, http, redis
        self.stop = asyncio.Event()
        self.instance = f"{os.uname().nodename}-{uuid.uuid4().hex[:6]}"
        self.fails: dict[int, int] = {}
        self._http_slots = asyncio.Semaphore(20)

    async def _sleep(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self.stop.wait(), seconds)
        except asyncio.TimeoutError:
            pass

    # ---- HTTP
    async def _get(self, path: str, params: dict | None = None) -> httpx.Response:
        for attempt in range(3):
            try:
                response = await self.http.get(path, params=params)
            except (httpx.ConnectError, httpx.TimeoutException):
                if attempt == 2:
                    raise
                await self._sleep(self.cfg.retry_base_s * (1 + attempt))
                continue
            if response.status_code in RETRY_STATUS and attempt < 2:
                await self._sleep(self.cfg.retry_base_s * (1 + attempt))
                continue
            return response
        raise StreamError("tidak tercapai")

    async def fetch_page(self, page: int) -> tuple[list[dict], dict]:
        params = {"page": page, "per_page": self.cfg.per_page, **self.cfg.extra_params}
        response = await self._get(LIST_PATH, params)
        if response.status_code in (401, 403):
            raise StreamError(f"IRIS menolak akses (HTTP {response.status_code}): periksa IRIS_API_KEY / izin user")
        response.raise_for_status()
        try:
            return parse_list(response.json())
        except ValueError:
            raise StreamError("respons daftar alert bukan JSON (IRIS_URL salah / bukan IRIS v3?)") from None

    async def fetch_detail(self, alert_id: int) -> dict | None:
        """None bila alert sudah dihapus (404). Error lain -> exception (dicoba lagi nanti)."""
        response = await self._get(DETAIL_PATH.format(id=alert_id))
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()

    # ---- mencari alert baru
    def _is_desc(self, ids: list[int]) -> bool:
        if self.cfg.order != "auto":
            return self.cfg.order == "desc"
        return len(ids) < 2 or ids[0] >= ids[-1]

    def _has_next(self, page: int, items: list[dict], last_page: int | None) -> bool:
        return page < last_page if last_page else len(items) >= self.cfg.per_page

    async def collect_new(self, last_id: int, newest_only: bool = False) -> dict[int, dict]:
        """Alert dengan ID > last_id. newest_only: hanya halaman terbaru (untuk baseline awal)."""
        items, meta = await self.fetch_page(1)
        found: dict[int, dict] = {}

        def take(batch: list[dict]) -> int:
            lowest = 0
            for item in batch:
                alert_id = _alert_id(item)
                if alert_id is None:
                    continue
                lowest = alert_id if not lowest else min(lowest, alert_id)
                if alert_id > last_id:
                    found[alert_id] = item
            return lowest

        ids = [i for i in (_alert_id(x) for x in items) if i is not None]
        if not ids:
            return found
        last_page = _last_page(meta, self.cfg.per_page)
        desc = self._is_desc(ids)

        if desc:
            page, current = 1, items
            lowest = take(current)
            while (not newest_only and page < self.cfg.max_pages and lowest > last_id
                   and self._has_next(page, current, last_page)):
                page += 1
                current, _ = await self.fetch_page(page)
                if not current:
                    break
                lowest = take(current)
            return found

        # urutan naik: alert terbaru ada di halaman terakhir
        if last_page and last_page > 1:
            page, walked = last_page, 0
            while page >= 1 and walked < self.cfg.max_pages:
                current = items if page == 1 else (await self.fetch_page(page))[0]
                lowest = take(current)
                walked += 1
                if newest_only or page == 1 or (lowest and lowest <= last_id):
                    break
                page -= 1
            return found
        # urutan naik tanpa jumlah halaman: satu-satunya cara adalah memindai maju sampai habis
        page, current = 1, items
        take(current)
        while page < self.cfg.max_pages and self._has_next(page, current, last_page):
            page += 1
            current, _ = await self.fetch_page(page)
            if not current:
                break
            take(current)
        if page > 1 or self._has_next(page, current, last_page):
            log.warning("API IRIS mengurutkan alert menaik dan tanpa jumlah halaman: memindai %d halaman per siklus%s. "
                        "Set IRIS_STREAM_LIST_PARAMS (mis. sort=desc) bila API mendukungnya.", page,
                        " (TERPOTONG di IRIS_STREAM_MAX_PAGES; alert terbaru bisa terlewat)"
                        if self._has_next(page, current, last_page) else "")
        return found

    # ---- HTTP read-only (membaca Redis saja, tidak memanggil IRIS)
    @staticmethod
    def _response(status: int, body: bytes, head_only: bool = False,
                  ctype: str = "application/json; charset=utf-8", extra: str = "") -> bytes:
        reason = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 404: "Not Found",
                  405: "Method Not Allowed"}.get(status, "Error")
        head = (f"HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
                f"Cache-Control: no-store\r\nConnection: close\r\n{extra}\r\n").encode()
        return head if head_only else head + body

    def _authorized(self, headers: dict, query: dict) -> bool:
        if not self.cfg.token:
            return self.cfg.allow_anon
        supplied = headers.get("x-api-key", "")
        auth = headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            supplied = auth[7:].strip()
        supplied = supplied or (query.get("token") or [""])[0]
        return hmac.compare_digest(supplied.encode(), self.cfg.token.encode())

    async def _route(self, head: bytes) -> bytes:
        lines = head.decode("latin-1").split("\r\n")
        try:
            method, target, _ = lines[0].split(" ", 2)
        except ValueError:
            return self._response(400, b'{"error":"bad request"}')
        head_only = method == "HEAD"
        if method not in ("GET", "HEAD"):
            return self._response(405, b'{"error":"method not allowed"}', extra="Allow: GET, HEAD\r\n")
        headers = {k.strip().lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:]) if k}
        url = urlsplit(target)
        query = parse_qs(url.query)
        path = url.path.rstrip("/") or "/"
        if path == "/health":
            body = json.dumps({"status": "ok", "last_id": await self.redis.get(CURSOR_KEY),
                               "recent": await self.redis.llen(self.cfg.recent_key)}).encode()
            return self._response(200, body, head_only)
        if not self._authorized(headers, query):
            return self._response(401, b'{"error":"unauthorized"}', head_only,
                                  extra='WWW-Authenticate: Bearer realm="iris-stream"\r\n')
        if path not in ("/", "/alerts"):
            return self._response(404, b'{"error":"not found"}', head_only)
        try:
            since = int((query.get("since_id") or ["0"])[0])
            limit = min(self.cfg.recent_len, max(1, int((query.get("limit") or ["100"])[0])))
        except ValueError:
            return self._response(400, b'{"error":"since_id/limit harus angka"}', head_only)
        items = []
        for raw in await self.redis.lrange(self.cfg.recent_key, -self.cfg.recent_len, -1):
            try:
                item = json.loads(raw)
            except ValueError:
                continue
            if isinstance(item, dict) and int(item.get("iris_alert_id") or 0) > since:
                items.append(item)
        body = json.dumps(items[-limit:], ensure_ascii=False, indent=2, default=str).encode()
        return self._response(200, body, head_only)

    async def handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        async with self._http_slots:
            response = None
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.cfg.http_timeout_s)
                response = await self._route(head)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError,
                    ConnectionError, OSError):
                pass                                       # klien diam/rusak/menutup: cukup tutup koneksi
            except Exception:
                log.exception("Error HTTP")
                response = self._response(400, b'{"error":"internal"}')
            try:
                if response:
                    writer.write(response)
                    await writer.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                writer.close()

    async def start_http(self) -> asyncio.AbstractServer | None:
        if not self.cfg.http_port:
            return None
        try:
            server = await asyncio.start_server(self.handle_http, self.cfg.http_host,
                                                self.cfg.http_port, limit=16384)
        except OSError as exc:
            raise StreamError(f"Tidak bisa membuka {self.cfg.http_host}:{self.cfg.http_port}: {exc}") from exc
        log.info("HTTP read-only aktif di %s:%d (token %s)", self.cfg.http_host, self.cfg.http_port,
                 "diwajibkan" if self.cfg.token else "TIDAK ADA - terbuka untuk siapa saja")
        return server

    # ---- Redis
    async def am_leader(self) -> bool:
        ttl = max(15, int(self.cfg.poll_s * 3))
        holder = await self.redis.get(LOCK_KEY)
        if holder == self.instance:
            await self.redis.expire(LOCK_KEY, ttl)
            return True
        return bool(await self.redis.set(LOCK_KEY, self.instance, nx=True, ex=ttl))

    async def push(self, payload: dict, cursor: int | None) -> None:
        line = json.dumps(payload, ensure_ascii=False, default=str)
        pipe = self.redis.pipeline(transaction=True)
        pipe.rpush(self.cfg.list_key, line)
        pipe.ltrim(self.cfg.list_key, -self.cfg.maxlen, -1)
        if self.cfg.http_port:                            # salinan untuk endpoint HTTP (tidak ikut dikonsumsi Logstash)
            pipe.rpush(self.cfg.recent_key, line)
            pipe.ltrim(self.cfg.recent_key, -self.cfg.recent_len, -1)
        if cursor is not None:
            pipe.set(CURSOR_KEY, cursor)
        await pipe.execute()

    async def _payload_for(self, alert_id: int, summary: dict) -> dict | None:
        """Payload untuk satu alert; None = tunda ke siklus berikutnya; {} = lewati (alert dihapus)."""
        try:
            detail = await self.fetch_detail(alert_id)
        except (httpx.HTTPError, ValueError) as exc:
            count = self.fails[alert_id] = self.fails.get(alert_id, 0) + 1
            if count < self.cfg.max_fails:
                log.warning("Detail alert %s gagal (%s) percobaan %d/%d; dicoba lagi siklus berikutnya",
                            alert_id, type(exc).__name__, count, self.cfg.max_fails)
                return None
            log.error("Detail alert %s gagal %d kali; dikirim dengan data ringkasan saja", alert_id, count)
            self.fails.pop(alert_id, None)
            return build_payload(alert_id, None, summary)
        self.fails.pop(alert_id, None)
        if detail is None:
            log.info("Alert %s sudah dihapus di IRIS; dilewati", alert_id)
            return {}
        return build_payload(alert_id, detail, summary)

    async def poll_once(self) -> int:
        """Satu siklus. Mengembalikan jumlah alert yang dikirim."""
        raw = await self.redis.get(CURSOR_KEY)
        sent = 0
        if raw is None:                                   # jalan pertama: tentukan titik awal
            newest = await self.collect_new(0, newest_only=True)
            ids = sorted(newest)
            baseline = ids[-1] if ids else 0
            await self.redis.set(CURSOR_KEY, baseline)
            log.info("Jalan pertama: titik awal alert ID=%d (backfill=%d)", baseline, self.cfg.backfill)
            for alert_id in (ids[-self.cfg.backfill:] if self.cfg.backfill else []):
                payload = await self._payload_for(alert_id, newest[alert_id])
                if payload:
                    await self.push(payload, None)
                    sent += 1
            return sent

        last_id = int(raw)
        found = await self.collect_new(last_id)
        for alert_id in sorted(found):
            payload = await self._payload_for(alert_id, found[alert_id])
            if payload is None:
                break                                     # jaga urutan: ulangi dari ID ini nanti
            if payload:
                await self.push(payload, alert_id)
                sent += 1
            else:
                await self.redis.set(CURSOR_KEY, alert_id)
        if sent:
            log.info("%d alert dikirim ke list '%s'", sent, self.cfg.list_key)
        return sent

    async def run(self) -> None:
        log.info("Mulai: IRIS=%s list=%s interval=%.1fs instance=%s",
                 self.cfg.iris_url, self.cfg.list_key, self.cfg.poll_s, self.instance)
        server = await self.start_http()
        failures = 0
        while not self.stop.is_set():
            try:
                if await self.am_leader():
                    await self.poll_once()
                failures = 0
                delay = self.cfg.poll_s
            except asyncio.CancelledError:
                raise
            except StreamError as exc:
                failures += 1
                delay = min(60.0, self.cfg.poll_s * 2 ** min(failures, 5))
                log.error("%s (coba lagi %.0fs)", exc, delay)
            except Exception as exc:
                failures += 1
                delay = min(60.0, self.cfg.poll_s * 2 ** min(failures, 5))
                log.error("Polling gagal: %s: %s (coba lagi %.0fs)", type(exc).__name__, str(exc)[:200], delay)
            await self._sleep(delay)
        if server:
            server.close()
            await server.wait_closed()


# ------------------------------------------------------------------------------ main
async def amain() -> int:
    try:
        cfg = Config.from_env()
    except StreamError as exc:
        log.error("%s", exc)
        return 2
    http = build_http(cfg)
    redis = aioredis.from_url(cfg.redis_url, decode_responses=True, socket_connect_timeout=5,
                              health_check_interval=30, socket_keepalive=True)
    streamer = Streamer(cfg, http, redis)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, streamer.stop.set)
    try:
        await streamer.run()
    except StreamError as exc:
        log.error("%s", exc)
        return 2
    finally:
        await http.aclose()
        await redis.aclose()
    log.info("Berhenti.")
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    sys.exit(asyncio.run(amain()))