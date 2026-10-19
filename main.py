"""
main.py - Orchestrator Analisis_Log

Redis Stream/list -> hitung risk -> PostgreSQL (temp) -> Logstash -> DFIR-IRIS

Ketahanan terhadap burst:
- Redis Streams + consumer group (at-least-once, bisa scale horizontal, XAUTOCLAIM untuk pesan nyangkut)
- Pemrosesan per-batch (1 pipeline Redis, 1 executemany DB, 1 POST Logstash)
- Connection pool (asyncpg, httpx, redis)
- UUID deterministik (uuid5 dari ID pesan stream) => redelivery idempoten
- Dead-letter stream untuk pesan rusak / gagal kirim ke Logstash
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import os
import signal
import socket
import time
import uuid
from dataclasses import dataclass
from typing import Awaitable, Callable
from datetime import datetime, timezone

import asyncpg
import httpx
import orjson
import redis.asyncio as aioredis
from redis.exceptions import ResponseError

from iris_client import IrisClient
from normalizer import normalize
from risk_calculator import assess_event

try:
    import uvloop
except ImportError:  # opsional
    uvloop = None

log = logging.getLogger("analisis-log")
UUID_NS = uuid.UUID("6f1c2f0e-8c1e-4e0a-9d52-3b1f7a5e9c11")
LATENCY_BUDGET_S = 1.0


def _error_label(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP{exc.response.status_code}"
    public_message = getattr(exc, "public_message", None)
    if public_message:
        return str(public_message)[:200]
    return type(exc).__name__


# ----------------------------------------------------------------- Konfigurasi
def _e(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True)
class Settings:
    redis_url: str
    stream_key: str
    group: str
    dlq_key: str
    redis_mode: str
    redis_lists: tuple
    consumer_workers: int
    batch_size: int
    block_ms: int
    reclaim_idle_ms: int
    repeat_window_s: int
    pg_dsn: str
    pg_pool_min: int
    pg_pool_max: int
    retention_minutes: int
    retention_interval_s: int
    logstash_url: str
    logstash_user: str
    logstash_password: str
    logstash_timeout_s: float
    iris_min_risk: float
    iris_dedup_s: int
    iris_workers: int
    iris_queue_max: int
    iris_mode: str
    iris_case_min_risk: float
    iris_case_window_s: int
    risk_normalize: bool
    shutdown_grace_s: float

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            redis_url=_e("REDIS_URL", "redis://localhost:6379/0"),
            stream_key=_e("REDIS_STREAM", "logs:raw"),
            group=_e("REDIS_GROUP", "log-analyzer"),
            dlq_key=_e("REDIS_DLQ_STREAM", "logs:dlq"),
            redis_mode=_e("REDIS_MODE", "list").lower(),
            redis_lists=tuple(x.strip() for x in _e("REDIS_LISTS", "analysis-in").split(",") if x.strip()),
            consumer_workers=int(_e("CONSUMER_WORKERS", "2")),
            batch_size=int(_e("BATCH_SIZE", "200")),
            block_ms=int(_e("BLOCK_MS", "1000")),
            reclaim_idle_ms=int(_e("RECLAIM_IDLE_MS", "30000")),
            repeat_window_s=int(_e("REPEAT_WINDOW_S", "300")),
            pg_dsn=_e("POSTGRES_DSN", "postgresql://analyzer:analyzer@localhost:5432/analyzer"),
            pg_pool_min=int(_e("PG_POOL_MIN", "2")),
            pg_pool_max=int(_e("PG_POOL_MAX", "10")),
            retention_minutes=int(_e("RETENTION_MINUTES", "60")),
            retention_interval_s=int(_e("RETENTION_INTERVAL_S", "60")),
            logstash_url=_e("LOGSTASH_URL", "http://localhost:8080"),
            logstash_user=_e("LOGSTASH_USER", ""),
            logstash_password=_e("LOGSTASH_PASSWORD", ""),
            logstash_timeout_s=float(_e("LOGSTASH_TIMEOUT_S", "5")),
            iris_min_risk=float(_e("IRIS_MIN_RISK", "60")),
            iris_dedup_s=int(_e("IRIS_DEDUP_WINDOW_S", "300")),
            iris_workers=int(_e("IRIS_WORKERS", "1")),
            iris_queue_max=int(_e("IRIS_QUEUE_MAX", "500")),
            iris_mode=_e("IRIS_MODE", "alert").lower(),
            iris_case_min_risk=float(_e("IRIS_CASE_MIN_RISK", "75")),
            iris_case_window_s=int(_e("IRIS_CASE_WINDOW_S", "3600")),
            risk_normalize=_e("RISK_NORMALIZE", "false").lower() == "true",
            shutdown_grace_s=float(_e("SHUTDOWN_GRACE_S", "20")),
        )


# ------------------------------------------------------------------ Data model
@dataclass(slots=True)
class Record:
    msg_id: str
    log_uuid: uuid.UUID
    received_at: datetime
    log_day: str
    risk_score: float
    doc: dict


@dataclass(slots=True)
class Item:
    msg_id: str          # ID stream, atau hash konten (mode list) -> UUID deterministik
    source: str          # nama list/stream asal
    raw: str | None      # payload JSON mentah
    ts_ms: int | None    # waktu masuk Redis (hanya stream) untuk latensi e2e


SCHEMA_SQL = """
CREATE UNLOGGED TABLE IF NOT EXISTS log_events (
    log_uuid      UUID PRIMARY KEY,
    received_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    risk_score    REAL NOT NULL,
    payload       JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_log_events_received_at ON log_events (received_at);
ALTER TABLE log_events ADD COLUMN IF NOT EXISTS iris_alert_id INTEGER;
ALTER TABLE log_events ADD COLUMN IF NOT EXISTS iris_case_id INTEGER;
"""


def merge_enrichment(target: dict, event: dict) -> None:
    entity_type = str(event.get("entity_type") or "").lower()
    value = event.get("value")

    if entity_type in {"ipv4-addr", "ipv6-addr"}:
        reputation = event.get("reputation")
        if isinstance(reputation, dict):
            current = target.get("reputation")
            current = dict(current) if isinstance(current, dict) else {}
            current.update(reputation)
            if reputation.get("opencti_score") is not None:
                current["ioc_match"] = True
            target["reputation"] = current

        geolocation = event.get("geolocation")
        if isinstance(geolocation, dict):
            target["geolocation"] = geolocation

        asset_result = event.get("asset")
        asset_candidates: list[dict] = []
        if isinstance(asset_result, dict):
            items = asset_result.get("items")
            if isinstance(items, list):
                asset_candidates.extend(item for item in items if isinstance(item, dict))
            elif any(asset_result.get(k) is not None for k in (
                "name", "ip", "owner", "serial_number", "operating_system", "status"
            )):
                asset_candidates.append(asset_result)
        elif isinstance(asset_result, list):
            asset_candidates.extend(item for item in asset_result if isinstance(item, dict))

        glpi_asset = next(
            (
                item for item in asset_candidates
                if any(item.get(k) not in (None, "") for k in (
                    "name", "ip", "owner", "serial_number", "operating_system", "status"
                ))
            ),
            None,
        )
        side_ips = {}
        for side_name in ("source", "destination"):
            side = target.get(side_name)
            side = side if isinstance(side, dict) else {}
            side_ip = side.get("ip")
            if isinstance(side_ip, str):
                try:
                    side_ips[side_name] = str(ipaddress.ip_address(side_ip))
                except ValueError:
                    pass

        matched_sides = [side for side, side_ip in side_ips.items() if side_ip == value]
        if not matched_sides and not side_ips and isinstance(value, str):
            matched_sides = ["source"]

        if glpi_asset:
            glpi_details = {
                key: glpi_asset[key]
                for key in ("name", "ip", "owner", "user", "serial_number",
                            "operating_system", "status", "location", "type")
                if glpi_asset.get(key) not in (None, "")
            }
            side_asset = {"found": True, "inventory_source": "GLPI", **glpi_details}
        elif isinstance(asset_result, dict) and asset_result.get("found") is False:
            side_asset = {
                "found": False,
                "ip": value,
                "error": asset_result.get("error"),
            }
        else:
            side_asset = None

        for side_name in matched_sides:
            side = target.get(side_name)
            side = dict(side) if isinstance(side, dict) else {}
            side["ip"] = value
            if side_asset is not None:
                side["asset"] = side_asset
            target[side_name] = side

        if glpi_asset and "source" in matched_sides:
            asset = target.get("asset")
            asset = dict(asset) if isinstance(asset, dict) else {}
            host = target.get("host")
            host_name = host.get("name") if isinstance(host, dict) else None
            if host_name and host_name != glpi_asset.get("name"):
                asset["agent_name"] = host_name
            asset.update(glpi_details)
            asset["inventory_source"] = "GLPI"
            target["asset"] = asset

    elif entity_type == "domain-name" and value:
        domain = target.get("domain")
        domain = dict(domain) if isinstance(domain, dict) else {}
        domain["name"] = value
        age = event.get("domain_age")
        if isinstance(age, dict):
            domain.update(age)
        target["domain"] = domain

    section = target.get("enrichment")
    if not isinstance(section, dict):
        section = {}
        target["enrichment"] = section
    observables = section.get("observables")
    if not isinstance(observables, list):
        observables = []
        section["observables"] = observables
    entry = {
        key: event[key]
        for key in (
            "entity_type", "value", "file_hash", "reputation",
            "geolocation", "asset", "domain_age", "opencti",
        )
        if event.get(key) is not None
    }
    identity = (entry.get("entity_type"), entry.get("value"))
    for index, existing in enumerate(observables):
        if isinstance(existing, dict) and (
            existing.get("entity_type"), existing.get("value")
        ) == identity:
            observables[index] = entry
            return
    observables.append(entry)


def normalize_ioc_value(entity_type: str, value: str) -> str:
    normalized = value.strip()
    kind = entity_type.lower()
    if kind in {"ipv4-addr", "ipv6-addr"}:
        address = ipaddress.ip_address(normalized)
        expected_version = 4 if kind == "ipv4-addr" else 6
        if address.version != expected_version:
            raise ValueError(f"{entity_type} has an address of the wrong IP version")
        return str(address)
    if kind == "stixfile":
        return normalized.lower()
    return normalized


# -------------------------------------------------------------------- Database
class Database:
    def __init__(self, s: Settings):
        self.s = s
        self.pool: asyncpg.Pool | None = None

    async def start(self) -> None:
        for attempt in range(10):  # tunggu DB siap
            try:
                self.pool = await asyncpg.create_pool(
                    self.s.pg_dsn, min_size=self.s.pg_pool_min,
                    max_size=self.s.pg_pool_max, command_timeout=10)
                break
            except (OSError, asyncpg.PostgresError) as exc:
                log.warning("DB belum siap (%s), retry %d", type(exc).__name__, attempt + 1)
                await asyncio.sleep(2)
        else:
            raise RuntimeError("Tidak bisa terhubung ke PostgreSQL")
        async with self.pool.acquire() as conn:
            await conn.execute(SCHEMA_SQL)

    async def insert_many(self, records: list[Record]) -> list[Record]:
        """Insert batch. Baris yang ditolak PostgreSQL (DataError) dikembalikan -> DLQ,
        agar satu payload aneh tidak membuat seluruh batch gagal selamanya."""
        sql = ("INSERT INTO log_events (log_uuid, received_at, risk_score, payload) "
               "VALUES ($1,$2,$3,$4::jsonb) ON CONFLICT (log_uuid) DO NOTHING")
        rows = [(r.log_uuid, r.received_at, r.risk_score,
                 orjson.dumps(r.doc).decode().replace("\\u0000", "")) for r in records]
        async with self.pool.acquire() as conn:
            try:
                await conn.executemany(sql, rows)
                return []
            except asyncpg.exceptions.DataError:
                pass
            failed = []
            for r, row in zip(records, rows):
                try:
                    await conn.execute(sql, *row)
                except asyncpg.exceptions.DataError:
                    failed.append(r)
            return failed

    async def attach_enrichment(self, event: dict, retention_minutes: int) -> list[Record]:
        """Attach one IOC enrichment event to matching recent Wazuh alerts."""
        entity_type = str(event.get("entity_type") or "").lower()
        value = normalize_ioc_value(entity_type, str(event.get("value") or ""))
        if not value:
            return []

        ip_value = value if entity_type in {"ipv4-addr", "ipv6-addr"} else None
        file_hash = event.get("file_hash") if isinstance(event.get("file_hash"), dict) else {}
        hash_value = str(file_hash.get("value") or value).strip().lower() if entity_type == "stixfile" else None
        query = """
            SELECT log_uuid, received_at, risk_score, payload
            FROM log_events
            WHERE received_at >= now() - make_interval(mins => $5)
              AND payload->>'data_source' = 'wazuh'
              AND (
                ($1::text IS NOT NULL AND (
                    payload #>> '{source,ip}' = $1
                    OR payload #>> '{destination,ip}' = $6
                ))
                OR ($2::text IS NOT NULL AND payload #>> '{file,hash,md5}' = $2)
                OR ($3::text IS NOT NULL AND payload #>> '{file,hash,sha1}' = $3)
                OR ($4::text IS NOT NULL AND (
                    payload #>> '{file,hash,sha256}' = $4
                    OR payload #>> '{file,hash,sha512}' = $4
                ))
              )
            ORDER BY received_at DESC
            LIMIT 500
            FOR UPDATE
        """
        hash_args = [None, None, None]
        if hash_value:
            algorithm = str(file_hash.get("algorithm") or "").lower().replace("-", "")
            hash_indexes = {"md5": 0, "sha1": 1, "sha256": 2, "sha512": 2}
            if algorithm in hash_indexes:
                hash_args[hash_indexes[algorithm]] = hash_value

        records: list[Record] = []
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                rows = await conn.fetch(
                    query, ip_value, hash_args[0], hash_args[1], hash_args[2],
                    retention_minutes, ip_value
                )
                for row in rows:
                    payload = row["payload"]
                    if isinstance(payload, str):
                        payload = orjson.loads(payload)
                    if not isinstance(payload, dict):
                        continue

                    merge_enrichment(payload, event)
                    encoded = orjson.dumps(payload).decode().replace("\\u0000", "")
                    await conn.execute(
                        "UPDATE log_events SET payload=$2::jsonb WHERE log_uuid=$1",
                        row["log_uuid"], encoded,
                    )
                    log_day = payload.get("log_day") or row["received_at"].strftime("%Y.%m.%d")
                    records.append(Record(
                        msg_id=f"enrichment:{event.get('id') or value}:{row['log_uuid']}",
                        log_uuid=row["log_uuid"],
                        received_at=row["received_at"],
                        log_day=log_day,
                        risk_score=float(row["risk_score"]),
                        doc=payload,
                    ))
        return records

    async def set_iris(self, log_uuid: uuid.UUID, alert_id: int | None, case_id: int | None) -> None:
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE log_events SET iris_alert_id=COALESCE($2::int, iris_alert_id), "
                "iris_case_id=COALESCE($3::int, iris_case_id) WHERE log_uuid=$1",
                log_uuid, alert_id, case_id)

    async def get_iris_ids(self, log_uuid: uuid.UUID) -> tuple[int | None, int | None]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT iris_alert_id, iris_case_id FROM log_events WHERE log_uuid=$1",
                log_uuid,
            )
        return (row["iris_alert_id"], row["iris_case_id"]) if row else (None, None)

    async def purge_old(self, minutes: int) -> int:
        """Retensi: hapus log yang umurnya > N menit (default 60)."""
        async with self.pool.acquire() as conn:
            res = await conn.execute(
                "DELETE FROM log_events WHERE received_at < now() - make_interval(mins => $1)", minutes)
        return int(res.split()[-1])

    async def close(self) -> None:
        if self.pool:
            await self.pool.close()


# -------------------------------------------------------------------- Logstash
class LogstashClient:
    """Logstash http input (codec json): array JSON dipecah menjadi banyak event."""

    def __init__(self, s: Settings):
        auth = (s.logstash_user, s.logstash_password) if s.logstash_user else None
        self._client = httpx.AsyncClient(
            base_url=s.logstash_url, auth=auth,
            timeout=httpx.Timeout(s.logstash_timeout_s, connect=2.0),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10))

    async def send(self, docs: list[dict], attempts: int = 3) -> bool:
        body = orjson.dumps(docs)
        for i in range(attempts):
            try:
                r = await self._client.post("/", content=body,
                                            headers={"Content-Type": "application/json"})
                if r.status_code < 300:
                    return True
                if r.status_code < 500 and r.status_code != 429:
                    log.error("Logstash menolak payload: HTTP %s", r.status_code)
                    return False
            except httpx.HTTPError as exc:
                log.warning("Logstash error (%s) percobaan %d", type(exc).__name__, i + 1)
            await asyncio.sleep(min(0.2 * 2 ** i, 2.0))
        return False

    async def aclose(self) -> None:
        await self._client.aclose()


# ------------------------------------------------------------------------- App
class App:
    def __init__(self, s: Settings):
        self.s = s
        self.stop = asyncio.Event()
        self.db = Database(s)
        self.logstash = LogstashClient(s)
        self.redis = aioredis.from_url(s.redis_url, decode_responses=True, max_connections=50,
                                       health_check_interval=30, socket_keepalive=True,
                                       socket_connect_timeout=5)
        if s.iris_mode not in ("alert", "alert_case", "case"):
            raise ValueError("IRIS_MODE harus: alert | alert_case | case")
        self.iris = IrisClient.from_env(os.environ)  # None jika IRIS_ENABLED!=true
        self.iris_queue: asyncio.Queue = asyncio.Queue(maxsize=s.iris_queue_max)
        self._host = socket.gethostname()

    # ---- lifecycle
    async def run(self) -> None:
        s = self.s
        await self.db.start()
        await self._wait_redis()
        if s.redis_mode == "list":
            ver = (await self.redis.info("server")).get("redis_version", "0")
            if tuple(int(x) for x in ver.split(".")[:2]) < (6, 2):
                raise RuntimeError(f"Redis {ver}: mode list butuh >= 6.2 (BLMOVE)")
        else:
            await self._ensure_group()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self.stop.set)

        iris_tasks = [asyncio.create_task(self._iris_worker()) for _ in range(s.iris_workers if self.iris else 0)]
        loops = [asyncio.create_task(self._consumer_loop(f"{self._host}-{os.getpid()}-{i}", src))
                 for src in self._sources() for i in range(s.consumer_workers)]
        loops += [asyncio.create_task(self._reclaim_loop()), asyncio.create_task(self._retention_loop())]
        log.info("Started: mode=%s sources=%s, %d worker/sumber, %d worker IRIS",
                 s.redis_mode, self._sources(), s.consumer_workers,
                 s.iris_workers if self.iris else 0)

        await self.stop.wait()
        log.info("Shutdown: menghentikan consumer...")
        await asyncio.gather(*loops, return_exceptions=True)
        try:
            await asyncio.wait_for(self.iris_queue.join(), s.shutdown_grace_s)
        except asyncio.TimeoutError:
            log.warning("Antrean IRIS belum kosong (%d)", self.iris_queue.qsize())
        for t in iris_tasks:
            t.cancel()
        await asyncio.gather(*iris_tasks, return_exceptions=True)
        await asyncio.gather(self.logstash.aclose(), self.db.close(),
                             *([self.iris.aclose()] if self.iris else []),
                             self.redis.aclose(), return_exceptions=True)

    async def _wait_redis(self) -> None:
        for attempt in range(1, 11):
            try:
                await self.redis.ping()
                return
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("Redis belum bisa dihubungi (%s) percobaan %d/10. Cek REDIS_URL (IP/port/password), "
                            "firewall, dan 'bind' di redis.conf", type(exc).__name__, attempt)
                await asyncio.sleep(3)
        raise RuntimeError("Tidak bisa terhubung ke Redis; periksa REDIS_URL dan firewall")

    async def _ensure_group(self) -> None:
        try:
            await self.redis.xgroup_create(self.s.stream_key, self.s.group, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def _sleep(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self.stop.wait(), seconds)
        except asyncio.TimeoutError:
            pass

    # ---- ingestion
    def _sources(self) -> list[str]:
        if self.s.redis_mode != "list":
            return [self.s.stream_key]
        return list(dict.fromkeys((*self.s.redis_lists, "enrichment-events")))

    async def _consumer_loop(self, name: str, src: str) -> None:
        s, backoff = self.s, 0.5
        proc, lease = f"{src}:processing:{name}", f"{src}:lease:{name}"
        while not self.stop.is_set():
            try:
                if s.redis_mode == "list":
                    await self.redis.set(lease, "1", ex=60)  # tanda "worker ini masih hidup"
                    items = await self._fetch_list(src, proc)
                    if items:
                        try:
                            await self._handle_batch(items, lambda: self.redis.delete(proc))
                        except Exception:
                            n = await self._requeue(proc, src)  # kembalikan ke antrean, jangan hilang
                            log.warning("Batch gagal; %d item dikembalikan ke %s", n, src)
                            raise
                else:
                    resp = await self.redis.xreadgroup(s.group, name, {src: ">"},
                                                       count=s.batch_size, block=s.block_ms)
                    if resp:
                        items = self._stream_items(resp[0][1], src)
                        await self._handle_batch(items, self._stream_ack(items))
                backoff = 0.5
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Consumer %s/%s error", src, name)
                await self._sleep(backoff)
                backoff = min(backoff * 2, 5.0)

    async def _fetch_list(self, src: str, proc: str) -> list[Item]:
        """Pop andal: pindahkan atomik list -> processing list (BLMOVE/LMOVE), bukan BLPOP,
        sehingga data tidak hilang jika proses mati di tengah jalan."""
        first = await self.redis.blmove(src, proc, max(1, self.s.block_ms // 1000), "LEFT", "RIGHT")
        if first is None:
            return []
        raws = [first]
        if self.s.batch_size > 1:
            pipe = self.redis.pipeline(transaction=False)
            for _ in range(self.s.batch_size - 1):
                pipe.lmove(src, proc, "LEFT", "RIGHT")
            raws += [r for r in await pipe.execute() if r is not None]
        return [Item(hashlib.sha256(f"{src}\0{raw}".encode()).hexdigest(), src, raw, None) for raw in raws]

    async def _requeue(self, proc: str, src: str) -> int:
        n = 0
        while await self.redis.lmove(proc, src, "RIGHT", "LEFT") is not None:  # urutan asli terjaga
            n += 1
        return n

    @staticmethod
    def _stream_items(entries: list, src: str) -> list[Item]:
        out = []
        for msg_id, fields in entries:
            try:
                ts = int(msg_id.split("-")[0])
            except ValueError:
                ts = None
            out.append(Item(msg_id, src, (fields or {}).get("data"), ts))
        return out

    def _stream_ack(self, items: list[Item]) -> Callable[[], Awaitable]:
        ids = [i.msg_id for i in items]
        return lambda: self.redis.xack(self.s.stream_key, self.s.group, *ids)

    async def _reclaim_loop(self) -> None:
        """Mode stream: XAUTOCLAIM pesan pending. Mode list: kembalikan processing list
        milik worker yang sudah mati (lease habis)."""
        s = self.s
        while not self.stop.is_set():
            await self._sleep(s.reclaim_idle_ms / 2000)
            try:
                if s.redis_mode == "list":
                    await self._reclaim_lists()
                else:
                    await self._reclaim_stream()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Reclaim error")

    async def _reclaim_lists(self) -> None:
        for src in self._sources():
            async for key in self.redis.scan_iter(match=f"{src}:processing:*", count=100):
                name = key.rsplit(":", 1)[1]
                if await self.redis.exists(f"{src}:lease:{name}"):
                    continue  # worker masih hidup
                n = await self._requeue(key, src)
                if n:
                    log.warning("Reclaim: %d item dari worker mati (%s) dikembalikan ke %s", n, name, src)

    async def _reclaim_stream(self) -> None:
        s, name = self.s, f"{self._host}-{os.getpid()}-reclaim"
        cursor = "0-0"
        while not self.stop.is_set():
            res = await self.redis.xautoclaim(s.stream_key, s.group, name,
                                              min_idle_time=s.reclaim_idle_ms,
                                              start_id=cursor, count=s.batch_size)
            cursor, entries = res[0], [e for e in res[1] if e and e[1]]
            if entries:
                log.info("Reclaim %d pesan pending", len(entries))
                items = self._stream_items(entries, s.stream_key)
                await self._handle_batch(items, self._stream_ack(items))
            if cursor in ("0-0", b"0-0") or not res[1]:
                break

    async def _handle_batch(self, items: list[Item], ack: Callable[[], Awaitable]) -> None:
        if items and all(item.source == "enrichment-events" for item in items):
            await self._handle_enrichment_batch(items, ack)
            return

        s, t0 = self.s, time.perf_counter()
        parsed: list[tuple[Item, dict]] = []
        dlq: list[tuple[str, str, str]] = []  # (msg_id, reason, payload)
        for it in items:
            try:
                if it.raw is None:
                    raise ValueError("payload kosong")
                data = orjson.loads(it.raw)
                if not isinstance(data, dict):
                    raise ValueError("payload bukan objek")
                parsed.append((it, normalize(it.source, data)))
            except Exception as exc:
                dlq.append((it.msg_id, f"parse_error:{type(exc).__name__}", (it.raw or "")[:20000]))

        records_ok: list[Record] = []
        sent_s = 0.0
        if parsed:
            await self._apply_cached_enrichment(parsed)
            extras = await self._enrich([d for _, d in parsed])
            now = datetime.now(timezone.utc)
            records = [self._build_record(it.msg_id, data, repeat, crit, now)
                       for (it, data), (repeat, crit) in zip(parsed, extras)]
            # Error koneksi DB -> exception -> batch dikembalikan & diulang (idempoten)
            rejected = {r.msg_id for r in await self.db.insert_many(records)}
            for r in records:
                if r.msg_id in rejected:
                    dlq.append((r.msg_id, "db_rejected", orjson.dumps(r.doc).decode()))
            records = [r for r in records if r.msg_id not in rejected]
            accepted_data = [data for item, data in parsed if item.msg_id not in rejected]
            if accepted_data:
                await self._queue_glpi_asset_lookups(accepted_data)
            ok = await self.logstash.send([r.doc for r in records]) if records else True
            sent_s = time.perf_counter() - t0
            if not ok:
                for r in records:
                    dlq.append((r.msg_id, "logstash_failed", orjson.dumps(r.doc).decode()))
                log.error("Logstash tidak tersedia; %d alert tetap diteruskan ke antrean IRIS",
                          len(records))
            records_ok = records

        if dlq:
            await self._send_dlq(dlq)
        await ack()

        if records_ok:
            self._enqueue_iris(records_ok)
            ts = [i.ts_ms for i in items if i.ts_ms]
            e2e = f" e2e_max={(time.time() * 1000 - min(ts)) / 1000:.3f}s" if ts else ""
            level = logging.WARNING if sent_s > LATENCY_BUDGET_S else logging.DEBUG
            log.log(level, "batch=%d proses+kirim=%.3fs%s iris_queue=%d",
                    len(records_ok), sent_s, e2e, self.iris_queue.qsize())

    @staticmethod
    def _enrichment_cache_key(entity_type: str, value: str) -> str:
        normalized_type = entity_type.lower()
        normalized_value = normalize_ioc_value(normalized_type, value)
        identity = f"{normalized_type}\0{normalized_value}"
        return f"analysis:enrichment:{hashlib.sha256(identity.encode()).hexdigest()}"

    async def _handle_enrichment_batch(
        self, items: list[Item], ack: Callable[[], Awaitable]
    ) -> None:
        parsed: list[tuple[Item, dict]] = []
        dlq: list[tuple[str, str, str]] = []
        for item in items:
            try:
                if item.raw is None:
                    raise ValueError("payload kosong")
                event = orjson.loads(item.raw)
                if not isinstance(event, dict):
                    raise ValueError("payload bukan objek")
                entity_type = event.get("entity_type")
                value = event.get("value")
                if not entity_type or not value:
                    raise ValueError("enrichment harus memiliki entity_type dan value")
                event["value"] = normalize_ioc_value(str(entity_type), str(value))
                parsed.append((item, event))
            except Exception as exc:
                dlq.append((item.msg_id, f"enrichment_parse_error:{type(exc).__name__}",
                            (item.raw or "")[:20000]))

        matched: dict[uuid.UUID, Record] = {}
        for _, event in parsed:
            cache_key = self._enrichment_cache_key(event["entity_type"], str(event["value"]))
            await self.redis.set(
                cache_key,
                orjson.dumps(event).decode(),
                ex=max(86400, self.s.retention_minutes * 60),
            )
            for record in await self.db.attach_enrichment(event, self.s.retention_minutes):
                matched[record.log_uuid] = record

        records = list(matched.values())
        if records:
            if not await self.logstash.send([record.doc for record in records]):
                for record in records:
                    dlq.append((record.msg_id, "logstash_enrichment_failed",
                                orjson.dumps(record.doc).decode()))
                log.error("Logstash tidak tersedia; %d alert hasil enrichment tetap "
                          "diteruskan ke antrean IRIS", len(records))
            self._enqueue_iris(records)
            log.info("Enrichment dicocokkan ke %d alert", len(records))
        elif parsed:
            log.info("Enrichment disimpan untuk pencocokan; alert terkait belum ditemukan")

        if dlq:
            await self._send_dlq(dlq)
        await ack()

    @staticmethod
    def _alert_iocs(data: dict) -> list[tuple[str, str]]:
        iocs: set[tuple[str, str]] = set()
        for side_name in ("source", "destination"):
            side = data.get(side_name) if isinstance(data.get(side_name), dict) else {}
            side_ip = side.get("ip")
            if isinstance(side_ip, str):
                try:
                    parsed_ip = ipaddress.ip_address(side_ip)
                    entity_type = "IPv4-Addr" if parsed_ip.version == 4 else "IPv6-Addr"
                    iocs.add((entity_type, str(parsed_ip)))
                except ValueError:
                    pass

        file_data = data.get("file") if isinstance(data.get("file"), dict) else {}
        hashes = file_data.get("hash") if isinstance(file_data.get("hash"), dict) else {}
        for value in hashes.values():
            if isinstance(value, str) and value.strip():
                iocs.add(("StixFile", value.strip().lower()))
        return sorted(iocs)

    async def _apply_cached_enrichment(self, parsed: list[tuple[Item, dict]]) -> None:
        lookups: list[tuple[dict, str]] = []
        pipe = self.redis.pipeline(transaction=False)
        for _, data in parsed:
            if data.get("data_source") != "wazuh":
                continue
            for entity_type, value in self._alert_iocs(data):
                key = self._enrichment_cache_key(entity_type, value)
                lookups.append((data, key))
                pipe.get(key)
        if not lookups:
            return
        cached_events = await pipe.execute()
        for (data, _), raw_event in zip(lookups, cached_events):
            if raw_event:
                merge_enrichment(data, orjson.loads(raw_event))

    async def _queue_glpi_asset_lookups(self, events: list[dict]) -> None:
        """Queue GLPI and OpenCTI lookups for Wazuh source and destination IPs."""
        for event in events:
            if event.get("data_source") != "wazuh":
                continue
            addresses = set()
            for side_name in ("source", "destination"):
                side = event.get(side_name) if isinstance(event.get(side_name), dict) else {}
                value = side.get("ip")
                if not isinstance(value, str):
                    continue
                try:
                    addresses.add(ipaddress.ip_address(value))
                except ValueError:
                    continue

            for address in sorted(addresses, key=lambda item: (item.version, int(item))):
                ip = str(address)
                entity_type = "IPv4-Addr" if address.version == 4 else "IPv6-Addr"
                cache_key = self._enrichment_cache_key(entity_type, ip)
                cached = await self.redis.get(cache_key)
                if cached:
                    try:
                        cached_event = orjson.loads(cached)
                    except orjson.JSONDecodeError:
                        cached_event = {}
                    asset = cached_event.get("asset") if isinstance(cached_event, dict) else None
                    asset_cached = isinstance(asset, dict) and asset.get("found") and asset.get("items")
                else:
                    asset_cached = False

                if not asset_cached:
                    lookup_key = f"analysis:glpi-lookup:{ip}"
                    if await self.redis.set(lookup_key, "1", nx=True, ex=300):
                        request = {"action": "lookup_asset", "ip": ip,
                                   "entity_type": entity_type}
                        try:
                            await self.redis.rpush("outbound-glpi", orjson.dumps(request).decode())
                            log.info("GLPI asset lookup queued ip=%s", ip)
                        except Exception:
                            await self.redis.delete(lookup_key)
                            log.exception("Gagal mengantrekan pencarian aset GLPI untuk IP %s", ip)

                opencti_key = f"analysis:opencti-enrichment:{ip}"
                if await self.redis.set(opencti_key, "1", nx=True, ex=300):
                    request = {"action": "lookup_enrichment", "ip": ip,
                               "entity_type": entity_type}
                    try:
                        await self.redis.rpush("outbound-opencti", orjson.dumps(request).decode())
                        log.info("OpenCTI connector lookup queued ip=%s", ip)
                    except Exception:
                        await self.redis.delete(opencti_key)
                        log.exception("Gagal mengantrekan lookup connector OpenCTI untuk IP %s", ip)

    async def _enrich(self, events: list[dict]) -> list[tuple[int, float | None]]:
        """1 pipeline Redis per batch: counter pengulangan (+ fallback asset criticality)."""
        s = self.s
        pipe = self.redis.pipeline(transaction=False)
        need_asset: list[bool] = []
        for d in events:
            pipe.incr(self._repeat_key(d))
            pipe.expire(self._repeat_key(d), s.repeat_window_s)
            asset = d.get("asset") if isinstance(d.get("asset"), dict) else {}
            host = (d.get("host") or {}).get("name") if isinstance(d.get("host"), dict) else None
            need = asset.get("criticality") is None and bool(host or asset.get("id"))
            if need:
                pipe.hget(f"asset:{asset.get('id') or host}", "criticality")
            need_asset.append(need)
        res = await pipe.execute()
        out, i = [], 0
        for need in need_asset:
            repeat = int(res[i]); i += 2
            crit = None
            if need:
                try:
                    crit = float(res[i]) if res[i] is not None else None
                except (TypeError, ValueError):
                    crit = None
                i += 1
            out.append((repeat, crit))
        return out

    @staticmethod
    def _repeat_key(d: dict) -> str:
        src = d.get("source") if isinstance(d.get("source"), dict) else {}
        ev = d.get("event") if isinstance(d.get("event"), dict) else {}
        host = d.get("host") if isinstance(d.get("host"), dict) else {}
        who = str(src.get("ip") or host.get("name") or "unknown")[:80]
        what = str(ev.get("action") or ev.get("category") or "unknown")[:80]
        return f"repeat:{who}:{what}"

    def _build_record(self, msg_id: str, data: dict, repeat: int, crit: float | None,
                      now: datetime) -> Record:
        risk = assess_event(data, repeat, crit, self.s.risk_normalize)
        log_uuid = uuid.uuid5(UUID_NS, msg_id)  # deterministik => idempoten
        ev = data.get("event") if isinstance(data.get("event"), dict) else {}
        log_day = now.strftime("%Y.%m.%d")
        doc = {
            "event_type": "raw",
            "log_uuid": str(log_uuid),
            "log_day": log_day,
            "@timestamp": data.get("@timestamp") or now.isoformat(),
            "event": {k: ev.get(k) for k in ("action", "category", "severity", "outcome", "wazuh_level", "rule_id") if k in ev},
            "data_source": data.get("data_source"),
            "source": data.get("source"),
            "agent": data.get("agent"),
            "host": data.get("host"),
            "original": data.get("original"),
            "reputation": data.get("reputation"),
            "geolocation": data.get("geolocation"),
            "asset": data.get("asset"),
            "domain": data.get("domain"),
            "enrichment": data.get("enrichment"),
            "risk": {**risk.as_dict(), "repeat_count": repeat},
        }
        for k in ("destination", "file"):  # opsional dari normalizer (mis. Wazuh dstip / hash syscheck)
            if data.get(k):
                doc[k] = data[k]
        return Record(msg_id, log_uuid, now, log_day, risk.score, doc)

    async def _send_dlq(self, items: list[tuple[str, str, str]]) -> None:
        pipe = self.redis.pipeline(transaction=False)
        for msg_id, reason, payload in items:
            pipe.xadd(self.s.dlq_key, {"msg_id": msg_id, "reason": reason, "data": payload},
                      maxlen=100_000, approximate=True)
        await pipe.execute()
        log.error("%d pesan dikirim ke DLQ (%s)", len(items), self.s.dlq_key)

    # ---- DFIR-IRIS
    def _enqueue_iris(self, records: list[Record]) -> None:
        for record in records:
            self._to_iris(record)

    def _to_iris(self, r: Record) -> None:
        if r.doc.get("data_source") in {"opencti", "glpi"}:
            return  # threat-intel and collector feedback enrich alerts; they are not alerts
        if not self.iris or r.risk_score < self.s.iris_min_risk or not self.iris.allows(r.doc):
            return
        try:
            self.iris_queue.put_nowait(r)
        except asyncio.QueueFull:
            log.warning("Antrean IRIS penuh; alert %s tidak dikirim", r.log_uuid)

    @staticmethod
    def _who(doc: dict) -> str:
        src = doc.get("source") if isinstance(doc.get("source"), dict) else {}
        asset = doc.get("asset") if isinstance(doc.get("asset"), dict) else {}
        return str(src.get("ip") or asset.get("name") or "unknown")[:80]

    @classmethod
    def _dedup_key(cls, doc: dict) -> str:
        ev = doc.get("event") if isinstance(doc.get("event"), dict) else {}
        what = str(ev.get("action") or ev.get("category") or "unknown")[:80]
        return f"iris:dedup:{cls._who(doc)}:{what}"

    async def _case_for(self, r: Record, alert_id: int) -> int | None:
        """Alert risk tinggi -> case. Alert dari sumber yang sama dalam jendela waktu digabung
        ke case yang sudah ada (bukan membuat case baru tiap alert)."""
        who = self._who(r.doc)
        case_key, lock = f"iris:case:{who}", f"iris:case-lock:{who}"
        got_lock = False
        try:
            got_lock = bool(await self.redis.set(lock, "1", nx=True, ex=30))
            if not got_lock:
                await asyncio.sleep(1.5)  # worker lain sedang membuat case untuk sumber ini
            existing = await self.redis.get(case_key)
            if existing:
                try:
                    await self.iris.merge_alert(alert_id, int(existing), r.doc)
                    return int(existing)
                except httpx.HTTPStatusError:  # mis. case sudah ditutup -> buat case baru
                    await self.redis.delete(case_key)
            case_id = await self.iris.escalate_alert(alert_id, r.doc)
            if case_id is not None:
                await self.redis.set(case_key, case_id, ex=self.s.iris_case_window_s)
            else:
                log.warning("Alert %s dieskalasi tapi ID case tidak terbaca dari respons IRIS", alert_id)
            return case_id
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.error("Gagal eskalasi alert %s ke case: %s", alert_id, _error_label(exc))
            return None  # alert tetap ada, analis bisa eskalasi manual
        finally:
            if got_lock:
                await self.redis.delete(lock)

    async def _add_case_update_note(self, case_id: int, r: Record) -> None:
        observables = (r.doc.get("enrichment") or {}).get("observables") or []
        note_hash = hashlib.sha256(orjson.dumps(observables, option=orjson.OPT_SORT_KEYS)).hexdigest()
        note_key = f"iris:update-note:{case_id}:{note_hash}"
        if not await self.redis.set(note_key, "1", nx=True, ex=86400):
            return
        try:
            await self.iris.add_case_note(case_id, r.doc)
        except Exception:
            await self.redis.delete(note_key)
            raise
        log.info("IRIS case %s menerima catatan enrichment log=%s", case_id, r.log_uuid)

    async def _iris_worker(self) -> None:
        s = self.s
        while True:
            r = await self.iris_queue.get()
            key = self._dedup_key(r.doc)
            try:
                alert_id, case_id = await self.db.get_iris_ids(r.log_uuid)
                if alert_id is not None:
                    await self.iris.update_alert(int(alert_id), r.doc)
                    log.info("IRIS alert %s diperbarui log=%s", alert_id, r.log_uuid)
                    if case_id is not None and (r.doc.get("enrichment") or {}).get("observables"):
                        await self._add_case_update_note(int(case_id), r)
                    continue
                if case_id is not None:
                    if (r.doc.get("enrichment") or {}).get("observables"):
                        await self._add_case_update_note(int(case_id), r)
                    continue
                # cegah banjir: 1 item / (source, action) / window
                if not await self.redis.set(key, "1", nx=True, ex=s.iris_dedup_s):
                    continue
                alert_id = case_id = None
                try:
                    if s.iris_mode == "case":
                        case_id = await self.iris.create_case(r.doc)
                    else:
                        alert_id = await self.iris.create_alert(r.doc)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    await self.redis.delete(key)  # izinkan retry oleh event berikutnya
                    log.error("Gagal membuat %s IRIS %s: %s", "case" if s.iris_mode == "case" else "alert",
                              r.log_uuid, _error_label(exc))
                    continue
                if s.iris_mode == "alert_case" and alert_id and r.risk_score >= s.iris_case_min_risk:
                    case_id = await self._case_for(r, int(alert_id))
                if alert_id is not None or case_id is not None:
                    await self.db.set_iris(r.log_uuid, int(alert_id) if alert_id else None,
                                           int(case_id) if case_id else None)
                log.info("IRIS: alert=%s case=%s log=%s", alert_id, case_id, r.log_uuid)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("IRIS worker error")
            finally:
                self.iris_queue.task_done()

    # ---- retensi
    async def _retention_loop(self) -> None:
        while not self.stop.is_set():
            try:
                n = await self.db.purge_old(self.s.retention_minutes)
                if n:
                    log.info("Retensi: %d baris > %d menit dihapus", n, self.s.retention_minutes)
            except Exception:
                log.exception("Retensi gagal")
            await self._sleep(self.s.retention_interval_s)


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if uvloop:
        uvloop.install()
    asyncio.run(App(Settings.from_env()).run())


if __name__ == "__main__":
    main()
