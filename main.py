"""
main.py - Orchestrator "Analisis Log by AI/LLM"

Redis Stream (consumer group) -> hitung risk -> PostgreSQL (temp) -> Logstash (log awal, 1 POST/batch)
                                                   `-> antrean prioritas -> worker Ollama (background)
                                                          -> Logstash (hasil AI, UUID sama) + update PostgreSQL

Ketahanan terhadap burst:
- Redis Streams + consumer group (at-least-once, bisa scale horizontal, XAUTOCLAIM untuk pesan nyangkut)
- Pemrosesan per-batch (1 pipeline Redis, 1 executemany DB, 1 POST Logstash)
- Connection pool (asyncpg, httpx, redis)
- UUID deterministik (uuid5 dari ID pesan stream) => redelivery idempoten
- Antrean AI terbatas + prioritas risk tertinggi; kelebihan beban => status 'skipped_overload'
- Dead-letter stream untuk pesan rusak / gagal kirim ke Logstash
"""
from __future__ import annotations

import asyncio
import hashlib
import itertools
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
from llm_analyzer import build_analyzer, describe_error
from normalizer import normalize
from risk_calculator import assess_event

try:
    import uvloop
except ImportError:  # opsional
    uvloop = None

log = logging.getLogger("log-analyzer")
UUID_NS = uuid.UUID("6f1c2f0e-8c1e-4e0a-9d52-3b1f7a5e9c11")
LATENCY_BUDGET_S = 1.0


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
    ollama_url: str
    ollama_model: str
    ollama_timeout_s: float
    persona_path: str
    ai_workers: int
    ai_queue_max: int
    ai_min_risk: float
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
            ollama_url=_e("OLLAMA_URL", "http://localhost:11434"),
            ollama_model=_e("OLLAMA_MODEL", "llama3.1:8b"),
            ollama_timeout_s=float(_e("OLLAMA_TIMEOUT_S", "600")),
            persona_path=_e("PERSONA_PATH", "soc_persona.md"),
            ai_workers=int(_e("AI_WORKERS", "2")),
            ai_queue_max=int(_e("AI_QUEUE_MAX", "1000")),
            ai_min_risk=float(_e("AI_MIN_RISK", "40")),
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
    ai_status: str
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
    payload       JSONB NOT NULL,
    ai_status     TEXT NOT NULL DEFAULT 'pending',
    ai_result     JSONB,
    ai_updated_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_log_events_received_at ON log_events (received_at);
ALTER TABLE log_events ADD COLUMN IF NOT EXISTS iris_alert_id INTEGER;
ALTER TABLE log_events ADD COLUMN IF NOT EXISTS iris_case_id INTEGER;
"""


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
        sql = ("INSERT INTO log_events (log_uuid, received_at, risk_score, payload, ai_status) "
               "VALUES ($1,$2,$3,$4::jsonb,$5) ON CONFLICT (log_uuid) DO NOTHING")
        rows = [(r.log_uuid, r.received_at, r.risk_score,
                 orjson.dumps(r.doc).decode().replace("\\u0000", ""),  # JSONB menolak NUL
                 r.ai_status) for r in records]
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

    async def update_ai(self, log_uuid: uuid.UUID, status: str, result: dict | None = None) -> None:
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE log_events SET ai_status=$2, ai_result=$3::jsonb, ai_updated_at=now() "
                "WHERE log_uuid=$1",
                log_uuid, status, orjson.dumps(result).decode() if result is not None else None)

    async def set_iris(self, log_uuid: uuid.UUID, alert_id: int | None, case_id: int | None) -> None:
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE log_events SET iris_alert_id=COALESCE($2::int, iris_alert_id), "
                "iris_case_id=COALESCE($3::int, iris_case_id) WHERE log_uuid=$1",
                log_uuid, alert_id, case_id)

    async def mark_many(self, ids: list[uuid.UUID], status: str) -> None:
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE log_events SET ai_status=$2, ai_updated_at=now() WHERE log_uuid = ANY($1::uuid[])",
                ids, status)

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
        self.llm = build_analyzer(os.environ, s.persona_path)  # ollama/openai/anthropic/gemini + fallback
        self.redis = aioredis.from_url(s.redis_url, decode_responses=True, max_connections=50,
                                       health_check_interval=30, socket_keepalive=True,
                                       socket_connect_timeout=5)
        if s.iris_mode not in ("alert", "alert_case", "case"):
            raise ValueError("IRIS_MODE harus: alert | alert_case | case")
        self.iris = IrisClient.from_env(os.environ)  # None jika IRIS_ENABLED!=true
        self.iris_queue: asyncio.Queue = asyncio.Queue(maxsize=s.iris_queue_max)
        self.ai_queue: asyncio.PriorityQueue = asyncio.PriorityQueue(maxsize=s.ai_queue_max)
        self._seq = itertools.count()
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

        ai_tasks = [asyncio.create_task(self._ai_worker(i)) for i in range(s.ai_workers)]
        iris_tasks = [asyncio.create_task(self._iris_worker()) for _ in range(s.iris_workers if self.iris else 0)]
        loops = [asyncio.create_task(self._consumer_loop(f"{self._host}-{os.getpid()}-{i}", src))
                 for src in self._sources() for i in range(s.consumer_workers)]
        loops += [asyncio.create_task(self._reclaim_loop()), asyncio.create_task(self._retention_loop())]
        log.info("Started: mode=%s sources=%s, %d worker/sumber, %d AI worker, providers=%s",
                 s.redis_mode, self._sources(), s.consumer_workers, s.ai_workers, self.llm.label)

        await self.stop.wait()
        log.info("Shutdown: menghentikan consumer...")
        await asyncio.gather(*loops, return_exceptions=True)
        try:
            await asyncio.wait_for(self.ai_queue.join(), s.shutdown_grace_s)
        except asyncio.TimeoutError:
            log.warning("Antrean AI belum kosong (%d); sisa dibuang", self.ai_queue.qsize())
        for t in ai_tasks:
            t.cancel()
        await asyncio.gather(*ai_tasks, return_exceptions=True)
        try:
            await asyncio.wait_for(self.iris_queue.join(), s.shutdown_grace_s)
        except asyncio.TimeoutError:
            log.warning("Antrean IRIS belum kosong (%d)", self.iris_queue.qsize())
        for t in iris_tasks:
            t.cancel()
        await asyncio.gather(*iris_tasks, return_exceptions=True)
        await asyncio.gather(self.llm.aclose(), self.logstash.aclose(), self.db.close(),
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
        return list(self.s.redis_lists) if self.s.redis_mode == "list" else [self.s.stream_key]

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
        for src in self.s.redis_lists:
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
            ok = await self.logstash.send([r.doc for r in records]) if records else True
            sent_s = time.perf_counter() - t0
            if not ok:
                for r in records:
                    dlq.append((r.msg_id, "logstash_failed", orjson.dumps(r.doc).decode()))
            records_ok = records if ok else []

        if dlq:
            await self._send_dlq(dlq)
        await ack()

        if records_ok:
            await self._enqueue_ai(records_ok)
            ts = [i.ts_ms for i in items if i.ts_ms]
            e2e = f" e2e_max={(time.time() * 1000 - min(ts)) / 1000:.3f}s" if ts else ""
            level = logging.WARNING if sent_s > LATENCY_BUDGET_S else logging.DEBUG
            log.log(level, "batch=%d proses+kirim=%.3fs%s ai_queue=%d",
                    len(records_ok), sent_s, e2e, self.ai_queue.qsize())

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
        ai_status = "pending" if risk.score >= self.s.ai_min_risk else "skipped_low_risk"
        log_day = now.strftime("%Y.%m.%d")
        doc = {
            "event_type": "raw",
            "log_uuid": str(log_uuid),
            "log_day": log_day,
            "@timestamp": data.get("@timestamp") or now.isoformat(),
            "event": {k: ev.get(k) for k in ("action", "category", "severity", "outcome", "wazuh_level", "rule_id") if k in ev},
            "data_source": data.get("data_source"),
            "source": data.get("source"),
            "original": data.get("original"),
            "reputation": data.get("reputation"),
            "geolocation": data.get("geolocation"),
            "asset": data.get("asset"),
            "domain": data.get("domain"),
            "risk": {**risk.as_dict(), "repeat_count": repeat},
            "ai": {"status": ai_status},
        }
        for k in ("destination", "file"):  # opsional dari normalizer (mis. Wazuh dstip / hash syscheck)
            if data.get(k):
                doc[k] = data[k]
        return Record(msg_id, log_uuid, now, log_day, risk.score, ai_status, doc)

    async def _send_dlq(self, items: list[tuple[str, str, str]]) -> None:
        pipe = self.redis.pipeline(transaction=False)
        for msg_id, reason, payload in items:
            pipe.xadd(self.s.dlq_key, {"msg_id": msg_id, "reason": reason, "data": payload},
                      maxlen=100_000, approximate=True)
        await pipe.execute()
        log.error("%d pesan dikirim ke DLQ (%s)", len(items), self.s.dlq_key)

    # ---- background AI
    async def _enqueue_ai(self, records: list[Record]) -> None:
        skipped: list[Record] = []
        for r in records:
            if r.ai_status != "pending":
                self._to_iris(r, None)  # AI tidak jalan, tapi risk tinggi tetap dieskalasi
                continue
            try:  # prioritas: risk tertinggi diproses lebih dulu
                self.ai_queue.put_nowait((-r.risk_score, next(self._seq), r))
            except asyncio.QueueFull:
                skipped.append(r)
        if skipped:
            log.warning("Antrean AI penuh: %d log di-skip (overload)", len(skipped))
            for r in skipped:
                self._to_iris(r, None)
            try:
                await self.db.mark_many([r.log_uuid for r in skipped], "skipped_overload")
                await self.logstash.send([self._ai_doc(r, {"status": "skipped_overload"}) for r in skipped])
            except Exception:
                log.exception("Gagal mencatat skipped_overload")

    @staticmethod
    def _ai_doc(r: Record, ai: dict) -> dict:
        return {"event_type": "ai_analysis", "log_uuid": str(r.log_uuid),
                "log_day": r.log_day, "ai": ai}

    async def _ai_worker(self, n: int) -> None:
        while True:
            _, _, r = await self.ai_queue.get()
            t0 = time.perf_counter()
            try:
                await self.db.update_ai(r.log_uuid, "running")
                result, provider, model = await self.llm.analyze(str(r.log_uuid), r.doc)
                ai = {"status": "done", "analysis": result, "provider": provider, "model": model,
                      "duration_s": round(time.perf_counter() - t0, 2),
                      "completed_at": datetime.now(timezone.utc).isoformat()}
                await self.db.update_ai(r.log_uuid, "done", result)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("AI gagal untuk %s: %s", r.log_uuid, type(exc).__name__)
                ai = {"status": "failed", "error": type(exc).__name__, "providers": self.llm.label}
                try:
                    await self.db.update_ai(r.log_uuid, "failed")
                except Exception:
                    pass
            try:
                # UUID sama => Logstash/ES meng-upsert ke dokumen log mentah
                if not await self.logstash.send([self._ai_doc(r, ai)], attempts=5):
                    log.error("Hasil AI %s gagal dikirim ke Logstash", r.log_uuid)
                self._to_iris(r, ai)
            finally:
                self.ai_queue.task_done()

    # ---- DFIR-IRIS
    def _to_iris(self, r: Record, ai: dict | None) -> None:
        if not self.iris or r.risk_score < self.s.iris_min_risk or not self.iris.allows(r.doc):
            return
        verdict = ((ai or {}).get("analysis") or {}).get("verdict")
        if verdict in ("false_positive", "benign"):
            return
        try:
            self.iris_queue.put_nowait((r, ai))
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

    async def _case_for(self, r: Record, ai: dict | None, alert_id: int) -> int | None:
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
            case_id = await self.iris.escalate_alert(alert_id, r.doc, ai)
            if case_id is not None:
                await self.redis.set(case_key, case_id, ex=self.s.iris_case_window_s)
            else:
                log.warning("Alert %s dieskalasi tapi ID case tidak terbaca dari respons IRIS", alert_id)
            return case_id
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.error("Gagal eskalasi alert %s ke case: %s", alert_id, describe_error(exc))
            return None  # alert tetap ada, analis bisa eskalasi manual
        finally:
            if got_lock:
                await self.redis.delete(lock)

    async def _iris_worker(self) -> None:
        s = self.s
        while True:
            r, ai = await self.iris_queue.get()
            key = self._dedup_key(r.doc)
            try:
                # cegah banjir: 1 item / (source, action) / window
                if not await self.redis.set(key, "1", nx=True, ex=s.iris_dedup_s):
                    continue
                alert_id = case_id = None
                try:
                    if s.iris_mode == "case":
                        case_id = await self.iris.create_case(r.doc, ai)
                    else:
                        alert_id = await self.iris.create_alert(r.doc, ai)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    await self.redis.delete(key)  # izinkan retry oleh event berikutnya
                    log.error("Gagal membuat %s IRIS %s: %s", "case" if s.iris_mode == "case" else "alert",
                              r.log_uuid, describe_error(exc))
                    continue
                if s.iris_mode == "alert_case" and alert_id and r.risk_score >= s.iris_case_min_risk:
                    case_id = await self._case_for(r, ai, int(alert_id))
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
