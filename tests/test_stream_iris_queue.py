import asyncio
import unittest
from unittest.mock import patch

import stream_iris


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.seen = {}
        self.jobs = []
        self.acked = []
        self.deleted = []
        self.dead_letters = []

    async def get(self, key):
        return self.values.get(key)

    async def set(self, key, value):
        self.values[key] = value
        return True

    async def eval(
        self, script, number_of_keys, seen_key, stream_key, alert_id, available_at, ttl
    ):
        if seen_key in self.seen:
            return f"0:{self.seen[seen_key]}"
        stream_id = f"{len(self.jobs) + 1}-0"
        self.seen[seen_key] = stream_id
        self.jobs.append({
            "stream_id": stream_id,
            "alert_id": alert_id,
            "available_at": available_at,
        })
        return f"1:{stream_id}"

    async def xack(self, stream, group, message_id):
        self.acked.append(message_id)

    async def xdel(self, stream, message_id):
        self.deleted.append(message_id)

    async def xadd(self, stream, fields, **kwargs):
        self.dead_letters.append((stream, fields))
        return "dead-1"

    async def xlen(self, stream):
        return len(self.jobs) - len(self.deleted)


class IrisStreamQueueTests(unittest.TestCase):
    def test_scanner_pages_until_it_reaches_the_persisted_watermark(self):
        redis = FakeRedis()
        redis.values[stream_iris.ALERT_WATERMARK_KEY] = "100"
        pages = {
            1: [{"id": 104}, {"id": 103}],
            2: [{"id": 102}, {"id": 101}],
            3: [{"id": 100}, {"id": 99}],
        }
        calls = []

        async def fetch_page(page, per_page):
            calls.append((page, per_page))
            return pages.get(page, [])

        with (
            patch.object(stream_iris, "ALERT_PAGE_SIZE", 2),
            patch.object(stream_iris, "fetch_alert_list", side_effect=fetch_page),
            patch.object(stream_iris, "SETTLE_SECONDS", 0),
        ):
            queued = asyncio.run(stream_iris.scan_iris_alerts(redis))

        self.assertEqual(queued, 4)
        self.assertEqual([job["alert_id"] for job in redis.jobs], ["104", "103", "102", "101"])
        self.assertEqual(redis.values[stream_iris.ALERT_WATERMARK_KEY], "104")
        self.assertEqual(calls, [(1, 2), (2, 2), (3, 2)])

    def test_scanner_does_not_advance_watermark_when_a_page_fails(self):
        redis = FakeRedis()
        redis.values[stream_iris.ALERT_WATERMARK_KEY] = "100"

        async def fetch_page(page, per_page):
            if page == 1:
                return [{"id": 102}, {"id": 101}]
            return None

        with (
            patch.object(stream_iris, "ALERT_PAGE_SIZE", 2),
            patch.object(stream_iris, "fetch_alert_list", side_effect=fetch_page),
            patch.object(stream_iris, "SETTLE_SECONDS", 0),
        ):
            queued = asyncio.run(stream_iris.scan_iris_alerts(redis))

        self.assertEqual(queued, 2)
        self.assertEqual(redis.values[stream_iris.ALERT_WATERMARK_KEY], "100")

    def test_failed_external_send_retries_without_rebroadcasting(self):
        redis = FakeRedis()
        attempts = 0
        broadcasts = []

        async def send(payload):
            nonlocal attempts
            attempts += 1
            return attempts == 2

        async def broadcast(payload):
            broadcasts.append(payload)

        with (
            patch.object(stream_iris, "ALERT_MAX_ATTEMPTS", 2),
            patch.object(stream_iris, "ALERT_RETRY_BASE_SECONDS", 0.01),
            patch.object(stream_iris, "EXTERNAL_API_KEY", "configured"),
            patch.object(
                stream_iris,
                "fetch_alert_detail",
                new=lambda alert_id: asyncio.sleep(0, result={"alert_id": alert_id}),
            ),
            patch.object(stream_iris, "build_minimal_payload", lambda detail: detail),
            patch.object(stream_iris, "send_to_external_server", side_effect=send),
            patch.object(stream_iris, "broadcast_all", side_effect=broadcast),
        ):
            asyncio.run(stream_iris._deliver_alert_job(
                redis,
                "1-0",
                {"alert_id": "42", "available_at": "0"},
            ))

        self.assertEqual(attempts, 2)
        self.assertEqual(broadcasts, [{"alert_id": "42"}])
        self.assertEqual(redis.acked, ["1-0"])
        self.assertEqual(redis.deleted, ["1-0"])

    def test_exhausted_delivery_attempts_are_saved_to_dead_letter(self):
        redis = FakeRedis()
        broadcasts = []

        async def broadcast(payload):
            broadcasts.append(payload)

        with (
            patch.object(stream_iris, "ALERT_MAX_ATTEMPTS", 2),
            patch.object(stream_iris, "ALERT_RETRY_BASE_SECONDS", 0.01),
            patch.object(stream_iris, "EXTERNAL_API_KEY", "configured"),
            patch.object(
                stream_iris,
                "fetch_alert_detail",
                new=lambda alert_id: asyncio.sleep(0, result={"alert_id": alert_id}),
            ),
            patch.object(stream_iris, "build_minimal_payload", lambda detail: detail),
            patch.object(stream_iris, "send_to_external_server", return_value=False),
            patch.object(stream_iris, "broadcast_all", side_effect=broadcast),
        ):
            asyncio.run(stream_iris._deliver_alert_job(
                redis,
                "1-0",
                {"alert_id": "42", "available_at": "0"},
            ))

        self.assertEqual(len(redis.dead_letters), 1)
        self.assertEqual(redis.dead_letters[0][1]["alert_id"], "42")
        self.assertEqual(redis.acked, ["1-0"])
        self.assertEqual(redis.deleted, ["1-0"])
        self.assertEqual(len(broadcasts), 1)


if __name__ == "__main__":
    unittest.main()
