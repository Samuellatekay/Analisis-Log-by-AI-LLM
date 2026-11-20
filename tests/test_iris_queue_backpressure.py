import asyncio
import unittest
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

from main import App, Record


class _IrisClient:
    @staticmethod
    def allows(_doc):
        return True


class IrisQueueBackpressureTests(unittest.TestCase):
    def test_full_queue_waits_instead_of_dropping_alert(self):
        app = App.__new__(App)
        app.s = SimpleNamespace(iris_min_risk=60)
        app.iris = _IrisClient()
        app.iris_queue = asyncio.Queue(maxsize=1)
        existing = Record(
            "first",
            uuid.uuid4(),
            datetime.now(timezone.utc),
            "2026.11.20",
            80,
            {"data_source": "wazuh"},
        )
        incoming = Record(
            "second",
            uuid.uuid4(),
            datetime.now(timezone.utc),
            "2026.11.20",
            80,
            {"data_source": "wazuh"},
        )
        app.iris_queue.put_nowait(existing)

        async def verify_backpressure():
            enqueue_task = asyncio.create_task(app._to_iris(incoming))
            await asyncio.sleep(0)
            self.assertFalse(enqueue_task.done())
            self.assertEqual(app.iris_queue.qsize(), 1)

            self.assertIs(await app.iris_queue.get(), existing)
            await asyncio.wait_for(enqueue_task, timeout=1)
            self.assertIs(await app.iris_queue.get(), incoming)

        asyncio.run(verify_backpressure())


if __name__ == "__main__":
    unittest.main()
