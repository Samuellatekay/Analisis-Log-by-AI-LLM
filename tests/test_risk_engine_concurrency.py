import asyncio
import unittest

from main import App


class _TrackingRiskClient:
    def __init__(self):
        self.active = 0
        self.max_active = 0

    async def post(self, path, *, json):
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            await asyncio.sleep(0.01)
            return object()
        finally:
            self.active -= 1


class RiskEngineConcurrencyTests(unittest.TestCase):
    def test_risk_requests_respect_semaphore_limit(self):
        app = App.__new__(App)
        app.risk_semaphore = asyncio.Semaphore(3)
        app.risk_client = _TrackingRiskClient()

        async def run_requests():
            await asyncio.gather(
                *(app._calculate_risk({}) for _ in range(20))
            )

        asyncio.run(run_requests())

        self.assertEqual(app.risk_client.max_active, 3)
        self.assertEqual(app.risk_client.active, 0)


if __name__ == "__main__":
    unittest.main()
