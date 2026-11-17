import asyncio
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

from main import App, merge_enrichment


class _RiskResponse:
    status_code = 200

    def raise_for_status(self):
        pass

    def json(self):
        return {"score": 50.0, "level": "medium", "breakdown": {"target": 0.5}}


class _RiskClient:
    def __init__(self):
        self.payload = None

    async def post(self, path, *, json):
        self.payload = json
        return _RiskResponse()


class RiskAssetMetadataTests(unittest.TestCase):
    def setUp(self):
        self.app = App.__new__(App)
        self.app.s = SimpleNamespace(risk_strategy="ahp_2026")
        self.app.risk_client = _RiskClient()

    def _build_record(self, data):
        asyncio.run(
            self.app._build_record(
                "message-id",
                data,
                repeat=0,
                crit=None,
                now=datetime(2026, 11, 17, tzinfo=timezone.utc),
            )
        )
        return self.app.risk_client.payload["asset"]

    def test_destination_glpi_description_populates_risk_payload(self):
        data = {
            "destination": {"ip": "192.168.51.144"},
            "event": {"category": "network"},
        }
        merge_enrichment(
            data,
            {
                "entity_type": "ipv4-addr",
                "value": "192.168.51.144",
                "asset": {
                    "items": [
                        {
                            "id": 4,
                            "name": "ubuntu2404-soclab",
                            "ip": "192.168.51.144",
                            "description": (
                                "business_value=core  data_sensitivity=confidential"
                            ),
                        }
                    ]
                },
            },
        )

        payload_asset = self._build_record(data)

        self.assertEqual(payload_asset["business_value"], "core")
        self.assertEqual(payload_asset["data_sensitivity"], "confidential")

    def test_explicit_glpi_fields_take_precedence_over_description(self):
        payload_asset = self._build_record(
            {
                "destination": {
                    "asset": {
                        "found": True,
                        "inventory_source": "GLPI",
                        "business_value": "test",
                        "data_sensitivity": "public",
                        "description": (
                            "business_value=core data_sensitivity=top_secret"
                        ),
                    }
                }
            }
        )

        self.assertEqual(payload_asset["business_value"], "test")
        self.assertEqual(payload_asset["data_sensitivity"], "public")

    def test_invalid_or_missing_glpi_values_use_existing_defaults(self):
        payload_asset = self._build_record(
            {
                "asset": {
                    "description": (
                        "business_value=unknown data_sensitivity=secret"
                    )
                }
            }
        )

        self.assertEqual(payload_asset["business_value"], "support")
        self.assertEqual(payload_asset["data_sensitivity"], "internal")


if __name__ == "__main__":
    unittest.main()
