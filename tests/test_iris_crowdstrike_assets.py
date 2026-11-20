import asyncio
import unittest

from iris_client import IrisClient, PATHS, _parse_customer_routing_map


class FakeResponse:
    status_code = 200
    text = ""

    @staticmethod
    def raise_for_status():
        pass


class FakeHttpClient:
    def __init__(self):
        self.requests = []

    async def put(self, path: str, *, json: dict):
        self.requests.append((path, json))
        return FakeResponse()


class FakeIrisClient(IrisClient):
    async def get_alert(self, alert_id: int) -> dict:
        return {
            "assets": [{
                "id": 42,
                "name": "hids-soclab",
                "tags": [{"tag_title": "destination"}],
                "asset_description": "Destination lama",
                "ip": "",
                "asset_type_id": 1,
            }]
        }


class CrowdStrikeAlertAssetTests(unittest.TestCase):
    def test_existing_destination_asset_is_renamed_to_dhost(self):
        client = FakeIrisClient.__new__(FakeIrisClient)
        client.paths = PATHS["v2"]
        client.sync_assets_enabled = True
        client._asset_sync_done = set()
        client._asset_sync_lock = asyncio.Lock()
        client._client = FakeHttpClient()
        doc = {
            "host": {"name": "ubuntu2402-soclab"},
            "agent": {"name": "hids-soclab"},
            "asset": {"name": "ubuntu2402-soclab"},
            "source": {},
            "destination": {},
        }

        updated = asyncio.run(client.sync_alert_assets(7, doc))

        self.assertEqual(updated, 1)
        self.assertEqual(
            client._client.requests[0],
            (
                "/api/v2/alerts/7/assets/42",
                {
                    "asset_name": "ubuntu2402-soclab",
                    "asset_type_id": 1,
                    "asset_description": (
                        "Destination (host yang diserang)\n"
                        "- Tidak ada aset GLPI yang cocok dengan hostname ubuntu2402-soclab."
                    ),
                    "asset_ip": "",
                    "asset_domain": "",
                    "asset_tags": "destination",
                },
            ),
        )

    def test_collector_name_does_not_replace_endpoint_when_dhost_is_missing(self):
        client = FakeIrisClient.__new__(FakeIrisClient)
        client.paths = PATHS["v2"]
        client.sync_assets_enabled = True
        client._asset_sync_done = set()
        client._asset_sync_lock = asyncio.Lock()
        client._client = FakeHttpClient()
        doc = {
            "host": {"name": "hids-soclab"},
            "agent": {"name": "hids-soclab"},
            "asset": {"name": "hids-soclab"},
            "crowdstrike": {"event_name": "MitreAttack"},
            "source": {},
            "destination": {},
        }

        updated = asyncio.run(client.sync_alert_assets(7, doc))

        self.assertEqual(updated, 0)
        self.assertEqual(client._client.requests, [])


class CrowdStrikeAlertIocTests(unittest.TestCase):
    def test_file_hash_is_attached_as_ioc_before_enrichment(self):
        client = IrisClient.__new__(IrisClient)
        client.ioc_type_ids = {"md5": 17}
        client.tlp_id = 2
        file_hash = "38cdcffd5d19eddfdbb4457c5bac7899"

        iocs = client._build_alert_iocs({
            "file": {"hash": {"md5": file_hash}},
            "enrichment": {"observables": []},
        })

        self.assertEqual(len(iocs), 1)
        self.assertEqual(iocs[0]["ioc_value"], file_hash)
        self.assertEqual(iocs[0]["ioc_type_id"], 17)
        self.assertEqual(iocs[0]["ioc_tlp_id"], 2)


class RawAlertPayloadTests(unittest.TestCase):
    def test_build_payload_keeps_original_larger_than_previous_500kb_limit(self):
        client = IrisClient.__new__(IrisClient)
        client.min_wazuh_level = 0
        client.max_wazuh_level = 0
        client.show_event = True
        client.assets_in_description = False
        client.iocs_in_description = False
        client.asset_type_id = 1
        client.severity_map = {"medium": 4}
        client.customer_id = 1
        client.status_id = None
        client.source_link_tpl = ""
        client.ioc_type_ids = {}
        client.tlp_id = None
        original = "raw-event|" * 60_000
        doc = {
            "log_uuid": "raw-log",
            "original": original,
            "event": {"action": "test", "severity": 3, "outcome": "alert"},
            "risk": {"level": "medium"},
        }

        payload = client.build_payload(doc)

        self.assertEqual(payload["alert_source_content"]["original"], original)

    def test_customer_routing_uses_manager_or_keyword_and_falls_back_when_unknown(self):
        client = IrisClient.__new__(IrisClient)
        client.customer_id = 99
        client.customer_routing_map = _parse_customer_routing_map(
            "1:customer-a|hids-a,2:customer-b|hids-b"
        )
        client._customer_route_warnings = set()
        client.min_wazuh_level = 0
        client.max_wazuh_level = 0
        client.show_event = True
        client.assets_in_description = False
        client.iocs_in_description = False
        client.asset_type_id = 1
        client.severity_map = {"medium": 4}
        client.status_id = None
        client.source_link_tpl = ""
        client.ioc_type_ids = {}
        client.tlp_id = None

        self.assertEqual(
            client._customer_id_for({"agent": {"manager": "wazuh-hids-a-prod"}}),
            1,
        )
        self.assertEqual(
            client._customer_id_for({"event": {"action": "Alert for CUSTOMER-B"}}),
            2,
        )
        self.assertEqual(
            client._customer_id_for({"agent": {"manager": "unmapped-manager"}}),
            99,
        )
        self.assertEqual(
            client.build_payload({
                "event": {"action": "Alert for CUSTOMER-B", "severity": 3},
                "risk": {"level": "medium"},
            })["alert_customer_id"],
            2,
        )

    def test_customer_routing_rejects_ambiguous_or_malformed_maps(self):
        with self.assertRaises(ValueError):
            _parse_customer_routing_map("not-a-customer-map")
        with self.assertRaises(ValueError):
            _parse_customer_routing_map("1:hids,2:hids")


if __name__ == "__main__":
    unittest.main()
