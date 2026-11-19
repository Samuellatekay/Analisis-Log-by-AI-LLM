import asyncio
import unittest

from iris_client import IrisClient, PATHS


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


if __name__ == "__main__":
    unittest.main()
