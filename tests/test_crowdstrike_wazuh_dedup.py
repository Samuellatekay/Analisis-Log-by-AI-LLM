import asyncio
import unittest
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

from iris_client import IrisClient
from main import App, Record, merge_crowdstrike_event
from normalizer import crowdstrike_detection_id, normalize


FILE_HASH = "38cdcffd5d19eddfdbb4457c5bac7899"
COMPOSITE_ID = (
    "150efeb191b3436ab095c30d81bbb9a4:ind:"
    "82cbc83af15b46daa02afa032564fd41:"
    "1795060590492439466-30112-2227984"
)

DETECTION_CEF = (
    "CEF:0|CrowdStrike|FalconHost|1.0|EppDetectionSummaryEvent|"
    "EppDetectionSummaryEvent|70|"
    "externalId=82cbc83af15b46daa02afa032564fd41 "
    "dhost=ubuntu2402-soclab duser=root fname=cp filePath=/usr/bin/cp "
    f"fileHash={FILE_HASH} "
    "msg=The activity may be related to data exfiltration. "
    "cs5Label=CommandLine cs5=cp /etc/shadow /tmp/shadow_direct.txt "
    f"CompositeIdLabel=CompositeId CompositeId={COMPOSITE_ID}"
)

MITRE_CEF = (
    "CEF:0|CrowdStrike|FalconHost|1.0|EppDetectionSummaryEvent|MitreAttack|"
    "30112|tacticLabel=Tactic tactic=Exfiltration "
    "tacticIdLabel=TacticID tacticId=TA0010 "
    "techniqueLabel=Technique technique=Automated Exfiltration "
    "techniqueIdLabel=TechniqueID techniqueId=T1020 "
    f"CompositeIdLabel=CompositeId CompositeId={COMPOSITE_ID}"
)


def wazuh_alert(event_id: str, action: str, full_log: str, host: str) -> dict:
    return {
        "id": event_id,
        "agent": {"name": host, "id": "000"},
        "rule": {
            "id": "200002",
            "level": 12,
            "description": action,
            "groups": ["crowdstrike", "cef", "exfiltration"],
        },
        "full_log": full_log,
        "data": {"cs_event_type": "EppDetectionSummaryEvent"},
    }


class CrowdStrikeWazuhDedupTests(unittest.TestCase):
    @staticmethod
    def build_record(data: dict, msg_id: str) -> dict:
        class RiskResponse:
            status_code = 200

            @staticmethod
            def raise_for_status():
                pass

            @staticmethod
            def json():
                return {"score": 64.84, "level": "high", "breakdown": {}}

        class RiskClient:
            @staticmethod
            async def post(path: str, *, json: dict):
                return RiskResponse()

        app = App.__new__(App)
        app.s = SimpleNamespace(risk_strategy="ahp_2026")
        app.risk_client = RiskClient()
        return asyncio.run(
            app._build_record(
                msg_id,
                data,
                repeat=1,
                crit=None,
                now=datetime(2026, 11, 19, tzinfo=timezone.utc),
            )
        ).doc

    def test_detection_and_mitre_alerts_share_dedup_identity(self):
        detection = normalize(
            "wazuh-alerts",
            wazuh_alert("first", "Data Exfiltration Detected", DETECTION_CEF, "hids-soclab"),
        )
        mitre = normalize(
            "crowdstrike",
            wazuh_alert("second", "MitreAttack", MITRE_CEF, "hids-soclab"),
        )

        self.assertEqual(detection["data_source"], "wazuh")
        self.assertEqual(mitre["data_source"], "wazuh")
        self.assertEqual(detection["host"]["name"], "ubuntu2402-soclab")
        self.assertEqual(detection["user"]["name"], "root")
        self.assertEqual(detection["agent"]["name"], "hids-soclab")
        self.assertEqual(detection["crowdstrike"]["host_name"], "ubuntu2402-soclab")
        self.assertEqual(detection["crowdstrike"]["detection_id"], COMPOSITE_ID)
        self.assertEqual(mitre["crowdstrike"]["detection_id"], COMPOSITE_ID)
        self.assertEqual(crowdstrike_detection_id(detection), COMPOSITE_ID)
        self.assertEqual(App._dedup_key(detection), App._dedup_key(mitre))
        self.assertEqual(mitre["crowdstrike"]["technique_id"], "T1020")

    def test_record_builder_preserves_correlation_and_mitre_metadata(self):
        detection = self.build_record(
            normalize(
                "wazuh-alerts",
                wazuh_alert("first", "Data Exfiltration Detected", DETECTION_CEF, "hids-soclab"),
            ),
            "first",
        )
        mitre = self.build_record(
            normalize(
                "crowdstrike",
                wazuh_alert("second", "MitreAttack", MITRE_CEF, "hids-soclab"),
            ),
            "second",
        )

        self.assertEqual(detection["crowdstrike"]["detection_id"], COMPOSITE_ID)
        self.assertEqual(detection["host"]["name"], "ubuntu2402-soclab")
        self.assertEqual(detection["user"]["name"], "root")
        self.assertEqual(detection["agent"]["name"], "hids-soclab")
        self.assertEqual(mitre["threat"]["technique"], "Automated Exfiltration")
        self.assertEqual(mitre["crowdstrike"]["technique_id"], "T1020")
        self.assertEqual(App._dedup_key(detection), App._dedup_key(mitre))

    def test_related_event_is_merged_once_and_enriches_primary_context(self):
        primary = normalize(
            "wazuh-alerts",
            wazuh_alert("first", "Data Exfiltration Detected", DETECTION_CEF, "ubuntu2402-soclab"),
        )
        related = normalize(
            "crowdstrike",
            wazuh_alert("second", "MitreAttack", MITRE_CEF, "hids-soclab"),
        )
        primary["log_uuid"] = "first-log"
        related["log_uuid"] = "second-log"

        self.assertTrue(merge_crowdstrike_event(primary, related))
        self.assertFalse(merge_crowdstrike_event(primary, related))
        self.assertEqual(len(primary["related_events"]), 1)
        self.assertEqual(primary["threat"]["technique"], "Automated Exfiltration")
        self.assertEqual(primary["crowdstrike"]["technique_id"], "T1020")
        self.assertEqual(primary["crowdstrike"]["event_name"], "EppDetectionSummaryEvent")
        self.assertEqual(
            primary["related_events"][0]["crowdstrike"]["event_name"],
            "MitreAttack",
        )

    def test_related_detection_updates_endpoint_when_mitre_event_arrives_first(self):
        primary = normalize(
            "crowdstrike",
            wazuh_alert("first", "MitreAttack", MITRE_CEF, "hids-soclab"),
        )
        related = normalize(
            "wazuh-alerts",
            wazuh_alert("second", "Data Exfiltration Detected", DETECTION_CEF, "hids-soclab"),
        )
        primary["log_uuid"] = "first-log"
        related["log_uuid"] = "second-log"

        self.assertEqual(primary["host"]["name"], "hids-soclab")
        self.assertTrue(merge_crowdstrike_event(primary, related))
        self.assertEqual(primary["host"]["name"], "ubuntu2402-soclab")
        self.assertEqual(primary["asset"]["name"], "ubuntu2402-soclab")
        self.assertEqual(primary["agent"]["name"], "hids-soclab")

    def test_detection_id_can_be_read_from_existing_original_json(self):
        import json

        doc = {"original": json.dumps({"full_log": MITRE_CEF})}
        self.assertEqual(crowdstrike_detection_id(doc), COMPOSITE_ID)

    def test_mitre_event_waits_for_detection_so_alert_contains_file_hash(self):
        class FakeRedis:
            def __init__(self):
                self.values = {}

            async def get(self, key: str):
                return self.values.get(key)

            async def set(self, key: str, value: str, *, nx=False, ex=None, xx=False, keepttl=False):
                if nx and key in self.values:
                    return None
                if xx and key not in self.values:
                    return None
                self.values[key] = value
                return True

            async def delete(self, key: str):
                self.values.pop(key, None)

        class FakeDatabase:
            def __init__(self, documents):
                self.documents = documents
                self.iris_ids = {}

            async def get_iris_ids(self, log_uuid):
                return self.iris_ids.get(log_uuid, (None, None))

            async def bump_risk(self, log_uuid, risk, risk_score, related_event=None):
                doc = self.documents[log_uuid]
                if related_event:
                    merge_crowdstrike_event(doc, related_event)
                return doc

            async def set_iris(self, log_uuid, alert_id, case_id):
                self.iris_ids[log_uuid] = (alert_id, case_id)

        class FakeIris(IrisClient):
            def __init__(self):
                self.created = asyncio.Event()
                self.doc = None
                self.ioc_type_ids = {"md5": 17}
                self.tlp_id = 2
                self.iocs = []

            async def create_alert(self, doc):
                self.doc = doc
                self.iocs = self._build_alert_iocs(doc)
                self.created.set()
                return 2999

        mitre_uuid = uuid.UUID("11111111-1111-4111-8111-111111111111")
        detection_uuid = uuid.UUID("22222222-2222-4222-8222-222222222222")
        mitre = normalize(
            "crowdstrike",
            wazuh_alert("mitre", "MitreAttack", MITRE_CEF, "hids-soclab"),
        )
        detection = normalize(
            "wazuh-alerts",
            wazuh_alert("detection", "Data Exfiltration Detected", DETECTION_CEF, "hids-soclab"),
        )
        for doc, log_uuid in ((mitre, mitre_uuid), (detection, detection_uuid)):
            doc["log_uuid"] = str(log_uuid)
            doc["risk"] = {"score": 64.84, "level": "high", "repeat_count": 1}

        app = App.__new__(App)
        app.s = SimpleNamespace(
            iris_dedup_s=300,
            iris_mode="alert",
            iris_update_s=10,
            iris_auto_escalate=False,
            iris_case_min_risk=75,
        )
        app.redis = FakeRedis()
        app.db = FakeDatabase({mitre_uuid: mitre, detection_uuid: detection})
        app.iris = FakeIris()
        app.iris_queue = asyncio.Queue()
        app.iris_queue.put_nowait(Record(
            "mitre", mitre_uuid, datetime.now(timezone.utc), "2026.11.19", 64.84, mitre
        ))
        app.iris_queue.put_nowait(Record(
            "detection", detection_uuid, datetime.now(timezone.utc), "2026.11.19", 64.84, detection
        ))

        async def run_worker():
            worker = asyncio.create_task(app._iris_worker())
            try:
                await asyncio.wait_for(app.iris.created.wait(), timeout=1)
            finally:
                worker.cancel()
                await asyncio.gather(worker, return_exceptions=True)

        asyncio.run(run_worker())

        self.assertEqual(app.iris.doc["file"]["hash"]["md5"], FILE_HASH)
        self.assertEqual(app.iris.iocs[0]["ioc_value"], FILE_HASH)
        self.assertEqual(app.iris.iocs[0]["ioc_type_id"], 17)
        self.assertEqual(app.iris.doc["user"]["name"], "root")
        self.assertEqual(len(app.iris.doc["related_events"]), 1)
        self.assertEqual(
            app.iris.doc["related_events"][0]["crowdstrike"]["event_name"],
            "MitreAttack",
        )
        self.assertEqual(app.db.iris_ids[mitre_uuid], (2999, None))
        self.assertEqual(app.db.iris_ids[detection_uuid], (2999, None))


if __name__ == "__main__":
    unittest.main()
