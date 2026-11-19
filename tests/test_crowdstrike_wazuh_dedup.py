import asyncio
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

from main import App, merge_crowdstrike_event
from normalizer import crowdstrike_detection_id, normalize


COMPOSITE_ID = (
    "150efeb191b3436ab095c30d81bbb9a4:ind:"
    "82cbc83af15b46daa02afa032564fd41:"
    "1795060590492439466-30112-2227984"
)

DETECTION_CEF = (
    "CEF:0|CrowdStrike|FalconHost|1.0|EppDetectionSummaryEvent|"
    "EppDetectionSummaryEvent|70|"
    "externalId=82cbc83af15b46daa02afa032564fd41 "
    "dhost=ubuntu2402-soclab duser=root "
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


if __name__ == "__main__":
    unittest.main()
