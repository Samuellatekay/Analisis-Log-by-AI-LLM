import unittest

from stream_iris import build_minimal_payload


class StreamIrisPayloadTests(unittest.TestCase):
    def test_payload_preserves_complete_source_content_and_related_raw_events(self):
        primary_raw = '{"full_log":"' + ("primary|" * 1200) + '"}'
        related_raw = '{"full_log":"' + ("related|" * 1200) + '"}'
        related_events = [{"log_uuid": "related-uuid", "original": related_raw}]
        source_content = {
            "original": primary_raw,
            "related_events": related_events,
            "file": {"hash": {"md5": "a" * 32}},
        }

        payload = build_minimal_payload({
            "alert_id": 3006,
            "alert_source_ref": "primary-uuid",
            "alert_source_content": source_content,
        })

        self.assertEqual(payload["original"], primary_raw)
        self.assertEqual(payload["alert_source_content"], source_content)
        self.assertEqual(payload["related_events"], related_events)


if __name__ == "__main__":
    unittest.main()
