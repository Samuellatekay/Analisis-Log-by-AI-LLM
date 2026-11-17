import unittest

from risk_graph import build_event_opencti_graph


class EventOpenCTIGraphTests(unittest.TestCase):
    def test_builds_exact_opencti_ioc_match_with_provenance(self):
        graph = build_event_opencti_graph(
            {
                "observables": [
                    {
                        "entity_type": "IPv4-Addr",
                        "value": "203.0.113.7",
                        "opencti": {
                            "acquired_at": "2026-11-17T10:00:00+00:00",
                            "observable": {
                                "id": "observable--1",
                                "entity_type": "IPv4-Addr",
                            },
                            "indicators": [
                                {
                                    "id": "indicator--1",
                                    "entity_type": "Indicator",
                                    "source": "MISP",
                                    "confidence": 80,
                                    "created": "2026-11-16T10:00:00+00:00",
                                    "modified": "2026-11-17T09:00:00+00:00",
                                    "pattern": "[ipv4-addr:value = '203.0.113.7']",
                                }
                            ],
                        },
                    }
                ]
            },
            "alert-1",
        )

        self.assertIsNotNone(graph)
        match = next(edge for edge in graph["edges"] if edge["type"] == "matches_observable")
        self.assertEqual(match["to"], "indicator--1")
        self.assertEqual(match["provenance"], "MISP")
        self.assertEqual(match["confidence"], 0.8)
        self.assertTrue(graph["snapshot_id"].startswith("opencti:"))

    def test_does_not_create_graph_without_opencti_enrichment(self):
        self.assertIsNone(build_event_opencti_graph({}, "alert-1"))


if __name__ == "__main__":
    unittest.main()
