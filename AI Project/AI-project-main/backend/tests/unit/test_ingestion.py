import unittest
from backend.app.ingestion.mapper import ProvenanceMapper, IngestionPipeline
from backend.app.models.core import SourceType

class TestPhase2Ingestion(unittest.TestCase):
    def setUp(self):
        self.mapper = ProvenanceMapper()
        self.pipeline = IngestionPipeline(self.mapper)

    def test_full_request_mapping(self):
        request = {
            "system_instruction": "You are a helpful assistant.",
            "user_input": "Summarize this.",
            "external_data_blobs": [
                {"id": "1", "source": "web", "content": "Malicious content here."}
            ],
            "tool_outputs": [
                {"id": "t1", "source": "weather_api", "content": "It is sunny."}
            ]
        }

        result = self.pipeline.process(request)
        self.assertEqual(result["status"], "success")
        spans = result["spans"]

        # Check count
        self.assertEqual(len(spans), 4)

        # Verify Taint Logic
        for span in spans:
            if span.source in [SourceType.DATA, SourceType.TOOL]:
                self.assertTrue(span.tainted, f"Span from {span.source} should be tainted")
            elif span.source in [SourceType.SYSTEM, SourceType.USER]:
                self.assertFalse(span.tainted, f"Span from {span.source} should not be tainted")

    def test_missing_fields(self):
        # Minimal request
        request = {"user_input": "Hello"}
        result = self.pipeline.process(request)
        self.assertEqual(len(result["spans"]), 1)
        self.assertEqual(result["spans"][0].source, SourceType.USER)

    def test_empty_blobs(self):
        request = {
            "user_input": "Hello",
            "external_data_blobs": []
        }
        result = self.pipeline.process(request)
        self.assertEqual(len(result["spans"]), 1)

if __name__ == "__main__":
    unittest.main()
