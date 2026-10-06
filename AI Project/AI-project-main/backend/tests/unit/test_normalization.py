import unittest
from backend.app.models.core import ContentSpan, SourceType
from backend.app.normalization.engine import NormalizationEngine

class TestPhase3Normalization(unittest.TestCase):
    def setUp(self):
        self.engine = NormalizationEngine()

    def test_basic_normalization(self):
        span = ContentSpan(source=SourceType.USER, origin="test", original="Hello    World\nNew Line")
        self.engine.normalize(span)
        self.assertEqual(span.normalized, "Hello World New Line")
        self.assertIn("whitespace_norm", span.metadata)

    def test_unicode_normalization(self):
        # Use a homoglyph (Cyrillic 'а' instead of Latin 'a')
        # Latin 'a' is U+0061, Cyrillic 'а' is U+0430
        original = "Pаyload"
        span = ContentSpan(source=SourceType.USER, origin="test", original=original)
        self.engine.normalize(span)
        self.assertIn("unicode_nfkc", span.metadata)

    def test_base64_decoding(self):
        # "Ignore" in base64: SWdub3Jl
        original = "SWdub3Jl"
        span = ContentSpan(source=SourceType.USER, origin="test", original=original)
        self.engine.normalize(span)
        self.assertEqual(span.normalized, "Ignore")
        self.assertIn("base64_decode", span.metadata)

    def test_url_decoding(self):
        # "Ignore" url encoded: Ignore -> Ignore (no change)
        # " " -> %20
        original = "Ignore%20previous"
        span = ContentSpan(source=SourceType.USER, origin="test", original=original)
        self.engine.normalize(span)
        self.assertEqual(span.normalized, "Ignore previous")
        self.assertIn("url_decode", span.metadata)

    def test_recursive_decoding(self):
        # Ignore -> SWdub3Jl -> U1dkdWIzSmw=
        original = "U1dkdWIzSmw="
        span = ContentSpan(source=SourceType.USER, origin="test", original=original)
        self.engine.normalize(span)
        self.assertEqual(span.normalized, "Ignore")
        self.assertEqual(span.metadata.count("base64_decode"), 2)

    def test_max_depth_limit(self):
        # 4 layers of base64
        # Ignore -> SWlnb3Jl -> U1dpZ25vcmU= -> U1VpZWVnZ3ZvaW5uRU= -> ...
        val = "Ignore"
        for _ in range(4):
            import base64
            val = base64.b64encode(val.encode()).decode()

        span = ContentSpan(source=SourceType.USER, origin="test", original=val)
        self.engine.normalize(span)
        # Should only decode 3 times
        self.assertEqual(span.metadata.count("base64_decode"), 3)

    def test_original_preserved(self):
        original = "SWlnb3Jl"
        span = ContentSpan(source=SourceType.USER, origin="test", original=original)
        self.engine.normalize(span)
        self.assertEqual(span.original, original)
        self.assertNotEqual(span.original, span.normalized)

if __name__ == "__main__":
    unittest.main()
