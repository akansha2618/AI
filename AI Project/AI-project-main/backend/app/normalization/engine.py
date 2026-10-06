import unicodedata
import base64
import urllib.parse
import re
from typing import List, Tuple, Optional
from backend.app.models.core import ContentSpan
from backend.app.config import settings

class NormalizationEngine:
    """
    Creates a 'Detection View' of content without modifying the 'Execution View'.
    Implements triggered decoding and NFKC normalization.
    """

    def __init__(self):
        # Indicators that trigger deep decoding attempts
        self.suspicious_indicators = [
            r"[A-Za-z0-9+/]{4,}=*",           # Base64-like (lower threshold to 4 chars)
            r"%[0-9a-fA-F]{2}",              # URL encoded
            r"0x[0-9a-fA-F]{2,}",            # Hex
            r"\\x[0-9a-fA-F]{2}",             # Escaped hex
        ]

    def normalize(self, span: ContentSpan) -> str:
        """
        The main entry point for normalizing a ContentSpan.
        Returns the normalized string and updates span metadata.
        """
        text = span.original

        # 1. Zero-Width and Control Character Removal (Fixes "Ghost Font" / Invisible Text attacks)
        # Removes characters like ​ (Zero Width Space), ‌, ‍, etc.
        invisible_chars = r"[​-‍﻿\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]"
        if re.search(invisible_chars, text):
            text = re.sub(invisible_chars, "", text)
            span.metadata.append("invisible_char_removal")

        # 2. Bidi/Directional Control Character Removal
        # Prevents text-reversal attacks (e.g., using ‮ to make text read backwards)
        bidi_chars = r"[‎‏‪-‮]"
        if re.search(bidi_chars, text):
            text = re.sub(bidi_chars, "", text)
            span.metadata.append("bidi_char_removal")

        # 3. Unicode NFKC Normalization
        # This handles homoglyphs and normalization of combined characters
        text = unicodedata.normalize('NFKC', text)
        span.metadata.append("unicode_nfkc")

        # 4. Triggered Decoding
        if self._is_suspicious(text):
            decoded_text, transformations = self._recursive_decode(text, depth=0)
            if decoded_text != text:
                text = decoded_text
                span.metadata.extend(transformations)

        # 5. Whitespace Normalization
        text = re.sub(r'\s+', ' ', text).strip()
        span.metadata.append("whitespace_norm")

        span.normalized = text
        return text

    def _is_suspicious(self, text: str) -> bool:
        """Checks if the text contains patterns that suggest encoding."""
        if not text:
            return False
        for pattern in self.suspicious_indicators:
            if re.search(pattern, text):
                return True
        return False

    def _recursive_decode(self, text: str, depth: int) -> Tuple[str, List[str]]:
        """
        Attempts to decode text recursively up to MAX_DECODING_DEPTH.
        """
        if depth >= settings.MAX_DECODING_DEPTH:
            return text, []

        current_text = text
        transformations = []

        # Try URL Decoding
        decoded_url = urllib.parse.unquote(current_text)
        if decoded_url != current_text:
            current_text = decoded_url
            transformations.append("url_decode")

        # Try Base64 Decoding
        try:
            # Base64 requires padding and specific charset; we try to strip whitespace
            b64_candidate = re.sub(r'\s+', '', current_text)
            decoded_b64 = base64.b64decode(b64_candidate, validate=True).decode('utf-8', errors='ignore')
            if decoded_b64 and decoded_b64 != current_text:
                # Only accept if it's actually printable text to avoid binary junk
                if decoded_b64.isprintable():
                    current_text = decoded_b64
                    transformations.append("base64_decode")
        except Exception:
            # Decoding failures are logged as [DECODING_FAILED] in the specific span
            # but we continue with the current text
            pass

        # Try Hex Decoding
        try:
            # Look for 0x... or \x... patterns
            hex_pattern = re.sub(r'(0x|\\x)', '', current_text)
            if all(c in '0123456789abcdefABCDEF' for c in hex_pattern) and len(hex_pattern) % 2 == 0:
                decoded_hex = bytes.fromhex(hex_pattern).decode('utf-8', errors='ignore')
                if decoded_hex and decoded_hex != current_text:
                    current_text = decoded_hex
                    transformations.append("hex_decode")
        except Exception:
            pass

        if current_text != text:
            # If we successfully decoded something, try to decode the result recursively
            further_text, further_trans = self._recursive_decode(current_text, depth + 1)
            return further_text, transformations + further_trans

        return text, []
