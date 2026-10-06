import secrets
import string
import re
from typing import Tuple, List
from backend.app.models.core import ContentSpan, Finding, Severity, SourceType

class NonceManager:
    """
    Generates cryptographically secure nonces for request fencing.
    """
    @staticmethod
    def generate_nonce(length: int = 6) -> str:
        """Generates a random alphanumeric nonce."""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def wrap_data(content: str, nonce: str) -> str:
        """Wraps content in the security fence delimiters."""
        return f"<<<UNTRUSTED-DATA-{nonce}>>>\n{content}\n<<<END-UNTRUSTED-DATA-{nonce}>>>"

class NonceDetectionRule:
    """
    Specialized detector for provenance forgery.
    Detects if the USER_INPUT contains the current request's nonce.
    """
    def __init__(self, request_nonce: str):
        self.request_nonce = request_nonce
        self.start_fence = f"<<<UNTRUSTED-DATA-{request_nonce}>>>"
        self.end_fence = f"<<<END-UNTRUSTED-DATA-{request_nonce}>>>"

    def scan(self, span: ContentSpan) -> List[Finding]:
        # User-supplied fence-shaped tokens are untrusted even when their nonce
        # does not match the current request. Never let user text impersonate a
        # system-generated provenance boundary.
        if span.source != SourceType.USER:
            return []

        match = re.search(r"<<<(?:END-)?UNTRUSTED-DATA-[A-Za-z0-9_-]+>>>", span.normalized, re.IGNORECASE)
        if not match:
            return []

        return [Finding(
            rule_id="PF-001",
            category="PROVENANCE_FORGERY",
            severity=Severity.CRITICAL,
            confidence=1.0,
            evidence=match.group(),
            source=span.source,
            location=match.start(),
        )]
