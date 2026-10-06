import re
from typing import List, Dict, Any, Optional
from backend.app.models.core import Finding, Severity, SourceType, Decision, FirewallDecision
from backend.app.config import settings

class EgressFirewall:
    """
    Inspects LLM output before it reaches the user.
    Detects secret leakage and unauthorized URL exfiltration.
    """
    def __init__(self):
        # Canary secrets (e.g., from .env)
        configured_secrets = [s.strip() for s in settings.CANARY_SECRETS.split(",") if s.strip()]
        self.canary_secrets = configured_secrets or ["CYBERDESK-SECRET-7F39"]
        # Trusted domains
        self.allowed_hosts = [h.strip() for h in settings.ALLOWED_HOSTS.split(",")] if hasattr(settings, 'ALLOWED_HOSTS') else ["example.com"]

    def scan_output(self, output_text: str, request_id: str) -> Optional[Finding]:
        """
        Scans model output for leaks or dangerous URLs.
        Returns a Finding if a violation is found, otherwise None.
        """
        # 1. Canary Secret Leakage Detection
        # We check for the secret and simple variations (case-insensitive, spaces)
        for secret in self.canary_secrets:
            # Check for exact secret or secret with spaces/hyphens (common evasion)
            normalized_secret = secret.replace("-", "").replace(" ", "").lower()
            normalized_output = output_text.replace("-", "").replace(" ", "").lower()

            if normalized_secret in normalized_output:
                return Finding(
                    rule_id="EG-001",
                    category="SECRET_LEAKAGE",
                    severity=Severity.CRITICAL,
                    confidence=1.0,
                    evidence="Configured canary secret detected (value redacted).",
                    source=SourceType.MODEL,
                    location=output_text.find(secret) if secret in output_text else -1,
                    request_id=request_id
                )

        # 2. URL Exfiltration Detection
        # Find all URLs in the output
        urls = re.findall(r'(?i)(?:https?://)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?(?:/[^\s]*)?', output_text)
        for url in urls:
            # Basic domain extraction
            from urllib.parse import urlparse
            domain = (urlparse(url).netloc or urlparse("//" + url).netloc).lower()

            hostname = domain.rsplit("@", 1)[-1].split(":", 1)[0].rstrip(".")
            is_allowed = any(hostname == allowed.lower().lstrip(".") or hostname.endswith("." + allowed.lower().lstrip(".")) for allowed in self.allowed_hosts if allowed)
            if not is_allowed:
                return Finding(
                    rule_id="EG-002",
                    category="UNAUTHORIZED_URL",
                    severity=Severity.HIGH,
                    confidence=1.0,
                    evidence=url,
                    source=SourceType.MODEL,
                    location=output_text.find(url),
                    request_id=request_id
                )

        return None
