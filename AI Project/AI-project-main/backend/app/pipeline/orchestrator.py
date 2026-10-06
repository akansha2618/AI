from typing import List, Dict, Any, Optional, Tuple
from backend.app.ingestion.mapper import IngestionPipeline, ProvenanceMapper
from backend.app.normalization.engine import NormalizationEngine
from backend.app.detection.engine import DetectionEngine
from backend.app.policy.engine import PolicyEngine
from backend.app.nonce.manager import NonceManager, NonceDetectionRule
from backend.app.audit.logger import AuditLogger
from backend.app.audit.fail_closed import FailClosedHandler
from backend.app.models.core import FirewallDecision, ContentSpan, SourceType, Decision, Finding
from backend.app.firewall.egress import EgressFirewall

class FirewallPipeline:
    """
    The orchestrator that wires together all the firewall components.
    Input -> Provenance -> Normalization -> Detection -> Policy -> Decision
    """

    def __init__(self):
        self.ingestion = IngestionPipeline(ProvenanceMapper())
        self.normalizer = NormalizationEngine()
        self.detector = DetectionEngine()
        self.policy = PolicyEngine()
        self.nonce_manager = NonceManager()
        self.audit_logger = AuditLogger(__import__("backend.app.config", fromlist=["settings"]).settings.AUDIT_LOG_FILE)
        self.fail_handler = FailClosedHandler()
        self.egress_firewall = EgressFirewall()

    def process_request(self, request_data: Dict[str, Any]) -> FirewallDecision:
        request_id = None
        try:
            # 1. Ingestion & Provenance Mapping
            ingest_result = self.ingestion.process(request_data)
            if ingest_result["status"] == "error":
                raise RuntimeError(f"Ingestion failed: {ingest_result['error']}")

            request_id = ingest_result["request_id"]
            spans: List[ContentSpan] = ingest_result["spans"]

            # 2. Nonce Generation & Fencing
            request_nonce = self.nonce_manager.generate_nonce()

            # 3. Normalization (Detection View)
            transformations = []
            for span in spans:
                self.normalizer.normalize(span)
                transformations.append({
                    "source": span.source.value,
                    "origin": span.origin,
                    "transforms": span.metadata
                })

            # 4. Detection
            findings = self.detector.scan(spans)
            nonce_detector = NonceDetectionRule(request_nonce)
            for span in spans:
                findings.extend(nonce_detector.scan(span))

            # 5. Policy Decision
            decision = self.policy.evaluate(request_id, findings, transformations)

            # 6. Audit Log
            self.audit_logger.log_decision(decision, request_data)

            return decision

        except Exception as e:
            rid = request_id if request_id else "unknown"
            decision = self.fail_handler.handle_failure(rid, "FirewallPipeline", e)
            self.audit_logger.log_failure(rid, "FirewallPipeline", str(e))
            return decision

    def process_response(self, request_id: str, response_text: str) -> Tuple[bool, Optional[Finding]]:
        """
        Checks LLM output for leakage or dangerous URLs.
        Returns (is_safe, finding).
        """
        finding = self.egress_firewall.scan_output(response_text, request_id)
        if finding:
            return False, finding
        return True, None
