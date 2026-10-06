import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid
import os
from backend.app.models.core import FirewallDecision, Finding

class AuditLogger:
    """
    Handles secure logging of all firewall requests and decisions.
    Ensures a complete audit trail for security analysis.
    """
    def __init__(self, log_file: str = "firewall_audit.log"):
        self.log_file = log_file
        log_dir = os.path.dirname(os.path.abspath(log_file))
        os.makedirs(log_dir, exist_ok=True)
        self.logger = logging.getLogger(f"FirewallAudit_{log_file}")
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            handler = logging.FileHandler(log_file)
            formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def close(self):
        """Closes the file handlers to allow file deletion in tests."""
        for handler in self.logger.handlers[:]:
            handler.close()
            self.logger.removeHandler(handler)

    def log_decision(self, decision: FirewallDecision, original_request: Dict[str, Any]):
        """
        Logs a complete firewall transaction.
        Sensitive data is handled by logging only the request_id and metadata.
        """
        log_entry = {
            "request_id": decision.request_id,
            "timestamp": decision.timestamp.isoformat(),
            "decision": decision.decision.value,
            "score": decision.score,
            "reason": decision.reason,
            "findings_count": len(decision.findings),
            "findings": [
                {
                    "rule": f.rule_id,
                    "cat": f.category,
                    "sev": f.severity.value,
                    "src": f.source.value
                } for f in decision.findings
            ],
            "transformations": [t.get("type", "unknown") for t in decision.transformations]
        }

        self.logger.info(f"DECISION_EVENT | {log_entry}")

    def log_failure(self, request_id: str, component: str, error: str):
        """Logs a system failure that triggered a fail-closed block."""
        self.logger.error("SYSTEM_FAILURE | request_id=%s | component=%s | error_type=%s", request_id, component, type(error).__name__)
