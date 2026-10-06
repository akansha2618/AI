import re
from typing import List, Optional
from backend.app.models.core import ContentSpan, Finding, Severity, SourceType

class DetectionRule:
    """Base class for a detection rule."""
    def __init__(self, rule_id: str, category: str, severity: Severity, pattern: str, description: str):
        self.rule_id = rule_id
        self.category = category
        self.severity = severity
        self.pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        self.description = description

    def scan(self, span: ContentSpan) -> List[Finding]:
        findings = []
        # Scan the normalized view
        for match in self.pattern.finditer(span.normalized):
            findings.append(Finding(
                rule_id=self.rule_id,
                category=self.category,
                severity=self.severity,
                confidence=1.0, # Rule-based is high confidence
                evidence=match.group(),
                source=span.source,
                location=match.start()
            ))
        return findings

class DetectionEngine:
    """
    Observational engine that scans ContentSpans for malicious patterns.
    Produces Findings but does NOT make blocking decisions.
    """

    def __init__(self):
        # Define the core rule set based on the architecture
        self.rules = [
            # Instruction Overrides
            DetectionRule(
                "IO-001", "INSTRUCTION_OVERRIDE", Severity.HIGH,
                r"(ignore|disregard|forget|override|bypass)\s+(all\s+)?(previous|system|developer|hidden|safety)\s+(instructions|rules|prompt|message|guidelines|filters)",
                "Attempt to override higher-priority instructions"
            ),
            DetectionRule(
                "IO-002", "INSTRUCTION_OVERRIDE", Severity.MEDIUM,
                r"do\s+not\s+(follow|obey)\s+(any\s+)?(previous\s+)?rules",
                "Direct command to stop following rules"
            ),
            DetectionRule(
                "IO-003", "INSTRUCTION_OVERRIDE", Severity.HIGH,
                r"ignore\s+(the\s+)?(user|human|user's request)\b",
                "Attempt to redirect the assistant away from the user's request"
            ),

            # Role Manipulation
            DetectionRule(
                "RM-001", "ROLE_MANIPULATION", Severity.HIGH,
                r"(you\s+are\s+now|act\s+as|pretend\s+to\s+be|become)\s+(an?\s+)?(unrestricted|unfiltered|developer|administrator|DAN|jailbroken|god-mode)",
                "Attempt to assume an unrestricted persona"
            ),
            DetectionRule(
                "RM-002", "ROLE_MANIPULATION", Severity.HIGH,
                r"break\s+all\s+rules|disable\s+all\s+safeguards",
                "Direct attempt to disable safety filters"
            ),
            DetectionRule(
                "RM-003", "ROLE_MANIPULATION", Severity.MEDIUM,
                r"enter\s+(developer|admin|god)\s+mode",
                "Attempt to enter a privileged mode"
            ),

            # System Prompt Extraction
            DetectionRule(
                "SP-001", "SYSTEM_PROMPT_EXTRACTION", Severity.HIGH,
                r"(reveal|show|print|output|tell\s+me|display)\s+.*?(system\s+prompt|hidden\s+instructions|developer\s+message|internal\s+rules|instructions\s+above|your\s+rules|internal\s+developer\s+rules)",
                "Attempt to extract the system prompt"
            ),
            DetectionRule(
                "SP-002", "SYSTEM_PROMPT_EXTRACTION", Severity.MEDIUM,
                r"what\s+are\s+your\s+(instructions|rules|guidelines)",
                "General inquiry into internal instructions"
            ),

            # Obfuscation (Looking for remnants of obfuscation in normalized text)
            DetectionRule(
                "OB-001", "OBFUSCATION_ENCODING", Severity.LOW,
                r"(\[DECODING_FAILED\]|\\x[0-9a-fA-F]{2})",
                "Presence of failed or partial obfuscation patterns"
            ),
        ]

    def scan(self, spans: List[ContentSpan]) -> List[Finding]:
        """
        Scans all provided spans and returns a consolidated list of findings.
        """
        all_findings = []
        for span in spans:
            for rule in self.rules:
                findings = rule.scan(span)

                # Taint escalation: if untrusted DATA/TOOL content matches a rule,
                # increase severity because it may be an indirect injection.
                if span.tainted:
                    for f in findings:
                        f.severity = self._escalate_severity(f.severity)

                # Obfuscated payloads that decode into a matched attack are a strong
                # evasion signal. Likewise for instruction text hidden with bidi or
                # zero-width controls. Escalate only when a rule actually matched.
                evasion_transforms = {"base64_decode", "url_decode", "hex_decode", "invisible_char_removal", "bidi_char_removal"}
                for f in findings:
                    if evasion_transforms.intersection(span.metadata):
                        f.severity = Severity.CRITICAL
                    if f.rule_id == "RM-001" and re.search(r"\b(unrestricted|unfiltered|DAN|jailbroken|god-mode)\b", f.evidence, re.IGNORECASE):
                        f.severity = Severity.CRITICAL
                    if f.rule_id == "SP-001":
                        f.severity = Severity.CRITICAL

                all_findings.extend(findings)

        return all_findings

    def _escalate_severity(self, severity: Severity) -> Severity:
        """Increases severity for tainted content."""
        escalation_map = {
            Severity.LOW: Severity.MEDIUM,
            Severity.MEDIUM: Severity.HIGH,
            Severity.HIGH: Severity.CRITICAL,
            Severity.CRITICAL: Severity.CRITICAL
        }
        return escalation_map.get(severity, severity)
