from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
import uuid

class SourceType(Enum):
    SYSTEM = "SYSTEM"
    USER = "USER"
    DATA = "DATA"
    TOOL = "TOOL"
    MODEL = "MODEL"

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Decision(Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"

@dataclass
class ContentSpan:
    source: SourceType
    origin: str
    original: str
    normalized: str = ""
    tainted: bool = False
    metadata: List[str] = field(default_factory=list)

@dataclass
class Finding:
    rule_id: str
    category: str
    severity: Severity
    confidence: float
    evidence: str
    source: SourceType
    location: int
    request_id: Optional[str] = None

@dataclass
class FirewallDecision:
    request_id: str
    decision: Decision
    score: float
    findings: List[Finding]
    transformations: List[Dict[str, Any]]
    reason: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
