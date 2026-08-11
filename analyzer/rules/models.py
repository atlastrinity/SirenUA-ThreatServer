"""
Data structures and Enums for Gemini Rules Engine.
"""

from enum import Enum
from dataclasses import dataclass
from typing import Optional, Dict, Any, List


class RuleType(str, Enum):
    ROUTE_PATTERN = "route_pattern"
    CONFIDENCE_CORRECTION = "confidence_correction"
    TIME_PATTERN = "time_pattern"
    ETA_MATH = "eta_math"
    LAUNCH_HUB = "launch_hub"


@dataclass
class GeminiRule:
    id: Optional[int] = None
    rule_type: str = "route_pattern"
    source_region: Optional[str] = None
    target_region: Optional[str] = None
    threat_type: Optional[str] = None
    rule_text: str = ""
    rule_json: Optional[Dict[str, Any]] = None
    evidence_count: int = 0
    accuracy_score: float = 1.0
    is_active: bool = True
    updated_at: Optional[str] = None


@dataclass
class RuleAuditLogEntry:
    id: Optional[int] = None
    action: str = "created"
    rule_type: Optional[str] = None
    rule_text: Optional[str] = None
    source_region: Optional[str] = None
    target_region: Optional[str] = None
    threat_type: Optional[str] = None
    reason: Optional[str] = None
    timestamp: Optional[str] = None
