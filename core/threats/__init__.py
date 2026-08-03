"""
Threats sub-package exposing SingleThreat, ThreatState, MockThreatManager, and consistency helpers.
"""

from core.threats.single_threat import SingleThreat, sanitize_threat_consistency
from core.threats.threat_state_model import ThreatState
from core.threats.threat_manager import MockThreatManager

__all__ = [
    "SingleThreat",
    "sanitize_threat_consistency",
    "ThreatState",
    "MockThreatManager",
]
