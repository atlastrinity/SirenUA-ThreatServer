"""
SirenUA Threat State Compatibility Re-exporter.
Re-exports SingleThreat, ThreatState, MockThreatManager, and THREAT_TYPES from modular packages.
"""

from core.threat_types import THREAT_TYPES
from core.threats.single_threat import SingleThreat, sanitize_threat_consistency
from core.threats.threat_state_model import ThreatState
from core.threats.threat_manager import MockThreatManager

__all__ = [
    "THREAT_TYPES",
    "SingleThreat",
    "sanitize_threat_consistency",
    "ThreatState",
    "MockThreatManager",
]
