"""
SirenUA Threat State Facade.
Re-exports SingleThreat, ThreatState, and MockThreatManager from core.threats for full backward compatibility.
"""

from core.threats import (
    SingleThreat,
    sanitize_threat_consistency,
    ThreatState,
    MockThreatManager,
)

__all__ = [
    "SingleThreat",
    "sanitize_threat_consistency",
    "ThreatState",
    "MockThreatManager",
]
