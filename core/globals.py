"""
SirenUA Global Managers Registry.
Holds singleton instances of managers to prevent circular dependency loops.
"""

from core.threat_state import MockThreatManager
from database.shelter_manager import ShelterManager

threat_manager = MockThreatManager()
shelter_manager = ShelterManager()

# Will be initialized at runtime in server.py if running in live mode
telegram_monitor = None
