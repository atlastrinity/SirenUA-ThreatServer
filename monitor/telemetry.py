"""
Telemetry calculation utilities for Telegram threat monitor.
"""

from datetime import datetime


def get_time_of_day_modifier(threat_type: str) -> int:
    """Returns a confidence modifier based on current time of day in Kyiv timezone and threat type.
    Night attacks with shaheds are statistically more common → boost confidence."""
    try:
        import zoneinfo
        kyiv_tz = zoneinfo.ZoneInfo("Europe/Kiev")
    except ImportError:
        return 0
    
    hour = datetime.now(kyiv_tz).hour
    
    # Shaheds predominantly attack at night (22:00-06:00)
    if threat_type == "shahed":
        if 22 <= hour or hour < 6:
            return 5  # Night shahed attack — boost
        elif 6 <= hour < 9:
            return 2  # Early morning — still possible
        else:
            return -3  # Daytime shahed — less likely
    
    # Ballistic and cruise missiles — any time, slight daytime bias
    if threat_type in ("ballistic", "iskander", "cruise_missile"):
        if 5 <= hour < 8:
            return 3  # Dawn attacks are historically common
        return 0
    
    # KABs — primarily daytime (requires visual targeting)
    if threat_type == "kab":
        if 7 <= hour < 17:
            return 3  # Daytime — prime KAB window
        else:
            return -4  # Night — unlikely for KABs
    
    return 0


def get_default_auto_clear_delay(threat_type: str) -> int:
    """Returns standard auto-clear timeout in seconds for a given threat type."""
    delays = {
        "mig31k": 1800,
        "ballistic": 600,
        "kab": 1200,
        "shahed": 10800,
        "cruise_missile": 2700,
        "tu95": 5400,
        "iskander": 1200,
        "artillery": 1800,
    }
    return delays.get(threat_type, 3600)
