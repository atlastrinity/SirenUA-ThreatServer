"""
SirenUA Core Configuration.
Defines environment mode flags, API credentials, file paths, and parsing keywords.
"""

import os
import sys
import logging

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Configure global logging format and level
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    stream=sys.stdout
)
logger = logging.getLogger("sirenua")

# Live Mode vs Mock Mode
IS_LIVE_MODE = "--live" in sys.argv or os.environ.get("LIVE_MODE", "false").lower() == "true"

# Database Configuration
DB_PATH = "threat_analytics.db"
if os.path.exists("threat_server"):
    DB_PATH = "threat_server/threat_analytics.db"

# API Credentials (for Telegram Telethon API client)
TELEGRAM_API_ID = int(os.environ.get("TELEGRAM_API_ID", 20294647))
TELEGRAM_API_HASH = os.environ.get("TELEGRAM_API_HASH", "454a9c055308a8d118608bb6b032bc30")

# Ngrok Domain Configuration
NGROK_DOMAIN = os.environ.get("NGROK_DOMAIN", "bobbing-armchair-daylong.ngrok-free.dev")
NGROK_URL = os.environ.get("NGROK_URL", f"https://{NGROK_DOMAIN}")

# Target Telegram channels to monitor
TARGET_CHANNELS = [
    "kpszsu",            # Повітряні Сили ЗСУ
    "monitorwarr",       # Найшвидша аналітика радарів
    "vanek_nikolaev",    # Николаевский Ванек
    "eRadarrua",         # eРадар (ОСІНТ радари)
    "operativnoZSU"      # Оперативно ЗСУ
]

# Threat Keywords (Refined for >90% Siren Correlation)
CRITICAL_KEYWORDS = [
    r"масований\s*(ракетний\s*)?удар", 
    r"масований\s*обстріл", 
    r"комбінований\s*удар",
    r"крилаті\s*ракети\s*в\s*повітряному\s*просторі"
]

HIGH_KEYWORDS = [
    r"МіГ[-\s]?31", 
    r"Кинджал", 
    r"Ту[-\s]?95", 
    r"Ту[-\s]?22", 
    r"Ту[-\s]?160",
    r"стратегічн\w+\s*авіаці", 
    r"крилат\w+\s*ракет", 
    r"[ХX][-\s]?101",
    r"[ХX][-\s]?555", 
    r"Калібр", 
    r"Іскандер", 
    r"балісти",            # Matches "балістика", "балістичний", "балістики" (99% chance of siren)
    r"пуски?\s*ракет",
    r"ракет[аи]\s*(в\s*напрямку|на)",  # Missile heading directly towards a region
    r"керована\s*авіаційна\s*ракета",
    r"[ХX][-\s]?59",
    r"[ХX][-\s]?69",
    r"\bукритт[яі]\b",
    r"\bтривог[аи]\b"
]

MEDIUM_KEYWORDS = [
    r"[ШШ]ахед", 
    r"Shahed", 
    r"БПЛА", 
    r"безпілотни", 
    r"дрон", 
    r"БпЛА", 
    r"мопед",
    r"ударн\w+\s*бпла"
]

LOW_KEYWORDS = [
    r"зліт\s*(тактичної|су|міг-29)", 
    r"підйом\s*авіаці", 
    r"активність\s*авіаці", 
    r"загроза\s*застосування\s*каб",
    r"пусти\s*каб",
    r"каб\s*в\s*напрямку",
    r"\bкаб(и|ів)?\b",
    r"пуск\w*\s*каб[и]?",
    r"керован\w*\s*авіаційн\w*\s*бомб\w*"
]

CLEAR_KEYWORDS = [
    r"відбій", 
    r"загроз\w*\s*нема", 
    r"загроз\w*\s*відсутн", 
    r"збит[оіа]", 
    r"знищен[оіа]", 
    r"посадка", 
    r"чисто", 
    r"дорозвідка"
]


def get_kyiv_tz_offset() -> str:
    """Returns Kyiv timezone offset string (+02:00 or +03:00) for SQLite queries."""
    from datetime import datetime
    import zoneinfo
    try:
        kyiv_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        offset = datetime.now(kyiv_tz).utcoffset()
        hours = int(offset.total_seconds() // 3600)
        return f"+{hours:02d}:00"
    except Exception:
        return "+03:00"


def get_kyiv_tz_modifier() -> str:
    """Returns Kyiv timezone modifier for SQLite datetime functions e.g. '+3 hours'."""
    from datetime import datetime
    import zoneinfo
    try:
        kyiv_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        offset = datetime.now(kyiv_tz).utcoffset()
        hours = int(offset.total_seconds() // 3600)
        return f"+{hours} hours"
    except Exception:
        return "+3 hours"

