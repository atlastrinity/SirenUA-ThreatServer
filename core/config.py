"""
SirenUA Core Configuration.
Defines environment mode flags, API credentials, file paths, and parsing keywords.
"""

import os
import sys

# Live Mode vs Mock Mode
IS_LIVE_MODE = "--live" in sys.argv or os.environ.get("LIVE_MODE", "false").lower() == "true"

# Database Configuration
DB_PATH = "threat_analytics.db"
if os.path.exists("threat_server"):
    DB_PATH = "threat_server/threat_analytics.db"

# API Credentials (for Telegram Telethon API client)
TELEGRAM_API_ID = int(os.environ.get("TELEGRAM_API_ID", 20294647))
TELEGRAM_API_HASH = os.environ.get("TELEGRAM_API_HASH", "454a9c055308a8d118608bb6b032bc30")

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
