"""
Regex text parsers and threat keyword extraction logic for Telegram Threat Monitor.
"""

import re
from typing import Optional, List, Set, Dict, Any
from core.regions import ALL_REGIONS

THREAT_KEYWORDS = {
    # Дрони / БПЛА
    "бпла", "бпла!", "шахед", "shahed", "дрон", "безпілотник", "мопед", "балалайк",
    "крило", "орлан", "supercam",
    # Ракети / Балістика
    "ракет", "пуск", "балістик", "балістич", "кинджал", "х-47", "х47м2",
    "міг-31", "міг31", "mig-31", "mig31", "калібр", "іскандер", "крилат",
    "х-101", "х-55", "х-555", "х-22", "х-32", "х-59", "х-69", "с-300", "с-400", "c300", "c400",
    # Авіація
    "су-34", "су-35", "су-30", "су-57", "сушки", "сушка", "су ",
    "ту-95", "ту-22", "ту-160", "ту95", "ту22", "ту160", "міг-29", "міг29", "mig-29", "mig29",
    "борт", "авіац", "зліт", "виліт", "посадка", "підйом", "активність",
    # Бомби / КАБи
    "каб", "кабами", "фаб", "уаб", "авіабомб",
    # Тривоги / Стан
    "тривог", "вибух", "ппо", "повітр", "курс", "напрямк", "загроз",
    "цілі", "ціль", "перехопл", "відбій", "відбої", "чисто", "збит", "зник",
    "відстежен", "маневру", "дорозвідка", "безпечно", "увага", "небезпека", "гучно",
    "приліт", "прильот", "обстріл", "артилерія", "рсзв", "град", "смерч", "ураган"
}


def is_threat_relevant(text: str) -> bool:
    """Quick keyword check to filter out obviously non-threat messages."""
    text_lower = text.lower()
    for kw in THREAT_KEYWORDS:
        if kw in text_lower:
            return True
    return False


def extract_regions_from_text(text: str) -> List[str]:
    """Extract region names matching ALL_REGIONS keywords from text."""
    text_lower = text.lower()
    found_regions = set()
    for region, data in ALL_REGIONS.items():
        for kw in data.get("keywords", []):
            if kw in text_lower:
                found_regions.add(region)
                break
    return list(found_regions)
