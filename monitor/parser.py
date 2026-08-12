"""
Text cleaning and regex parsing utilities for Telegram threat monitor.
"""

import re
from typing import List


def clean_user_facing_threat_detail(text: str) -> str:
    """Sanitizes raw telegram message text for display to end-users."""
    if not text:
        return ""
    # Remove brackets like [AI], [Telegram], [kpszsu]
    text = re.sub(r'\[[A-Za-z0-9_.\-\s]+\]', '', text)
    # Remove Telegram handles @monitoring_channel
    text = re.sub(r'@[A-Za-z0-9_]+', '', text)
    # Remove URLs
    text = re.sub(r'https?://\S+', '', text)
    # Replace references to AI / ШІ with system
    text = re.sub(r'(?i)\bШІ\b', 'системи', text)
    text = re.sub(r'(?i)\bAI\b', 'системи', text)
    # Clean up double spaces or leading/trailing whitespace
    text = re.sub(r' +', ' ', text).strip()
    return text


def extract_keywords(text: str, keywords: List[str]) -> bool:
    """Checks if any keyword matches as a word boundary in text."""
    if not text or not keywords:
        return False
    text_lower = text.lower()
    for kw in keywords:
        if kw.lower() in text_lower:
            return True
    return False


def extract_threat_type(text: str) -> str:
    """Extracts threat type category from raw message text."""
    if not text:
        return "unknown"
    text_lower = text.lower()
    if any(kw in text_lower for kw in ["міг-31к", "міг31к", "mig-31k", "mig31k", "міг31", "кінджал", "кинджал"]):
        return "mig31k"
    if any(kw in text_lower for kw in ["ту-95", "ту95", "tu-95", "tu95", "ту-22", "ту22", "tu-22", "tu22", "ту-160", "tu160"]):
        return "tu95"
    if any(kw in text_lower for kw in ["шахед", "shahed", "бпла", "дрон", "мопед", "гербер", "орлан", "supercam", "крило"]):
        return "shahed"
    if any(kw in text_lower for kw in ["іскандер", "iskander"]):
        return "iskander"
    if any(kw in text_lower for kw in ["балісти", "с-300", "с300", "с-400", "с400", "c-300", "c300", "c-400", "c400"]):
        return "ballistic"
    if any(kw in text_lower for kw in ["ракет", "крилат", "калібр", "х-101", "х101", "х-55", "х55", "х-555", "х555", "х-59", "х59", "х-69", "х69"]):
        return "cruise_missile"
    if any(kw in text_lower for kw in ["артилерія", "рсзв", "обстріл", "град", "смерч", "ураган", "міномет"]):
        return "artillery"
    if re.search(r"\bкаб(и|ів)?\b|авіабомб|фаб|уаб", text_lower) or any(kw in text_lower for kw in ["су-34", "су-35", "су-30", "су-57", "сушка", "сушки"]):
        return "kab"
    return "unknown"


def extract_regions(text: str, all_regions: dict) -> List[str]:
    """Resolves regions from explicit names, keywords, and macro-direction terms."""
    if not text:
        return []
    found = set()
    for region, info in all_regions.items():
        for kw in info.get("keywords", []):
            if re.search(kw, text, re.IGNORECASE):
                found.add(region)
                
    text_lower = text.lower()
    west_regions = ["Львівська область", "Волинська область", "Рівненська область", "Тернопільська область", "Хмельницька область", "Івано-Франківська область", "Закарпатська область", "Чернівецька область"]
    north_regions = ["Київська область", "м. Київ", "Чернігівська область", "Сумська область", "Житомирська область"]
    center_regions = ["Черкаська область", "Кіровоградська область", "Полтавська область", "Вінницька область", "Дніпропетровська область"]
    south_regions = ["Одеська область", "Миколаївська область", "Херсонська область", "Запорізька область"]
    east_regions = ["Харківська область", "Донецька область", "Дніпропетровська область", "Запорізька область"]

    if re.search(r"\bзахідн\w*\b|\bзаході\b|\bзахід\b", text_lower):
        if not any(landing_kw in text_lower for landing_kw in ["посадка", "захід на посадку"]):
            for r in west_regions:
                found.add(r)
                
    if re.search(r"\bпівнічн\w*\b|\bпівночі\b|\bпівніч\b", text_lower):
        for r in north_regions:
            found.add(r)
            
    if re.search(r"\bцентральн\w*\b|\bцентрі\b|\bцентр\b", text_lower):
        if not any(skip in text_lower for skip in ["прес-центр", "інфо-центр"]):
            for r in center_regions:
                found.add(r)
                
    if re.search(r"\bпівденн\w*\b|\bпівдні\b|\bпівдень\b", text_lower):
        for r in south_regions:
            found.add(r)
            
    if re.search(r"\bсхідн\w*\b|\bсході\b|\bсхід\b", text_lower):
        for r in east_regions:
            found.add(r)
            
    return list(found)

