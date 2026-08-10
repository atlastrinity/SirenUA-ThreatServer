"""
Text cleaning and regex parsing utilities for Telegram threat monitor.
"""

import re
from typing import List, Tuple, Optional


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
