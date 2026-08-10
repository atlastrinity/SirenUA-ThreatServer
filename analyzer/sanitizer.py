"""
Robust JSON parsing and sanitization utilities for Gemini API responses.
"""

import json
import re
from typing import Any, List, Dict, Optional


def clean_json_markdown(text: str) -> str:
    """Removes markdown code fences (```json ... ```) and leading/trailing whitespace."""
    if not text:
        return ""
    
    cleaned = text.strip()
    
    # Strip markdown block wrappers
    if cleaned.startswith("```json"):
        cleaned = cleaned.split("```json", 1)[1]
    elif cleaned.startswith("```"):
        cleaned = cleaned.split("```", 1)[1]
        
    if cleaned.endswith("```"):
        cleaned = cleaned.rsplit("```", 1)[0]
        
    return cleaned.strip()


def parse_gemini_json(text: str) -> Optional[Any]:
    """Attempts to clean and parse JSON returned from Gemini model calls.
    Returns parsed object or None if parsing fails."""
    cleaned = clean_json_markdown(text)
    if not cleaned:
        return None
        
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        # Fallback: try to extract JSON array using regex
        match = re.search(r'\[\s*\{.*\}\s*\]', cleaned, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
                
        # Fallback: try to extract JSON object using regex
        match_obj = re.search(r'\{\s*".*"\s*:.*\}', cleaned, re.DOTALL)
        if match_obj:
            try:
                return json.loads(match_obj.group(0))
            except json.JSONDecodeError:
                pass
                
        return None
