"""
SingleThreat model and threat consistency sanitizer.
"""

from datetime import datetime, timezone
import uuid
import re
from typing import Optional

def sanitize_threat_consistency(level: str, detail: Optional[str], is_predictive: bool, eta: Optional[str]) -> tuple[str, Optional[str], bool, Optional[str], bool]:
    """
    Гарантує абсолютну узгодженість між статусом загрози та текстом деталізації.
    Активний переліт через область або знаходження цілі у просторі області є підтвердженою загрозою (is_predictive = False).
    """
    if not detail:
        detail = ""
    
    detail_lower = detail.lower()
    is_active_flight = any(p in detail_lower for p in ["переліт", "через область", "в повітряному просторі", "у повітряному просторі", "в області", "в межах області", "у межах області"])
    
    if is_active_flight:
        is_predictive = False
        if level in ["low", "none"]:
            level = "high"

    if is_predictive:
        if eta == "в області":
            eta = "~15-30 хв"
        clean_detail = detail
        for p in ["в області", "в межах області", "у межах області", "в повітряному просторі"]:
            clean_detail = re.sub(re.escape(p), "у напрямку області", clean_detail, flags=re.IGNORECASE)
        detail = clean_detail
        if level == "critical":
            level = "high"
        
    return level, detail, is_predictive, eta, False


class SingleThreat:
    """Одна конкретна загроза з унікальним ідентифікатором."""

    LEVEL_PRIORITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

    def __init__(self, level: str, threat_type: Optional[str] = None,
                 detail: Optional[str] = None, confidence: Optional[int] = None,
                 eta: Optional[str] = None, is_predictive: bool = False,
                 is_test: bool = False, group_id: Optional[str] = None,
                 paired_event_id: Optional[int] = None,
                 eta_seconds: Optional[int] = None,
                 transit_from: Optional[str] = None,
                 telemetry: Optional[dict] = None,
                 carrier_type: Optional[str] = None,
                 carrier_origin_name: Optional[str] = None,
                 carrier_origin_latitude: Optional[float] = None,
                 carrier_origin_longitude: Optional[float] = None,
                 launch_sector_name: Optional[str] = None,
                 launch_sector_latitude: Optional[float] = None,
                 launch_sector_longitude: Optional[float] = None,
                 target_region: Optional[str] = None,
                 since: Optional[str] = None,
                 last_updated_at: Optional[str] = None):
        if not eta and detail:
            # Автоматично витягуємо розрахований час на прильот (ETA) з тексту деталізації
            m = re.search(r'Очікуваний час:\s*([~0-9\sа-яА-ЯіІїЇєЄ\-\+]+?)(?:\)|\n|$)', detail, re.IGNORECASE)
            if m:
                eta = m.group(1).strip()

        level, detail, is_predictive, eta, _ = sanitize_threat_consistency(level, detail, is_predictive, eta)
        self.threat_id: str = group_id or f"t_{uuid.uuid4().hex[:12]}"
        self.level: str = level
        self.threat_type: Optional[str] = threat_type
        self.detail: Optional[str] = detail
        self.since: str = since or datetime.now(timezone.utc).isoformat()
        self.last_updated_at: str = last_updated_at or self.since
        self.eta: Optional[str] = eta
        self.eta_seconds: Optional[int] = eta_seconds
        self.confidence: Optional[int] = confidence
        self.is_predictive: bool = is_predictive
        self.is_test: bool = is_test
        self.group_id: Optional[str] = group_id
        self.paired_event_id: Optional[int] = paired_event_id
        if transit_from is None and telemetry and isinstance(telemetry, dict):
            transit_from = telemetry.get("transit_from")

        if transit_from is None and detail:
            match = re.search(r'з\s+([А-Яа-яіЇїЄє\s\'-]+?)(?:\s+області|\s+область|\s+РФ|\s+Криму|щини|чини|\s+\()', detail, re.IGNORECASE)
            if match:
                src_text = match.group(1).strip().lower()
                ORIGIN_MAP = {
                    "одес": "Одеська область", "одещ": "Одеська область",
                    "сумск": "Сумська область", "сумськ": "Сумська область", "сумщ": "Сумська область",
                    "харків": "Харківська область", "харківщ": "Харківська область",
                    "чернігів": "Чернігівська область", "чернігівщ": "Чернігівська область",
                    "полтав": "Полтавська область", "полтавщ": "Полтавська область",
                    "дніпро": "Дніпропетровська область", "дніпропетровщ": "Дніпропетровська область",
                    "донецьк": "Донецька область", "донечч": "Донецька область",
                    "луганськ": "Луганська область", "луганщ": "Луганська область",
                    "запоріж": "Запорізька область",
                    "херсон": "Херсонська область", "херсонщ": "Херсонська область",
                    "миколаїв": "Миколаївська область", "миколаївщ": "Миколаївська область",
                    "київ": "Київська область", "київщ": "Київська область",
                    "крим": "АР Крим"
                }
                for stem, reg in ORIGIN_MAP.items():
                    if stem in src_text:
                        transit_from = reg
                        break

        self.transit_from: Optional[str] = transit_from
        self.telemetry: Optional[dict] = telemetry
        self.target_region: Optional[str] = target_region

        # Auto-resolve aviation / missile / drone profile if not explicitly supplied
        from core.threat_types import resolve_aviation_strike_profile
        av_profile = resolve_aviation_strike_profile(threat_type, detail, target_region, transit_from=self.transit_from)
        self.carrier_type: Optional[str] = carrier_type or av_profile.get("carrier_type")
        self.carrier_origin_name: Optional[str] = carrier_origin_name or av_profile.get("carrier_origin_name")
        self.carrier_origin_latitude: Optional[float] = carrier_origin_latitude or av_profile.get("carrier_origin_latitude")
        self.carrier_origin_longitude: Optional[float] = carrier_origin_longitude or av_profile.get("carrier_origin_longitude")
        self.launch_sector_name: Optional[str] = launch_sector_name or av_profile.get("launch_sector_name")
        self.launch_sector_latitude: Optional[float] = launch_sector_latitude or av_profile.get("launch_sector_latitude")
        self.launch_sector_longitude: Optional[float] = launch_sector_longitude or av_profile.get("launch_sector_longitude")

    def apply_confidence_decay(self, amount: int = 10) -> int:
        """Зменшує рівень довіри (confidence) при відсутності нових підтверджень."""
        if self.confidence is None:
            self.confidence = 50
        self.confidence = max(0, self.confidence - amount)
        if self.confidence < 30 and self.level in ["high", "medium"]:
            self.level = "low"
        return self.confidence

    def to_dict(self) -> dict:
        from core.topology import REGION_CENTROIDS
        origin_lat = None
        origin_lon = None
        
        if self.telemetry and isinstance(self.telemetry, dict):
            if self.telemetry.get("origin_latitude") is not None and self.telemetry.get("origin_longitude") is not None:
                origin_lat = self.telemetry["origin_latitude"]
                origin_lon = self.telemetry["origin_longitude"]

        if origin_lat is None and self.transit_from and self.transit_from in REGION_CENTROIDS:
            origin_lat, origin_lon = REGION_CENTROIDS[self.transit_from]

        if origin_lat is None and self.detail:
            SPECIAL_ORIGIN_PATTERNS = {
                "чорн": (45.20, 31.00),
                "акватор": (45.20, 31.00),
                "мор": (45.20, 31.00),
                "чауд": (45.00, 35.83),
                "приморск": (46.04, 38.17),
                "азов": (46.40, 36.50),
                "курск": (51.32, 34.85),
                "брянск": (52.05, 31.50),
                "бєлгород": (50.30, 36.40),
                "белгород": (50.30, 36.40),
            }

            detail_lower = self.detail.lower()
            for key, coords in SPECIAL_ORIGIN_PATTERNS.items():
                if key in detail_lower:
                    origin_lat, origin_lon = coords[0], coords[1]
                    break

        if origin_lat is None and self.launch_sector_latitude is not None and self.launch_sector_longitude is not None:
            origin_lat = self.launch_sector_latitude
            origin_lon = self.launch_sector_longitude

        return {
            "threat_id": self.threat_id,
            "level": self.level,
            "type": self.threat_type,
            "detail": self.detail,
            "since": self.since,
            "last_updated_at": self.last_updated_at,
            "confidence": self.confidence,
            "eta": self.eta,
            "eta_seconds": self.eta_seconds,
            "is_predictive": self.is_predictive,
            "is_test": self.is_test,
            "group_id": self.group_id,
            "paired_event_id": self.paired_event_id,
            "transit_from": self.transit_from,
            "origin_latitude": origin_lat,
            "origin_longitude": origin_lon,
            "carrier_type": self.carrier_type,
            "carrier_origin_name": self.carrier_origin_name,
            "carrier_origin_latitude": self.carrier_origin_latitude,
            "carrier_origin_longitude": self.carrier_origin_longitude,
            "launch_sector_name": self.launch_sector_name,
            "launch_sector_latitude": self.launch_sector_latitude,
            "launch_sector_longitude": self.launch_sector_longitude,
            "telemetry": self.telemetry,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SingleThreat":
        """Відновлення з словника (для load_from_db/file)."""
        t = cls(
            level=data.get("level", "low"),
            threat_type=data.get("type"),
            detail=data.get("detail"),
            confidence=data.get("confidence"),
            eta=data.get("eta"),
            is_predictive=data.get("is_predictive", False),
            is_test=data.get("is_test", False),
            group_id=data.get("group_id"),
            paired_event_id=data.get("paired_event_id"),
            eta_seconds=data.get("eta_seconds"),
            transit_from=data.get("transit_from"),
            carrier_type=data.get("carrier_type"),
            carrier_origin_name=data.get("carrier_origin_name"),
            carrier_origin_latitude=data.get("carrier_origin_latitude"),
            carrier_origin_longitude=data.get("carrier_origin_longitude"),
            launch_sector_name=data.get("launch_sector_name"),
            launch_sector_latitude=data.get("launch_sector_latitude"),
            launch_sector_longitude=data.get("launch_sector_longitude"),
        )
        t.threat_id = data.get("threat_id", t.threat_id)
        t.since = data.get("since", t.since)
        t.last_updated_at = data.get("last_updated_at", t.last_updated_at)
        return t
