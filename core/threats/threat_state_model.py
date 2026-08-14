"""
ThreatState regional threat container model.
"""

from typing import Optional
from datetime import datetime, timezone

from core.threats.single_threat import SingleThreat


class ThreatState:
    """Стан загроз для однієї області (підтримка множинних загроз)."""

    DEDUP_WINDOW_SECONDS = 300

    def __init__(self, region_name: str = ""):
        self.region_name = region_name
        self.active_threats: list[SingleThreat] = []
        self._is_official_active: bool = (region_name in ["АР Крим", "Автономна Республіка Крим", "м. Севастополь"])
        self.is_test: bool = False

    @property
    def region(self) -> str:
        return self.region_name

    @property
    def is_active(self) -> bool:
        """Повертає True ТІЛЬКИ якщо активна офіційна тривога або це АР Крим/Луганщина (офіційні червоні зони)."""
        if self.region_name in ["АР Крим", "Автономна Республіка Крим", "м. Севастополь", "Луганська область"]:
            return True
        return self._is_official_active

    @is_active.setter
    def is_active(self, value: bool):
        self._is_official_active = value

    @property
    def level(self) -> str:
        """Найвищий рівень серед усіх активних загроз."""
        if not self.active_threats:
            return "none"
        return max(self.active_threats,
                   key=lambda t: SingleThreat.LEVEL_PRIORITY.get(t.level, 0)).level

    @property
    def threat_type(self) -> Optional[str]:
        """Тип primary (найновішої) загрози."""
        return self.active_threats[-1].threat_type if self.active_threats else None

    @property
    def detail(self) -> Optional[str]:
        """Detail primary загрози."""
        return self.active_threats[-1].detail if self.active_threats else None

    @property
    def since(self) -> Optional[str]:
        """Час найновішої загрози."""
        return self.active_threats[-1].since if self.active_threats else None

    @property
    def confidence(self) -> Optional[int]:
        """Confidence primary загрози."""
        return self.active_threats[-1].confidence if self.active_threats else None

    @property
    def eta(self) -> Optional[str]:
        """ETA primary загрози."""
        return self.active_threats[-1].eta if self.active_threats else None

    @property
    def is_predictive(self) -> bool:
        return self.active_threats[-1].is_predictive if self.active_threats else False

    def clear(self):
        self.active_threats.clear()
        self._is_official_active = False
        self.is_test = False

    def clear_by_group_id(self, group_id: str) -> Optional[SingleThreat]:
        for i, t in enumerate(self.active_threats):
            if t.group_id == group_id:
                return self.active_threats.pop(i)
        return None

    def clear_by_type(self, threat_type: str) -> Optional[SingleThreat]:
        for i, t in enumerate(self.active_threats):
            if t.threat_type == threat_type:
                return self.active_threats.pop(i)
        return None

    def to_dict(self) -> dict:
        """Серіалізація — зворотно-сумісний формат + масив active_threats."""
        primary = self.active_threats[-1] if self.active_threats else None
        return {
            "level": self.level,
            "type": primary.threat_type if primary else None,
            "detail": primary.detail if primary else None,
            "since": primary.since if primary else None,
            "confidence": primary.confidence if primary else None,
            "eta": primary.eta if primary else None,
            "is_predictive": self.is_predictive,
            "is_active": self.is_active,
            "is_test": self.is_test,
            "active_threats": [t.to_dict() for t in self.active_threats],
        }

    def load_from_dict(self, data: dict):
        self._is_official_active = data.get("is_official_alarm", data.get("is_active", False))
        self.is_test = data.get("is_test", False)
        if "active_threats" in data:
            self.active_threats = [SingleThreat.from_dict(t) for t in data["active_threats"]]
        else:
            self.active_threats = []
            level = data.get("level", "none")
            if level != "none":
                t = SingleThreat(
                    level=level,
                    threat_type=data.get("type"),
                    detail=data.get("detail"),
                    confidence=data.get("confidence"),
                    eta=data.get("eta"),
                    is_predictive=data.get("is_predictive", False),
                    is_test=self.is_test
                )
                if data.get("since"):
                    t.since = data["since"]
                self.active_threats.append(t)

    def _update_existing_threat(self, existing: SingleThreat, level: str, detail: Optional[str],
                                confidence: Optional[int], eta: Optional[str],
                                eta_seconds: Optional[int], is_predictive: bool,
                                telemetry: Optional[dict] = None) -> bool:
        """Updates properties of an existing SingleThreat if they changed and shifts coordinate history."""
        changed = False
        existing.last_updated_at = datetime.now(timezone.utc).isoformat()
        
        if existing.level != level:
            existing.level = level
            changed = True
        if detail and existing.detail != detail:
            existing.detail = detail
            changed = True
        if confidence is not None and existing.confidence != confidence:
            existing.confidence = confidence
            changed = True
        if eta and existing.eta != eta:
            existing.eta = eta
            changed = True
        if eta_seconds is not None and existing.eta_seconds != eta_seconds:
            existing.eta_seconds = eta_seconds
            changed = True
        if existing.is_predictive != is_predictive:
            existing.is_predictive = is_predictive
            changed = True

        if telemetry and isinstance(telemetry, dict):
            new_lat = telemetry.get("last_checkpoint_latitude") or telemetry.get("target_latitude") or telemetry.get("origin_latitude")
            new_lon = telemetry.get("last_checkpoint_longitude") or telemetry.get("target_longitude") or telemetry.get("origin_longitude")
            if new_lat is not None and new_lon is not None:
                if existing.telemetry is None:
                    existing.telemetry = {}
                if "last_checkpoint_latitude" in existing.telemetry:
                    existing.telemetry["origin_latitude"] = existing.telemetry["last_checkpoint_latitude"]
                    existing.telemetry["origin_longitude"] = existing.telemetry["last_checkpoint_longitude"]
                existing.telemetry["last_checkpoint_latitude"] = new_lat
                existing.telemetry["last_checkpoint_longitude"] = new_lon
                changed = True

        return changed

    def set_threat(self, level: str, threat_type: Optional[str] = None,
                   detail: Optional[str] = None, confidence: Optional[int] = None,
                   eta: Optional[str] = None, is_predictive: bool = False,
                   is_test: bool = False, group_id: Optional[str] = None,
                   eta_seconds: Optional[int] = None,
                   telemetry: Optional[dict] = None,
                   since: Optional[str] = None) -> bool:
        if self.region_name in ["АР Крим", "Автономна Республіка Крим", "м. Севастополь"]:
            return False

        if level == "none":
            if threat_type == "official_alarm":
                self._is_official_active = False
            if threat_type:
                self.clear_by_type(threat_type)
            else:
                self.clear()
            return True

        self.is_test = is_test
        if threat_type == "official_alarm":
            self._is_official_active = True

        if group_id:
            for existing in self.active_threats:
                if existing.group_id == group_id:
                    return self._update_existing_threat(
                        existing, level, detail, confidence, eta, eta_seconds, is_predictive
                    )

        for existing in self.active_threats:
            if existing.threat_type == threat_type and existing.level != "none":
                return self._update_existing_threat(
                    existing, level, detail, confidence, eta, eta_seconds, is_predictive
                )

        new_threat = SingleThreat(
            level=level,
            threat_type=threat_type,
            detail=detail,
            confidence=confidence,
            eta=eta,
            is_predictive=is_predictive,
            is_test=is_test,
            group_id=group_id,
            eta_seconds=eta_seconds,
            target_region=self.region,
            since=since,
        )
        self.active_threats.append(new_threat)
        return True
