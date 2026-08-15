"""
ThreatState regional threat container model.
"""

from typing import Optional
from datetime import datetime, timezone
import uuid
import re

from core.threats.single_threat import SingleThreat


def _parse_iso_time(iso_str: Optional[str]) -> Optional[datetime]:
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _extract_group_signature(detail: Optional[str], telemetry: Optional[dict]) -> tuple[Optional[str], set[str], Optional[int]]:
    """
    Extracts group/wave signature: (group_marker, target_cities_set, wave_number).
    """
    group_marker = None
    target_cities = set()
    wave_number = None

    if telemetry and isinstance(telemetry, dict):
        if telemetry.get("wave_number"):
            try:
                wave_number = int(telemetry["wave_number"])
            except (ValueError, TypeError):
                pass
        cities = telemetry.get("final_target_cities") or []
        if isinstance(cities, list):
            for c in cities:
                if isinstance(c, str) and c.strip():
                    target_cities.add(c.strip().lower())

    if detail:
        detail_lower = detail.lower()
        # Check for explicit group markers
        m = re.search(
            r'(?:(\d+)[-–—\s]*(?:ша|га|я|та|ва|а)?\s*(?:група|хвиля)|(?:група|хвиля)\s*№?\s*(\d+)|нова\s*група|ще\s*(?:одна\s*)?група|чергова\s*група|інша\s*група|повторн(?:і|ий)\s*пуск)',
            detail_lower
        )
        if m:
            num = m.group(1) or m.group(2)
            if num:
                group_marker = f"group_{num}"
            else:
                group_marker = "new_group"

        # Look for sub-targets / cities in text
        KNOWN_TACTICAL_TARGETS = [
            "ізмаїл", "измаил", "білгород", "белгород-днестровск", "чорноморськ", "черноморск",
            "южне", "южний", "подільськ", "подольск", "одеса", "одесс",
            "кривий ріг", "нікополь", "павлоград", "дніпро", "дніпропетровськ",
            "квіткове", "умань", "черкаси", "сміла", "конотоп", "шостка", "суми",
            "охтирка", "лубни", "миргород", "полтава", "кременчук", "старокостянтинів",
            "шепетівка", "хмельницьк", "дубно", "рівне", "луцьк", "ковель",
            "стрий", "дрогобич", "львів", "яворів", "чугуїв", "харків", "куп'янськ",
            "ізюм", "балаклія", "лозова", "краматорськ", "слов'янськ", "покровськ",
            "мирноград", "запоріжжя", "дніпрорудне", "херсон", "берислав", "миколаїв",
            "очаків", "вознесенськ", "первомайськ", "біла церква", "бориспіль", "бровари",
            "васильків", "обухів", "ірпінь", "буча", "київ"
        ]
        for t in KNOWN_TACTICAL_TARGETS:
            if t in detail_lower:
                target_cities.add(t)

    return group_marker, target_cities, wave_number


class ThreatState:
    """Стан загроз для однієї області (підтримка множинних загроз)."""

    DEDUP_WINDOW_SECONDS = 300

    def __init__(self, region_name: str = ""):
        self.region_name = region_name
        self.active_threats: list[SingleThreat] = []
        self._is_official_active: bool = (region_name in ["АР Крим", "Автономна Республіка Крим", "м. Севастополь"])
        self.official_alert_type: Optional[str] = None
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
        """Тип primary (найвищого пріоритету) загрози."""
        if not self.active_threats:
            return None
        highest = max(self.active_threats, key=lambda t: SingleThreat.LEVEL_PRIORITY.get(t.level, 0))
        return highest.threat_type

    @property
    def detail(self) -> Optional[str]:
        """Detail primary загрози."""
        if not self.active_threats:
            return None
        highest = max(self.active_threats, key=lambda t: SingleThreat.LEVEL_PRIORITY.get(t.level, 0))
        return highest.detail

    @property
    def since(self) -> Optional[str]:
        """Час найновішої загрози."""
        return self.active_threats[-1].since if self.active_threats else None

    @property
    def confidence(self) -> Optional[int]:
        """Confidence primary загрози."""
        if not self.active_threats:
            return None
        highest = max(self.active_threats, key=lambda t: SingleThreat.LEVEL_PRIORITY.get(t.level, 0))
        return highest.confidence

    @property
    def eta(self) -> Optional[str]:
        """ETA primary загрози."""
        if not self.active_threats:
            return None
        highest = max(self.active_threats, key=lambda t: SingleThreat.LEVEL_PRIORITY.get(t.level, 0))
        return highest.eta

    @property
    def is_predictive(self) -> bool:
        if not self.active_threats:
            return False
        highest = max(self.active_threats, key=lambda t: SingleThreat.LEVEL_PRIORITY.get(t.level, 0))
        return highest.is_predictive

    def clear(self):
        self.active_threats.clear()
        self._is_official_active = False
        self.official_alert_type = None
        self.is_test = False

    def clear_by_group_id(self, group_id: str) -> Optional[SingleThreat]:
        for i, t in enumerate(self.active_threats):
            if t.group_id == group_id:
                return self.active_threats.pop(i)
        return None

    def clear_by_type(self, threat_type: str) -> Optional[SingleThreat]:
        removed = None
        indices_to_remove = [i for i, t in enumerate(self.active_threats) if t.threat_type == threat_type]
        for i in reversed(indices_to_remove):
            removed = self.active_threats.pop(i)
        return removed

    def to_dict(self) -> dict:
        """Серіалізація — зворотно-сумісний формат + масив active_threats."""
        primary = None
        if self.active_threats:
            primary = max(self.active_threats, key=lambda t: SingleThreat.LEVEL_PRIORITY.get(t.level, 0))
        return {
            "level": self.level,
            "type": primary.threat_type if primary else None,
            "detail": primary.detail if primary else None,
            "since": primary.since if primary else None,
            "confidence": primary.confidence if primary else None,
            "eta": primary.eta if primary else None,
            "is_predictive": self.is_predictive,
            "is_active": self.is_active,
            "official_alert_type": self.official_alert_type if self.is_active else None,
            "is_test": self.is_test,
            "active_threats": [t.to_dict() for t in self.active_threats],
        }

    def load_from_dict(self, data: dict):
        self._is_official_active = data.get("is_official_alarm", data.get("is_active", False))
        self.official_alert_type = data.get("official_alert_type")
        self.is_test = data.get("is_test", False)
        from core.regions import extract_region_specific_text
        if "active_threats" in data:
            self.active_threats = [SingleThreat.from_dict(t) for t in data["active_threats"]]
            for t in self.active_threats:
                if t.detail:
                    t.detail = extract_region_specific_text(t.detail, self.region)
        else:
            self.active_threats = []
            level = data.get("level", "none")
            if level != "none":
                raw_detail = data.get("detail")
                clean_detail = extract_region_specific_text(raw_detail, self.region) if raw_detail else None
                t = SingleThreat(
                    level=level,
                    threat_type=data.get("type"),
                    detail=clean_detail,
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
            if existing.telemetry is None:
                existing.telemetry = {}
            for k, v in telemetry.items():
                if v is not None:
                    existing.telemetry[k] = v
            new_lat = telemetry.get("last_checkpoint_latitude") or telemetry.get("target_latitude") or telemetry.get("origin_latitude")
            new_lon = telemetry.get("last_checkpoint_longitude") or telemetry.get("target_longitude") or telemetry.get("origin_longitude")
            if new_lat is not None and new_lon is not None:
                if "last_checkpoint_latitude" in existing.telemetry:
                    existing.telemetry["origin_latitude"] = existing.telemetry["last_checkpoint_latitude"]
                    existing.telemetry["origin_longitude"] = existing.telemetry["last_checkpoint_longitude"]
                existing.telemetry["last_checkpoint_latitude"] = new_lat
                existing.telemetry["last_checkpoint_longitude"] = new_lon
                changed = True

        return changed

    def _is_same_or_duplicate_threat(
        self,
        existing: SingleThreat,
        incoming_threat_type: Optional[str],
        incoming_detail: Optional[str],
        incoming_group_id: Optional[str],
        incoming_telemetry: Optional[dict]
    ) -> bool:
        """
        Determines whether incoming threat data is an update/duplicate of an existing threat
        vs a separate tactical group/wave.
        """
        if not incoming_threat_type or existing.threat_type != incoming_threat_type:
            return False

        # 1. Exact or conflicting group IDs
        if incoming_group_id and existing.group_id:
            if incoming_group_id == existing.group_id:
                return True
            # Both have distinct explicit IDs (e.g. "shahed_1" vs "shahed_2")
            return False

        # 2. Extract signatures
        existing_grp, existing_targets, existing_wave = _extract_group_signature(existing.detail, existing.telemetry)
        incoming_grp, incoming_targets, incoming_wave = _extract_group_signature(incoming_detail, incoming_telemetry)

        # Different wave numbers
        if existing_wave is not None and incoming_wave is not None and existing_wave != incoming_wave:
            return False

        # Different group numbering (e.g. "group_1" vs "group_2")
        if existing_grp and incoming_grp and existing_grp != incoming_grp:
            return False

        # Explicit marker of an additional/new group in incoming text
        if incoming_grp == "new_group":
            return False

        # 3. Disjoint tactical targets / cities within the region
        if existing_targets and incoming_targets:
            if existing_targets.isdisjoint(incoming_targets):
                return False

        # 4. Attack vector conflict check
        if existing.telemetry and incoming_telemetry:
            v_exist = existing.telemetry.get("attack_vector")
            v_inc = incoming_telemetry.get("attack_vector")
            if v_exist and v_inc and v_exist != "unknown" and v_inc != "unknown":
                if v_exist != v_inc:
                    return False

        # 5. Time window check for deduplication
        ref_time = _parse_iso_time(existing.last_updated_at or existing.since)
        if ref_time:
            now = datetime.now(timezone.utc)
            elapsed = (now - ref_time).total_seconds()
            if elapsed > self.DEDUP_WINDOW_SECONDS:
                return False

        return True

    def set_threat(self, level: str, threat_type: Optional[str] = None,
                   detail: Optional[str] = None, confidence: Optional[int] = None,
                   eta: Optional[str] = None, is_predictive: bool = False,
                   is_test: bool = False, group_id: Optional[str] = None,
                   eta_seconds: Optional[int] = None,
                   telemetry: Optional[dict] = None,
                   since: Optional[str] = None,
                   transit_from: Optional[str] = None) -> bool:
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

        matched_existing = None

        # 1. Exact match by group_id
        if group_id:
            for existing in self.active_threats:
                if existing.group_id == group_id:
                    matched_existing = existing
                    break

        # 2. Semantic duplicate / multi-channel update match
        if matched_existing is None:
            for existing in self.active_threats:
                if self._is_same_or_duplicate_threat(existing, threat_type, detail, group_id, telemetry):
                    matched_existing = existing
                    break

        if matched_existing is not None:
            return self._update_existing_threat(
                matched_existing, level, detail, confidence, eta, eta_seconds, is_predictive, telemetry=telemetry
            )

        # 3. New distinct group/wave
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
            telemetry=telemetry,
            transit_from=transit_from
        )
        self.active_threats.append(new_threat)
        return True
