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


def normalize_group_id(group_id: Optional[str]) -> Optional[str]:
    """
    Normalizes a tactical threat group_id string to a canonical form, preventing
    spurious duplicate cards caused by minor formatting differences across channels or LLM runs
    (e.g., '_wave2' vs '_w2', '_group1' vs '_g1', '_wave_1' vs '_w1', trailing timestamps).
    """
    if not group_id:
        return None
    gid = str(group_id).strip().lower()
    
    # 1. Normalize wave representations: _wave2, _wave_2, _wave-2 -> _w2
    gid = re.sub(r'[_.-]?wave[_.-]?(\d+)', r'_w\1', gid)
    gid = re.sub(r'[_.-]?хвиля[_.-]?(\d+)', r'_w\1', gid)
    
    # 2. Normalize group representations: _group1, _group_1, _group-1 -> _g1
    gid = re.sub(r'[_.-]?group[_.-]?(\d+)', r'_g\1', gid)
    gid = re.sub(r'[_.-]?група[_.-]?(\d+)', r'_g\1', gid)
    
    # 3. Normalize single wave/group without number
    gid = re.sub(r'[_.-]?wave$', r'_w', gid)
    gid = re.sub(r'[_.-]?group$', r'_g', gid)
    
    # 4. Remove transient time/date suffixes (e.g., _aug16, _1608, _1040, _1051, _20260816)
    gid = re.sub(r'_\d{4,8}$', '', gid)
    gid = re.sub(r'_(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\d{1,2}$', '', gid)
    
    # 5. Collapse duplicate underscores/dashes
    gid = re.sub(r'[_.-]+', '_', gid).strip('_')
    return gid


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

    DEDUP_WINDOW_SECONDS = 1800

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
        norm_gid = normalize_group_id(group_id)
        for i, t in enumerate(self.active_threats):
            if t.group_id == group_id or (norm_gid and normalize_group_id(t.group_id) == norm_gid):
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
        vs a separate tactical group/wave across all threat types (Shaheds, Missiles, Ballistics, KABs, Aviation).
        """
        if not incoming_threat_type or not existing.threat_type:
            return False

        # Threat types must match or be in the same tactical family
        t_exist = existing.threat_type.lower()
        t_inc = incoming_threat_type.lower()
        same_family = (
            t_exist == t_inc or
            (t_exist in ["ballistic", "iskander_m", "kn23", "s300_s400"] and t_inc in ["ballistic", "iskander_m", "kn23", "s300_s400"]) or
            (t_exist in ["cruise_missile", "kalibr", "kh101", "tu95_ms", "tu160"] and t_inc in ["cruise_missile", "kalibr", "kh101", "tu95_ms", "tu160"]) or
            (t_exist in ["mig31k", "kinzhal"] and t_inc in ["mig31k", "kinzhal"]) or
            (t_exist in ["shahed", "drone", "recon_uav", "shahed_jet"] and t_inc in ["shahed", "drone", "recon_uav", "shahed_jet"]) or
            (t_exist in ["kab", "guided_bomb", "tactical_aviation", "su34", "su35"] and t_inc in ["kab", "guided_bomb", "tactical_aviation", "su34", "su35"])
        )
        if not same_family:
            return False

        # 1. Normalized group IDs comparison (e.g. '_wave2' vs '_w2')
        norm_incoming_gid = normalize_group_id(incoming_group_id)
        norm_existing_gid = normalize_group_id(existing.group_id)

        if norm_incoming_gid and norm_existing_gid:
            if norm_incoming_gid == norm_existing_gid:
                return True
            # Conflicting wave/group numbers (e.g. "shahed_1" vs "shahed_2", "missile_w1" vs "missile_w2")
            m_inc = re.search(r'[_.-](?:w|g|wave|group)?(\d+)$', norm_incoming_gid)
            m_ext = re.search(r'[_.-](?:w|g|wave|group)?(\d+)$', norm_existing_gid)
            if m_inc and m_ext and m_inc.group(1) != m_ext.group(1):
                return False

        # 2. Extract signatures
        existing_grp, existing_targets, existing_wave = _extract_group_signature(existing.detail, existing.telemetry)
        incoming_grp, incoming_targets, incoming_wave = _extract_group_signature(incoming_detail, incoming_telemetry)

        # Explicitly different wave numbers (e.g. Wave 1 vs Wave 2)
        if existing_wave is not None and incoming_wave is not None and existing_wave != incoming_wave:
            return False

        # Explicitly different numbered groups (e.g. group_1 vs group_2)
        if existing_grp and incoming_grp and existing_grp.startswith("group_") and incoming_grp.startswith("group_") and existing_grp != incoming_grp:
            return False

        # 3. Telemetry deep comparison across all threat types
        t_exist_tel = existing.telemetry or {}
        t_inc_tel = incoming_telemetry or {}

        origin_exist = str(t_exist_tel.get("launch_origin") or "").strip().lower()
        origin_inc = str(t_inc_tel.get("launch_origin") or "").strip().lower()
        
        vec_exist = str(t_exist_tel.get("attack_vector") or "").strip().lower()
        vec_inc = str(t_inc_tel.get("attack_vector") or "").strip().lower()

        count_exist = t_exist_tel.get("target_count")
        count_inc = t_inc_tel.get("target_count")

        # Check if origins conflict (e.g. "Курськ" vs "Приморсько-Ахтарськ" or "Брянськ" vs "Чорне море")
        if origin_exist and origin_inc and origin_exist != "unknown" and origin_inc != "unknown":
            if origin_exist != origin_inc:
                return False

        # Check if vectors conflict (e.g. "sea_to_coast" vs "northeast_to_southwest")
        if vec_exist and vec_inc and vec_exist != "unknown" and vec_inc != "unknown":
            if vec_exist != vec_inc:
                return False

        # 4. Tactical target cities within the region
        if existing_targets and incoming_targets:
            if existing_targets.isdisjoint(incoming_targets):
                return False

        # 5. Telemetry signature match: update existing threat even if different channel used "Нова група"
        has_origin_match = bool(origin_exist and origin_inc and origin_exist == origin_inc)
        has_vector_match = bool(vec_exist and vec_inc and vec_exist == vec_inc)
        has_targets_match = bool(existing_targets and incoming_targets and not existing_targets.isdisjoint(incoming_targets))
        has_count_match = bool(count_exist is not None and count_inc is not None and count_exist == count_inc)
        has_wave_match = bool(existing_wave is not None and incoming_wave is not None and existing_wave == incoming_wave)

        if (has_origin_match and has_vector_match and has_targets_match) or \
           (has_origin_match and has_count_match and has_targets_match) or \
           (has_wave_match and has_origin_match) or \
           (has_count_match and has_targets_match and has_vector_match):
            return True

        # If incoming has explicit marker of an additional/new group without matching telemetry
        if incoming_grp == "new_group":
            return False

        # 6. Time window check for generic/unspecified updates
        ref_time = _parse_iso_time(existing.last_updated_at or existing.since)
        if ref_time:
            now = datetime.now(timezone.utc)
            elapsed = (now - ref_time).total_seconds()
            
            # Dynamic dedup window based on threat type speed/flight time
            max_window = 1800 if t_exist in ["shahed", "drone", "recon_uav"] else 900
            if elapsed <= max_window:
                if not (existing_targets and incoming_targets and existing_targets.isdisjoint(incoming_targets)):
                    return True

        return False

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

        # 1. Exact match by normalized group_id
        if group_id:
            norm_gid = normalize_group_id(group_id)
            for existing in self.active_threats:
                if existing.group_id == group_id or (norm_gid and normalize_group_id(existing.group_id) == norm_gid):
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
