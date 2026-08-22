"""
ThreatState regional threat container model.
"""

from typing import Optional
from datetime import datetime, timezone
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
    (e.g., '_wave2' vs '_w2', '_group1' vs '_g1', '_wave_1' vs '_w1', 'south_sea' vs 'black_sea', trailing timestamps).
    """
    if not group_id:
        return None
    gid = str(group_id).strip().lower()

    # 1. Standardize sector / geographic aliases
    gid = re.sub(r'south[_-]?sea', 'black_sea', gid)
    gid = re.sub(r'blacksea', 'black_sea', gid)
    gid = re.sub(r'caspian[_-]?sea[_-]?launch', 'caspian_sea', gid)
    gid = re.sub(r'caspian(?![_a-z])', 'caspian_sea', gid)
    gid = re.sub(r'cape[_-]?chauda|chauda[_-]?crimea', 'chauda', gid)
    gid = re.sub(r'akhtarsk|primorsko[_-]?akhtarsk', 'primorsko_akhtarsk', gid)
    gid = re.sub(r'savasleyka[_-]?airbase|savasleyka[_-]?airfield', 'savasleyka', gid)
    gid = re.sub(r'khalino|kursk[_-]?khalino', 'kursk', gid)
    gid = re.sub(r'belgorod[_-]?region', 'belgorod', gid)
    
    # 2. Normalize wave representations: _wave2, _wave_2, _wave-2 -> _w2
    gid = re.sub(r'[_.-]?wave[_.-]?(\d+)', r'_w\1', gid)
    gid = re.sub(r'[_.-]?хвиля[_.-]?(\d+)', r'_w\1', gid)
    
    # 3. Normalize group representations: _group1, _group_1, _group-1 -> _g1
    gid = re.sub(r'[_.-]?group[_.-]?(\d+)', r'_g\1', gid)
    gid = re.sub(r'[_.-]?група[_.-]?(\d+)', r'_g\1', gid)
    
    # 4. Normalize single wave/group without number
    gid = re.sub(r'[_.-]?wave$', r'_w', gid)
    gid = re.sub(r'[_.-]?group$', r'_g', gid)
    
    # 5. Remove transient time/date suffixes (e.g., _aug16, _1608, _1040, _1051, _20260816)
    gid = re.sub(r'_\d{4,8}$', '', gid)
    gid = re.sub(r'_(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\d{1,2}$', '', gid)
    
    # 6. Collapse duplicate underscores/dashes
    gid = re.sub(r'[_.-]+', '_', gid).strip('_')
    return gid


def normalize_launch_origin(origin: Optional[str]) -> str:
    """
    Normalizes a launch origin string to a canonical geographical cluster name,
    stripping parenthetical annotations (e.g. '(Флот РФ)', '(Краснодарський край РФ)', '(АР Крим)')
    and consolidating synonymous terminology.
    """
    if not origin:
        return ""
    
    text = str(origin).strip().lower()
    if not text or text == "unknown":
        return ""
    
    # Remove parenthetical comments: '(флот рф)', '(краснодарський край рф)', etc.
    text = re.sub(r'\(.*?\)', '', text).strip()
    
    # Strip military prefixes and noisy descriptors
    prefixes = [
        "аеродром", "авіабаза", "позиційний район", "район пусків", "майданчик пусків",
        "акваторія", "вогневі позиції", "передові позиції", "полігон", "брк",
        "передові", "вогневі", "позиції", "лбз", "зона ризику", "флот рф", "рф", "тот"
    ]
    for p in prefixes:
        text = re.sub(r'\b' + re.escape(p) + r'\b', '', text)
    
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    
    # Cluster matching
    if any(k in text for k in ["чорн", "море", "чф", "півден"]):
        return "чорне море"
    if "каспій" in text:
        return "каспійське море"
    if "азов" in text:
        return "азовське море"
    if "чауд" in text:
        return "мис чауда"
    if any(k in text for k in ["ахтарськ", "приморсько"]):
        return "приморсько-ахтарськ"
    if "єйськ" in text or "ейск" in text:
        return "єйськ"
    if "курськ" in text or "халін" in text:
        return "курськ"
    if "бєлгород" in text or "белгород" in text:
        return "бєлгород"
    if "брянськ" in text or "сеща" in text:
        return "брянськ"
    if "орел" in text or "орел" in text:
        return "орел"
    if "саваслейк" in text:
        return "саваслейка"
    if "олень" in text or "оленья" in text:
        return "оленья"
    if "енгельс" in text:
        return "енгельс"
    if "шайковк" in text:
        return "шайковка"
    if "моздок" in text:
        return "моздок"
    if "мачулищ" in text:
        return "мачулищі"
    if any(k in text for k in ["тарханкут", "бельбек", "саки", "гвардійськ", "джанкой", "крим"]):
        return "крим"
    if "капустін" in text or "капустин" in text:
        return "капустін яр"
    if "кінбурн" in text:
        return "кінбурнська коса"
    if "запорізьк" in text or "енергодар" in text or "пологи" in text:
        return "запорізький напрямок"
    if "донецьк" in text or "горлівк" in text:
        return "донецький напрямок"
    if "херсонськ" in text or "олешк" in text or "каховк" in text:
        return "херсонський напрямок"

    return text


def are_origins_conflicting(origin1: Optional[str], origin2: Optional[str]) -> bool:
    """
    Returns True ONLY if both origins are valid, non-empty, and map to genuinely conflicting/disjoint
    launch locations (e.g. Kursk vs Primorsko-Akhtarsk). Returns False if either is unknown or both match.
    """
    norm1 = normalize_launch_origin(origin1)
    norm2 = normalize_launch_origin(origin2)
    
    if not norm1 or not norm2 or norm1 == "unknown" or norm2 == "unknown":
        return False
    
    if norm1 == norm2 or norm1 in norm2 or norm2 in norm1:
        return False
    
    return True


def are_vectors_conflicting(vec1: Optional[str], vec2: Optional[str]) -> bool:
    """
    Returns True ONLY if attack vectors are distinctly diametric / mutually exclusive
    (e.g., north_to_south vs south_to_north).
    """
    v1 = str(vec1 or "").strip().lower()
    v2 = str(vec2 or "").strip().lower()
    
    if not v1 or not v2 or v1 == "unknown" or v2 == "unknown" or v1 == v2:
        return False
    
    # Compatible combinations (e.g. sea_to_coast with south_to_north)
    compatible_pairs = [
        {"sea_to_coast", "south_to_north"},
        {"sea_to_coast", "southeast_to_northwest"},
        {"crimea_inland", "south_to_north"},
        {"crimea_inland", "sea_to_coast"},
        {"northeast_to_southwest", "north_to_south"},
        {"southeast_to_northwest", "south_to_north"},
        {"east_to_west", "northeast_to_southwest"},
        {"east_to_west", "southeast_to_northwest"},
    ]
    pair = {v1, v2}
    if any(pair == c for c in compatible_pairs):
        return False
    
    # Strictly opposite vectors
    opposite_pairs = [
        {"north_to_south", "south_to_north"},
        {"east_to_west", "west_to_east"},
        {"northeast_to_southwest", "southwest_to_northeast"},
        {"northwest_to_southeast", "southeast_to_northwest"},
    ]
    if any(pair == o for o in opposite_pairs):
        return True
    
    return False


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
        self.active_districts: list[str] = []
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
        self.active_districts.clear()
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
        """Серіалізація — зворотно-сумісний формат + масив active_threats + active_districts."""
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
            "active_districts": getattr(self, "active_districts", []) if self.is_active else [],
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
            (t_exist in ["tu22m3", "kh22", "kh32"] and t_inc in ["tu22m3", "kh22", "kh32"]) or
            (t_exist in ["mig31k", "kinzhal"] and t_inc in ["mig31k", "kinzhal"]) or
            (t_exist in ["tu95", "tu95_ms", "tu160", "cruise_missile", "kalibr", "kh101"] and t_inc in ["tu95", "tu95_ms", "tu160", "cruise_missile", "kalibr", "kh101"]) or
            (t_exist in ["ballistic", "iskander", "iskander_m", "kn23", "s300_s400", "zircon"] and t_inc in ["ballistic", "iskander", "iskander_m", "kn23", "s300_s400", "zircon"]) or
            (t_exist in ["shahed", "drone", "recon", "recon_uav", "shahed_jet", "reactive_uav", "jet_shahed", "reactive_drone", "jet_drone", "fpv"] and t_inc in ["shahed", "drone", "recon", "recon_uav", "shahed_jet", "reactive_uav", "jet_shahed", "reactive_drone", "jet_drone", "fpv"]) or
            (t_exist in ["kab", "guided_bomb", "tactical_aviation", "su34", "su35", "su57", "su35_su57"] and t_inc in ["kab", "guided_bomb", "tactical_aviation", "su34", "su35", "su57", "su35_su57"]) or
            (t_exist in ["artillery", "mlrs"] and t_inc in ["artillery", "mlrs"])
        )
        if not same_family:
            return False

        # 1. Normalized group IDs comparison (e.g. '_wave2' vs '_w2', 'tu22m3_south_sea_1' vs 'tu22m3_black_sea_1')
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

        # 3. Special handling for Strategic & Long-Range Aviation (Tu-22M3, MiG-31K, Tu-95MS, Tu-160)
        # Multiple channels reporting the same bomber or missile launch in the same region must merge unless explicitly numbered as distinct waves
        if t_exist in ["tu22m3", "kh22", "kh32", "mig31k", "kinzhal", "tu95", "tu95_ms", "tu160"]:
            return True

        # 4. Telemetry deep comparison across all threat types
        t_exist_tel = existing.telemetry or {}
        t_inc_tel = incoming_telemetry or {}

        origin_exist = str(t_exist_tel.get("launch_origin") or "").strip()
        origin_inc = str(t_inc_tel.get("launch_origin") or "").strip()
        
        vec_exist = str(t_exist_tel.get("attack_vector") or "").strip()
        vec_inc = str(t_inc_tel.get("attack_vector") or "").strip()

        count_exist = t_exist_tel.get("target_count")
        count_inc = t_inc_tel.get("target_count")

        # Check if origins genuinely conflict (e.g. "Курськ" vs "Приморсько-Ахтарськ")
        if are_origins_conflicting(origin_exist, origin_inc):
            return False

        # Check if vectors genuinely conflict (e.g. "north_to_south" vs "south_to_north")
        if are_vectors_conflicting(vec_exist, vec_inc):
            return False

        # 5. Tactical target cities within the region
        if existing_targets and incoming_targets:
            if existing_targets.isdisjoint(incoming_targets):
                return False

        # 6. Telemetry signature match: update existing threat even if different channel used "Нова група"
        norm_orig_exist = normalize_launch_origin(origin_exist)
        norm_orig_inc = normalize_launch_origin(origin_inc)
        has_origin_match = bool(norm_orig_exist and norm_orig_inc and norm_orig_exist == norm_orig_inc)
        has_vector_match = bool(vec_exist and vec_inc and (vec_exist == vec_inc or not are_vectors_conflicting(vec_exist, vec_inc)))
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

        # 7. Time window check for generic/unspecified updates
        ref_time = _parse_iso_time(existing.last_updated_at or existing.since)
        if ref_time:
            now = datetime.now(timezone.utc)
            elapsed = (now - ref_time).total_seconds()
            
            # Dynamic dedup window based on threat type speed/flight time
            max_window = 1800 if t_exist in ["shahed", "drone", "recon", "recon_uav", "shahed_jet", "reactive_uav", "jet_shahed", "reactive_drone", "jet_drone", "fpv"] else 900
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
