from typing import List, Optional, Dict
from pydantic import BaseModel, Field, field_validator

class TelemetryDataModel(BaseModel):
    group_id: Optional[str] = None
    attack_vector: str = "unknown"
    target_count: Optional[int] = None
    speed_kmh: Optional[int] = None
    altitude_category: str = "unknown"
    heading_degrees: Optional[int] = None
    distance_to_target_km: Optional[float] = None
    launch_origin: Optional[str] = None
    weapon_subtype: Optional[str] = None
    engagement_status: str = "unknown"
    air_defense_active: bool = False
    multiple_waves: bool = False
    wave_number: int = 1
    time_of_day_category: str = "unknown"
    weather_factor: str = "unknown"
    source_reliability: str = "medium"
    message_context_tags: List[str] = Field(default_factory=list)
    strategic_priority: Optional[str] = None
    civilian_risk_level: str = "moderate"
    event_phase: str = "unknown"
    correlation_group: Optional[str] = None
    final_target_cities: List[str] = Field(default_factory=list)
    target_cities_coords: Dict[str, List[float]] = Field(default_factory=dict)

    @field_validator("attack_vector", mode="before")
    def val_attack_vector(cls, v):
        valid = {"south_to_north", "east_to_west", "north_to_south", "west_to_east",
                 "southeast_to_northwest", "northeast_to_southwest", "crimea_inland",
                 "sea_to_coast", "border_shelling", "unknown"}
        return v if v in valid else "unknown"

    @field_validator("altitude_category", mode="before")
    def val_altitude_category(cls, v):
        valid = {"low", "medium", "high", "unknown"}
        return v if v in valid else "unknown"

    @field_validator("engagement_status", mode="before")
    def val_engagement_status(cls, v):
        valid = {"launched", "approaching", "in_transit", "overhead", "intercepted",
                 "impact", "missed", "lost", "unknown"}
        return v if v in valid else "unknown"

    @field_validator("time_of_day_category", mode="before")
    def val_time_of_day_category(cls, v):
        valid = {"night", "dawn", "day", "dusk", "unknown"}
        return v if v in valid else "unknown"

    @field_validator("source_reliability", mode="before")
    def val_source_reliability(cls, v):
        valid = {"official", "high", "medium", "low"}
        return v if v in valid else "medium"

    @field_validator("strategic_priority", mode="before")
    def val_strategic_priority(cls, v):
        valid = {"energy", "military", "industrial", "civilian", "port", "airfield", "unknown", None}
        return v if v in valid else None

    @field_validator("civilian_risk_level", mode="before")
    def val_civilian_risk_level(cls, v):
        valid = {"low", "moderate", "elevated", "high", "critical"}
        return v if v in valid else "moderate"

    @field_validator("event_phase", mode="before")
    def val_event_phase(cls, v):
        valid = {"launch", "cruise", "transit", "terminal", "impact", "aftermath", "intercept", "all_clear", "unknown"}
        return v if v in valid else "unknown"

    @field_validator("target_count", "speed_kmh", mode="before")
    def val_int_fields(cls, v):
        if v is None: return None
        try: return int(v)
        except (ValueError, TypeError): return None

    @field_validator("heading_degrees", mode="before")
    def val_heading(cls, v):
        if v is None: return None
        try: return int(v) % 360
        except (ValueError, TypeError): return None

    @field_validator("distance_to_target_km", mode="before")
    def val_float_fields(cls, v):
        if v is None: return None
        try: return float(v)
        except (ValueError, TypeError): return None

    @field_validator("wave_number", mode="before")
    def val_wave_number(cls, v):
        try: return max(1, int(v))
        except (ValueError, TypeError): return 1

    @field_validator("air_defense_active", "multiple_waves", mode="before")
    def val_bool_fields(cls, v):
        return bool(v)

    @field_validator("message_context_tags", mode="before")
    def val_tags(cls, v):
        if not isinstance(v, list): return []
        return [str(t) for t in v[:5]]

    @field_validator("final_target_cities", mode="before")
    def val_cities(cls, v):
        if not isinstance(v, list): return []
        return [str(c) for c in v]

    @field_validator("target_cities_coords", mode="before")
    def val_coords(cls, v):
        if not isinstance(v, dict): return {}
        cleaned = {}
        for city, coords in v.items():
            if isinstance(coords, list) and len(coords) >= 2:
                try: cleaned[str(city)] = [float(coords[0]), float(coords[1])]
                except (ValueError, TypeError): pass
        return cleaned


class ClearingTelemetryModel(BaseModel):
    linked_group_id: Optional[str] = None
    linked_correlation_group: Optional[str] = None
    resolution_type: str = "unknown"
    intercepted_count: Optional[int] = None
    total_targets_in_wave: Optional[int] = None
    impact_confirmed: bool = False
    damage_assessment: str = "unknown"
    civilian_casualties_reported: bool = False
    infrastructure_hit: Optional[str] = None
    air_defense_effectiveness: str = "unknown"
    threat_duration_assessment: str = "unknown"
    prediction_accuracy_hint: str = "not_applicable"
    clearing_context_tags: List[str] = Field(default_factory=list)
    source_reliability: str = "medium"
    time_of_day_category: str = "unknown"

    @field_validator("resolution_type", mode="before")
    def val_resolution(cls, v):
        valid = {"intercepted", "passed_through", "impact", "lost_contact",
                 "diverted", "false_alarm", "all_clear_official", "expired", "unknown"}
        return v if v in valid else "unknown"

    @field_validator("damage_assessment", mode="before")
    def val_damage(cls, v):
        valid = {"none", "minor", "moderate", "severe", "catastrophic", "unknown"}
        return v if v in valid else "unknown"

    @field_validator("infrastructure_hit", mode="before")
    def val_infra(cls, v):
        valid = {"energy", "military", "residential", "industrial", "transport", "medical", "none", None}
        return v if v in valid else None

    @field_validator("air_defense_effectiveness", mode="before")
    def val_ad_eff(cls, v):
        valid = {"excellent", "high", "medium", "low", "none", "unknown"}
        return v if v in valid else "unknown"

    @field_validator("threat_duration_assessment", mode="before")
    def val_duration(cls, v):
        valid = {"very_short", "short", "medium", "long", "unknown"}
        return v if v in valid else "unknown"

    @field_validator("prediction_accuracy_hint", mode="before")
    def val_pred_acc(cls, v):
        valid = {"confirmed", "partially_confirmed", "overestimated", "underestimated", "not_applicable", "unknown"}
        return v if v in valid else "unknown"

    @field_validator("source_reliability", mode="before")
    def val_source_reliability(cls, v):
        valid = {"official", "high", "medium", "low"}
        return v if v in valid else "medium"

    @field_validator("time_of_day_category", mode="before")
    def val_time_of_day_category(cls, v):
        valid = {"night", "dawn", "day", "dusk", "unknown"}
        return v if v in valid else "unknown"

    @field_validator("intercepted_count", "total_targets_in_wave", mode="before")
    def val_positive_ints(cls, v):
        if v is None: return None
        try: return max(0, int(v))
        except (ValueError, TypeError): return None

    @field_validator("impact_confirmed", "civilian_casualties_reported", mode="before")
    def val_bools(cls, v):
        return bool(v)

    @field_validator("clearing_context_tags", mode="before")
    def val_tags(cls, v):
        if not isinstance(v, list): return []
        return [str(t) for t in v[:5]]
