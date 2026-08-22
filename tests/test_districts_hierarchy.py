import pytest
from core.regions import (
    UKRAINE_DISTRICTS,
    DISTRICT_TO_REGION,
    COMMUNITY_TO_DISTRICT,
    resolve_district_to_region,
    normalize_region_name
)
from core.threats.threat_manager import MockThreatManager
from core.threats.threat_state_model import ThreatState


def test_ukraine_districts_taxonomy():
    assert len(UKRAINE_DISTRICTS) >= 25
    # Total count across 24 oblasts + Crimea + Kyiv City
    total_districts = sum(len(dists) for dists in UKRAINE_DISTRICTS.values())
    assert total_districts >= 136

    # Specific key districts
    assert "Ізюмський район" in UKRAINE_DISTRICTS["Харківська область"]
    assert "Нікопольський район" in UKRAINE_DISTRICTS["Дніпропетровська область"]
    assert "Стрийський район" in UKRAINE_DISTRICTS["Львівська область"]
    assert "Ізмаїльський район" in UKRAINE_DISTRICTS["Одеська область"]


def test_resolve_district_to_region():
    # Whole oblast
    reg, dist = resolve_district_to_region("Харківська область")
    assert reg == "Харківська область"
    assert dist is None

    # District name
    reg, dist = resolve_district_to_region("Ізюмський район")
    assert reg == "Харківська область"
    assert dist == "Ізюмський район"

    reg, dist = resolve_district_to_region("Нікопольський район")
    assert reg == "Дніпропетровська область"
    assert dist == "Нікопольський район"

    # Known Community
    reg, dist = resolve_district_to_region("м. Нікополь та Нікопольська територіальна громада")
    assert reg == "Дніпропетровська область"
    assert dist == "Нікопольський район"


def test_threat_state_and_manager_active_districts():
    state = ThreatState("Харківська область")
    state.is_active = True
    state.active_districts = ["Ізюмський район", "Куп'янський район"]

    d = state.to_dict()
    assert d["is_active"] is True
    assert d["active_districts"] == ["Ізюмський район", "Куп'янський район"]

    # When alarm is deactivated, active_districts is empty
    state.is_active = False
    assert state.to_dict()["active_districts"] == []
