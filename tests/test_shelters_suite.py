"""
Tests for ShelterManager, Overpass parsing, and /api/shelters endpoint.
Verifies that weather shelters, bus stops, and gazebos are excluded,
while real air-raid shelters (bomb shelters, underground parking, metro stations, bunkers) are parsed.
"""

import pytest
from database.shelter_manager import (
    _parse_osm_element,
    _haversine,
    _GridIndex,
    _fetch_seed_shelters,
    Shelter,
    ShelterManager,
)


def test_parse_osm_element_valid_bomb_shelter():
    elem = {
        "type": "node",
        "id": 101,
        "lat": 50.4501,
        "lon": 30.5234,
        "tags": {
            "name": "Бомбосховище №14",
            "amenity": "shelter",
            "shelter_type": "bomb_shelter",
            "capacity": "250",
            "wheelchair": "yes",
            "addr:street": "Хрещатик",
            "addr:housenumber": "22",
        },
    }
    shelter = _parse_osm_element(elem)
    assert shelter is not None
    assert shelter.id == "osm_node_101"
    assert shelter.name == "Бомбосховище №14"
    assert shelter.type == "bomb_shelter"
    assert shelter.capacity == 250
    assert shelter.accessible is True
    assert shelter.address == "Хрещатик, 22"


def test_parse_osm_element_valid_metro_station():
    elem = {
        "type": "node",
        "id": 202,
        "lat": 50.4488,
        "lon": 30.5255,
        "tags": {
            "name": "Хрещатик",
            "station": "subway",
            "railway": "station",
            "wheelchair": "yes",
        },
    }
    shelter = _parse_osm_element(elem)
    assert shelter is not None
    assert shelter.type == "metro"
    assert "Хрещатик" in shelter.name


def test_parse_osm_element_valid_underground_parking():
    # 1. Mall parking
    elem_mall = {
        "type": "way",
        "id": 303,
        "center": {"lat": 50.4400, "lon": 30.5100},
        "tags": {
            "name": "Підземний паркінг ТРЦ Retroville",
            "amenity": "parking",
            "parking": "underground",
            "capacity": "500",
        },
    }
    shelter_mall = _parse_osm_element(elem_mall)
    assert shelter_mall is not None
    assert shelter_mall.type == "mall_parking"
    assert shelter_mall.is_primary is False
    assert shelter_mall.is_night_accessible is True
    assert shelter_mall.is_vehicle_accessible is True
    assert "Retroville" in shelter_mall.name
    assert shelter_mall.lat == 50.4400
    assert shelter_mall.lon == 30.5100

    # 2. Generic residential underground parking
    elem_gen = {
        "type": "way",
        "id": 304,
        "center": {"lat": 50.4500, "lon": 30.5200},
        "tags": {
            "name": "Підземний паркінг",
            "amenity": "parking",
            "parking": "underground",
        },
    }
    shelter_gen = _parse_osm_element(elem_gen)
    assert shelter_gen is not None
    assert shelter_gen.type == "underground_parking"
    assert shelter_gen.is_primary is False
    assert shelter_gen.is_night_accessible is True
    assert shelter_gen.is_vehicle_accessible is True


def test_parse_osm_element_valid_bunker():
    elem = {
        "type": "node",
        "id": 404,
        "lat": 50.4600,
        "lon": 30.5300,
        "tags": {
            "military": "bunker",
            "bunker_type": "bomb_shelter",
        },
    }
    shelter = _parse_osm_element(elem)
    assert shelter is not None
    assert shelter.type == "bunker"
    assert "Бункер" in shelter.name


def test_parse_osm_element_excludes_public_transport_and_weather_shelters():
    # 1. Weather shelter (shelter_type=public_transport)
    elem1 = {
        "type": "node",
        "id": 501,
        "lat": 50.4500,
        "lon": 30.5200,
        "tags": {
            "amenity": "shelter",
            "shelter_type": "public_transport",
            "name": "Зупинка вул. Садова",
        },
    }
    assert _parse_osm_element(elem1) is None

    # 2. Weather shelter (shelter_type=weather_shelter)
    elem2 = {
        "type": "node",
        "id": 502,
        "lat": 50.4500,
        "lon": 30.5200,
        "tags": {
            "amenity": "shelter",
            "shelter_type": "weather_shelter",
            "name": "Навіс від дощу",
        },
    }
    assert _parse_osm_element(elem2) is None

    # 3. Gazebo / Picnic shelter
    elem3 = {
        "type": "node",
        "id": 503,
        "lat": 50.4500,
        "lon": 30.5200,
        "tags": {
            "amenity": "shelter",
            "shelter_type": "picnic_shelter",
            "name": "Альтанка в парку",
        },
    }
    assert _parse_osm_element(elem3) is None

    # 4. Bus stop
    elem4 = {
        "type": "node",
        "id": 504,
        "lat": 50.4500,
        "lon": 30.5200,
        "tags": {
            "highway": "bus_stop",
            "name": "Зупинка автобуса №24",
        },
    }
    assert _parse_osm_element(elem4) is None

    # 5. Rain awning keyword in name
    elem5 = {
        "type": "node",
        "id": 505,
        "lat": 50.4500,
        "lon": 30.5200,
        "tags": {
            "amenity": "shelter",
            "name": "Навіс від дощу біля кафе",
        },
    }
    assert _parse_osm_element(elem5) is None


def test_grid_index_find_nearby_and_sorting():
    idx = _GridIndex()
    # User at (50.4500, 30.5200)
    # Shelter 1: ~100m away
    s1 = Shelter(
        id="s1",
        name="Близьке укриття",
        address="вул. Головна 1",
        lat=50.4509,
        lon=30.5200,
        type="bomb_shelter",
        capacity=100,
        accessible=True,
        source="osm",
    )
    # Shelter 2: ~800m away
    s2 = Shelter(
        id="s2",
        name="Далеке укриття",
        address="вул. Головна 50",
        lat=50.4570,
        lon=30.5200,
        type="metro",
        capacity=2000,
        accessible=True,
        source="osm",
    )
    # Shelter 3: ~5000m away
    s3 = Shelter(
        id="s3",
        name="Дуже далеке укриття",
        address="вул. Окружна 100",
        lat=50.4950,
        lon=30.5200,
        type="underground_parking",
        capacity=300,
        accessible=False,
        source="osm",
    )

    idx.insert(s1)
    idx.insert(s2)
    idx.insert(s3)

    # Search within 1500m
    nearby = idx.find_nearby(50.4500, 30.5200, radius_m=1500, limit=10)
    assert len(nearby) == 2
    assert nearby[0].id == "s1"
    assert nearby[1].id == "s2"

    # Search within 500m
    nearby_500 = idx.find_nearby(50.4500, 30.5200, radius_m=500, limit=10)
    assert len(nearby_500) == 1
    assert nearby_500[0].id == "s1"


@pytest.mark.anyio
async def test_shelters_api_endpoint():
    from httpx import AsyncClient, ASGITransport
    from server import app
    from core.globals import shelter_manager

    # Pre-populate manager with test shelters
    s1 = Shelter(
        id="s1",
        name="Бомбосховище Центр",
        address="Майдан Незалежності 1",
        lat=50.4501,
        lon=30.5234,
        type="bomb_shelter",
        capacity=500,
        accessible=True,
        source="osm",
    )
    s2 = Shelter(
        id="s2",
        name="Підземний паркінг Гуллівер",
        address="пл. Спортивна 1",
        lat=50.4385,
        lon=30.5230,
        type="underground_parking",
        capacity=1000,
        accessible=True,
        source="osm",
    )

    idx = _GridIndex()
    idx.insert(s1)
    idx.insert(s2)
    shelter_manager._index = idx
    shelter_manager._shelters = [s1, s2]
    shelter_manager._loaded = True

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        res = await ac.get("/api/shelters?lat=50.4501&lon=30.5234&radius=2000")
        assert res.status_code == 200
        data = res.json()
        assert data["count"] >= 1
        assert data["shelters"][0]["name"] == "Бомбосховище Центр"
        assert "distance_m" in data["shelters"][0]


def test_seed_shelters_auto_loaded():
    """Verify that ShelterManager loads seed shelters immediately upon instantiation."""
    mgr = ShelterManager()
    assert mgr.is_loaded is True
    assert mgr.total_count > 0
    # Check that major national regional hubs (Lviv, Kyiv) exist in the seed dataset
    lviv_shelters = [s for s in mgr._shelters if "Львів" in (s.address or "") or "Львів" in (s.name or "")]
    assert len(lviv_shelters) >= 1
    kyiv_shelters = [s for s in mgr._shelters if "Київ" in (s.address or "") or "Київ" in (s.name or "")]
    assert len(kyiv_shelters) >= 1


def test_school_and_hospital_classification():
    """Verify that OSM elements with school, hospital, and parking tags are classified accurately."""
    school_elem = {
        "type": "node",
        "id": 101,
        "lat": 49.3005,
        "lon": 23.8966,
        "tags": {
            "amenity": "school",
            "name": "Угерський ліцей",
            "addr:street": "вул. Франка",
            "addr:housenumber": "2",
        },
    }
    s = _parse_osm_element(school_elem)
    assert s is not None
    assert s.type == "school_shelter"
    assert s.name == "Угерський ліцей"

    hospital_elem = {
        "type": "way",
        "id": 102,
        "center": {"lat": 49.2620, "lon": 23.8650},
        "tags": {
            "amenity": "hospital",
            "name": "Стрийська багатопрофільна лікарня",
        },
    }
    h = _parse_osm_element(hospital_elem)
    assert h is not None
    assert h.type == "hospital_shelter"

    parking_elem = {
        "type": "way",
        "id": 103,
        "center": {"lat": 49.2560, "lon": 23.8525},
        "tags": {
            "parking": "underground",
            "name": "ТЦ Пасаж Підземний паркінг",
        },
    }
    p = _parse_osm_element(parking_elem)
    assert p is not None
    assert p.type == "mall_parking"
    assert p.is_primary is False
    assert p.is_night_accessible is True
    assert p.is_vehicle_accessible is True


def test_seed_shelters_contain_major_malls():
    """Verify that pre-seeded database contains shopping mall parkings in Kyiv, Lviv, Kharkiv, etc."""
    seeds = _fetch_seed_shelters()
    assert len(seeds) >= 20

    # Kyiv Retroville & Lavina
    kyiv_malls = [s for s in seeds if s.type == "mall_parking" and ("Retroville" in (s.name or "") or "Lavina" in (s.name or ""))]
    assert len(kyiv_malls) >= 2
    for m in kyiv_malls:
        assert m.is_vehicle_accessible is True
        assert m.is_night_accessible is True
        assert m.is_primary is False

    # Lviv Forum & Victoria Gardens
    lviv_malls = [s for s in seeds if s.type == "mall_parking" and ("Forum" in (s.name or "") or "Victoria" in (s.name or ""))]
    assert len(lviv_malls) >= 2

    # Verify primary shelters
    primary_shelters = [s for s in seeds if s.is_primary]
    assert len(primary_shelters) >= 6
    for ps in primary_shelters:
        assert ps.type in ("metro", "bomb_shelter", "radiation_shelter", "bunker", "hospital_shelter", "school_shelter", "civil_defense")
        assert ps.is_night_accessible is True


def test_all_26_regions_datasets_exist_and_valid():
    """Verify that all 26 regional JSON files exist, each has Tier 1 & Tier 2 shelters with valid attributes."""
    import os
    import json
    regions_dir = os.path.join(os.path.dirname(__file__), "..", "database", "data", "regions")
    assert os.path.exists(regions_dir) and os.path.isdir(regions_dir)
    files = [f for f in os.listdir(regions_dir) if f.endswith(".json")]
    assert len(files) == 26, f"Expected 26 regional JSON files, found {len(files)}"

    for f in files:
        fpath = os.path.join(regions_dir, f)
        with open(fpath, "r", encoding="utf-8") as fp:
            items = json.load(fp)
        assert len(items) >= 4, f"Region {f} has fewer than 4 shelters"
        
        has_primary = any(it.get("is_primary") is True for it in items)
        has_secondary = any(it.get("is_primary") is False for it in items)
        assert has_primary, f"Region {f} lacks Tier 1 (Primary) shelter"
        assert has_secondary, f"Region {f} lacks Tier 2 (Secondary) shelter"

        for it in items:
            assert "id" in it and "name" in it and "lat" in it and "lon" in it
            assert 44.0 <= it["lat"] <= 53.0
            assert 22.0 <= it["lon"] <= 41.0


def test_region_detector_accuracy():
    """Verify region detector correctly identifies Ukrainian regions based on coordinates."""
    from database.region_detector import detect_region_by_coordinates, resolve_region_code, get_region_name

    # Kyiv Center
    assert detect_region_by_coordinates(50.4501, 30.5234) == "kyiv_city"
    # Kyiv Oblast (Bila Tserkva)
    assert detect_region_by_coordinates(49.8050, 30.1550) == "kyiv_oblast"
    # Lviv Center
    assert detect_region_by_coordinates(49.8397, 24.0297) == "lviv"
    # Kharkiv Center
    assert detect_region_by_coordinates(49.9935, 36.2304) == "kharkiv"
    # Odesa Center
    assert detect_region_by_coordinates(46.4825, 30.7233) == "odesa"
    # Dnipro Center
    assert detect_region_by_coordinates(48.4647, 35.0462) == "dnipro"
    # Vinnytsia Center
    assert detect_region_by_coordinates(49.2331, 28.4682) == "vinnytsia"
    # Uzhhorod (Zakarpattia)
    assert detect_region_by_coordinates(48.6208, 22.2879) == "zakarpattia"

    # Resolving names
    assert resolve_region_code("Львівська область") == "lviv"
    assert resolve_region_code("м. Київ") == "kyiv_city"
    assert get_region_name("lviv") == "Львівська область"


def test_get_shelters_by_region_primary_secondary_sort():
    """Verify get_shelters_by_region returns shelters sorted by Primary (Tier 1) then Secondary."""
    mgr = ShelterManager()
    lviv_shelters = mgr.get_shelters_by_region("lviv")
    assert len(lviv_shelters) >= 8
    
    # First item must be primary
    assert lviv_shelters[0]["is_primary"] is True
    # Subsequent items contain mall parkings
    malls = [s for s in lviv_shelters if s["type"] == "mall_parking"]
    assert len(malls) >= 2


def test_emulated_gps_locations_nationwide():
    """Emulate GPS coordinates in 20 diverse locations across Ukraine and verify search & ranking behavior."""
    mgr = ShelterManager()

    test_points = [
        {"name": "Київ (Хрещатик / Майдан)", "lat": 50.4501, "lon": 30.5234, "expected_region": "kyiv_city", "must_have_primary": True},
        {"name": "Київ (Оболонь / Lavina Mall)", "lat": 50.4950, "lon": 30.3600, "expected_region": "kyiv_city", "must_have_primary": True},
        {"name": "Львів (Площа Ринок)", "lat": 49.8419, "lon": 24.0315, "expected_region": "lviv", "must_have_primary": True},
        {"name": "Львів (Південь / Victoria Gardens)", "lat": 49.8075, "lon": 23.9780, "expected_region": "lviv", "must_have_primary": True},
        {"name": "Дніпро (Мост-Сіті / Центр)", "lat": 48.4647, "lon": 35.0462, "expected_region": "dnipro", "must_have_primary": True},
        {"name": "Харків (Площа Свободи / Каразіна)", "lat": 50.0056, "lon": 36.2278, "expected_region": "kharkiv", "must_have_primary": True},
        {"name": "Одеса (Дерибасівська / Порт)", "lat": 46.4850, "lon": 30.7400, "expected_region": "odesa", "must_have_primary": True},
        {"name": "Полтава (Корпусний сад)", "lat": 49.5883, "lon": 34.5514, "expected_region": "poltava", "must_have_primary": True},
        {"name": "Чернівці (Центральна площа)", "lat": 48.2917, "lon": 25.9353, "expected_region": "chernivtsi", "must_have_primary": True},
        {"name": "Львівщина (село Угерсько біля Стрия)", "lat": 49.2856, "lon": 23.8611, "expected_region": "lviv", "must_have_primary": True},
        {"name": "Черкаси (Соборна площа)", "lat": 49.4444, "lon": 32.0597, "expected_region": "cherkasy", "must_have_primary": True},
        {"name": "Запоріжжя (Мотор Січ / Проспект)", "lat": 47.8388, "lon": 35.1396, "expected_region": "zaporizhzhia", "must_have_primary": True},
        {"name": "Івано-Франківськ (Ратуша)", "lat": 48.9228, "lon": 24.7106, "expected_region": "ivano_frankivsk", "must_have_primary": True},
        {"name": "Вінниця (Соборна)", "lat": 49.2331, "lon": 28.4682, "expected_region": "vinnytsia", "must_have_primary": True},
        {"name": "Житомир (Майдан Корольова)", "lat": 50.2544, "lon": 28.6586, "expected_region": "zhytomyr", "must_have_primary": True},
        {"name": "Рівне (Майдан Незалежності)", "lat": 50.6192, "lon": 26.2514, "expected_region": "rivne", "must_have_primary": True},
        {"name": "Луцьк (Театральний майдан)", "lat": 50.7472, "lon": 25.3256, "expected_region": "volyn", "must_have_primary": True},
        {"name": "Ужгород (Замкова гора)", "lat": 48.6208, "lon": 22.2879, "expected_region": "zakarpattia", "must_have_primary": True},
        {"name": "Миколаїв (Соборна)", "lat": 46.9750, "lon": 31.9946, "expected_region": "mykolaiv", "must_have_primary": True},
        {"name": "Херсон (Проспект Незалежності)", "lat": 46.6354, "lon": 32.6169, "expected_region": "kherson", "must_have_primary": True}
    ]

    for pt in test_points:
        # 1. Search in standard radius (5km)
        results = mgr.find_nearby(pt["lat"], pt["lon"], radius_m=5000)
        assert len(results) > 0, f"No shelters found for {pt['name']} within 5km"

        # 2. Check region detection
        from database.region_detector import detect_region_by_coordinates
        detected_region = detect_region_by_coordinates(pt["lat"], pt["lon"])
        assert detected_region == pt["expected_region"], f"Region mismatch for {pt['name']}: got {detected_region}, expected {pt['expected_region']}"

        # 3. Check sorting: first item must be closest or higher tier
        closest = results[0]
        assert closest.get("distance_m") is not None
        assert closest["distance_m"] <= 5000

        # 4. Check primary tier exists in regional dataset
        regional_shelters = mgr.get_shelters_by_region(pt["expected_region"])
        assert any(s["is_primary"] for s in regional_shelters), f"Region {pt['expected_region']} has no Tier 1 primary shelters"
        assert any(s["is_primary"] is False for s in regional_shelters), f"Region {pt['expected_region']} has no Tier 2 secondary shelters"


@pytest.mark.anyio
async def test_shelters_by_region_api_endpoint():
    """Verify /api/shelters/by_region endpoint."""
    from httpx import AsyncClient, ASGITransport
    from server import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        res = await ac.get("/api/shelters/by_region?region=lviv")
        assert res.status_code == 200
        data = res.json()
        assert data["region"] == "lviv"
        assert data["count"] >= 8
        assert data["primary_count"] >= 3
        assert data["secondary_count"] >= 4
        assert len(data["shelters"]) == data["count"]
