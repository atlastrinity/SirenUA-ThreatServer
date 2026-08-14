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
    elem = {
        "type": "way",
        "id": 303,
        "center": {"lat": 50.4400, "lon": 30.5100},
        "tags": {
            "name": "Підземний паркінг ТРЦ",
            "amenity": "parking",
            "parking": "underground",
            "capacity": "500",
        },
    }
    shelter = _parse_osm_element(elem)
    assert shelter is not None
    assert shelter.type == "underground_parking"
    assert shelter.name == "Підземний паркінг ТРЦ"
    assert shelter.lat == 50.4400
    assert shelter.lon == 30.5100


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
