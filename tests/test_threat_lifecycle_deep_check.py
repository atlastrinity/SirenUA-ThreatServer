"""
Comprehensive Verification Test Suite for Threat Setting, Updating, Lifecycle,
and Clearing across MockThreatManager, ThreatState, TestingPackage, and API.
"""

import os
import sys
import pytest
from datetime import datetime, timezone, timedelta

# Ensure SirenUA-ThreatServer is on python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))

from core.threat_state import MockThreatManager
from core.threats.threat_state_model import ThreatState
from core.threats.single_threat import SingleThreat
from testing.scenarios import VALID_SCENARIOS, generate_scenario_threats
from testing.manager import test_scenario_manager
from services.missile_lifecycle_service import (
    should_expire_missile_threat,
    prune_expired_missile_threats,
    MAX_FLIGHT_TIMEOUT_SECONDS,
)
from fastapi.testclient import TestClient
from server import app


class TestThreatSettingAndUpdating:
    """Перевірка логіки встановлення та оновлення загроз."""

    def test_single_threat_setting(self):
        manager = MockThreatManager()
        region = "Київська область"

        # Початковий стан — чистий
        assert manager.threats[region].level == "none"
        assert len(manager.threats[region].active_threats) == 0

        # Встановлюємо загрозу Шахедів
        success = manager.set_threat(
            region=region,
            level="medium",
            threat_type="shahed",
            detail="БпЛА у напрямку Білої Церкви",
            confidence=85,
            eta="~20 хв",
            is_predictive=False,
            is_test=True,
        )
        assert success is True
        state = manager.threats[region]
        assert state.level == "medium"
        assert state.threat_type == "shahed"
        assert state.confidence == 85
        assert state.eta == "~20 хв"
        assert state.is_test is True
        assert len(state.active_threats) == 1

    def test_multiple_threats_priority_resolution(self):
        manager = MockThreatManager()
        region = "Одеська область"

        # 1. Додаємо Shahed (medium)
        manager.set_threat(
            region=region,
            level="medium",
            threat_type="shahed",
            detail="Шахеди з моря",
            confidence=70,
        )
        assert manager.threats[region].level == "medium"

        # 2. Додаємо Балістику (critical)
        manager.set_threat(
            region=region,
            level="critical",
            threat_type="ballistic",
            detail="Загроза балістики з Криму",
            confidence=95,
        )
        # Загальний рівень області повинен піднятися до critical
        assert manager.threats[region].level == "critical"
        assert len(manager.threats[region].active_threats) == 2

    def test_threat_update_by_group_id(self):
        manager = MockThreatManager()
        region = "Сумська область"
        gid = "group_shahed_sumy_101"

        # 1. Встановлюємо загрозу з group_id
        manager.set_threat(
            region=region,
            level="low",
            threat_type="shahed",
            detail="БпЛА на кордоні",
            confidence=60,
            telemetry={"group_id": gid, "speed_kmh": 180, "distance_to_target_km": 60}
        )
        assert len(manager.threats[region].active_threats) == 1
        assert manager.threats[region].level == "low"

        # 2. Оновлюємо ту ж саму загрозу новішим повідомленням (підвищуємо рівень)
        manager.set_threat(
            region=region,
            level="high",
            threat_type="shahed",
            detail="БпЛА увійшов у повітряний простір області",
            confidence=90,
            telemetry={"group_id": gid, "speed_kmh": 180, "distance_to_target_km": 20}
        )
        # Має бути оновлено існуючу загрозу, а не створено другу
        assert len(manager.threats[region].active_threats) == 1
        assert manager.threats[region].level == "high"
        assert manager.threats[region].confidence == 90

    def test_occupied_regions_behavior(self):
        manager = MockThreatManager()
        # Крим не повинен приймати пряме динамічне встановлення загроз
        res = manager.set_threat("АР Крим", "high", "shahed")
        assert res is False
        assert manager.threats["АР Крим"].is_active is True


class TestThreatClearing:
    """Перевірка зняття загроз (по одній, за group_id, за типом та всіх разом)."""

    def test_clear_by_group_id(self):
        manager = MockThreatManager()
        region = "Харківська область"
        gid1 = "grp_1"
        gid2 = "grp_2"

        manager.set_threat(region, "medium", "shahed", detail="Група 1", telemetry={"group_id": gid1})
        manager.set_threat(region, "high", "kab", detail="Група 2", telemetry={"group_id": gid2})
        assert len(manager.threats[region].active_threats) == 2
        assert manager.threats[region].level == "high"

        # Знімаємо тільки КАБ (grp_2)
        cleared = manager.clear_threat(region, group_id=gid2)
        assert cleared is True
        assert len(manager.threats[region].active_threats) == 1
        # Залишився Шахед з рівнем medium
        assert manager.threats[region].level == "medium"
        assert manager.threats[region].threat_type == "shahed"

    def test_clear_by_threat_type(self):
        manager = MockThreatManager()
        region = "Дніпропетровська область"

        manager.set_threat(region, "medium", "shahed", detail="БпЛА")
        manager.set_threat(region, "high", "cruise_missile", detail="Ракета")

        # Знімаємо ракету за типом
        manager.clear_threat(region, threat_type="cruise_missile")
        assert len(manager.threats[region].active_threats) == 1
        assert manager.threats[region].threat_type == "shahed"
        assert manager.threats[region].level == "medium"

        # Знімаємо останню загрозу
        manager.clear_threat(region, threat_type="shahed")
        assert len(manager.threats[region].active_threats) == 0
        assert manager.threats[region].level == "none"

    def test_clear_all_only_test(self):
        manager = MockThreatManager()
        # Ставимо реальну загрозу у Львівській та тестову у Вінницькій
        manager.set_threat("Львівська область", "high", "cruise_missile", is_test=False)
        manager.set_threat("Вінницька область", "medium", "shahed", is_test=True)

        manager.clear_all(only_test=True)

        # Тестова у Вінницькій знята
        assert manager.threats["Вінницька область"].level == "none"
        # Реальна у Львівській залишилась
        assert manager.threats["Львівська область"].level == "high"


class TestScenarioManagement:
    """Перевірка роботи сценаріїв тестування та очищення."""

    @pytest.mark.parametrize("scenario_name", [
        "shaheds_south", "mig_takeoff", "ballistic_kharkiv", "cruise_missiles_west"
    ])
    def test_apply_and_clear_scenarios(self, scenario_name):
        manager = MockThreatManager()
        success = test_scenario_manager.apply_scenario(scenario_name, manager)
        assert success is True

        # Перевіряємо що хоча б одна область має активну загрозу
        active_regions = [r for r, s in manager.threats.items() if s.level != "none"]
        assert len(active_regions) > 0

        # Очищуємо через сценарій 'clear'
        clear_success = test_scenario_manager.apply_scenario("clear", manager)
        assert clear_success is True

        # Всі тестові загрози повинні бути зняті
        for r, s in manager.threats.items():
            assert s.level == "none"
            assert len(s.active_threats) == 0


class TestMissileLifecycleExpiration:
    """Перевірка автоматичного зняття протермінованих загроз та траєкторій."""

    def test_ballistic_flight_timeout_expiration(self):
        # Створюємо загрозу балістики, що була створена 6 хвилин тому (таймаут 5 хв)
        past_time = datetime.now(timezone.utc) - timedelta(minutes=6)
        threat = SingleThreat(
            level="critical",
            threat_type="ballistic",
            detail="Пуск балістики"
        )
        threat.since = past_time.isoformat()

        should_expire, res_type, reason = should_expire_missile_threat(
            threat, is_official_alarm_active=True
        )
        assert should_expire is True
        assert res_type == "intercepted"
        assert "Перевищено максимальний час польоту" in reason

    def test_parse_eta_seconds_from_str(self):
        from services.missile_lifecycle_service import parse_eta_seconds_from_str
        assert parse_eta_seconds_from_str("~15 хв") == 900
        assert parse_eta_seconds_from_str("до 20 хв") == 1200
        assert parse_eta_seconds_from_str("3-5 хв") == 300
        assert parse_eta_seconds_from_str("1 год 10 хв") == 4200
        assert parse_eta_seconds_from_str("до 1 год") == 3600
        assert parse_eta_seconds_from_str(None) is None

    def test_yellow_zone_eta_expiration(self):
        # Загроза в жовтій зоні (без тривоги) з ETA 10 хв, створена 12 хв тому
        past_time = datetime.now(timezone.utc) - timedelta(minutes=12)
        threat = SingleThreat(
            level="medium",
            threat_type="shahed",
            detail="БпЛА курсом на область",
            eta="~10 хв",
            is_predictive=True
        )
        threat.since = past_time.isoformat()

        should_expire, res_type, reason = should_expire_missile_threat(
            threat, is_official_alarm_active=False
        )
        assert should_expire is True
        assert res_type == "expired"
        assert "Прогноз не реалізувався" in reason

    def test_official_alarm_all_clear_clears_active_threats(self):
        # При відбої офіційної тривоги всі активні загрози в області автоматично очищаються
        manager = MockThreatManager()
        region = "Полтавська область"

        # 1. Встановлюємо загрозу та вмикаємо офіційну тривогу
        manager.set_threat(region, "high", "shahed", detail="БпЛА над областю", is_test=False)
        manager.set_alarm_active(region, True)
        assert manager.threats[region].is_active is True
        assert manager.threats[region].level == "high"
        assert len(manager.threats[region].active_threats) == 1

        # 2. Офіційний відбій тривоги
        manager.set_alarm_active(region, False)
        assert manager.threats[region].is_active is False
        assert manager.threats[region].level == "none"
        assert len(manager.threats[region].active_threats) == 0


class TestAPIEndpoints:
    """Перевірка API маршрутів FastApi для встановлення та зняття загроз."""

    @pytest.fixture
    def client(self):
        return TestClient(app)

    def test_mock_threat_and_clear_api(self, client):
        # 1. Ставимо mock загрозу через API
        payload = {
            "region": "Полтавська область",
            "level": "high",
            "threat_type": "shahed",
            "detail": "БпЛА над Полтавою"
        }
        res = client.post("/api/threats/mock", json=payload)
        assert res.status_code == 200
        assert res.json()["status"] == "ok"

        # 2. Перевіряємо GET /api/threats
        get_res = client.get("/api/threats")
        assert get_res.status_code == 200
        threats_data = get_res.json()["threats"]
        assert threats_data["Полтавська область"]["level"] == "high"
        assert threats_data["Полтавська область"]["type"] == "shahed"

        # 3. Очищуємо через POST /api/threats/clear
        clear_res = client.post("/api/threats/clear")
        assert clear_res.status_code == 200

        # 4. Перевіряємо що рівень став 'none'
        get_res_after = client.get("/api/threats")
        assert get_res_after.json()["threats"]["Полтавська область"]["level"] == "none"

    def test_scenario_api(self, client):
        # Запуск сценарію mig_takeoff
        res = client.post("/api/threats/scenario", json={"scenario": "mig_takeoff"})
        assert res.status_code == 200

        get_res = client.get("/api/threats")
        # Всі неокуповані області повинні бути в high через МіГ-31К
        threats = get_res.json()["threats"]
        assert threats["м. Київ"]["level"] == "high"
        assert threats["м. Київ"]["type"] == "mig31k"

        # Очищення через сценарій 'clear'
        res_clear = client.post("/api/threats/scenario", json={"scenario": "clear"})
        assert res_clear.status_code == 200
        get_res_clear = client.get("/api/threats")
        assert get_res_clear.json()["threats"]["м. Київ"]["level"] == "none"
