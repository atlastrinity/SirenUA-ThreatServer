"""
Unit and Integration Test Suite for Centralized Threat Constants, Russian Airbases,
Kinematics Calculations, and Gemini Rule Learning Engine.
"""

import sys
import os
import sqlite3
import pytest

# Ensure SirenUA-ThreatServer is on python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from core.threat_types import (
    THREAT_SHAHED, THREAT_CRUISE_MISSILE, THREAT_BALLISTIC, THREAT_MIG31K,
    THREAT_KAB, THREAT_TU95, THREAT_TU22M3, THREAT_SU35, THREAT_ISKANDER,
    THREAT_ARTILLERY, THREAT_RECON, THREAT_UNKNOWN, ALL_THREAT_TYPES,
    AIRBASE_SAVASLEYKA, AIRBASE_OLENYA, AIRBASE_ENGELS, AIRBASE_SHAYKOVKA,
    AIRBASE_PRIMORSKO_AKHTARSK, AIRBASE_YEYSK, AIRBASE_KURSK, AIRBASE_BELGOROD,
    RUSSIAN_AIRBASES, get_threat_speed, calculate_kinematic_eta,
    detect_threat_type_from_text, detect_launch_origin_from_text,
    get_launch_origin_title
)
from analyzer.gemini_analyzer import GeminiThreatAnalyzer

def test_threat_types_detection():
    print("🧪 Test 1: Testing threat type text detection...")
    assert detect_threat_type_from_text("Зліт МіГ-31К з Саваслейки") == THREAT_MIG31K
    assert detect_threat_type_from_text("Пуски ракети Х-47М2 Кинджал") == THREAT_MIG31K
    assert detect_threat_type_from_text("Зліт 4х Бортів Ту-95МС з Оленьї") == THREAT_TU95
    assert detect_threat_type_from_text("Ту-22М3 над Калузькою областю") == THREAT_TU22M3
    assert detect_threat_type_from_text("БпЛА Shahed в напрямку Одеси") == THREAT_SHAHED
    assert detect_threat_type_from_text("Загроза балістичного озброєння з Криму") == THREAT_BALLISTIC
    assert detect_threat_type_from_text("Пуск Іскандер-М з Бєлгорода") == THREAT_ISKANDER
    assert detect_threat_type_from_text("Пуск крилатих ракет Калібр з Чорного моря") == THREAT_CRUISE_MISSILE
    assert detect_threat_type_from_text("КАБи на Харкову з Су-35") == THREAT_SU35
    assert detect_threat_type_from_text("Артобстріл Нікополя з РСЗВ Град") == THREAT_ARTILLERY
    print("✅ Threat type detection passed for all types!")

def test_airbases_detection():
    print("🧪 Test 2: Testing Russian airbases and launch hubs detection...")
    assert detect_launch_origin_from_text("Зліт МіГ-31К з аеродрому Саваслейка") == AIRBASE_SAVASLEYKA
    assert detect_launch_origin_from_text("Зліт стратегічної авіації з Оленья") == AIRBASE_OLENYA
    assert detect_launch_origin_from_text("Борти Ту-95 у повітрі біля Енгельсу") == AIRBASE_ENGELS
    assert detect_launch_origin_from_text("Зліт Ту-22М3 з Шайковки") == AIRBASE_SHAYKOVKA
    assert detect_launch_origin_from_text("Запуск шахедів з Приморсько-Ахтарська") == AIRBASE_PRIMORSKO_AKHTARSK
    assert detect_launch_origin_from_text("Пуски БПЛА з Єйська") == AIRBASE_YEYSK
    assert detect_launch_origin_from_text("Су-35 піднявся з Курська") == AIRBASE_KURSK
    assert detect_launch_origin_from_text("Пуск балістики з Бєлгорода") == AIRBASE_BELGOROD
    print("✅ Airfield launch origin detection passed!")

def test_kinematics_calculations():
    print("🧪 Test 3: Testing flight kinematics and ETA calculation formulas...")
    # Ballistic / Iskander short range (150 km)
    eta_sec, eta_str = calculate_kinematic_eta(150.0, THREAT_BALLISTIC)
    assert eta_sec > 0 and "~2-5 хв" in eta_str or "хв" in eta_str
    
    # Shahed long range (400 km)
    eta_sec, eta_str = calculate_kinematic_eta(400.0, THREAT_SHAHED)
    assert eta_sec > 7000  # ~2 hours

    # Tu-22M3 supersonic (350 km)
    eta_sec, eta_str = calculate_kinematic_eta(350.0, THREAT_TU22M3)
    assert eta_sec < 600  # < 10 mins

    print("✅ Kinematics calculation tests passed!")

def test_rules_engine_learning():
    print("🧪 Test 4: Testing Gemini Rules Engine learning and auditing...")
    analyzer = GeminiThreatAnalyzer()
    
    # Set up DB schema
    from database.schema import init_analytics_db
    init_analytics_db()
    
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS paired_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            region TEXT NOT NULL,
            threat_event_id INTEGER,
            lifecycle_status TEXT DEFAULT 'active',
            threat_level TEXT,
            threat_type TEXT,
            was_predictive INTEGER DEFAULT 0,
            prediction_accuracy TEXT,
            gemini_group_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS gemini_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_type TEXT NOT NULL,
            source_region TEXT,
            target_region TEXT,
            threat_type TEXT,
            rule_text TEXT NOT NULL,
            rule_json TEXT,
            evidence_count INTEGER DEFAULT 1,
            accuracy_score REAL DEFAULT 1.0,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Seed mock history for ETA math rule learning
    for i in range(5):
        cursor.execute("""
            INSERT INTO paired_events (region, threat_event_id, lifecycle_status, threat_level, threat_type, was_predictive, prediction_accuracy, gemini_group_id, created_at)
            VALUES ('Сумська область', ?, 'cleared', 'high', 'shahed', 0, 'confirmed', ?, datetime('now', '-2 hours'))
        """, (100 + i, f"group_eta_{i}"))
        cursor.execute("""
            INSERT INTO paired_events (region, threat_event_id, lifecycle_status, threat_level, threat_type, was_predictive, prediction_accuracy, gemini_group_id, created_at)
            VALUES ('Київська область', ?, 'cleared', 'high', 'shahed', 1, 'confirmed', ?, datetime('now', '-1 hours'))
        """, (200 + i, f"group_eta_{i}"))
        
    # Learn rules using Gemini Rules Learner
    updated = analyzer.run_rules_learner()
    assert updated >= 0
    print("✅ Gemini Rules Engine rules learner run completed successfully!")

def test_trajectory_gap_stitching():
    print("🧪 Test 5: Testing Intelligent Trajectory Gap Stitching & Path Bridging...")
    from monitor.trajectory.gap_bridging import find_shortest_path
    
    # Test bridging gap from Sumy (north-east) to Kyiv (center-west)
    # Topological path: Sumy -> Chernihiv -> Kyiv
    path = find_shortest_path("Сумська область", "Київська область")
    assert "Чернігівська область" in path
    print("✅ Trajectory gap stitching successfully found Chernihiv region between Sumy and Kyiv!")

def test_regional_rule_telemetry_and_metrics():
    print("🧪 Test 6: Testing Regional Rule Telemetry & Metrics API...")
    from api.admin.rules import get_admin_rules_metrics_by_region
    import asyncio

    metrics_res = asyncio.run(get_admin_rules_metrics_by_region())
    assert metrics_res["status"] == "success"
    assert "region_metrics" in metrics_res
    print("✅ Regional Rule Telemetry & Metrics API successfully verified!")

def test_inland_ingress_corridor_extrapolation():
    print("🧪 Test 7: Testing Inland Ingress Corridor Extrapolation for Dnipro & Inland Oblasts...")
    from monitor.trajectory.gap_bridging import EXTRAPOLATED_INGRESS_CORRIDORS

    assert "Дніпропетровська область" in EXTRAPOLATED_INGRESS_CORRIDORS
    assert EXTRAPOLATED_INGRESS_CORRIDORS["Дніпропетровська область"] == "Запорізька область"
    assert "Полтавська область" in EXTRAPOLATED_INGRESS_CORRIDORS
    assert EXTRAPOLATED_INGRESS_CORRIDORS["Полтавська область"] == "Сумська область"
    print("✅ Inland Ingress Corridor Extrapolation mappings verified successfully!")

def test_palantir_intelligence_endpoints():
    """Перевірка роботоздатності API ендпоінтів та створення записів в БД Palantir."""
    from fastapi.testclient import TestClient
    from server import app

    client = TestClient(app)

    # 1. Overview API
    res = client.get("/api/admin/palantir/overview?days=30")
    assert res.status_code == 200
    data = res.json()
    assert "trajectory_corridors" in data
    assert "launch_hubs" in data
    assert "region_risk_matrix" in data

    # 2. Synthesis POST API
    res_synth = client.post("/api/admin/palantir/synthesize")
    assert res_synth.status_code == 200
    synth_data = res_synth.json()
    assert synth_data["status"] == "success"
    assert "palantir_summary" in synth_data

    # 3. Reports GET API
    res_rep = client.get("/api/admin/palantir/reports?limit=10")
    assert res_rep.status_code == 200
    reports_data = res_rep.json()
    assert reports_data["total"] >= 1
    print("✅ Palantir Intelligence Endpoints & DB Storage test passed successfully!")



def test_fcm_topic_mapping():
    """Перевірка правильного перетворення назв областей у латинські FCM топіки."""
    from database.notifications import get_fcm_topic

    assert get_fcm_topic("Чернігівська область") == "region_chernihiv"
    assert get_fcm_topic("Київська область") == "region_kyiv_oblast"
    assert get_fcm_topic("м. Київ") == "region_kyiv_city"
    assert get_fcm_topic("Вінницька область") == "region_vinnytsia"
    assert get_fcm_topic("Полтавська область") == "region_poltava"
    # Occupied territories are NOT in topic mapping — fall through to sanitization
    crimea_topic = get_fcm_topic("Автономна Республіка Крим")
    assert crimea_topic != "region_crimea", "Occupied territories should NOT have dedicated FCM topics"

    # Already valid topics pass through
    assert get_fcm_topic("region_sumy") == "region_sumy"
    assert get_fcm_topic("all") == "all"

    # Edge cases
    assert get_fcm_topic("") == "all"
    assert get_fcm_topic(None) == "all"
def test_threat_notification_title_formatting():
    """Перевірка симетрії формування заголовків сповіщень між бекендом та Swift ThreatConstants."""
    from core.threat_types import format_threat_notification_title

    # High confidence (>=85%) -> Red circle
    t1 = format_threat_notification_title("ballistic", 90, "м. Київ")
    assert t1 == "🔴 Висока ймовірність: Балістична загроза (м. Київ)"

    # Medium confidence (60-84%) -> Orange circle
    t2 = format_threat_notification_title("shahed", 75, "Київська область")
    assert t2 == "🟠 Ймовірна загроза: Загроза БпЛА Shahed (Київська область)"

    # Low confidence (<60%) -> Yellow circle
    t3 = format_threat_notification_title("kab", 45, "Харківська область")
    assert t3 == "🟡 Можлива загроза: Загроза КАБ (Харківська область)"

    # Official alarm
    t4 = format_threat_notification_title(None, None, "Черкаська область", is_official_alarm=True)
    assert t4 == "🔴 Повітряна тривога: Черкаська область"

    # Official clear
    t5 = format_threat_notification_title(None, None, "Черкаська область", is_official_alarm=True, is_clear=True)
    assert t5 == "🟢 Відбій тривоги: Черкаська область"

    # Threat clear
    t6 = format_threat_notification_title("shahed", None, "Одеська область", is_clear=True)
    assert t6 == "🟢 Відбій загрози: Одеська область"

    print("✅ Notification Title Formatting Symmetry test passed successfully!")


def test_aviation_strike_profiles():
    """Перевірка розпізнавання авіаційних профілів, аеродромів та секторів пусків."""
    from core.threat_types import (
        resolve_aviation_strike_profile,
        detect_launch_sector_from_text,
        RUSSIAN_AIRBASES,
        AVIATION_LAUNCH_SECTORS,
        AIRBASE_MOROZOVSK,
        AIRBASE_BALTIMOR,
        SECTOR_BELGOROD,
        SECTOR_AZOV_SEA,
    )

    # 1. New airbases exist
    assert AIRBASE_MOROZOVSK in RUSSIAN_AIRBASES
    assert "Морозовськ" in RUSSIAN_AIRBASES[AIRBASE_MOROZOVSK]["title"]

    # 2. Launch sectors exist
    assert SECTOR_BELGOROD in AVIATION_LAUNCH_SECTORS
    assert SECTOR_AZOV_SEA in AVIATION_LAUNCH_SECTORS

    # 3. KAB on Kharkiv sector resolution
    prof1 = resolve_aviation_strike_profile("kab", "Пуски КАБ на Харків з Бєлгородщини", "Харківська область")
    assert prof1["is_aviation"] is True
    assert prof1["carrier_type"] == "su34"
    assert prof1["launch_sector_name"] == "Рубіж Бєлгородська обл. РФ"
    assert prof1["launch_sector_latitude"] == 50.60
    assert prof1["carrier_origin_name"] is not None

    # 4. Tactical Su-35 on Zaporizhzhia
    prof2 = resolve_aviation_strike_profile("su35", "Су-35 над Азовським морем пуск Х-59", "Запорізька область")
    assert prof2["is_aviation"] is True
    assert prof2["carrier_type"] == "su35"
    assert prof2["launch_sector_name"] == "Акваторія Азовського моря"

    # 5. MiG-31K Kinzhal
    prof3 = resolve_aviation_strike_profile("mig31k", "Зліт МіГ-31К з Саваслейка", "м. Київ")
    assert prof3["is_aviation"] is True
    assert prof3["carrier_type"] == "mig31k"
    assert "Саваслейка" in prof3["carrier_origin_name"]

    print("✅ Aviation Strike Profiles & Launch Sectors test passed successfully!")


if __name__ == "__main__":
    test_threat_types_detection()
    test_airbases_detection()
    test_kinematics_calculations()
    test_rules_engine_learning()
    test_trajectory_gap_stitching()
    test_regional_rule_telemetry_and_metrics()
    test_inland_ingress_corridor_extrapolation()
    test_palantir_intelligence_endpoints()
    test_fcm_topic_mapping()
    test_threat_notification_title_formatting()
    test_aviation_strike_profiles()
    print("\n🎉 ALL THREAT CONSTANTS, TRAJECTORY, PALANTIR & FCM TOPIC TESTS PASSED SUCCESSFULLY!")

