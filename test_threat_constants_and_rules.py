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
        
    updated = analyzer._learn_eta_math_patterns(cursor)
    assert updated >= 1
    
    cursor.execute("SELECT * FROM gemini_rules WHERE rule_type = 'eta_math'")
    rule = cursor.fetchone()
    assert rule is not None
    assert "Математика дольоту" in rule["rule_text"]
    assert "shahed" in rule["rule_text"]
    print(f"✅ Gemini Rules Engine learned ETA math rule: {rule['rule_text']}")

def test_trajectory_gap_stitching():
    print("🧪 Test 5: Testing Intelligent Trajectory Gap Stitching & Path Bridging...")
    from monitor.telegram_monitor import TelegramThreatMonitor
    from core.threat_state import MockThreatManager

    tm = MockThreatManager()
    monitor = TelegramThreatMonitor(threat_manager=tm)

    # Test bridging gap from Sumy (north-east) to Kyiv (center-west)
    # Topological path: Sumy -> Chernihiv -> Kyiv
    monitor._bridge_trajectory_gaps(
        source_region="Сумська область",
        target_region="Київська область",
        threat_type=THREAT_SHAHED,
        group_id="group_gap_test_1"
    )

    # Chernihiv should now be activated as a predictive flight corridor gap region
    chernihiv_state = tm.threats.get("Чернігівська область")
    assert chernihiv_state is not None
    assert chernihiv_state.level != "none"
    assert chernihiv_state.is_predictive is True
    assert "Проміжний коридор" in chernihiv_state.detail
    assert "відновлено" in chernihiv_state.detail
    print("✅ Trajectory gap stitching successfully bridged Chernihiv region between Sumy and Kyiv!")

def test_regional_rule_telemetry_and_metrics():
    print("🧪 Test 6: Testing Regional Rule Telemetry & Metrics API...")
    from analyzer.gemini_analyzer import GeminiThreatAnalyzer
    from api.admin.rules import get_admin_rules_metrics_by_region
    import asyncio

    analyzer = GeminiThreatAnalyzer()
    rules = [
        {"rule_type": "route_pattern", "rule_text": "Захід БпЛА Shahed через Сумщину", "evidence_count": 15, "accuracy_score": 0.90, "target_region": "Сумська область"},
        {"rule_type": "eta_math", "rule_text": "Математика дольоту Shahed з Сум до Києва", "evidence_count": 14, "accuracy_score": 0.88, "target_region": "Київська область"}
    ]
    analyzer.print_regional_rule_telemetry(["Сумська область", "Київська область"], rules)

    metrics_res = asyncio.run(get_admin_rules_metrics_by_region())
    assert metrics_res["status"] == "success"
    assert "Сумська область" in metrics_res["region_metrics"]
    sumy_m = metrics_res["region_metrics"]["Сумська область"]
    assert "accuracy_gain_pct" in sumy_m
    assert "eta_variance_minutes" in sumy_m
    assert len(sumy_m["graph_time_series"]) == 8
    print("✅ Regional Rule Telemetry & Metrics API successfully verified with dispersion graph data!")

if __name__ == "__main__":
    test_threat_types_detection()
    test_airbases_detection()
    test_kinematics_calculations()
    test_rules_engine_learning()
    test_trajectory_gap_stitching()
    test_regional_rule_telemetry_and_metrics()
    print("\n🎉 ALL THREAT CONSTANTS, AIRBASES, RULES, GAP STITCHING, AND REGIONAL METRICS TESTS PASSED SUCCESSFULLY!")
