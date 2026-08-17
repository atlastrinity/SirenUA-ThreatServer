"""
Test suite for weapon launch platforms taxonomy, AI learning, Palantir coordinates,
and strike profile disambiguation.
"""
import pytest
import sqlite3
import json
import os
import tempfile

from core.threat_types import (
    THREAT_SHAHED,
    THREAT_CRUISE_MISSILE,
    THREAT_BALLISTIC,
    THREAT_KAB,
    THREAT_MIG31K,
    THREAT_TU95,
    DRONE_LAUNCH_SITES,
    NAVAL_LAUNCH_BASES,
    BALLISTIC_LAUNCH_SITES,
    RUSSIAN_AIRBASES,
    resolve_aviation_strike_profile,
)
from api.admin.analytics_intelligence import resolve_entity_coordinates
from analyzer.rules.learner import GeminiRulesLearner
from database.schema import init_analytics_db_tables_only


def test_drone_launch_profile_disambiguation():
    """Shahed drone threats must ALWAYS have a land-based drone_pad origin and never launch from the sea."""
    # 1. Drone approaching Odesa from the Black Sea
    profile_sea = resolve_aviation_strike_profile(
        threat_type=THREAT_SHAHED,
        text="Шахеди з акваторії Чорного моря курсом на Одесу",
        target_region="Одеська область"
    )
    assert profile_sea["platform_type"] == "drone_pad"
    assert profile_sea["carrier_origin_name"] == "Мис Чауда (АР Крим)"
    assert "Акваторія Чорного моря" in profile_sea["launch_sector_name"]
    assert profile_sea["is_aviation"] is False
    assert profile_sea["carrier_origin_latitude"] == 45.00
    assert profile_sea["carrier_origin_longitude"] == 35.83

    # 2. Drone from Primorsko-Akhtarsk
    profile_akhtarsk = resolve_aviation_strike_profile(
        threat_type=THREAT_SHAHED,
        text="Пуски шахедів з Приморсько-Ахтарська у напрямку Дніпра",
        target_region="Дніпропетровська область"
    )
    assert profile_akhtarsk["platform_type"] == "drone_pad"
    assert "Приморсько-Ахтарськ" in profile_akhtarsk["carrier_origin_name"]

    # 3. Drone targeting Sumy (Northern border)
    profile_north = resolve_aviation_strike_profile(
        threat_type=THREAT_SHAHED,
        text="БпЛА курсом на Сумщину",
        target_region="Сумська область"
    )
    assert profile_north["platform_type"] == "drone_pad"
    assert "Курськ" in profile_north["carrier_origin_name"] or "Орел" in profile_north["carrier_origin_name"]


def test_artillery_mlrs_fpv_recon_profiles():
    """Artillery, MLRS, FPV, and Recon threats must resolve to their respective firing positions and operator lines."""
    from core.threat_types import THREAT_ARTILLERY, THREAT_MLRS, THREAT_FPV, THREAT_RECON_UAV

    # 1. Artillery targeting Nikopol from Enerhodar
    profile_art = resolve_aviation_strike_profile(
        threat_type=THREAT_ARTILLERY,
        text="Обстріл Нікополя з боку Енергодару",
        target_region="Дніпропетровська область"
    )
    assert profile_art["platform_type"] == "artillery_position"
    assert "Енергодар" in profile_art["carrier_origin_name"]
    assert profile_art["carrier_origin_latitude"] > 0

    # 2. Kinburn spit artillery on Ochakiv
    profile_kinburn = resolve_aviation_strike_profile(
        threat_type=THREAT_ARTILLERY,
        text="Артзагроза Очаків з Кінбурнської коси",
        target_region="Миколаївська область"
    )
    assert profile_kinburn["platform_type"] == "artillery_position"
    assert "Кінбурнська коса" in profile_kinburn["carrier_origin_name"]

    # 3. FPV drone along Zaporizhzhia frontline
    profile_fpv = resolve_aviation_strike_profile(
        threat_type=THREAT_FPV,
        text="FPV дрон на Оріхівському напрямку",
        target_region="Запорізька область"
    )
    assert profile_fpv["platform_type"] == "fpv_recon_pad"
    assert "Запорізький напрямок" in profile_fpv["carrier_origin_name"]

    # 4. Recon drone (Supercam/Orlan) in South
    profile_recon = resolve_aviation_strike_profile(
        threat_type=THREAT_RECON_UAV,
        text="Розвідувальний БпЛА Орлан над Херсонщиною",
        target_region="Херсонська область"
    )
    assert profile_recon["platform_type"] == "fpv_recon_pad"


def test_special_hazards_and_western_regions():
    """Special threats (Zircon, Urban fights, Nuclear) and western regions must resolve accurately."""
    from core.threat_types import THREAT_ZIRCON, THREAT_URBAN_FIGHTS, THREAT_NUCLEAR

    # 1. Zircon hypersonic from Crimea
    profile_zircon = resolve_aviation_strike_profile(
        threat_type=THREAT_ZIRCON,
        text="Пуск ракети Циркон з Криму",
        target_region="Київська область"
    )
    assert profile_zircon["platform_type"] == "coastal_hypersonic"
    assert "Бастіон" in profile_zircon["carrier_origin_name"] or "Крим" in profile_zircon["carrier_origin_name"]

    # 2. ZNPP Radiation risk
    profile_nuke = resolve_aviation_strike_profile(
        threat_type=THREAT_NUCLEAR,
        text="Загроза радіаційного витоку на ЗАЕС",
        target_region="Запорізька область"
    )
    assert profile_nuke["platform_type"] == "special_hazard_zone"
    assert "ЗАЕС" in profile_nuke["carrier_origin_name"]

    # 3. Western region ballistic routing (Lviv / Kapustin Yar)
    profile_west_ballistic = resolve_aviation_strike_profile(
        threat_type=THREAT_BALLISTIC,
        target_region="Львівська область"
    )
    assert profile_west_ballistic["platform_type"] == "ballistic_launcher"
    assert "Капустін Яр" in profile_west_ballistic["carrier_origin_name"]


def test_naval_and_ballistic_profiles():
    """Naval cruise missiles and ballistic missile launchers must resolve accurately."""
    # 1. Kalibr naval launch
    profile_kalibr = resolve_aviation_strike_profile(
        threat_type=THREAT_CRUISE_MISSILE,
        text="Пуск крилатих ракет Калібр з Чорного моря",
        target_region="Одеська область"
    )
    assert profile_kalibr["platform_type"] == "naval_vessel"
    assert profile_kalibr["carrier_origin_name"] == "Акваторія Чорного моря (Флот РФ)"

    # 2. Ballistic launch from Crimea / Tarkhankut
    profile_ballistic = resolve_aviation_strike_profile(
        threat_type=THREAT_BALLISTIC,
        text="Швидкісна ціль на Одесу з Криму",
        target_region="Одеська область"
    )
    assert profile_ballistic["platform_type"] == "ballistic_launcher"
    assert "Тарханкут" in profile_ballistic["carrier_origin_name"]


def test_aviation_profiles():
    """Aviation threats (Tu-95, MiG-31K, KAB) must resolve to respective airbases."""
    profile_mig = resolve_aviation_strike_profile(
        threat_type=THREAT_MIG31K,
        text="Зліт МіГ-31К з Саваслейка"
    )
    assert profile_mig["platform_type"] == "airbase"
    assert "Саваслейка" in profile_mig["carrier_origin_name"]

    profile_tu95 = resolve_aviation_strike_profile(
        threat_type=THREAT_TU95,
        text="Зліт Ту-95МС з Оленья"
    )
    assert profile_tu95["platform_type"] == "airbase"
    assert "Оленья" in profile_tu95["carrier_origin_name"]


def test_palantir_coordinate_resolution():
    """All launch pads, airbases, firing positions, and special hazard zones must have valid nonzero coordinates."""
    from core.threat_types import ARTILLERY_MLRS_LAUNCH_SITES, FPV_RECON_LAUNCH_SITES, SPECIAL_THREAT_SITES
    all_sites = (
        list(DRONE_LAUNCH_SITES.values()) +
        list(NAVAL_LAUNCH_BASES.values()) +
        list(BALLISTIC_LAUNCH_SITES.values()) +
        list(RUSSIAN_AIRBASES.values()) +
        list(ARTILLERY_MLRS_LAUNCH_SITES.values()) +
        list(FPV_RECON_LAUNCH_SITES.values()) +
        list(SPECIAL_THREAT_SITES.values())
    )
    for site in all_sites:
        title = site["title"]
        lat, lon = resolve_entity_coordinates(title)
        assert lat != 0.0 and lon != 0.0, f"Zero coordinates for {title}"
        assert 30.0 <= lat <= 75.0, f"Invalid latitude {lat} for {title}"
        assert 20.0 <= lon <= 65.0, f"Invalid longitude {lon} for {title}"


def test_autonomous_launch_site_pattern_learning():
    """Rules learner must discover launch_site_pattern rules from paired telemetry events."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        init_analytics_db_tables_only(db_path)
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Seed telemetry and paired cleared events
        for i in range(5):
            cursor.execute("""
                INSERT INTO telemetry_data (threat_event_id, weapon_subtype, launch_origin, speed_kmh, heading_degrees)
                VALUES (?, 'shahed', 'Мис Чауда (АР Крим)', 180, 315)
            """, (i + 1,))
            telemetry_id = cursor.lastrowid

            cursor.execute("""
                INSERT INTO paired_events (threat_event_id, telemetry_id, region, threat_type, prediction_accuracy, lifecycle_status, created_at)
                VALUES (?, ?, 'Одеська область', 'shahed', 'confirmed', 'cleared', datetime('now', '-2 days'))
            """, (i + 1, telemetry_id))

        conn.commit()
        conn.close()

        learner = GeminiRulesLearner(db_path=db_path)
        total_learned = learner.run_rules_learner()
        assert total_learned >= 1

        # Check gemini_rules
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        rules = conn.execute("SELECT * FROM gemini_rules WHERE rule_type = 'launch_site_pattern'").fetchall()
        conn.close()

        assert len(rules) >= 1
        rule = rules[0]
        assert rule["source_region"] == "Мис Чауда (АР Крим)"
        assert rule["target_region"] == "Одеська область"
        assert rule["threat_type"] == "shahed"
        assert rule["accuracy_score"] >= 0.90
        assert "Майданчик пуску" in rule["rule_text"]

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)
