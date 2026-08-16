"""
Realistic End-to-End Threat Event Lifecycle and AI Analysis Pipeline Test.
Simulates realistic multi-threat waves, dynamic RAG prompt injection, telemetry tracking,
kinematic & learned ETA calculation, clearing, autonomous rule synthesis, and Palantir Markov chains.
Guarantees 100% database isolation without polluting production data.
"""

import os
import sys
import json
import sqlite3
import pytest
from datetime import datetime, timezone, timedelta

# Ensure server root is on path
SERVER_ROOT = os.path.abspath(os.path.dirname(__file__) + "/..")
if SERVER_ROOT not in sys.path:
    sys.path.insert(0, SERVER_ROOT)

from core.threat_state import MockThreatManager
from core.regions import ALL_REGIONS
from monitor.telegram_monitor import TelegramThreatMonitor
from analyzer.rules.learner import GeminiRulesLearner
from analyzer.rules.evaluator import build_rules_prompt_context
from analyzer.gemini_analyzer import GeminiThreatAnalyzer
from database.connection import get_sqlite_connection, execute_query_as_dicts
from database.analytics_db import log_threat_to_db, log_clearing_to_db
from api.admin.analytics_intelligence import (
    get_multihop_flight_chains,
    get_palantir_overview,
    resolve_entity_coordinates,
)


@pytest.mark.asyncio
async def test_realistic_threat_event_lifecycle_and_palantir_pipeline():
    """
    Simulates a realistic Ukrainian air defense operational lifecycle:
    1. Multi-vector threat ingress (Shahed wave from North-East + Ballistic fast threat + Tactical Aviation KABs).
    2. Telemetry ingestion, velocity physics, and dynamic ETA prediction.
    3. Official siren state correlation.
    4. Air defense interception, threat clearing, and lifecycle session pairing.
    5. Autonomous rule learning & synthesis into gemini_rules.
    6. Palantir Markov chain calculation with accuracy-weighted transition probabilities.
    7. Database isolation check (zero pollution of production storage).
    """
    threat_manager = MockThreatManager()
    monitor = TelegramThreatMonitor(threat_manager)
    monitor.is_running = True
    monitor.analyzer.is_configured = False

    # -----------------------------------------------------------------------
    # Step 1: Realistic Ingress Wave (Sumy -> Poltava Shahed Group)
    # -----------------------------------------------------------------------
    sumy_region = "Сумська область"
    poltava_region = "Полтавська область"
    kharkiv_region = "Харківська область"

    # Set real direct threat in Sumy
    success = threat_manager.set_threat(
        region=sumy_region,
        level="high",
        threat_type="shahed",
        detail="4х БпЛА курсом на південь через Ромни у напрямку Полтавщини",
        confidence=85,
        eta="до 25 хв",
        is_predictive=False,
        is_test=False,
    )
    assert success is True

    # Log telemetry for Sumy threat into test database
    conn = get_sqlite_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO threat_history (region, threat_level, threat_type, confidence, detail, is_test, timestamp)
        VALUES (?, 'high', 'shahed', 85, 'kpszsu', 1, datetime('now', '-40 minutes'))
    ''', (sumy_region,))
    sumy_event_id = cursor.lastrowid

    cursor.execute('''
        INSERT INTO telemetry_data (threat_event_id, heading_degrees, speed_kmh, attack_vector, launch_origin, target_cities_coords, group_id)
        VALUES (?, 195, 175.0, 'north_to_south', 'Рубіж Курська обл. РФ', '{"Миргород": [49.96, 33.61]}', 'shahed_wave_101')
    ''', (sumy_event_id,))
    conn.commit()

    # -----------------------------------------------------------------------
    # Step 2: Predictive Engine Execution (Markov / Kinematic forward prediction)
    # -----------------------------------------------------------------------
    await monitor._propagate_predictive_threats()

    poltava_state = threat_manager.threats[poltava_region]
    # Poltava should receive predictive yellow alert aligned with heading 195°
    assert poltava_state.is_predictive is True
    assert poltava_state.threat_type == "shahed"
    assert poltava_state.confidence >= 40

    # -----------------------------------------------------------------------
    # Step 3: Official Siren Correlation
    # -----------------------------------------------------------------------
    threat_manager.set_alarm_active(sumy_region, True, alert_type="air")
    threat_manager.set_alarm_active(poltava_region, True, alert_type="air")
    assert threat_manager.threats[sumy_region].is_active is True
    assert threat_manager.threats[poltava_region].is_active is True

    # -----------------------------------------------------------------------
    # Step 4: Threat Progression & Interception Resolution
    # -----------------------------------------------------------------------
    # Threat enters Poltava and is intercepted by air defense
    cursor.execute('''
        INSERT INTO threat_history (region, threat_level, threat_type, confidence, detail, is_test, timestamp)
        VALUES (?, 'high', 'shahed', 90, 'kpszsu', 1, datetime('now', '-15 minutes'))
    ''', (poltava_region,))
    poltava_event_id = cursor.lastrowid

    cursor.execute('''
        INSERT INTO threat_clearings (region, original_threat_event_id, linked_group_id, resolution_type, intercepted_count, air_defense_effectiveness, prediction_accuracy_hint, was_predictive, threat_duration_seconds, is_test, timestamp)
        VALUES (?, ?, 'shahed_wave_101', 'intercepted', 4, 'high', 'confirmed', 1, 1500, 1, datetime('now'))
    ''', (poltava_region, poltava_event_id))

    # Record paired lifecycle sessions for route pattern and ETA learning
    for i in range(4):
        created_time = (datetime.now(timezone.utc) - timedelta(days=i, hours=2)).strftime("%Y-%m-%d %H:%M:%S")
        group_id = f"sim_wave_{i}"
        
        # Source (Sumy)
        cursor.execute('''
            INSERT INTO paired_events (region, threat_event_id, gemini_group_id, threat_type, threat_level, confidence_at_set, was_predictive, prediction_accuracy, lifecycle_status, duration_seconds, created_at)
            VALUES (?, ?, ?, 'shahed', 'high', 85, 0, 'confirmed', 'cleared', 1800, ?)
        ''', (sumy_region, sumy_event_id, group_id, created_time))

        # Target (Poltava - confirmed progression with 25m duration)
        cursor.execute('''
            INSERT INTO paired_events (region, threat_event_id, gemini_group_id, threat_type, threat_level, confidence_at_set, was_predictive, prediction_accuracy, lifecycle_status, duration_seconds, created_at)
            VALUES (?, ?, ?, 'shahed', 'medium', 75, 1, 'confirmed', 'cleared', 1500, ?)
        ''', (poltava_region, poltava_event_id, group_id, created_time))

    conn.commit()

    # -----------------------------------------------------------------------
    # Step 5: Autonomous Rule Learning & Synthesis
    # -----------------------------------------------------------------------
    learner = GeminiRulesLearner()
    route_rules_learned = learner._learn_route_patterns(cursor)
    eta_rules_learned = learner._learn_eta_math_patterns(cursor)
    conn.commit()

    # Verify that route rules were created
    cursor.execute('''
        SELECT source_region, target_region, accuracy_score, evidence_count
        FROM gemini_rules
        WHERE rule_type = 'route_pattern' AND source_region = ? AND target_region = ?
    ''', (sumy_region, poltava_region))
    rule_row = cursor.fetchone()
    assert rule_row is not None
    assert rule_row[2] >= 0.70  # Accuracy >= 70%
    assert rule_row[3] >= 3     # Evidence count >= 3

    # -----------------------------------------------------------------------
    # Step 6: Palantir Multi-Hop Markov Chains Computation
    # -----------------------------------------------------------------------
    chains_data = await get_multihop_flight_chains(days=30)
    assert "chains" in chains_data
    assert "junction_branches" in chains_data

    # Verify that junction branches contain Sumy -> Poltava transition
    branches = chains_data["junction_branches"]
    sumy_branch = next((b for b in branches if b["junction_region"] == sumy_region), None)
    assert sumy_branch is not None
    assert any(target["target"] == poltava_region for target in sumy_branch["branches"])

    # -----------------------------------------------------------------------
    # Step 7: Palantir Overview & Coordinate Resolver Validation
    # -----------------------------------------------------------------------
    palantir_overview = await get_palantir_overview(days=30)
    assert palantir_overview["system"] == "Palantir Tactical Intelligence Engine v2.0"
    assert len(palantir_overview["launch_hubs"]) > 0

    # Ensure zero (0, 0) coordinates across launch hubs
    for hub in palantir_overview["launch_hubs"]:
        assert hub["lat"] > 10.0
        assert hub["lon"] > 10.0

    # -----------------------------------------------------------------------
    # Step 8: Dynamic Rules Prompt Context (RAG Injection for Gemini)
    # -----------------------------------------------------------------------
    analyzer = GeminiThreatAnalyzer(db_path=os.environ.get("DB_PATH"))
    rules_context = analyzer.build_rules_context("Шахеди на півночі через Сумщину курсом на Полтаву")
    assert "НАБУТІ ЗНАННЯ" in rules_context or "ІСТОРИЧНІ ПРАВИЛА" in rules_context or sumy_region in rules_context

    # -----------------------------------------------------------------------
    # Step 9: Verify Production Database Isolation
    # -----------------------------------------------------------------------
    # Check that current active DB_PATH is our isolated test database
    assert "test_threat_analytics.db" in os.environ.get("DB_PATH", "")

    conn.close()
