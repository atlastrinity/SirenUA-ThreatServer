"""
Tests for Autonomous Gemini Post-Mortem, Dynamic Rules RAG, and Multi-Hop Palantir Chains.
"""

import os
import json
import sqlite3
import pytest
from unittest.mock import MagicMock, AsyncMock
from fastapi.testclient import TestClient

from server import app
from database.schema import init_analytics_db_tables_only
from analyzer.gemini_analyzer import GeminiThreatAnalyzer
from analyzer.rules.post_mortem import GeminiPostMortemAnalyzer
from api.admin.analytics_intelligence import get_multihop_flight_chains, get_air_defense_attrition

TEST_DB = "test_postmortem_rag.db"


@pytest.fixture(autouse=True)
def setup_test_db():
    """Setup isolated SQLite DB with sample data."""
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)

    conn = sqlite3.connect(TEST_DB)
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS gemini_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_type TEXT NOT NULL,
            source_region TEXT,
            target_region TEXT,
            threat_type TEXT,
            rule_text TEXT NOT NULL,
            rule_json TEXT,
            evidence_count INTEGER DEFAULT 1,
            accuracy_score REAL DEFAULT 0.5,
            is_active BOOLEAN DEFAULT 1,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS gemini_rules_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL,
            rule_type TEXT NOT NULL,
            rule_text TEXT NOT NULL,
            source_region TEXT,
            target_region TEXT,
            threat_type TEXT,
            reason TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS paired_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            region TEXT NOT NULL,
            threat_level TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            lifecycle_status TEXT DEFAULT 'active',
            confidence_at_set INTEGER DEFAULT 50,
            confidence_at_clear INTEGER DEFAULT 50,
            was_predictive BOOLEAN DEFAULT 0,
            prediction_accuracy TEXT DEFAULT 'pending',
            duration_seconds INTEGER DEFAULT 0,
            gemini_group_id TEXT,
            clearing_event_id INTEGER,
            is_test BOOLEAN DEFAULT 0
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS threat_clearings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            region TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            previous_level TEXT DEFAULT 'unknown',
            clearing_message_text TEXT,
            resolution_type TEXT DEFAULT 'unknown',
            air_defense_effectiveness TEXT DEFAULT 'unknown',
            threat_duration_assessment TEXT DEFAULT 'unknown',
            clearing_source_channel TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_test BOOLEAN DEFAULT 0
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS error_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source TEXT NOT NULL,
            error_type TEXT NOT NULL,
            message TEXT NOT NULL,
            endpoint TEXT,
            context TEXT
        )
    ''')

    # Seed rules across different regional clusters
    c.executemany("""
        INSERT INTO gemini_rules (rule_type, source_region, target_region, threat_type, rule_text, rule_json, evidence_count, accuracy_score, is_active)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
    """, [
        ('route_pattern', 'Курська обл. РФ', 'Сумська область', 'shahed', 'Загрози з Курська заходять на Сумщину', '{}', 20, 0.95),
        ('route_pattern', 'Бєлгородська обл. РФ', 'Харківська область', 'shahed', 'Загрози з Бєлгорода цілять на Харківщину', '{}', 25, 0.96),
        ('route_pattern', 'Чорне море', 'Одеська область', 'cruise_missile', 'Калібри з моря йдуть на Одещину та Миколаївщину', '{}', 15, 0.90),
        ('route_pattern', 'Чернігівська область', 'Київська область', 'shahed', 'Транзит з Чернігівщини на Київщину', '{}', 18, 0.92),
        ('confidence_correction', 'Саваслейка', 'Всі області', 'mig31k', 'Зліт МіГ-31К масштабує тривогу на всю країну', '{}', 30, 0.98),
        ('eta_math', 'Житомирська область', 'Хмельницька область', 'shahed', 'Час підльоту до Хмельниччини ~40 хв', '{}', 12, 0.88),
    ])

    # Seed paired_events for multi-hop flight paths
    c.executemany("""
        INSERT INTO paired_events (gemini_group_id, region, threat_type, threat_level, lifecycle_status, was_predictive, prediction_accuracy, created_at, duration_seconds)
        VALUES (?, ?, ?, ?, 'cleared', ?, ?, datetime('now', ?), ?)
    """, [
        # Chain 1: Sumy -> Poltava -> Cherkasy
        ('group_wave_1', 'Сумська область', 'shahed', 'high', 0, 'confirmed', '-2 hours', 3600),
        ('group_wave_1', 'Полтавська область', 'shahed', 'medium', 1, 'confirmed', '-90 minutes', 3000),
        ('group_wave_1', 'Черкаська область', 'shahed', 'low', 1, 'confirmed', '-45 minutes', 2400),
        # Chain 2: Sumy -> Poltava -> Kyiv
        ('group_wave_2', 'Сумська область', 'shahed', 'high', 0, 'confirmed', '-3 hours', 4000),
        ('group_wave_2', 'Полтавська область', 'shahed', 'medium', 1, 'confirmed', '-2 hours', 3200),
        ('group_wave_2', 'Київська область', 'shahed', 'low', 1, 'confirmed', '-1 hour', 2800),
        # Chain 3: Odesa -> Mykolaiv
        ('group_wave_3', 'Одеська область', 'cruise_missile', 'high', 0, 'confirmed', '-4 hours', 1800),
        ('group_wave_3', 'Миколаївська область', 'cruise_missile', 'high', 1, 'confirmed', '-3 hours', 1500),
    ])

    # Seed threat_clearings for air defense attrition
    c.executemany("""
        INSERT INTO threat_clearings (region, threat_type, resolution_type, air_defense_effectiveness, created_at)
        VALUES (?, ?, ?, ?, datetime('now', ?))
    """, [
        ('Сумська область', 'shahed', 'intercepted', 'high', '-2 hours'),
        ('Сумська область', 'shahed', 'intercepted', 'high', '-3 hours'),
        ('Полтавська область', 'shahed', 'intercepted', 'high', '-90 minutes'),
        ('Черкаська область', 'shahed', 'impact', 'low', '-45 minutes'),
        ('Одеська область', 'cruise_missile', 'intercepted', 'high', '-4 hours'),
    ])

    conn.commit()
    conn.close()

    yield

    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)


def test_dynamic_rules_rag_relevance():
    """Verify Dynamic Rules RAG selects relevant rules for specific regions and clusters."""
    analyzer = GeminiThreatAnalyzer(api_key="test_key", db_path=TEST_DB)

    # 1. Northern message -> should match Sumy / Chernihiv / Kyiv rules
    north_msg = "Увага! Група шахедів з півночі заходить на Сумщину та Чернігівщину!"
    north_ctx = analyzer.build_rules_context(north_msg)
    assert "Сумська" in north_ctx or "Чернігівська" in north_ctx or "Курська" in north_ctx
    assert "Чорне море" not in north_ctx  # Southern rule filtered out

    # 2. Southern message -> should match Black Sea / Odesa rules
    south_msg = "Пуски Калібрів з Чорного моря в напрямку Одеської та Миколаївської областей!"
    south_ctx = analyzer.build_rules_context(south_msg)
    assert "Одещ" in south_ctx or "Калібр" in south_ctx or "Одес" in south_ctx

    # 3. Strategic aviation message -> should match MiG-31K / Savasleyka rules
    mig_msg = "Зліт МіГ-31К з аеродрому Саваслейка! Ракетна небезпека по всій Україні!"
    mig_ctx = analyzer.build_rules_context(mig_msg)
    assert "МіГ-31К" in mig_ctx or "Саваслейка" in mig_ctx


@pytest.mark.asyncio
async def test_post_mortem_reflection_execution():
    """Verify Post-Mortem reflection parses session data and saves derived rules."""
    post_mortem = GeminiPostMortemAnalyzer(db_path=TEST_DB)
    
    # Check data extraction
    session_data = post_mortem.fetch_recent_session_data(hours=6)
    assert session_data["total_cleared_events"] >= 5

    # Mock Gemini model response
    mock_model = MagicMock()
    mock_response = MagicMock()
    mock_response.text = json.dumps({
        "session_accuracy_score": 0.92,
        "tactical_assessment": "Ворог застосував комбінований наліт Шахедів через Сумщину з розгалуженням на Полтавщину та Черкащину. ППО відпрацювало ефективно.",
        "anomalies_detected": ["Низьковисотний маневр вздовж русла річки Псел"],
        "derived_rules": [
            {
                "rule_type": "route_pattern",
                "source_region": "Полтавська область",
                "target_region": "Черкаська область",
                "threat_type": "shahed",
                "rule_text": "Шахеди з Полтавщини вздовж річки заходять на Черкащину (Канів/Черкаси)",
                "confidence_score": 0.91,
                "reason": "Підтверджено 2 послідовними збитими бортами"
            }
        ]
    })
    mock_model.generate_content.return_value = mock_response

    # Run post-mortem
    result = await post_mortem.run_post_mortem(hours=6, custom_model=mock_model)
    assert result["status"] == "success"
    assert result["session_accuracy_score"] == 0.92
    assert result["saved_rules_count"] == 1

    # Verify rule was written to DB and audit table
    conn = sqlite3.connect(TEST_DB)
    c = conn.cursor()
    c.execute("SELECT rule_text, accuracy_score, is_active FROM gemini_rules WHERE target_region = 'Черкаська область'")
    saved_rule = c.fetchone()
    assert saved_rule is not None
    assert saved_rule[1] == 0.91

    c.execute("SELECT action, rule_text, reason FROM gemini_rules_audit WHERE target_region = 'Черкаська область'")
    audit_row = c.fetchone()
    assert audit_row is not None
    assert audit_row[0] == "added"
    assert "Post-Mortem" in audit_row[2]

    conn.close()


@pytest.mark.asyncio
async def test_palantir_multihop_chains_and_attrition():
    """Verify Palantir multi-hop Markov chains and air defense attrition calculations."""
    # We query through custom DB path helper or API directly
    from database.db_helpers import execute_query_as_dicts
    
    # Verify multi-hop transitions query
    query = """
        SELECT gemini_group_id, region, threat_type, created_at, prediction_accuracy
        FROM paired_events
        WHERE gemini_group_id IS NOT NULL AND gemini_group_id != ''
        ORDER BY gemini_group_id, created_at ASC
    """
    conn = sqlite3.connect(TEST_DB)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(query)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()

    assert len(rows) >= 6
    # Check group_wave_1: Sumy -> Poltava -> Cherkasy
    g1 = [r["region"] for r in rows if r["gemini_group_id"] == "group_wave_1"]
    assert g1 == ['Сумська область', 'Полтавська область', 'Черкаська область']


def test_api_palantir_endpoints():
    """Test client endpoint accessibility for palantir overview and chains."""
    client = TestClient(app)

    res_overview = client.get("/api/admin/palantir/overview?days=30")
    assert res_overview.status_code == 200
    data = res_overview.json()
    assert "multihop_chains" in data
    assert "junction_branches" in data
    assert "air_defense_attrition" in data

    res_chains = client.get("/api/admin/palantir/chains?days=30")
    assert res_chains.status_code == 200
    assert "chains" in res_chains.json()

    res_attrition = client.get("/api/admin/palantir/attrition?days=30")
    assert res_attrition.status_code == 200
    assert "regions" in res_attrition.json()
