"""
Comprehensive test suite for Gemini Rules Engine micro-package and Admin Console endpoints.
"""

import sqlite3
import pytest
from datetime import datetime, timezone
from analyzer.rules import (
    GeminiRulesLearner,
    GeminiRulesRepository,
    GeminiRulesEvaluator,
    build_rules_prompt_context,
    apply_rule_decay
)


@pytest.fixture
def temp_rules_db(tmp_path):
    """Creates a isolated temporary SQLite database with full schema for rules testing."""
    db_file = str(tmp_path / "test_rules.db")
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()

    cursor.execute('''
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
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS gemini_rules_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            rule_type TEXT,
            rule_text TEXT,
            source_region TEXT,
            target_region TEXT,
            threat_type TEXT,
            reason TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS paired_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_event_id INTEGER,
            gemini_group_id TEXT,
            region TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            threat_level TEXT NOT NULL,
            was_predictive INTEGER DEFAULT 0,
            prediction_accuracy TEXT DEFAULT 'pending',
            confidence_at_set INTEGER DEFAULT 80,
            lifecycle_status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()
    return db_file


def test_rules_repository_and_decay(temp_rules_db):
    """Test GeminiRulesRepository CRUD and apply_rule_decay."""
    repo = GeminiRulesRepository(temp_rules_db)

    # Insert test rules
    conn = sqlite3.connect(temp_rules_db)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO gemini_rules (rule_type, source_region, target_region, threat_type, rule_text, evidence_count, accuracy_score, is_active)
        VALUES ('route_pattern', 'Сумська область', 'Полтавська область', 'shahed', 'Сумська -> Полтавська', 5, 0.85, 1)
    ''')
    cursor.execute('''
        INSERT INTO gemini_rules (rule_type, source_region, target_region, threat_type, rule_text, evidence_count, accuracy_score, is_active)
        VALUES ('route_pattern', 'Запорізька область', 'Дніпропетровська область', 'shahed', 'Запорізька -> Дніпропетровська', 2, 0.40, 1)
    ''')
    conn.commit()

    # 1. Fetch active rules
    rules = repo.fetch_active_rules(min_accuracy=0.50)
    assert len(rules) == 1
    assert rules[0]["source_region"] == "Сумська область"

    # 2. Apply Decay (should deactivate 0.40 accuracy rule)
    decayed = apply_rule_decay(cursor)
    conn.commit()
    assert decayed == 1

    # 3. Fetch rules by region
    poltava_rules = repo.fetch_rules_by_region("Полтавська область")
    assert len(poltava_rules) == 1
    assert poltava_rules[0]["target_region"] == "Полтавська область"

    conn.close()


def test_rules_learner_and_evaluator(temp_rules_db):
    """Test autonomous learning of route patterns and confidence corrections."""
    conn = sqlite3.connect(temp_rules_db)
    cursor = conn.cursor()

    # Insert synthetic paired_events for route pattern learning
    group_id = "grp_test_100"
    for i in range(6):
        cursor.execute('''
            INSERT INTO paired_events (gemini_group_id, region, threat_type, threat_level, was_predictive, prediction_accuracy, lifecycle_status, created_at)
            VALUES (?, 'Чернігівська область', 'shahed', 'high', 0, 'cleared', 'cleared', datetime('now', '-1 hours'))
        ''', (group_id + str(i),))

        cursor.execute('''
            INSERT INTO paired_events (gemini_group_id, region, threat_type, threat_level, was_predictive, prediction_accuracy, lifecycle_status, created_at)
            VALUES (?, 'Київська область', 'shahed', 'high', 1, 'confirmed', 'cleared', datetime('now', '-30 minutes'))
        ''', (group_id + str(i),))

    conn.commit()
    conn.close()

    # Run learner
    learner = GeminiRulesLearner(temp_rules_db)
    learned_count = learner.run_rules_learner()
    assert learned_count >= 1

    # Evaluate learned rules
    evaluator = GeminiRulesEvaluator(temp_rules_db)
    rules_for_kyiv = evaluator.evaluate_rules_for_region_group(["Київська область"])
    assert len(rules_for_kyiv) >= 1
    assert "Чернігівська область" in rules_for_kyiv[0]["rule_text"]

    # Test prompt context builder
    prompt_ctx = build_rules_prompt_context(temp_rules_db, target_region="Київська область")
    assert "Чернігівська область" in prompt_ctx


def test_admin_rules_endpoints():
    """Test Admin Console API endpoints for Gemini rules."""
    from fastapi.testclient import TestClient
    from server import app

    client = TestClient(app)

    # 1. Rules History
    res_hist = client.get("/api/admin/rules/history?days=30")
    assert res_hist.status_code == 200
    assert "entries" in res_hist.json()

    # 2. Rules By Region
    res_reg = client.get("/api/admin/rules/by_region")
    assert res_reg.status_code == 200
    data_reg = res_reg.json()
    assert "grouped_rules" in data_reg

    # 3. Rules Metrics By Region
    res_metrics = client.get("/api/admin/rules/metrics_by_region")
    assert res_metrics.status_code == 200
    data_metrics = res_metrics.json()
    assert "region_metrics" in data_metrics

    # 4. Rules Relearn Trigger
    res_relearn = client.post("/api/admin/rules/relearn")
    assert res_relearn.status_code == 200
    data_relearn = res_relearn.json()
    assert data_relearn["status"] == "success"
    assert "total_learned" in data_relearn

