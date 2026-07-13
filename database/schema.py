"""
Database Schema Initialization.
Creates all SQLite tables, indexes, and seeds mock data in dev mode.
"""

import sqlite3

from core.config import DB_PATH, IS_LIVE_MODE


def init_analytics_db():
    """Create all analytics tables and indexes. Seeds mock data in non-live mode."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # --- threat_history ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            region TEXT,
            threat_level TEXT,
            threat_type TEXT,
            detail TEXT,
            confidence INTEGER,
            is_test BOOLEAN DEFAULT 0
        )
    ''')
    for col in [
        "ALTER TABLE threat_history ADD COLUMN detail TEXT",
        "ALTER TABLE threat_history ADD COLUMN confidence INTEGER",
        "ALTER TABLE threat_history ADD COLUMN is_test BOOLEAN DEFAULT 0",
    ]:
        try:
            cursor.execute(col)
        except sqlite3.OperationalError:
            pass

    # --- telemetry_data ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS telemetry_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_event_id INTEGER NOT NULL,
            group_id TEXT,
            attack_vector TEXT,
            target_count INTEGER,
            speed_kmh INTEGER,
            altitude_category TEXT,
            heading_degrees INTEGER,
            distance_to_target_km REAL,
            launch_origin TEXT,
            weapon_subtype TEXT,
            engagement_status TEXT,
            air_defense_active BOOLEAN DEFAULT 0,
            multiple_waves BOOLEAN DEFAULT 0,
            wave_number INTEGER DEFAULT 1,
            time_of_day_category TEXT,
            weather_factor TEXT,
            source_reliability TEXT,
            message_context_tags TEXT,
            strategic_priority TEXT,
            civilian_risk_level TEXT,
            event_phase TEXT,
            correlation_group TEXT,
            FOREIGN KEY (threat_event_id) REFERENCES threat_history(id)
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_telemetry_group ON telemetry_data(group_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_telemetry_vector ON telemetry_data(attack_vector)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_telemetry_correlation ON telemetry_data(correlation_group)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_telemetry_event ON telemetry_data(threat_event_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_history_region_ts ON threat_history(region, timestamp)')
    try:
        cursor.execute("ALTER TABLE telemetry_data ADD COLUMN target_cities_coords TEXT")
    except sqlite3.OperationalError:
        pass

    # --- threat_clearings ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_clearings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            region TEXT NOT NULL,
            original_threat_event_id INTEGER,
            linked_group_id TEXT,
            linked_correlation_group TEXT,
            resolution_type TEXT DEFAULT 'unknown',
            intercepted_count INTEGER,
            total_targets_in_wave INTEGER,
            impact_confirmed BOOLEAN DEFAULT 0,
            damage_assessment TEXT DEFAULT 'unknown',
            civilian_casualties_reported BOOLEAN DEFAULT 0,
            infrastructure_hit TEXT,
            air_defense_effectiveness TEXT DEFAULT 'unknown',
            threat_duration_assessment TEXT DEFAULT 'unknown',
            prediction_accuracy_hint TEXT DEFAULT 'not_applicable',
            was_predictive BOOLEAN DEFAULT 0,
            original_threat_level TEXT,
            original_threat_type TEXT,
            original_confidence INTEGER,
            clearing_confidence INTEGER,
            clearing_context_tags TEXT,
            source_reliability TEXT DEFAULT 'medium',
            time_of_day_category TEXT DEFAULT 'unknown',
            clearing_source_channel TEXT,
            clearing_message_text TEXT,
            threat_set_timestamp DATETIME,
            threat_duration_seconds INTEGER,
            is_test BOOLEAN DEFAULT 0,
            FOREIGN KEY (original_threat_event_id) REFERENCES threat_history(id)
        )
    ''')
    try:
        cursor.execute("ALTER TABLE threat_clearings ADD COLUMN is_test BOOLEAN DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clearings_region ON threat_clearings(region)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clearings_group ON threat_clearings(linked_group_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clearings_original ON threat_clearings(original_threat_event_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clearings_resolution ON threat_clearings(resolution_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clearings_prediction ON threat_clearings(prediction_accuracy_hint)')

    # --- gemini_rules ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS gemini_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            rule_type TEXT NOT NULL,
            source_region TEXT,
            target_region TEXT,
            threat_type TEXT,
            rule_text TEXT NOT NULL,
            rule_json TEXT,
            evidence_count INTEGER DEFAULT 1,
            accuracy_score REAL DEFAULT 0.5,
            is_active BOOLEAN DEFAULT 1,
            last_validated DATETIME
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_type ON gemini_rules(rule_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_active ON gemini_rules(is_active)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_regions ON gemini_rules(source_region, target_region)')

    # --- paired_events ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS paired_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            region TEXT NOT NULL,
            threat_event_id INTEGER NOT NULL,
            telemetry_id INTEGER,
            clearing_event_id INTEGER,
            lifecycle_status TEXT DEFAULT 'active',
            threat_level TEXT,
            threat_type TEXT,
            confidence_at_set INTEGER,
            confidence_at_clear INTEGER,
            was_predictive BOOLEAN DEFAULT 0,
            prediction_accuracy TEXT,
            duration_seconds INTEGER,
            gemini_group_id TEXT,
            rules_applied TEXT,
            FOREIGN KEY (threat_event_id) REFERENCES threat_history(id),
            FOREIGN KEY (clearing_event_id) REFERENCES threat_clearings(id)
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_paired_region ON paired_events(region)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_paired_status ON paired_events(lifecycle_status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_paired_threat ON paired_events(threat_event_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_paired_group ON paired_events(gemini_group_id)')

    # --- error_log ---
    cursor.execute('''
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
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_error_source ON error_log(source)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_error_type ON error_log(error_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_error_ts ON error_log(timestamp)')

    # --- gemini_rules_audit ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS gemini_rules_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL,
            rule_type TEXT,
            rule_text TEXT,
            source_region TEXT,
            target_region TEXT,
            threat_type TEXT,
            reason TEXT
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_audit_ts ON gemini_rules_audit(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_audit_action ON gemini_rules_audit(action)')

    # Seed mock data in dev mode
    if not IS_LIVE_MODE:
        _seed_mock_data(cursor)

    conn.commit()
    conn.close()
    print("💾 Аналітична БД ініціалізована (threat_history + telemetry_data + threat_clearings + gemini_rules + paired_events + error_log + gemini_rules_audit)")


def _seed_mock_data(cursor: sqlite3.Cursor):
    """Inserts initial mock rules and paired events when the database is empty."""
    cursor.execute("SELECT COUNT(*) as c FROM gemini_rules")
    if cursor.fetchone()[0] == 0:
        try:
            cursor.execute("""
                INSERT INTO gemini_rules (rule_type, source_region, target_region, threat_type, rule_text, accuracy_score, evidence_count, is_active)
                VALUES ('route_pattern', 'Crimea', 'Zaporizhzhia', 'shahed', 'Детекція БПЛА типу Shahed з Криму в бік Запоріжжя', 0.85, 12, 1)
            """)
            cursor.execute("""
                INSERT INTO gemini_rules (rule_type, source_region, target_region, threat_type, rule_text, accuracy_score, evidence_count, is_active)
                VALUES ('confidence_correction', 'Kursk', 'Sumy', 'mig31k', 'Зліт МіГ-31К з Курська в бік Сум', 0.90, 8, 1)
            """)
            cursor.execute("""
                INSERT INTO gemini_rules_audit (action, rule_type, rule_text, source_region, target_region, threat_type, reason)
                VALUES ('added', 'route_pattern', 'Детекція БПЛА типу Shahed з Криму в бік Запоріжжя', 'Crimea', 'Zaporizhzhia', 'shahed', 'Аналіз 12 аналогічних траєкторій за тиждень')
            """)
            cursor.execute("""
                INSERT INTO gemini_rules_audit (action, rule_type, rule_text, source_region, target_region, threat_type, reason)
                VALUES ('added', 'confidence_correction', 'Зліт МіГ-31К з Курська в бік Сум', 'Kursk', 'Sumy', 'mig31k', 'Корекція рівня загрози на основі високої ймовірності ракетного удару')
            """)
        except Exception as e:
            print(f"⚠️ Error seeding mock rules: {e}")

    cursor.execute("SELECT COUNT(*) as c FROM paired_events")
    if cursor.fetchone()[0] == 0:
        for i in range(1, 6):
            try:
                cursor.execute("""
                    INSERT INTO paired_events (region, threat_event_id, lifecycle_status, threat_level, threat_type, was_predictive, gemini_group_id, created_at)
                    VALUES ('Crimea', 9990 + ?, 'cleared', 'high', 'shahed', 0, ?, datetime('now', '-2 hours'))
                """, (i, f"group_seed_{i}"))
                cursor.execute("""
                    INSERT INTO paired_events (region, threat_event_id, lifecycle_status, threat_level, threat_type, was_predictive, prediction_accuracy, gemini_group_id, created_at)
                    VALUES ('Zaporizhzhia', 9995 + ?, 'cleared', 'high', 'shahed', 1, 'confirmed', ?, datetime('now', '-1 hours'))
                """, (i, f"group_seed_{i}"))
            except Exception as e:
                print(f"⚠️ Error seeding paired events: {e}")
