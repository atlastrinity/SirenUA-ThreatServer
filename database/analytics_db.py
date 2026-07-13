"""
SirenUA SQLite Analytics Database and Logging.
Manages database initialization, error logs, threat logs, rules audits, and clearing events.
"""

import os
import sqlite3
import json
import asyncio
import time
from datetime import datetime, timezone
from typing import Optional, List, Dict

from core.config import DB_PATH, IS_LIVE_MODE
from database.db_helpers import get_db, is_duplicate_event

# Global references
main_loop = None

# Track last logged threat states to avoid duplicate logging and properly detect changes
last_logged_states: Dict[str, dict] = {}

# Firestore history batch buffer — collects writes during _batch_mode for one flush
_history_batch_buffer: List[dict] = []

def init_analytics_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
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
    try:
        cursor.execute("ALTER TABLE threat_history ADD COLUMN detail TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE threat_history ADD COLUMN confidence INTEGER")
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE threat_history ADD COLUMN is_test BOOLEAN DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    
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

    # Seed mock rules and audit entries if empty and in mock mode
    if not IS_LIVE_MODE:
        cursor.execute("SELECT COUNT(*) as c FROM gemini_rules")
        if cursor.fetchone()[0] == 0:
            # We use custom ids (can be string or ints based on schema)
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

    conn.commit()
    conn.close()
    print("💾 Аналітична БД ініціалізована (threat_history + telemetry_data + threat_clearings + gemini_rules + paired_events + error_log + gemini_rules_audit)")


def log_error_to_db(source: str, message: str, endpoint: str = None, context: str = None, error_type: str = None):
    """Log an error event to the error_log table."""
    error_msg = str(message)
    error_msg_l = error_msg.lower()
    
    if not error_type or error_type in ["general", "systemic"]:
        if "429" in error_msg or "quota" in error_msg_l or "resource_exhausted" in error_msg_l or "rate limit" in error_msg_l:
            error_type = "429_rate_limit"
        elif "500" in error_msg or "internal" in error_msg_l:
            error_type = "500_server"
        elif "timeout" in error_msg_l:
            error_type = "timeout"
        elif "firebase" in error_msg_l or "fcm" in error_msg_l or "messaging" in error_msg_l:
            error_type = "firebase_error"
        elif "telegram" in error_msg_l or "telethon" in error_msg_l:
            error_type = "telegram_error"
        elif "gemini" in error_msg_l or "generativeai" in error_msg_l or "aiplatform" in error_msg_l:
            error_type = "gemini_api_error"
        elif "json" in error_msg_l or "decode" in error_msg_l or "parse" in error_msg_l:
            error_type = "json_parse_error"
        elif "sqlite" in error_msg_l or "database" in error_msg_l or "query" in error_msg_l or "locked" in error_msg_l:
            error_type = "database_error"
        elif "not found" in error_msg_l or "404" in error_msg:
            error_type = "404_not_found"
            error_type = "database_error"
        elif "validate" in error_msg_l or "missing field" in error_msg_l or "pydantic" in error_msg_l or "valueerror" in error_msg_l:
            error_type = "validation_error"
        elif "connection" in error_msg_l or "connectionerror" in error_msg_l or "socket" in error_msg_l or "network" in error_msg_l or "http" in error_msg_l:
            error_type = "network_error"
        elif "auth" in error_msg_l or "permission" in error_msg_l or "403" in error_msg:
            error_type = "auth"
        elif "traceback" in error_msg_l or "exception" in error_msg_l or "syntax" in error_msg_l or "system" in error_msg_l:
            error_type = "systemic"
        else:
            error_type = "general"
            
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO error_log (source, error_type, message, endpoint, context) VALUES (?, ?, ?, ?, ?)",
            (source, error_type, error_msg[:2000], endpoint, context)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def log_rule_audit_to_db(action: str, rule_type: str = None, rule_text: str = None,
                          source_region: str = None, target_region: str = None,
                          threat_type: str = None, reason: str = None):
    """Log a Gemini rule addition/removal/deactivation to the audit table."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO gemini_rules_audit (action, rule_type, rule_text, source_region, target_region, threat_type, reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (action, rule_type, rule_text[:1000] if rule_text else None, source_region, target_region, threat_type, reason)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def log_threat_to_db(region: str, level: str, threat_type: str, detail: str = None, confidence: int = None, telemetry: dict = None, is_test: bool = False, rules_applied: list = None, is_predictive: bool = False):
    """Log threat event and its telemetry to SQLite. Returns the threat_event_id."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO threat_history (region, threat_level, threat_type, detail, confidence, is_test) VALUES (?, ?, ?, ?, ?, ?)",
            (region, level, threat_type, detail, confidence, 1 if is_test else 0)
        )
        event_id = cursor.lastrowid
        
        telemetry_id = None
        group_id = None
        
        if telemetry and isinstance(telemetry, dict) and event_id:
            group_id = telemetry.get("group_id")
            tags_json = json.dumps(telemetry.get("message_context_tags", []), ensure_ascii=False)
            cursor.execute('''
                INSERT INTO telemetry_data (
                    threat_event_id, group_id, attack_vector, target_count, speed_kmh,
                    altitude_category, heading_degrees, distance_to_target_km,
                    launch_origin, weapon_subtype, engagement_status,
                    air_defense_active, multiple_waves, wave_number,
                    time_of_day_category, weather_factor, source_reliability,
                    message_context_tags, strategic_priority, civilian_risk_level,
                    event_phase, correlation_group, target_cities_coords
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event_id,
                group_id,
                telemetry.get("attack_vector", "unknown"),
                telemetry.get("target_count"),
                telemetry.get("speed_kmh"),
                telemetry.get("altitude_category", "unknown"),
                telemetry.get("heading_degrees"),
                telemetry.get("distance_to_target_km"),
                telemetry.get("launch_origin"),
                telemetry.get("weapon_subtype"),
                telemetry.get("engagement_status", "unknown"),
                1 if telemetry.get("air_defense_active") else 0,
                1 if telemetry.get("multiple_waves") else 0,
                telemetry.get("wave_number", 1),
                telemetry.get("time_of_day_category", "unknown"),
                telemetry.get("weather_factor", "unknown"),
                telemetry.get("source_reliability", "medium"),
                tags_json,
                telemetry.get("strategic_priority"),
                telemetry.get("civilian_risk_level", "moderate"),
                telemetry.get("event_phase", "unknown"),
                telemetry.get("correlation_group"),
                json.dumps(telemetry.get("target_cities_coords", {}), ensure_ascii=False) if telemetry.get("target_cities_coords") else None
            ))
            telemetry_id = cursor.lastrowid
        
        if level != "none" and event_id and threat_type != "official_alarm":
            rules_applied_json = json.dumps(rules_applied) if rules_applied else None
            cursor.execute('''
                INSERT INTO paired_events (
                    region, threat_event_id, telemetry_id, lifecycle_status,
                    threat_level, threat_type, confidence_at_set, was_predictive,
                    gemini_group_id, rules_applied
                ) VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?)
            ''', (
                region, event_id, telemetry_id, level, threat_type,
                confidence, 1 if is_predictive else 0, group_id, rules_applied_json
            ))
        
        conn.commit()
        conn.close()
        return event_id
    except Exception as e:
        print(f"⚠️ Помилка запису в БД аналітики: {e}")
        log_error_to_db("server", str(e), endpoint="log_threat_to_db", context=f"region={region}, level={level}")
        return None


def log_threat_to_firestore(region: str, level: str, threat_type: str, detail: str = None, confidence: int = None, telemetry: dict = None, is_test: bool = False):
    """Log threat event to Firebase Firestore with retry on quota errors."""
    db = get_db()
    if not db:
        return
        
    if is_duplicate_event(region, level, threat_type):
        print(f"⚠️ Duplicate history event detected for {region} ({level}, {threat_type}), skipping write to Firestore.")
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    unique_id = int(time.time() * 1000)
    
    doc_data = {
        "id": unique_id,
        "region": region,
        "timestamp": timestamp,
        "threat_level": level,
        "threat_type": threat_type,
        "detail": detail,
        "confidence": confidence,
        "is_test": is_test
    }
    if telemetry:
        doc_data["telemetry"] = telemetry
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            db.collection('sirenua_history').add(doc_data)
            print(f"🔥 Logged history event to Firestore for {region}: {level} ({threat_type}, is_test={is_test})")
            return
        except Exception as e:
            err_str = str(e)
            if ("429" in err_str or "Quota" in err_str) and attempt < max_retries - 1:
                wait = (2 ** attempt) * 5
                print(f"⚠️ Firestore quota hit writing history for {region}, retry {attempt+1}/{max_retries} in {wait}s")
                log_error_to_db("firebase", str(e), endpoint="log_threat_to_firestore", context=f"region={region}, attempt={attempt+1}")
                time.sleep(wait)
            else:
                print(f"⚠️ Помилка запису історії в Firestore: {e}")
                log_error_to_db("firebase", str(e), endpoint="log_threat_to_firestore", context=f"region={region}, final_failure")
                return
    print(f"❌ Firestore history write failed after {max_retries} retries for {region}")


def detect_mitigation_from_text(text: str) -> bool:
    if not text:
        return False
    text_lower = text.lower()
    keywords = [
        "збит", "збило", "збили", "знищен", "ліквід", 
        "локаційно втрат", "локаційна втрат", 
        "втрачено радіолокац", "втрачено з радар",
        "робота ппо", "працює ппо", "працювала ппо", "роботу ппо",
        "реб", "електронної боротьб", "приглуш"
    ]
    return any(kw in text_lower for kw in keywords)


def log_clearing_to_db(region: str, clearing_telemetry: dict = None,
                       source_channel: str = None, message_text: str = None,
                       clearing_confidence: int = None, was_predictive: bool = False,
                       is_test: bool = False):
    """Log threat clearing event linked to original threat. Closes active paired events."""
    if not clearing_telemetry:
        clearing_telemetry = {}
    
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        original_event_id = None
        original_level = None
        original_type = None
        original_confidence = None
        threat_set_ts = None
        threat_duration_sec = None
        
        linked_gid = clearing_telemetry.get("linked_group_id")
        row = None
        if linked_gid:
            cursor.execute('''
                SELECT th.id, th.timestamp, th.threat_level, th.threat_type, th.confidence
                FROM threat_history th
                JOIN telemetry_data td ON th.id = td.threat_event_id
                JOIN paired_events pe ON th.id = pe.threat_event_id
                WHERE th.region = ? AND td.group_id = ? AND pe.lifecycle_status = 'active'
                ORDER BY th.timestamp DESC LIMIT 1
            ''', (region, linked_gid))
            row = cursor.fetchone()
            
        if not row:
            cursor.execute('''
                SELECT th.id, th.timestamp, th.threat_level, th.threat_type, th.confidence
                FROM threat_history th
                LEFT JOIN threat_clearings tc ON th.id = tc.original_threat_event_id
                WHERE th.region = ? AND th.threat_type = 'official_alarm' AND tc.id IS NULL
                ORDER BY th.timestamp DESC LIMIT 1
            ''', (region,))
            row = cursor.fetchone()
            
        if not row:
            cursor.execute('''
                SELECT th.id, th.timestamp, th.threat_level, th.threat_type, th.confidence
                FROM threat_history th
                JOIN paired_events pe ON th.id = pe.threat_event_id
                WHERE th.region = ? AND pe.lifecycle_status = 'active'
                ORDER BY th.timestamp DESC LIMIT 1
            ''', (region,))
            row = cursor.fetchone()
            
        if not row:
            conn.close()
            return None
            
        original_event_id = row["id"]
        original_level = row["threat_level"]
        original_type = row["threat_type"]
        original_confidence = row["confidence"]
        threat_set_ts = row["timestamp"]
        
        try:
            set_time = datetime.fromisoformat(threat_set_ts.replace('Z', '+00:00') if threat_set_ts else "")
            now = datetime.now(timezone.utc)
            threat_duration_sec = int((now - set_time.replace(tzinfo=timezone.utc)).total_seconds())
            if threat_duration_sec < 0:
                threat_duration_sec = None
        except Exception:
            threat_duration_sec = None
        
        tags_json = json.dumps(clearing_telemetry.get("clearing_context_tags", []), ensure_ascii=False)
        
        cursor.execute('''
            INSERT INTO threat_clearings (
                region, original_threat_event_id, linked_group_id, linked_correlation_group,
                resolution_type, intercepted_count, total_targets_in_wave,
                impact_confirmed, damage_assessment, civilian_casualties_reported,
                infrastructure_hit, air_defense_effectiveness, threat_duration_assessment,
                prediction_accuracy_hint, was_predictive,
                original_threat_level, original_threat_type, original_confidence,
                clearing_confidence, clearing_context_tags,
                source_reliability, time_of_day_category,
                clearing_source_channel, clearing_message_text,
                threat_set_timestamp, threat_duration_seconds, is_test
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            region,
            original_event_id,
            clearing_telemetry.get("linked_group_id"),
            clearing_telemetry.get("linked_correlation_group"),
            clearing_telemetry.get("resolution_type", "unknown"),
            clearing_telemetry.get("intercepted_count"),
            clearing_telemetry.get("total_targets_in_wave"),
            1 if clearing_telemetry.get("impact_confirmed") else 0,
            clearing_telemetry.get("damage_assessment", "unknown"),
            1 if clearing_telemetry.get("civilian_casualties_reported") else 0,
            clearing_telemetry.get("infrastructure_hit"),
            clearing_telemetry.get("air_defense_effectiveness", "unknown"),
            clearing_telemetry.get("threat_duration_assessment", "unknown"),
            clearing_telemetry.get("prediction_accuracy_hint", "not_applicable"),
            1 if was_predictive else 0,
            original_level,
            original_type,
            original_confidence,
            clearing_confidence,
            tags_json,
            clearing_telemetry.get("source_reliability", "medium"),
            clearing_telemetry.get("time_of_day_category", "unknown"),
            source_channel,
            message_text[:500] if message_text else None,
            threat_set_ts,
            threat_duration_sec,
            1 if is_test else 0
        ))
        
        clearing_id = cursor.lastrowid
        prediction_accuracy = clearing_telemetry.get("prediction_accuracy_hint", "not_applicable")
        
        if original_event_id:
            cursor.execute('''
                SELECT prediction_accuracy FROM paired_events
                WHERE threat_event_id = ? AND lifecycle_status = 'active'
            ''', (original_event_id,))
            pe_row = cursor.fetchone()
            current_accuracy = pe_row[0] if pe_row else None
            
            if current_accuracy == 'confirmed' and prediction_accuracy != 'confirmed':
                prediction_accuracy = 'confirmed'
            elif prediction_accuracy in ["overestimated", "unknown", "not_applicable", "n/a"]:
                res_type = clearing_telemetry.get("resolution_type", "unknown")
                if res_type in ["intercepted", "lost_contact"] or detect_mitigation_from_text(message_text):
                    prediction_accuracy = 'mitigated'
                
            cursor.execute('''
                UPDATE paired_events SET
                    clearing_event_id = ?,
                    lifecycle_status = 'cleared',
                    confidence_at_clear = ?,
                    prediction_accuracy = ?,
                    duration_seconds = ?
                WHERE threat_event_id = ? AND lifecycle_status = 'active'
            ''', (
                clearing_id, clearing_confidence, prediction_accuracy,
                threat_duration_sec, original_event_id
            ))
            closed_count = cursor.rowcount
            if closed_count > 0:
                print(f"🔗 [Paired] Закрито {closed_count} paired_event(s) для {region} (accuracy: {prediction_accuracy})")
            
            if not clearing_telemetry.get("linked_group_id"):
                cursor.execute('''
                    UPDATE paired_events SET
                        clearing_event_id = ?,
                        lifecycle_status = 'cleared',
                        confidence_at_clear = ?,
                        prediction_accuracy = ?,
                        duration_seconds = CAST((strftime('%s', 'now') - strftime('%s', created_at)) AS INTEGER)
                    WHERE region = ? AND lifecycle_status = 'active'
                ''', (clearing_id, clearing_confidence, prediction_accuracy, region))
                other_closed = cursor.rowcount
                if other_closed > 0:
                    print(f"🔗 [Paired] Додатково закрито {other_closed} завислих подій для {region}")
        
        conn.commit()
        conn.close()
        
        res_type = clearing_telemetry.get("resolution_type", "unknown")
        pred_hint = clearing_telemetry.get("prediction_accuracy_hint", "n/a")
        dur = f"{threat_duration_sec}с" if threat_duration_sec else "?"
        print(f"📊 [Clearing DB] {region}: тип={res_type}, предикція={pred_hint}, тривалість={dur}, linked_event={original_event_id}")
        
        return clearing_id
    except Exception as e:
        print(f"⚠️ Помилка запису clearing в БД: {e}")
        log_error_to_db("server", str(e), endpoint="log_clearing_to_db", context=f"region={region}")
        return None


def validate_prediction_on_alarm(region: str):
    """Marks predictive paired_events as 'confirmed' when official alarm activates."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE paired_events 
            SET prediction_accuracy = 'confirmed'
            WHERE region = ? 
              AND was_predictive = 1 
              AND lifecycle_status = 'active'
              AND prediction_accuracy IS NULL
        ''', (region,))
        updated = cursor.rowcount
        conn.commit()
        conn.close()
        if updated > 0:
            print(f"✅ [Validation] Офіційна тривога підтвердила {updated} предикцій Gemini для {region}")
    except Exception as e:
        print(f"⚠️ [Validation] Помилка валідації предикції: {e}")
        log_error_to_db("server", str(e), endpoint="validate_prediction_on_alarm", context=f"region={region}")


def flush_history_batch():
    """Flush all buffered Firestore history writes in a single batch operation."""
    global _history_batch_buffer
    if not _history_batch_buffer:
        return
    
    db = get_db()
    if not db:
        _history_batch_buffer.clear()
        return
    
    items = list(_history_batch_buffer)
    _history_batch_buffer.clear()
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            batch = db.batch()
            for doc_data in items:
                ref = db.collection('sirenua_history').document()
                batch.set(ref, doc_data)
            batch.commit()
            print(f"🔥 Batch flush: {len(items)} history записів за один Firestore write")
            return
        except Exception as e:
            err_str = str(e)
            if ("429" in err_str or "Quota" in err_str) and attempt < max_retries - 1:
                wait = (2 ** attempt) * 5
                print(f"⚠️ Firestore quota hit on batch flush, retry {attempt+1}/{max_retries} in {wait}s")
                log_error_to_db("firebase", str(e), endpoint="flush_history_batch", context=f"batch_size={len(items)}, attempt={attempt+1}")
                time.sleep(wait)
            else:
                print(f"⚠️ Помилка batch flush Firestore history: {e}")
                log_error_to_db("firebase", str(e), endpoint="flush_history_batch", context=f"batch_size={len(items)}, final_failure")
                return


def safe_run_task(coro):
    """Safely schedules a coroutine in the main event loop."""
    global main_loop
    if main_loop and main_loop.is_running():
        asyncio.run_coroutine_threadsafe(coro, main_loop)
    else:
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(coro)
        except RuntimeError:
            new_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(new_loop)
            new_loop.run_until_complete(coro)
            new_loop.close()


def on_threat_changed(region, state, telemetry=None, rules_applied=None):
    global last_logged_states, _history_batch_buffer
    
    prev_state_dict = last_logged_states.get(region)
    if not isinstance(prev_state_dict, dict) or "active_threats" not in prev_state_dict:
        prev_state_dict = {
            "active_threats": {},
            "is_active": False,
            "level": "none"
        }
            
    prev_active = prev_state_dict["is_active"]
    prev_active_threats = prev_state_dict["active_threats"]
    
    from core.threat_state import MockThreatManager
    is_batch = getattr(state, '_batch_mode', False)  # state here is ThreatState, but we check manager if batch mode is on
    
    # 1. Official air alarm status change logging
    if prev_active != state.is_active:
        log_level = "high" if state.is_active else "none"
        detail = "Повітряна тривога" if state.is_active else "Відбій повітряної тривоги"
        safe_run_task(asyncio.to_thread(log_threat_to_db, region, log_level, "official_alarm", detail))
        
        if state.is_active:
            safe_run_task(asyncio.to_thread(validate_prediction_on_alarm, region))
        else:
            clearing_telemetry = {
                "resolution_type": "all_clear_official",
                "prediction_accuracy_hint": "confirmed"
            }
            safe_run_task(asyncio.to_thread(
                log_clearing_to_db,
                region=region,
                clearing_telemetry=clearing_telemetry,
                source_channel="official_alarm",
                message_text="Відбій повітряної тривоги (офіційно)",
                is_test=state.is_test
            ))
        
        # Buffer or write firestore
        doc_data = {
            "id": int(time.time() * 1000),
            "region": region,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "threat_level": log_level,
            "threat_type": "official_alarm",
            "detail": detail,
            "confidence": None,
            "is_test": state.is_test
        }
        # We will assume batch mode is controlled globally or on manager.
        # But we check state.is_test/etc
        safe_run_task(asyncio.to_thread(log_threat_to_firestore, region, log_level, "official_alarm", detail, is_test=state.is_test))
            
    # 2. AI/Telegram threat level/type changes tracking
    curr_active_threats = {
        t.threat_id: {
            "level": t.level,
            "threat_type": t.threat_type,
            "detail": t.detail,
            "confidence": t.confidence,
            "is_predictive": getattr(t, "is_predictive", False),
            "is_test": t.is_test
        }
        for t in state.active_threats
        if t.threat_type and t.threat_type != "official_alarm"
    }
    
    # Detect added threats
    added_ids = set(curr_active_threats.keys()) - set(prev_active_threats.keys())
    for tid in added_ids:
        t_data = curr_active_threats[tid]
        safe_run_task(asyncio.to_thread(
            log_threat_to_db,
            region=region,
            level=t_data["level"],
            threat_type=t_data["threat_type"],
            detail=t_data["detail"],
            confidence=t_data["confidence"],
            telemetry=telemetry,
            rules_applied=rules_applied,
            is_predictive=t_data["is_predictive"]
        ))
        
        safe_run_task(asyncio.to_thread(
            log_threat_to_firestore,
            region=region,
            level=t_data["level"],
            threat_type=t_data["threat_type"],
            detail=t_data["detail"],
            confidence=t_data["confidence"],
            telemetry=telemetry,
            is_test=t_data["is_test"]
        ))
            
    # Detect cleared threats
    cleared_ids = set(prev_active_threats.keys()) - set(curr_active_threats.keys())
    for tid in cleared_ids:
        t_data = prev_active_threats[tid]
        safe_run_task(asyncio.to_thread(
            log_threat_to_db,
            region,
            "none",
            t_data["threat_type"],
            "Відбій загрози"
        ))
        
        resolution_type = "expired"
        prediction_accuracy = "overestimated"
        if state.is_active:
            prediction_accuracy = "confirmed"
            resolution_type = "impact"
            
        c_telemetry = telemetry if telemetry else {
            "resolution_type": resolution_type,
            "prediction_accuracy_hint": prediction_accuracy,
            "damage_assessment": "unknown",
            "impact_confirmed": state.is_active
        }
        
        safe_run_task(asyncio.to_thread(
            log_clearing_to_db,
            region=region,
            clearing_telemetry=c_telemetry,
            source_channel="auto_clear" if not state.is_active else "official_alarm",
            message_text="Автоматичне зняття загрози або відбій тривоги",
            is_test=t_data["is_test"]
        ))
        
        safe_run_task(asyncio.to_thread(
            log_threat_to_firestore,
            region,
            "none",
            t_data["threat_type"],
            "Відбій загрози",
            is_test=t_data["is_test"]
        ))
            
    last_logged_states[region] = {
        "active_threats": curr_active_threats,
        "is_active": state.is_active,
        "level": state.level
    }
