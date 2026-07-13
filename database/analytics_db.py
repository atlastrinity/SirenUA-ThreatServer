"""
SirenUA Analytics DB — Public Aggregator.

This module re-exports everything that external code imports from analytics_db,
preserving backward compatibility. The actual logic lives in smaller sub-modules:

  database/schema.py          — init_analytics_db()
  database/error_logger.py    — log_error_to_db(), log_rule_audit_to_db(), safe_run_task()
  database/threat_logger.py   — log_threat_to_db(), log_threat_to_firestore(),
                                 flush_history_batch(), validate_prediction_on_alarm()
  database/clearing_logger.py — detect_mitigation_from_text(), log_clearing_to_db()
"""

import asyncio
import time
from datetime import datetime, timezone
from typing import Dict

# Re-export public API from sub-modules
from database.schema import init_analytics_db
from database.db_helpers import get_sqlite_connection
from database.error_logger import log_error_to_db, log_rule_audit_to_db, safe_run_task
from database.error_logger import main_loop  # mutable – callers set this directly
from database.threat_logger import (
    log_threat_to_db,
    log_threat_to_firestore,
    flush_history_batch,
    validate_prediction_on_alarm,
)
from database.clearing_logger import detect_mitigation_from_text, log_clearing_to_db

# --- State shared with on_threat_changed ---
# Track last logged threat states to avoid duplicate logging
last_logged_states: Dict[str, dict] = {}


def on_threat_changed(region, state, telemetry=None, rules_applied=None):
    """
    Called whenever threat state for a region changes.
    Logs alarm on/off transitions, AI threat additions, and AI threat clearings
    to both SQLite and Firestore.
    """
    global last_logged_states

    prev_state_dict = last_logged_states.get(region)
    if not isinstance(prev_state_dict, dict) or "active_threats" not in prev_state_dict:
        prev_state_dict = {
            "active_threats": {},
            "is_active": False,
            "level": "none"
        }

    prev_active = prev_state_dict["is_active"]
    prev_active_threats = prev_state_dict["active_threats"]

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

        safe_run_task(asyncio.to_thread(
            log_threat_to_firestore, region, log_level, "official_alarm", detail, is_test=state.is_test
        ))

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
            log_threat_to_db, region, "none", t_data["threat_type"], "Відбій загрози"
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
            region, "none", t_data["threat_type"], "Відбій загрози",
            is_test=t_data["is_test"]
        ))

    last_logged_states[region] = {
        "active_threats": curr_active_threats,
        "is_active": state.is_active,
        "level": state.level
    }


__all__ = [
    "init_analytics_db",
    "get_sqlite_connection",
    "log_error_to_db",
    "log_rule_audit_to_db",
    "safe_run_task",
    "main_loop",
    "log_threat_to_db",
    "log_threat_to_firestore",
    "flush_history_batch",
    "validate_prediction_on_alarm",
    "detect_mitigation_from_text",
    "log_clearing_to_db",
    "last_logged_states",
    "on_threat_changed",
]
