"""
Error & Audit Logging.
Functions: log_error_to_db, log_rule_audit_to_db, safe_run_task.
"""

import asyncio

from core.config import DB_PATH
from database.db_helpers import get_sqlite_connection

# Global reference to the main event loop (set from lifespan)
main_loop = None


def log_error_to_db(
    source: str,
    message: str,
    endpoint: str = None,
    context: str = None,
    error_type: str = None,
):
    """Log an error event to the error_log table with automatic type classification."""
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
        elif "gemini" in error_msg_l or "generativeai" in error_msg_l or "aiplatform" in error_msg_l or source == "gemini" or source == "analyzer":
            error_type = "gemini_api_error"
        elif "json" in error_msg_l or "decode" in error_msg_l or "parse" in error_msg_l:
            error_type = "json_parse_error"
        elif "sqlite" in error_msg_l or "database" in error_msg_l or "query" in error_msg_l or "locked" in error_msg_l:
            error_type = "database_error"
        elif "not found" in error_msg_l or "404" in error_msg:
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
        conn = get_sqlite_connection(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO error_log (source, error_type, message, endpoint, context) VALUES (?, ?, ?, ?, ?)",
            (source, error_type, error_msg[:2000], endpoint, context)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def log_rule_audit_to_db(
    action: str,
    rule_type: str = None,
    rule_text: str = None,
    source_region: str = None,
    target_region: str = None,
    threat_type: str = None,
    reason: str = None,
):
    """Log a Gemini rule addition/removal/deactivation to the audit table."""
    try:
        conn = get_sqlite_connection(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO gemini_rules_audit (action, rule_type, rule_text, source_region, target_region, threat_type, reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (action, rule_type, rule_text[:1000] if rule_text else None, source_region, target_region, threat_type, reason)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


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
