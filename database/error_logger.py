"""
Error & Audit Logging.
Functions: log_error_to_db, log_rule_audit_to_db, safe_run_task.
"""

import asyncio

from core.config import DB_PATH
from database.db_helpers import get_sqlite_connection, execute_write

# Global reference to the main event loop (set from lifespan)
main_loop = None


def _classify_error_type(error_msg: str, source: str) -> str:
    """Helper to classify error messages into standardized types."""
    error_msg_l = error_msg.lower()

    if "429" in error_msg or "quota" in error_msg_l or "resource_exhausted" in error_msg_l or "rate limit" in error_msg_l:
        return "429_rate_limit"
    if "500" in error_msg or "internal" in error_msg_l:
        return "500_server"
    if "timeout" in error_msg_l:
        return "timeout"
    if "firebase" in error_msg_l or "fcm" in error_msg_l or "messaging" in error_msg_l:
        return "firebase_error"
    if "telegram" in error_msg_l or "telethon" in error_msg_l:
        return "telegram_error"
    if "gemini" in error_msg_l or "generativeai" in error_msg_l or "aiplatform" in error_msg_l or source == "gemini" or source == "analyzer":
        return "gemini_api_error"
    if "json" in error_msg_l or "decode" in error_msg_l or "parse" in error_msg_l:
        return "json_parse_error"
    if "sqlite" in error_msg_l or "database" in error_msg_l or "query" in error_msg_l or "locked" in error_msg_l:
        return "database_error"
    if "not found" in error_msg_l or "404" in error_msg:
        return "database_error"
    if "validate" in error_msg_l or "missing field" in error_msg_l or "pydantic" in error_msg_l or "valueerror" in error_msg_l:
        return "validation_error"
    if "connection" in error_msg_l or "connectionerror" in error_msg_l or "socket" in error_msg_l or "network" in error_msg_l or "http" in error_msg_l:
        return "network_error"
    if "auth" in error_msg_l or "permission" in error_msg_l or "403" in error_msg:
        return "auth"
    if "traceback" in error_msg_l or "exception" in error_msg_l or "syntax" in error_msg_l or "system" in error_msg_l:
        return "systemic"

    return "general"


def log_error_to_db(
    source: str,
    message: str,
    endpoint: str = None,
    context: str = None,
    error_type: str = None,
):
    """Log an error event to the error_log table with automatic type classification."""
    error_msg = str(message)

    if not error_type or error_type in ["general", "systemic"]:
        error_type = _classify_error_type(error_msg, source)

    try:
        execute_write(
            "INSERT INTO error_log (source, error_type, message, endpoint, context) VALUES (?, ?, ?, ?, ?)",
            (source, error_type, error_msg[:2000], endpoint, context)
        )
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
        execute_write(
            "INSERT INTO gemini_rules_audit (action, rule_type, rule_text, source_region, target_region, threat_type, reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (action, rule_type, rule_text[:1000] if rule_text else None, source_region, target_region, threat_type, reason)
        )
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
