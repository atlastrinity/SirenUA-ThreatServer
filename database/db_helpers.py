"""
Database Helpers Facade.
Re-exports micro-modules from database package for 100% backward compatibility.
"""

from database.connection import (
    get_sqlite_connection,
    _log_error,
    delete_test_history_from_sqlite,
    execute_write,
    is_duplicate_event,
    execute_query_as_dicts
)
from database.firestore_sync import (
    HAS_FIREBASE,
    get_db,
    run_firestore_with_retry,
    local_sqlite_backup,
    local_sqlite_restore,
    backup_sqlite_to_firestore,
    _restore_from_payload,
    restore_sqlite_from_firestore,
    delete_test_history_from_firestore
)
from database.notifications import send_fcm_notification
from database.seed import seed_initial_rules_if_empty

__all__ = [
    "get_sqlite_connection",
    "_log_error",
    "delete_test_history_from_sqlite",
    "execute_query_as_dicts",
    "get_db",
    "run_firestore_with_retry",
    "local_sqlite_backup",
    "local_sqlite_restore",
    "backup_sqlite_to_firestore",
    "_restore_from_payload",
    "restore_sqlite_from_firestore",
    "send_fcm_notification",
    "seed_initial_rules_if_empty",
]
