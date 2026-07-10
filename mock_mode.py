"""
Mock Mode — генератор імітованих загроз для тестування.
Зберігає стан загроз в пам'яті (без бази даних).
"""

from regions import ALL_REGIONS, get_genitive_region, get_ukrainian_threat_type
from database_helpers import (
    get_db,
    backup_sqlite_to_firestore,
    restore_sqlite_from_firestore,
    delete_test_history_from_firestore,
    delete_test_history_from_sqlite,
    is_duplicate_event,
    send_fcm_notification,
    TOPIC_MAPPING,
    start_fcm_worker,
)
from threat_state import (
    THREAT_TYPES,
    SingleThreat,
    ThreatState,
    MockThreatManager,
)
