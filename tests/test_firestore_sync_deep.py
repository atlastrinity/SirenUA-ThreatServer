"""
Integration Test for Local SQLite Database <-> Firebase Firestore Synchronization.
Verifies real-time state sync, historical event sync, and atomic GZIP snapshot backup/restore.
"""

import os
import sys
import pytest

# Ensure SirenUA-ThreatServer is on python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))

from core.firebase_init import init_firebase
from database.firestore_sync import (
    get_db,
    backup_sqlite_to_firestore,
    restore_sqlite_from_firestore,
    delete_test_history_from_firestore,
)
from database.threat_logger import log_threat_to_db, log_threat_to_firestore, flush_history_batch
from database.connection import get_sqlite_connection, DB_PATH
from core.threat_state import MockThreatManager


@pytest.fixture(scope="module", autouse=True)
def setup_firebase():
    """Ініціалізація Firebase перед тестами синхронізації."""
    init_firebase()


def test_firestore_connectivity():
    """Перевірка з'єднання з Firestore."""
    db = get_db()
    assert db is not None, "Firestore client must not be None"
    
    test_ref = db.collection("sirenua_test_sync").document("connectivity_check")
    test_ref.set({"status": "connected", "verified": True})
    doc = test_ref.get()
    assert doc.exists
    assert doc.to_dict().get("status") == "connected"
    test_ref.delete()


def test_realtime_state_sync():
    """Перевірка синхронізації поточного стану загроз (sirenua_state/threats)."""
    db = get_db()
    manager = MockThreatManager()
    test_region = "Чернігівська область"

    # Встановлюємо загрозу
    manager.set_threat(test_region, "high", "shahed", detail="Синхронізаційний тест стану", is_test=True)
    manager._execute_save_to_db()

    # Перевіряємо в Firestore
    doc = db.collection("sirenua_state").document("threats").get()
    assert doc.exists, "Document sirenua_state/threats must exist in Firestore"
    data = doc.to_dict()
    assert test_region in data
    assert data[test_region]["level"] == "high"
    assert data[test_region]["type"] == "shahed"

    # Очищуємо стан
    manager.clear_threat(test_region)
    manager._execute_save_to_db()
    doc_after = db.collection("sirenua_state").document("threats").get()
    assert doc_after.to_dict()[test_region]["level"] == "none"


def test_history_event_sync():
    """Перевірка паралельного запису історії в локальну SQLite та колекцію Firestore sirenua_history."""
    import uuid
    db = get_db()
    test_region = "Полтавська область"
    unique_detail = f"Тестова подія синхронізації {uuid.uuid4().hex[:8]}"

    # 1. Запис у SQLite
    sqlite_id = log_threat_to_db(
        region=test_region,
        level="medium",
        threat_type="shahed",
        detail=unique_detail,
        is_test=True
    )
    assert sqlite_id is not None

    # Перевірка в SQLite
    conn = get_sqlite_connection(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, region, threat_level, detail FROM threat_history WHERE id = ?", (sqlite_id,))
    row = c.fetchone()
    conn.close()
    assert row is not None
    assert row[1] == test_region
    assert row[3] == unique_detail

    # 2. Запис у Firestore sirenua_history
    log_threat_to_firestore(
        region=test_region,
        level="medium",
        threat_type="shahed",
        detail=unique_detail,
        is_test=True
    )
    flush_history_batch()

    # Перевірка в Firestore
    docs = list(db.collection("sirenua_history").where("detail", "==", unique_detail).get())
    assert len(docs) > 0, "Test threat event must be found in Firestore sirenua_history"
    assert docs[0].to_dict().get("detail") == unique_detail
    assert docs[0].to_dict().get("region") == test_region
    # Clean up test doc
    docs[0].reference.delete()


def test_atomic_sqlite_compressed_backup():
    """Перевірка створення атомарного gzip-стиснутого бекапу SQLite в Firestore."""
    db = get_db()
    success = backup_sqlite_to_firestore()
    assert success is True, "backup_sqlite_to_firestore() should return True"

    doc = db.collection("sirenua_backup").document("sqlite_compressed").get()
    assert doc.exists, "Document sirenua_backup/sqlite_compressed must exist"
    payload = doc.to_dict()
    assert "data" in payload
    assert "tables_backed_up" in payload
    backed_tables = payload["tables_backed_up"]
    expected_tables = [
        "gemini_rules", "paired_events", "threat_history", "threat_clearings",
        "telemetry_data", "gemini_rules_audit", "error_log",
        "analytics_reports", "palantir_reports"
    ]
    for t in expected_tables:
        assert t in backed_tables, f"Table {t} must be backed up in Firestore snapshot"
    assert payload["compressed_size_kb"] > 0


def test_test_data_cleanup():
    """Перевірка очищення тестових записів з Firestore та локальної БД."""
    deleted_count = delete_test_history_from_firestore()
    assert isinstance(deleted_count, int)
