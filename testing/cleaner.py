"""
SirenUA Testing Cleaner Module.
Encapsulates all logic for purging test records from SQLite, Firestore, and RAM.
"""

import sqlite3
from core.config import DB_PATH, logger
from database.connection import get_db

def delete_test_history_from_sqlite() -> dict:
    """Видаляє всі тестові записи (is_test = 1) з SQLite таблиць аналітики."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            DELETE FROM paired_events 
            WHERE threat_event_id IN (SELECT id FROM threat_history WHERE is_test = 1)
               OR clearing_event_id IN (SELECT id FROM threat_clearings WHERE is_test = 1)
        ''')
        paired_deleted = cursor.rowcount

        cursor.execute('''
            DELETE FROM telemetry_data 
            WHERE threat_event_id IN (SELECT id FROM threat_history WHERE is_test = 1)
        ''')
        
        cursor.execute("DELETE FROM threat_history WHERE is_test = 1")
        threats_deleted = cursor.rowcount
        
        cursor.execute("DELETE FROM threat_clearings WHERE is_test = 1")
        clearings_deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        stats = {
            "threats": threats_deleted,
            "clearings": clearings_deleted,
            "paired": paired_deleted
        }
        logger.info(f"🧹 [TestingCleaner] Видалено з SQLite: {threats_deleted} загроз, {clearings_deleted} відбоїв, {paired_deleted} зв'язаних подій")
        return stats
    except Exception as e:
        logger.error(f"⚠️ [TestingCleaner] Помилка видалення тестової історії з SQLite: {e}")
        return {"error": str(e)}

def delete_test_history_from_firestore() -> int:
    """Видаляє всі тестові записи (is_test == True) з хмарної колекції Firestore sirenua_history."""
    db = get_db()
    if not db:
        return 0
    try:
        docs = db.collection('sirenua_history').where('is_test', '==', True).get()
        deleted_count = 0
        for doc in docs:
            doc.reference.delete()
            deleted_count += 1
        logger.info(f"🧹 [TestingCleaner] Видалено {deleted_count} тестових записів з Firestore (sirenua_history)")
        return deleted_count
    except Exception as e:
        logger.error(f"⚠️ [TestingCleaner] Помилка видалення тестової історії з Firestore: {e}")
        return 0

def purge_all_test_data() -> dict:
    """Виконує повне каскадне видалення всіх тестових даних із локальної БД та хмари."""
    sqlite_stats = delete_test_history_from_sqlite()
    firestore_count = delete_test_history_from_firestore()
    return {
        "sqlite": sqlite_stats,
        "firestore_deleted": firestore_count,
        "status": "success"
    }
