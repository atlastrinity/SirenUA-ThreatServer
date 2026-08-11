"""
SQLite Connection & Data Execution Helpers.
"""

import os
import sqlite3
from typing import List, Dict, Any
from core.config import DB_PATH, logger


def get_sqlite_connection(db_path: str = None) -> sqlite3.Connection:
    """Отримує SQLite з'єднання з PRAGMA wal та busy_timeout."""
    if db_path is None:
        db_path = DB_PATH
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def get_db(db_path: str = None) -> sqlite3.Connection:
    """Alias for get_sqlite_connection for database dependency injection."""
    return get_sqlite_connection(db_path)


def _log_error(source: str, message: str, endpoint: str = "", context: str = "", error_type: str = "general"):
    """Записує помилку в базу даних error_log та консоль."""
    try:
        from database.error_logger import log_error_to_db
        log_error_to_db(source, message, endpoint=endpoint, context=context, error_type=error_type)
    except Exception as log_ex:
        logger.error(f"Не вдалося записати помилку в БД: {log_ex}")


def delete_test_history_from_sqlite():
    """Видаляє тестові загрози та кліринги з SQLite."""
    try:
        conn = get_sqlite_connection(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM threat_history WHERE is_test = 1")
        cursor.execute("DELETE FROM threat_clearings WHERE is_test = 1")
        cursor.execute("DELETE FROM paired_events WHERE threat_level = 'none' OR is_test = 1")
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Помилка очищення тестової історії з SQLite: {e}")


def execute_write(query: str, params: tuple = ()) -> bool:
    """Виконує запис у базу даних SQLite з обробкою винятків та відкотом (rollback)."""
    try:
        conn = get_sqlite_connection(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Помилка виконання SQL запису: {e}")
        return False


def is_duplicate_event(region: str, level: str, threat_type: str, window_seconds: int = 300) -> bool:
    """Перевіряє, чи не було аналогічної загрози записано в БД протягом window_seconds."""
    try:
        conn = get_sqlite_connection(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) FROM threat_history
            WHERE region = ? AND threat_level = ? AND threat_type = ?
              AND timestamp >= datetime('now', ?)
        """, (region, level, threat_type or "unknown", f"-{window_seconds} seconds"))
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0
    except Exception as e:
        logger.error(f"Помилка перевірки дублікату загрози: {e}")
        return False


def execute_query_as_dicts(query: str, params: tuple = (), json_fields: list = None) -> List[Dict[str, Any]]:
    """Допоміжна функція для виконання SQL-запитів і повернення результату у вигляді списку словників."""
    import json
    conn = get_sqlite_connection(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    try:
        cursor.execute(query, params)
        rows = cursor.fetchall()
        result = []
        for row in rows:
            row_dict = dict(row)
            if json_fields:
                for jf in json_fields:
                    if jf in row_dict and isinstance(row_dict[jf], str) and row_dict[jf]:
                        try:
                            row_dict[jf] = json.loads(row_dict[jf])
                        except Exception:
                            pass
            result.append(row_dict)
        return result
    finally:
        conn.close()
