"""
Initial Seed Rules Generator for DB.
"""

from database.connection import get_sqlite_connection, _log_error
from core.config import DB_PATH, logger


def seed_initial_rules_if_empty():
    """
    Заповнює базу даних базовими емпіричними правилами траєкторій, якщо таблиця gemini_rules порожня.
    """
    try:
        conn = get_sqlite_connection(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM gemini_rules")
        count = cursor.fetchone()[0]
        if count > 0:
            conn.close()
            return
            
        print("🌱 [Seed] Таблиця gemini_rules порожня. Ініціалізація базових емпіричних правил...")
        initial_rules = [
            ("route_pattern", "Сумська область", "Чернігівська область", "shahed",
             "Шахеди через Сумщину часто прямують на Чернігівщину/Київщину", 15, 0.95),
            ("route_pattern", "Чернігівська область", "Київська область", "shahed",
             "Транзит з Чернігівщини на Київщину", 20, 0.92),
            ("route_pattern", "Курськ", "Сумська область", "shahed",
             "Запуск з аеродрому Халіно/Курськ через Сумщину", 30, 0.98),
            ("route_pattern", "Приморсько-Охтарськ", "Запорізька область", "shahed",
             "Вхід через Азовське море/Запоріжжя", 25, 0.90),
            ("launch_hub", "Саваслейка", "Всі області", "mig31k",
             "Зліт МіГ-31К з Саваслейкі — загроза Кинджал по всій Україні", 50, 0.99),
        ]
        
        for r_type, src, tgt, t_type, text, evidence, accuracy in initial_rules:
            cursor.execute("""
                INSERT INTO gemini_rules (rule_type, source_region, target_region, threat_type, rule_text, evidence_count, accuracy_score, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            """, (r_type, src, tgt, t_type, text, evidence, accuracy))
            
        conn.commit()
        conn.close()
        print("🌱 [Seed] Успішно додано базові емпіричні правила у gemini_rules!")
    except Exception as e:
        logger.error(f"Помилка ініціалізації seed правил: {e}")
        _log_error("database_seed", f"Помилка seed: {e}", "seed_initial_rules_if_empty", error_type="database_error")
