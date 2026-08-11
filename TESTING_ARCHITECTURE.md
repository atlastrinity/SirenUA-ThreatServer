# SirenUA Testing Architecture Documentation

Документація архітектури системи тестування та автоматичного очищення баз даних у **SirenUA-ThreatServer**.

## 📌 Архітектурні принципи

1. **Повна модульність та мікро-файли**:
   Вся логіка тестування винесена з генеральних менеджерів у виділений пакет `testing/`.
2. **Ізоляція тестових даних (`is_test = 1`)**:
   Усі тестові загрози маркуються прапорцем `is_test = True`. Це гарантує, що при каскадному очищенні реальна історія тривог України ніколи не буде зачеплена.
3. **Автоматична зачистка пам'яті та БД (Clean-on-Clear)**:
   Виклик `apply_scenario("clear")` виконує:
   - Скидання тестових загроз у RAM пам'яті сервера.
   - Видалення тестових записів з локальних SQLite таблиць `threat_history`, `threat_clearings`, `paired_events`, `telemetry_data`.
   - Видалення тестових документів з хмарної БД Firestore (`sirenua_history`).

## 🚀 Основні імпорти

```python
from testing import (
    VALID_SCENARIOS,
    generate_scenario_threats,
    test_scenario_manager,
    delete_test_history_from_sqlite,
    delete_test_history_from_firestore,
    purge_all_test_data,
)
```

## 🧪 Модульні тести
Пакет тестується за допомогою автоматизованих тестів:
```bash
pytest test_testing_package.py
```
