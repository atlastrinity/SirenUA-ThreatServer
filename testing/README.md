# SirenUA ThreatServer - Testing Package (`testing/`)

Цей пакет повністю ізолює та модулізує систему тестування загрозових сценаріїв та зачистки тестових даних з баз даних сервера SirenUA.

## 📂 Структура пакету

```
testing/
├── __init__.py      # Головна точка входу та ре-експорт інтерфейсів
├── cleaner.py       # Модуль каскадного очищення SQLite та Firestore
├── manager.py       # Фасад TestScenarioManager та відкладений запуск
└── scenarios.py     # Декларативний реєстр та генератор тестових загроз
```

## 🛠️ Мікро-модулі та їх призначення

### 1. `testing/scenarios.py`
- `VALID_SCENARIOS`: Набір допустимих імен сценаріїв (`mig_takeoff`, `shaheds_south`, `cruise_missiles_west`, `massive_attack`, `ballistic_kharkiv`, `clear`).
- `generate_scenario_threats(scenario_name)`: Повертає декларативну карту загроз для областей.

### 2. `testing/cleaner.py`
- `delete_test_history_from_sqlite()`: Каскадне вилучення записів з `is_test = 1` із таблиць `paired_events`, `telemetry_data`, `threat_history` та `threat_clearings`.
- `delete_test_history_from_firestore()`: Вилучення документів з `is_test == True` з хмарної колекції `sirenua_history`.
- `purge_all_test_data()`: Єдиний запуск повного очищення локальних і хмарних БД.

### 3. `testing/manager.py`
- `TestScenarioManager`: Фасад для активації сценаріїв (`apply_scenario`), відкладеного запуску у фоні (`apply_scenario_with_delay`) та повного скасування (`clear_test_mode`).
- `test_scenario_manager`: Синглтон екземпляр.

## 📡 Використання через REST API

### Запуск сценарію:
```http
POST /api/threats/scenario
Content-Type: application/json

{
  "scenario": "shaheds_south"
}
```

### Повне скасування сценарію та зачистка БД:
```http
POST /api/threats/scenario
Content-Type: application/json

{
  "scenario": "clear"
}
```
