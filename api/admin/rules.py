"""
Admin Rules API.
Endpoints for Gemini rules audit history and threat history seeding.
"""

from fastapi import APIRouter, HTTPException

from database.db_helpers import get_db, get_sqlite_connection, execute_query_as_dicts

router = APIRouter()


@router.get("/api/admin/rules/history")
async def get_admin_rules_history(
    days: int = 30,
    limit: int = 200,
    rule_type: str = None,
    action: str = None,
    threat_type: str = None
):
    """Аудит-лог змін правил Gemini."""
    try:
        query = "SELECT * FROM gemini_rules_audit WHERE timestamp >= datetime('now', ?)"
        params = [f'-{days} days']

        if rule_type:
            query += " AND rule_type = ?"
            params.append(rule_type)
        if action:
            query += " AND action = ?"
            params.append(action)
        if threat_type:
            query += " AND threat_type = ?"
            params.append(threat_type)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(min(limit, 500))

        entries = execute_query_as_dicts(query, tuple(params))
        return {
            "total": len(entries),
            "entries": entries
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/admin/seed_history")
async def seed_history():
    """Генерує початкову історію подій у Firestore для всіх областей."""
    db = get_db()
    if not db:
        raise HTTPException(status_code=503, detail="Firebase Firestore недоступний")

    import random
    from datetime import datetime, timedelta, timezone

    regions = [
        "Вінницька область", "Волинська область", "Дніпропетровська область",
        "Донецька область", "Житомирська область", "Закарпатська область",
        "Запорізька область", "Івано-Франківська область", "Київська область",
        "Кіровоградська область", "Луганська область", "Львівська область",
        "Миколаївська область", "Одеська область", "Полтавська область",
        "Рівненська область", "Сумська область", "Тернопільська область",
        "Харківська область", "Херсонська область", "Хмельницька область",
        "Черкаська область", "Чернівецька область", "Чернігівська область",
        "м. Київ", "АР Крим"
    ]

    threat_templates = [
        {"threat_level": "high", "threat_type": "mig31k", "detail": "Зліт МіГ-31К з аеродрому Саваслейка. Ракетна небезпека!"},
        {"threat_level": "medium", "threat_type": "shahed", "detail": "Група ударних БпЛА типу 'Shahed' наближається з півдня."},
        {"threat_level": "high", "threat_type": "cruise_missile", "detail": "Запуск крилатих ракет Х-101/Х-555 з бортів Ту-95МС."},
        {"threat_level": "critical", "threat_type": "ballistic", "detail": "Загроза застосування балістичного озброєння з Криму!"},
    ]

    total_added = 0

    try:
        for region in regions:
            base_time = datetime.now(timezone.utc)

            for i in range(3):
                alert_time = base_time - timedelta(days=i, hours=random.randint(2, 6))
                alert_timestamp = alert_time.strftime("%Y-%m-%d %H:%M:%S")

                clear_time = alert_time + timedelta(minutes=random.randint(45, 120))
                clear_timestamp = clear_time.strftime("%Y-%m-%d %H:%M:%S")

                alert_id = int(alert_time.timestamp() * 1000)
                clear_id = int(clear_time.timestamp() * 1000)

                is_tactical = random.choice([True, False])

                if is_tactical:
                    template = random.choice(threat_templates)
                    alert_doc = {
                        "id": alert_id, "region": region, "timestamp": alert_timestamp,
                        "threat_level": template["threat_level"], "threat_type": template["threat_type"],
                        "detail": template["detail"], "confidence": random.randint(70, 95),
                        "telemetry": {
                            "source_reliability": "high",
                            "civilian_risk_level": "high" if template["threat_level"] == "high" else "moderate",
                            "message_context_tags": ["rocket", "alert"] if template["threat_type"] != "shahed" else ["shahed", "drone"]
                        }
                    }
                    clear_doc = {
                        "id": clear_id, "region": region, "timestamp": clear_timestamp,
                        "threat_level": "none", "threat_type": template["threat_type"],
                        "detail": "Відбій загрози", "confidence": 100
                    }
                else:
                    alert_doc = {
                        "id": alert_id, "region": region, "timestamp": alert_timestamp,
                        "threat_level": "high", "threat_type": "official_alarm",
                        "detail": "Повітряна тривога", "confidence": 100
                    }
                    clear_doc = {
                        "id": clear_id, "region": region, "timestamp": clear_timestamp,
                        "threat_level": "none", "threat_type": "official_alarm",
                        "detail": "Відбій повітряної тривоги", "confidence": 100
                    }

                db.collection('sirenua_history').add(alert_doc)
                db.collection('sirenua_history').add(clear_doc)
                total_added += 2

        return {"status": "success", "message": f"Додано {total_added} записів хронології у Firestore для всіх областей"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
