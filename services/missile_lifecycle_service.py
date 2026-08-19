"""
SirenUA Missile Lifecycle Service.
Calculates realistic missile flight times and enforces automatic expiration & trajectory removal
when flight duration elapses or official alarms in transit corridors clear.
"""

import re
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any, List
import logging

from core.threat_types import (
    THREAT_SHAHED,
    THREAT_CRUISE_MISSILE,
    THREAT_BALLISTIC,
    THREAT_MIG31K,
    THREAT_KAB,
    THREAT_TU95,
    THREAT_ISKANDER,
    THREAT_ARTILLERY,
    calculate_kinematic_eta,
)

logger = logging.getLogger("sirenua.services.missile_lifecycle")

# Max realistic flight durations (in seconds) for each threat category
MAX_FLIGHT_TIMEOUT_SECONDS = {
    THREAT_BALLISTIC: 300,      # 5 хвилин (Іскандер-М / Кинжал / С-300)
    THREAT_MIG31K: 450,         # 7.5 хвилин
    THREAT_ISKANDER: 300,       # 5 хвилин
    THREAT_KAB: 300,            # 5 хвилин (КАБ / УМПК / УМПБ)
    THREAT_CRUISE_MISSILE: 900,  # 15 хвилин для одного транзитного сектора
    THREAT_TU95: 1200,          # 20 хвилин
    THREAT_ARTILLERY: 180,      # 3 хвилини
    THREAT_SHAHED: 2700,        # 45 хвилин
}


def parse_eta_seconds_from_str(eta_str: Optional[str]) -> Optional[int]:
    """
    Парсить рядкові формати ETA (наприклад '~15 хв', 'до 20 хв', '10-15 хв', '1 год 20 хв', 'до 1 год')
    у загальну кількість секунд.
    """
    if not eta_str:
        return None
    s = str(eta_str).lower().replace("~", "").replace("+", "").replace("до", "").strip()

    # 1. Години та хвилини ("1 год 20 хв")
    if "год" in s and "хв" in s:
        parts = s.split("год")
        if len(parts) == 2:
            try:
                hr = int(parts[0].strip())
                mn = int(parts[1].replace("хв", "").strip())
                return (hr * 60 + mn) * 60
            except ValueError:
                pass

    # 2. Тільки хвилини ("15 хв", "10-15 хв")
    if "хв" in s:
        val = s.replace("хв", "").strip()
        if "-" in val:
            comps = val.split("-")
            if len(comps) == 2:
                try:
                    max_mn = int(comps[1].strip())
                    return max_mn * 60
                except ValueError:
                    pass
        else:
            try:
                return int(val) * 60
            except ValueError:
                pass

    # 3. Тільки години ("1 год", "1-2 год")
    if "год" in s:
        val = s.replace("год", "").strip()
        if "-" in val:
            comps = val.split("-")
            if len(comps) == 2:
                try:
                    max_hr = float(comps[1].strip())
                    return int(max_hr * 3600)
                except ValueError:
                    pass
        else:
            try:
                return int(float(val) * 3600)
            except ValueError:
                pass

    # 4. Числові значення
    try:
        val = int(s)
        return val * 60 if val < 180 else val
    except ValueError:
        return None


def get_missile_max_flight_seconds(threat_type: Optional[str], distance_km: float = 150.0) -> int:
    """
    Обчислює максимальний реалістичний час польоту загрози у секундах.
    Якщо вказано конкретну відстань, використовується кінематичний розрахунок з допуском 2-3 хв buffer.
    """
    if not threat_type:
        return 900  # 15 min default fallback

    t_type = threat_type.lower()
    
    # Спершу пробуємо кінематичний розрахунок за швидкістю
    try:
        kinematic_sec, _ = calculate_kinematic_eta(distance_km, t_type)
        if kinematic_sec is not None and kinematic_sec > 0:
            if THREAT_KAB in t_type:
                return min(kinematic_sec + 120, 300)
            # Додаємо 3 хвилини буфера на протиповітряні маневри
            return min(kinematic_sec + 180, 2700)
    except Exception:
        pass

    # Стандартний таймаут з таблиці
    for key, timeout in MAX_FLIGHT_TIMEOUT_SECONDS.items():
        if key in t_type:
            return timeout
            
    return 900


def should_expire_missile_threat(
    threat_item: Any,
    is_official_alarm_active: bool,
    now_dt: Optional[datetime] = None
) -> Tuple[bool, str, str]:
    """
    Перевіряє, чи має бути знята загроза/траєкторія ракети або БПЛА:
    1. Для жовтих зон (де офіційної тривоги немає, is_official_alarm_active=False):
       якщо минув розрахунковий час ETA (+ буфер 45-90с), або перевищено максимальний час очікування —
       загроза знімається автоматично (не лишається безпідставно зі статусом 'в області').
    2. Для загального життєвого циклу: якщо минув максимальний час польоту (elapsed_seconds > max_flight_seconds) —
       загроза знімається (expired / intercepted).
    
    Повертає: (should_expire: bool, resolution_type: str, reason: str)
    """
    if now_dt is None:
        now_dt = datetime.now(timezone.utc)

    # Обчислюємо скільки секунд минуло з моменту реєстрації загрози
    since_str = getattr(threat_item, "since", None)
    if not since_str:
        return False, "", ""

    try:
        threat_dt = datetime.fromisoformat(since_str.replace("Z", "+00:00"))
        elapsed_seconds = (now_dt - threat_dt).total_seconds()
    except Exception:
        return False, "", ""

    t_type = (getattr(threat_item, "threat_type", "") or "").lower()
    is_predictive = getattr(threat_item, "is_predictive", False)
    is_fast_threat = any(k in t_type for k in [
        THREAT_CRUISE_MISSILE, THREAT_BALLISTIC, THREAT_MIG31K,
        THREAT_KAB, THREAT_TU95, THREAT_ISKANDER
    ])

    # ПРАВИЛО 1: Якщо в області немає офіційної тривоги (жовта зона або знята тривога)
    if not is_official_alarm_active:
        # Визначаємо розрахунковий час ETA (в секундах)
        eta_sec = getattr(threat_item, "eta_seconds", None)
        if not eta_sec or eta_sec <= 0:
            eta_str = getattr(threat_item, "eta", None)
            eta_sec = parse_eta_seconds_from_str(eta_str)

        if eta_sec and eta_sec > 0:
            # Буфер після досягнення 0 / "на підльоті" (короткий час верифікації без сирени)
            buffer_sec = 30 if is_fast_threat else 45
            max_seconds = eta_sec + buffer_sec
            if elapsed_seconds >= max_seconds:
                res = "expired" if is_predictive else ("intercepted" if is_fast_threat else "expired")
                reason = (f"Прогноз не реалізувався (офіційну тривогу не оголошено, час підльоту {int(elapsed_seconds)}с вичерпано)"
                          if is_predictive else
                          f"Час підльоту загрози {t_type} ({int(elapsed_seconds)}с) вичерпано без підтвердження тривоги")
                return True, res, f"{reason}. Загрозу знято."
        else:
            # Загроза без точного ETA у жовтій зоні без сирени (швидке очищення непідтверджених загроз)
            if is_predictive:
                max_seconds = 120 if is_fast_threat else 240  # 2 хв для ракет/КАБ, 4 хв для БпЛА
            else:
                max_seconds = 180 if is_fast_threat else 360  # 3 хв для ракет/КАБ, 6 хв для БпЛА
            
            if elapsed_seconds >= max_seconds:
                res = "expired"
                return True, res, f"Перевищено максимальний час очікування у жовтій зоні ({int(elapsed_seconds)}с). Загрозу знято."

    # ПРАВИЛО 2: Загальний таймаут польоту під час тривоги (запобігає вічним зависанням)
    max_seconds = get_missile_max_flight_seconds(t_type)
    if elapsed_seconds >= max_seconds:
        res = "intercepted" if (is_fast_threat and not is_predictive) else "expired"
        reason_label = "Прогноз не реалізувався" if is_predictive else ("Збито ППО або відбій небезпеки" if is_fast_threat else "Час польоту вичерпано")
        return True, res, f"{reason_label}. Перевищено максимальний час польоту ({int(elapsed_seconds)} сек). Траєкторію вилучено."

    return False, "", ""


def prune_expired_missile_threats(threat_manager: Any, official_alarms_dict: Dict[str, bool]) -> List[Dict[str, Any]]:
    """
    Періодично перевіряє всі активні загрози та траєкторії ракет у всіх областях,
    вилучаючи протерміновані загрози або загрози у знятих тривогах.
    """
    cleared_summary = []
    now_dt = datetime.now(timezone.utc)

    for region, state in list(threat_manager.threats.items()):
        is_official = official_alarms_dict.get(region, False)
        
        # Перевіряємо кожну загрозу в області
        for threat in list(state.active_threats):
            should_expire, res_type, reason = should_expire_missile_threat(threat, is_official, now_dt)
            if should_expire:
                logger.info(f"🚀 [Missile-Lifecycle] Зняття загрози для {region} (тип: {threat.threat_type}, група: {threat.group_id}): {reason}")
                
                # Точне визначення accuracy для AI навчання
                if not is_official:
                    accuracy_hint = "overestimated" if (threat.is_predictive or res_type == "expired") else "mitigated"
                else:
                    accuracy_hint = "confirmed" if res_type == "intercepted" else "mitigated"
                
                clearing_telemetry = {
                    "linked_group_id": threat.group_id,
                    "resolution_type": res_type,
                    "prediction_accuracy_hint": accuracy_hint,
                    "damage_assessment": "none",
                    "impact_confirmed": (res_type == "intercepted"),
                    "clearing_context_tags": ["missile_lifecycle", res_type, "yellow_zone_pruning" if not is_official else "alarm_pruning"]
                }
                
                # Логуємо зняття в БД
                try:
                    from database.analytics_db import log_clearing_to_db
                    log_clearing_to_db(
                        region=region,
                        clearing_telemetry=clearing_telemetry,
                        source_channel="MissileLifecycleService",
                        message_text=reason,
                        clearing_confidence=threat.confidence or 80,
                        was_predictive=threat.is_predictive
                    )
                except Exception as db_err:
                    logger.error(f"⚠️ Не вдалося записати зняття ракетної загрози у БД: {db_err}")

                # Знімаємо загрозу в менеджері
                threat_manager.clear_threat(region, clearing_telemetry=clearing_telemetry, threat_type=threat.threat_type, group_id=threat.group_id)
                cleared_summary.append({
                    "region": region,
                    "threat_type": threat.threat_type,
                    "group_id": threat.group_id,
                    "reason": reason
                })

    # Clean up any stale active paired_events in DB older than 2 hours
    try:
        from database.connection import execute_write
        stale_cleanup_sql = """
            UPDATE paired_events
            SET lifecycle_status = 'cleared',
                prediction_accuracy = CASE 
                    WHEN prediction_accuracy IS NOT NULL AND prediction_accuracy != '' THEN prediction_accuracy
                    WHEN was_predictive = 1 THEN 'overestimated'
                    ELSE 'mitigated'
                END
            WHERE lifecycle_status = 'active'
              AND created_at <= datetime('now', '-2 hours')
        """
        execute_write(stale_cleanup_sql)
    except Exception as cleanup_err:
        logger.debug(f"[Missile-Lifecycle] DB stale cleanup error: {cleanup_err}")

    return cleared_summary

