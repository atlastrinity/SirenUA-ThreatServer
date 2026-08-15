"""
SirenUA Missile Lifecycle Service.
Calculates realistic missile flight times and enforces automatic expiration & trajectory removal
when flight duration elapses or official alarms in transit corridors clear.
"""

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
    1. Для прямих швидкісних загроз (ракета/балістика/КАБ, is_predictive=False): якщо офіційна тривога в області знята
       і минуло щонайменше 90 секунд з моменту появи — загроза вважається завершеною (приліт/збиття).
    2. Для прогнозних загроз (жовті зони, is_predictive=True): відсутність офіційної тривоги є штатним станом
       (вони існують ДО включення сирени), тому вони знімаються за кінематичним розрахунком часу (ETA/таймаут).
    3. Якщо минув максимальний час польоту (elapsed_seconds > max_flight_seconds) — загроза знімається (expired).
    
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

    # ПРАВИЛО 1: Прямі загрози (ракети, балістика, КАБи, Шахеди, БпЛА) при знятті офіційної тривоги
    if not is_predictive and not is_official_alarm_active:
        if elapsed_seconds >= 60:  # Буфер 60с для синхронізації з сиренами
            res = "intercepted" if is_fast_threat else "expired"
            return True, res, f"Офіційну тривогу в області знято. Пряму загрозу {t_type} завершено (збито ППО або відбій небезпеки)."

    # ПРАВИЛО 2: Минув максимальний час польоту за кінематикою / ETA
    eta_sec = getattr(threat_item, "eta_seconds", None)
    if is_predictive:
        if eta_sec and eta_sec > 0:
            if is_fast_threat:
                buffer_sec = 30  # Швидкісні ракети/балістика/КАБ: 30 секунд буфера
            elif THREAT_SHAHED in t_type:
                buffer_sec = 90  # Шахеди/БпЛА: 90 секунд (1.5 хв) буфера
            else:
                buffer_sec = 45
            max_seconds = eta_sec + buffer_sec
        else:
            if is_fast_threat:
                max_seconds = 300  # 5 хвилин максимум для швидкісних без ETA
            elif THREAT_SHAHED in t_type:
                max_seconds = 1200 # 20 хвилин для Шахедів без ETA
            else:
                max_seconds = get_missile_max_flight_seconds(t_type)
    else:
        max_seconds = get_missile_max_flight_seconds(t_type)

    if elapsed_seconds >= max_seconds:
        res = "intercepted" if (is_fast_threat and not is_official_alarm_active and not is_predictive) else "expired"
        reason_label = "Прогноз не реалізувався (ціль змінила курс або ліквідована)" if is_predictive else ("Збито ППО або відбій небезпеки" if is_fast_threat else "Час польоту вичерпано")
        return True, res, f"{reason_label}. Перевищено час польоту ({int(elapsed_seconds)} сек). Траєкторію вилучено."

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
                
                clearing_telemetry = {
                    "linked_group_id": threat.group_id,
                    "resolution_type": res_type,
                    "prediction_accuracy_hint": "confirmed" if res_type == "intercepted" else "overestimated",
                    "damage_assessment": "none",
                    "impact_confirmed": (res_type == "intercepted"),
                    "clearing_context_tags": ["missile_lifecycle", res_type]
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

    return cleared_summary
