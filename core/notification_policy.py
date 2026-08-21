"""
SirenUA Notification & Sound Verification Policy Engine.
Defines verification pauses, hysteresis buffers, and priority rules for FCM push notifications on ThreatServer.
Encapsulates thread-safe timer scheduling, cancellation, and pending buffer state.
"""

import os
import threading
from typing import Optional, Callable, Dict
from database.db_helpers import send_fcm_notification

# ==============================================================================
# VERIFICATION DELAY BUFFERS (SECONDS)
# ==============================================================================

# Затримка верифікації для локальних ШІ-загроз (БпЛА, КАБ, ракети): 10.0 секунд
# Якщо загроза знімається в межах 10.0с — пуші загрози та відбою не надсилаються
AI_THREAT_VERIFICATION_DELAY: float = 10.0

# Затримка верифікації для офіційних тривог (alerts.in.ua / API): 5.0 секунд
# Запобігає микро-флікерам при нестабільному зв'язку з джерелом даних
OFFICIAL_ALARM_VERIFICATION_DELAY: float = 5.0

# Вікно утримання для відбоїв
CLEARANCE_HOLD_WINDOW: float = 10.0


def get_verification_delay(is_official: bool, is_test: bool, level: str) -> float:
    """
    Повертає необхідну секундну затримку верифікації перед відправкою FCM пуша.
    """
    if is_test or level == "none":
        return 0.0
    if is_official:
        return OFFICIAL_ALARM_VERIFICATION_DELAY
    return AI_THREAT_VERIFICATION_DELAY


class FCMNotificationScheduler:
    """
    Автономний менеджер верифікаційних затримок та буферизації сповіщень.
    Інкапсулює зняття з пендінгу, блокування потоків та скасування таймерів.
    """

    def __init__(self):
        self._pending_timers: Dict[str, threading.Timer] = {}
        self._lock = threading.Lock()

    def schedule_notification(
        self,
        region: str,
        level: str,
        threat_type: Optional[str],
        detail: Optional[str],
        confidence: Optional[int],
        eta: Optional[str],
        is_official_alarm: bool,
        is_test: bool,
        active_check_fn: Optional[Callable[[str], bool]] = None
    ):
        """
        Планує відправку FCM пуша з верифікаційною паузою.
        При повторній події для тієї ж області попередній таймер скасовується.
        """
        if "PYTEST_CURRENT_TEST" in os.environ or os.environ.get("ENV") == "test":
            return

        with self._lock:
            existing_timer = self._pending_timers.pop(region, None)
            if existing_timer:
                existing_timer.cancel()

        delay = get_verification_delay(is_official_alarm, is_test, level)

        if delay <= 0.0:
            try:
                threading.Thread(
                    target=send_fcm_notification,
                    args=(region, level, threat_type, detail),
                    kwargs={
                        "confidence": confidence,
                        "eta": eta,
                        "is_official_alarm": is_official_alarm,
                        "is_test": is_test
                    },
                    daemon=True
                ).start()
            except Exception as fcm_err:
                print(f"⚠️ Помилка старту фонової відправки FCM: {fcm_err}")
            return

        label = "Офіційну тривогу" if is_official_alarm else "ШІ-загрозу"

        def _execute_send():
            with self._lock:
                self._pending_timers.pop(region, None)

            if active_check_fn is None or active_check_fn(region):
                try:
                    send_fcm_notification(
                        region, level, threat_type, detail,
                        confidence=confidence, eta=eta,
                        is_official_alarm=is_official_alarm, is_test=is_test
                    )
                    print(f"🛡️ [NotificationPolicy] Верифіковано та відправлено {label} для {region} (після {delay}с перевірки)")
                except Exception as err:
                    print(f"⚠️ Помилка відправки верифікованого сповіщення: {err}")

        timer = threading.Timer(delay, _execute_send)
        with self._lock:
            self._pending_timers[region] = timer
        timer.start()
        print(f"⏳ [NotificationPolicy] {label} для {region} поставлено на {delay}с верифікаційну паузу...")

    def cancel_pending(self, region: str) -> bool:
        """
        Скасовує пендінг-таймер для області, якщо він існує.
        Повертає True, якщо загроза була на верифікаційній паузі і її скасовано.
        """
        with self._lock:
            pending_timer = self._pending_timers.pop(region, None)
            if pending_timer:
                pending_timer.cancel()
                print(f"🔇 [NotificationPolicy] Сповіщення для {region} скасовано в межах верифікаційної паузи! Жодного пуша не надсилалося.")
                return True
        return False
