"""
SirenUA Notification & Sound Verification Policy Engine.
Defines verification pauses, hysteresis buffers, and priority rules for FCM push notifications on ThreatServer.
"""

# ==============================================================================
# VERIFICATION DELAY BUFFERS (SECONDS)
# ==============================================================================

# Затримка верифікації для локальних ШІ-загроз (БпЛА, КАБ, ракети): 5.0 секунд
# Якщо загроза знімається в межах 5.0с — пуші загрози та відбою не надсилаються
AI_THREAT_VERIFICATION_DELAY: float = 5.0

# Затримка верифікації для офіційних тривог (alerts.in.ua / API): 2.0 секунди
# Запобігає микро-флікерам при нестабільному зв'язку з джерелом даних
OFFICIAL_ALARM_VERIFICATION_DELAY: float = 2.0

# Вікно утримання для відбоїв
CLEARANCE_HOLD_WINDOW: float = 10.0


def get_verification_delay(is_official: bool, is_test: bool, level: str) -> float:
    """
    Повертає необхідну секудну затримку верифікації перед відправкою FCM пуша.

    - Ручні тести (is_test=True) ➔ 0.0с (миттєво)
    - Відбої (level='none') ➔ 0.0с (скасування пендінгу обробляється окремо)
    - Офіційна сирена (is_official=True) ➔ OFFICIAL_ALARM_VERIFICATION_DELAY (2.0с)
    - Локальна ШІ-загроза (is_official=False) ➔ AI_THREAT_VERIFICATION_DELAY (5.0с)
    """
    if is_test or level == "none":
        return 0.0
    if is_official:
        return OFFICIAL_ALARM_VERIFICATION_DELAY
    return AI_THREAT_VERIFICATION_DELAY
