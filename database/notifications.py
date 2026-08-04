"""
FCM Push Notification Service Helpers.
"""

import re
from database.connection import _log_error
from core.config import logger


# Mapping of Ukrainian region/city names to FCM topic slugs.
# Must match iOS client NotificationManager.swift topicMapping.
REGION_TOPIC_MAP: dict[str, str] = {
    "Вінницька область":        "region_vinnytsia",
    "Волинська область":         "region_volyn",
    "Дніпропетровська область":  "region_dnipro",
    "Донецька область":          "region_donetsk",
    "Житомирська область":       "region_zhytomyr",
    "Закарпатська область":      "region_zakarpattya",
    "Запорізька область":        "region_zaporizhzhya",
    "Івано-Франківська область": "region_if",
    "Київська область":          "region_kyiv_oblast",
    "м. Київ":                   "region_kyiv_city",
    "Кіровоградська область":    "region_kirovohrad",
    "Луганська область":         "region_luhansk",
    "Львівська область":         "region_lviv",
    "Миколаївська область":      "region_mykolaiv",
    "Одеська область":           "region_odesa",
    "Полтавська область":        "region_poltava",
    "Рівненська область":        "region_rivne",
    "Сумська область":           "region_sumy",
    "Тернопільська область":     "region_ternopil",
    "Харківська область":        "region_kharkiv",
    "Херсонська область":        "region_kherson",
    "Хмельницька область":       "region_khmelnytskyi",
    "Черкаська область":         "region_cherkasy",
    "Чернівецька область":       "region_chernivtsi",
    "Чернігівська область":      "region_chernihiv",
    "Автономна Республіка Крим": "region_crimea",
    "АР Крим":                   "region_crimea",
    "м. Севастополь":            "region_sevastopol",
}


def get_fcm_topic(raw_topic: str) -> str:
    """
    Converts a region name or raw topic into a valid FCM topic slug.
    FCM topic names must match [a-zA-Z0-9-_.~%]+.
    """
    if not raw_topic:
        return "all"

    if raw_topic in REGION_TOPIC_MAP:
        return REGION_TOPIC_MAP[raw_topic]

    if re.match(r"^[a-zA-Z0-9-_.~%]+$", raw_topic):
        return raw_topic

    sanitized = re.sub(r"[^a-zA-Z0-9-_.~%]+", "_", raw_topic).strip("_")
    return sanitized if sanitized else "all"


def send_fcm_notification(topic: str, title: str = "", body: str = "", data: dict = None, **kwargs):
    """
    Асинхронно відправляє FCM сповіщення (Firebase Cloud Messaging).
    Підтримує APNs Критичні Сповіщення (Critical Alerts) зі звуком сирени/відбою,
    що обходять безшумний режим iOS.
    """
    fcm_topic = get_fcm_topic(topic)

    try:
        from firebase_admin import messaging
    except ImportError:
        logger.error("firebase_admin не встановлено, пропуск відправки FCM.")
        _log_error("database_helpers", "firebase_admin не встановлено", "send_fcm_notification", error_type="firebase_error")
        return False

    play_sound = kwargs.get("play_sound", True)
    is_clear = (title == "none" or topic == "none" or kwargs.get("level") == "none")

    # Format user-facing title and body
    if is_clear:
        final_title = f"🟢 ВІДБІЙ ТРИВОГИ — {topic}"
        final_body = "Загрозу нейтралізовано. Можна залишати укриття." if not body or body == "none" else body
        sound_file = "vidbiy.wav"
    else:
        if title in ("high", "critical", "moderate", "low", "warning"):
            final_title = f"🚨 ПОВІТРЯНА ТРИВОГА — {topic}"
        elif title:
            final_title = title
        else:
            final_title = f"🚨 ПОВІТРЯНА ТРИВОГА — {topic}"

        detail_text = kwargs.get("detail") or (data if isinstance(data, str) else "")
        if detail_text:
            final_body = str(detail_text)
        elif body and body not in ("high", "critical", "moderate", "low", "shahed", "ballistic", "cruise_missile"):
            final_body = body
        else:
            threat_name = kwargs.get("threat_type") or "Повітряна загроза"
            final_body = f"Виявлено загрозу ({threat_name}). Прямуйте в укриття!"

        sound_file = "siren.wav"

    def _send():
        try:
            fcm_data = {
                "region": topic,
                "sound_name": sound_file if play_sound else "",
                "is_critical": "true" if play_sound else "false",
                "level": "none" if is_clear else kwargs.get("level", "high"),
            }
            if isinstance(data, dict):
                for k, v in data.items():
                    fcm_data[k] = str(v)
            for k, v in kwargs.items():
                if v is not None and k not in fcm_data:
                    fcm_data[k] = str(v)

            # APNs Payload for iOS Critical Alerts & Custom Sounds
            apns_config = None
            if play_sound:
                critical_sound = messaging.CriticalSound(
                    name=sound_file,
                    critical=True,
                    volume=1.0
                )
                aps = messaging.Aps(
                    sound=critical_sound,
                    content_available=True,
                    mutable_content=True,
                    badge=0 if is_clear else 1,
                    custom_data={"interruption-level": "critical"}
                )
                apns_config = messaging.APNSConfig(
                    headers={
                        "apns-priority": "10",
                        "apns-push-type": "alert",
                    },
                    payload=messaging.APNSPayload(aps=aps)
                )
            else:
                aps = messaging.Aps(
                    sound=None,
                    content_available=True,
                    badge=0 if is_clear else 1,
                )
                apns_config = messaging.APNSConfig(
                    headers={"apns-priority": "5"},
                    payload=messaging.APNSPayload(aps=aps)
                )

            message = messaging.Message(
                notification=messaging.Notification(
                    title=final_title,
                    body=final_body,
                ),
                data=fcm_data,
                topic=fcm_topic,
                apns=apns_config,
            )
            response = messaging.send(message)
            logger.info(f"🔔 [FCM Sent] Успішно відправлено в топік {fcm_topic} (raw: {topic}, sound: {sound_file if play_sound else 'silent'}): {response}")
            return True
        except Exception as e:
            logger.error(f"Помилка відправки FCM у топік {fcm_topic} (raw: {topic}): {e}")
            _log_error("database_helpers", f"Помилка відправки FCM: {e}", "send_fcm_notification", context=f"topic={fcm_topic}", error_type="firebase_error")
            return False

    import threading
    threading.Thread(target=_send, daemon=True).start()
    return True


