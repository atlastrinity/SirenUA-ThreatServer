"""
FCM Push Notification Service Helpers.
"""

import re
from database.connection import _log_error
from core.config import logger


# Re-use the canonical topic mapping from db_helpers (single source of truth).
# Occupied territories (Crimea, Luhansk) are present in the mapping for lookup
# purposes, but upstream guards in ThreatState/MockThreatManager prevent
# threats from ever reaching this layer for those regions.
from database.db_helpers import TOPIC_MAPPING as REGION_TOPIC_MAP


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
    Надсилає тихий FCM data-push БЕЗ звуку.
    Звук, вібрація та рівень переривання визначаються виключно iOS-клієнтом
    на основі локальних налаштувань користувача (6 рубільників).
    """
    fcm_topic = get_fcm_topic(topic)

    try:
        from firebase_admin import messaging
    except ImportError:
        logger.error("firebase_admin не встановлено, пропуск відправки FCM.")
        _log_error("database_helpers", "firebase_admin не встановлено", "send_fcm_notification", error_type="firebase_error")
        return False

    is_clear = (title == "none" or topic == "none" or kwargs.get("level") == "none")
    is_official = kwargs.get("is_official", False) or kwargs.get("is_official_alarm", False)

    # Format user-facing title and body
    if is_clear:
        if is_official:
            final_title = f"🟢 ВІДБІЙ ТРИВОГИ — {topic}"
            final_body = "Офіційну тривогу завершено." if not body or body == "none" else body
        else:
            final_title = f"🟢 ВІДБІЙ ЗАГРОЗИ — {topic}"
            final_body = "Загрозу нейтралізовано. Можна залишати укриття." if not body or body == "none" else body
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

    def _send():
        try:
            if is_clear:
                event_type = "clear" if is_official else "threat_clear"
                sound_file = "vidbiy.wav" if is_official else "clearance.wav"
            else:
                event_type = "alarm" if is_official else "threat"
                sound_file = "siren.wav" if is_official else "warning.wav"

            fcm_data = {
                "region": topic,
                "level": "none" if is_clear else kwargs.get("level", "high"),
                "is_official": "true" if is_official else "false",
                # For iOS NotificationServiceExtension: determines which user toggle to check
                "event_type": event_type,
                "sound_file": sound_file,
            }
            if isinstance(data, dict):
                for k, v in data.items():
                    fcm_data[k] = str(v)
            for k, v in kwargs.items():
                if v is not None and k not in fcm_data:
                    fcm_data[k] = str(v)

            # Тихий APNS push — без звуку, без critical.
            # iOS-клієнт сам вирішує чи грати звук на основі своїх налаштувань.
            aps = messaging.Aps(
                sound="default",
                content_available=True,
                mutable_content=True,
                badge=0 if is_clear else 1,
            )
            apns_config = messaging.APNSConfig(
                headers={
                    "apns-priority": "10",
                    "apns-push-type": "alert",
                },
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
            logger.info(f"🔔 [FCM Sent] Надіслано (silent) в топік {fcm_topic} (raw: {topic}): {response}")
            return True
        except Exception as e:
            logger.error(f"Помилка відправки FCM у топік {fcm_topic} (raw: {topic}): {e}")
            _log_error("database_helpers", f"Помилка відправки FCM: {e}", "send_fcm_notification", context=f"topic={fcm_topic}", error_type="firebase_error")
            return False

    import threading
    threading.Thread(target=_send, daemon=True).start()
    return True


