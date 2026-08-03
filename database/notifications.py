"""
FCM Push Notification Service Helpers.
"""

from database.connection import _log_error
from core.config import logger


def send_fcm_notification(topic: str, title: str = "", body: str = "", data: dict = None, **kwargs):
    """
    Асинхронно відправляє FCM сповіщення (Firebase Cloud Messaging).
    """
    try:
        from firebase_admin import messaging
    except ImportError:
        logger.error("firebase_admin не встановлено, пропуск відправки FCM.")
        _log_error("database_helpers", "firebase_admin не встановлено", "send_fcm_notification", error_type="firebase_error")
        return False

    # Extract optional notification arguments if positional title/body were omitted
    if not title and "threat_type" in kwargs:
        title = f"Загроза: {kwargs.get('threat_type')}"
    if not body and "detail" in kwargs:
        body = kwargs.get("detail", "")

    def _send():
        try:
            fcm_data = {k: str(v) for k, v in data.items()} if isinstance(data, dict) else {}
            for k, v in kwargs.items():
                if v is not None and k not in fcm_data:
                    fcm_data[k] = str(v)

            message = messaging.Message(
                notification=messaging.Notification(
                    title=title,
                    body=body,
                ),
                data=fcm_data,
                topic=topic,
            )
            response = messaging.send(message)
            logger.info(f"🔔 [FCM Sent] Успішно відправлено в топік {topic}: {response}")
            return True
        except Exception as e:
            logger.error(f"Помилка відправки FCM у топік {topic}: {e}")
            _log_error("database_helpers", f"Помилка відправки FCM: {e}", "send_fcm_notification", context=f"topic={topic}", error_type="firebase_error")
            return False

    import threading
    threading.Thread(target=_send, daemon=True).start()
    return True
