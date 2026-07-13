"""
Firebase Admin SDK Initialization.
Reads credentials from environment or default file paths and initializes the app.
"""

import os
from core.config import logger
from database.db_helpers import HAS_FIREBASE


def init_firebase():
    """Initialize Firebase Admin SDK from credentials found in env or filesystem."""
    if not HAS_FIREBASE:
        logger.warning("Бібліотека firebase-admin не встановлена. Сповіщення не надсилатимуться.")
        return

    try:
        import firebase_admin
        from firebase_admin import credentials
    except ImportError:
        return

    cred_env = os.environ.get("FIREBASE_CREDENTIALS_JSON")
    if cred_env:
        if cred_env.strip().startswith("{"):
            try:
                import json
                cred_dict = json.loads(cred_env)
                cred = credentials.Certificate(cred_dict)
                firebase_admin.initialize_app(cred)
                logger.info("Firebase Admin SDK ініціалізовано за допомогою JSON-рядка з змінної оточення.")
                return
            except Exception as e:
                logger.error(f"Помилка ініціалізації Firebase за JSON-рядком: {e}")

        if os.path.exists(cred_env):
            try:
                cred = credentials.Certificate(cred_env)
                firebase_admin.initialize_app(cred)
                logger.info(f"Firebase Admin SDK ініціалізовано за допомогою файлу: {cred_env}")
                return
            except Exception as e:
                logger.error(f"Помилка ініціалізації Firebase за файлом ключів: {e}")

    default_paths = ["threat_server/firebase-credentials.json", "firebase-credentials.json"]
    for path in default_paths:
        if os.path.exists(path):
            try:
                cred = credentials.Certificate(path)
                firebase_admin.initialize_app(cred)
                logger.info(f"Firebase Admin SDK ініціалізовано за допомогою дефолтного файлу: {path}")
                return
            except Exception as e:
                logger.error(f"Помилка ініціалізації Firebase за дефолтним файлом {path}: {e}")

    try:
        firebase_admin.initialize_app()
        logger.info("Firebase Admin SDK ініціалізовано (Default Credentials / Env).")
    except Exception:
        logger.warning("Не знайдено credentials. Сповіщення у фоні не працюватимуть.")
