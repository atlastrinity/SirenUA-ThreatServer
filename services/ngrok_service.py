"""
SirenUA Ngrok Tunnel Manager & Watchdog Service.
Automatically verifies, starts, and maintains the ngrok tunnel on server startup/restart.
"""

import os
import shutil
import asyncio
import subprocess
import aiohttp
from core.config import logger, NGROK_DOMAIN

ENABLE_NGROK = os.environ.get("ENABLE_NGROK", "true").lower() == "true"
NGROK_AUTHTOKEN = os.environ.get("NGROK_AUTHTOKEN")
PORT = int(os.environ.get("PORT", 8085))
NGROK_API_URL = "http://127.0.0.1:4040/api/tunnels"


async def is_ngrok_tunnel_active(target_domain: str = None) -> bool:
    """Checks if the local ngrok client is running and serving the desired tunnel."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(NGROK_API_URL, timeout=aiohttp.ClientTimeout(total=2.0)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    tunnels = data.get("tunnels", [])
                    if not tunnels:
                        return False
                    if not target_domain:
                        return True
                    for t in tunnels:
                        public_url = t.get("public_url", "")
                        if target_domain in public_url:
                            return True
                    return True
    except Exception:
        return False
    return False


def setup_ngrok_authtoken():
    """Applies NGROK_AUTHTOKEN from configuration if present."""
    if not NGROK_AUTHTOKEN:
        return
    ngrok_bin = shutil.which("ngrok")
    if not ngrok_bin:
        return
    try:
        subprocess.run(
            [ngrok_bin, "config", "add-authtoken", NGROK_AUTHTOKEN],
            capture_output=True,
            timeout=5.0
        )
    except Exception as e:
        logger.warning(f"⚠️ [Ngrok] Не вдалося встановити authtoken: {e}")


def launch_ngrok_process(domain: str, port: int) -> bool:
    """Spawns the ngrok background process."""
    ngrok_bin = shutil.which("ngrok")
    if not ngrok_bin:
        logger.warning("⚠️ [Ngrok] Утиліту 'ngrok' не знайдено на системі. Автозапуск пропущено.")
        return False

    cmd = [ngrok_bin, "http"]
    if domain:
        cmd.append(f"--domain={domain}")
    cmd.append(str(port))

    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
        return True
    except Exception as e:
        logger.error(f"❌ [Ngrok] Помилка запуску процесу ngrok: {e}")
        return False


async def ensure_ngrok_running():
    """Verifies that ngrok is running and launches it in background if needed."""
    if not ENABLE_NGROK:
        logger.info("ℹ️ [Ngrok] Автозапуск вимкнено через ENABLE_NGROK=false.")
        return

    domain = NGROK_DOMAIN or "bobbing-armchair-daylong.ngrok-free.dev"

    if await is_ngrok_tunnel_active(domain):
        logger.info(f"✅ [Ngrok] Тунель вже активний: https://{domain} -> port {PORT}")
        return

    setup_ngrok_authtoken()
    logger.info(f"⚡ [Ngrok] Запуск фонового тунелю https://{domain} -> port {PORT}...")
    success = launch_ngrok_process(domain, PORT)
    if not success:
        return

    # Wait up to 6 seconds for tunnel startup
    for _ in range(6):
        await asyncio.sleep(1.0)
        if await is_ngrok_tunnel_active(domain):
            logger.info(f"🟢 [Ngrok] Тунель успішно запущено: https://{domain}")
            return

    logger.warning(f"⚠️ [Ngrok] Процес ngrok запущено, але статус API ще очікується.")


async def ngrok_watchdog_loop():
    """Background watchdog task that periodically verifies and revives ngrok if it drops."""
    if not ENABLE_NGROK:
        return
    domain = NGROK_DOMAIN or "bobbing-armchair-daylong.ngrok-free.dev"
    while True:
        await asyncio.sleep(15.0)  # Check every 15 seconds for rapid auto-recovery
        try:
            active = await is_ngrok_tunnel_active(domain)
            if not active:
                logger.warning(f"🔄 [Ngrok Watchdog] Тунель ngrok не відповідає. Спроба відновлення...")
                await ensure_ngrok_running()
        except Exception as e:
            logger.debug(f"[Ngrok Watchdog] Помилка перевірки: {e}")
