import os
import sys
import asyncio
from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.errors import SessionPasswordNeededError

TELEGRAM_API_ID = 20294647
TELEGRAM_API_HASH = "454a9c055308a8d118608bb6b032bc30"
SESSION_NAME = "sirenua_userbot_session"

def update_env_file(session_string: str):
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.exists(env_path):
        env_path = ".env"
        
    lines = []
    found = False
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("TELEGRAM_SESSION_STRING="):
                    lines.append(f'TELEGRAM_SESSION_STRING="{session_string}"\n')
                    found = True
                else:
                    lines.append(line)
                    
    if not found:
        lines.append(f'\n# Telethon Authenticated Session String\nTELEGRAM_SESSION_STRING="{session_string}"\n')
        
    with open(env_path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    print(f"✅ TELEGRAM_SESSION_STRING успішно збережено у {env_path}")

async def authenticate_interactive():
    print("\n=======================================================")
    print("🔐 SirenUA Telegram MTProto Userbot Авторизація")
    print("=======================================================")
    
    client = TelegramClient(SESSION_NAME, TELEGRAM_API_ID, TELEGRAM_API_HASH)
    await client.connect()
    
    if await client.is_user_authorized():
        print("✅ Клієнт вже успішно авторизований!")
        session_str = StringSession.save(client.session)
        update_env_file(session_str)
        await client.disconnect()
        return

    phone = input("📱 Введіть номер телефону Telegram (у міжнародному форматі, наприклад +380991234567): ").strip()
    if not phone:
        print("❌ Номер телефону не може бути порожнім.")
        await client.disconnect()
        return

    print(f"📡 Відправка запиту на код підтвердження для {phone}...")
    sent = await client.send_code_request(phone)
    phone_code_hash = sent.phone_code_hash
    print(f"📩 Код надіслано в додаток Telegram на номер {phone}.")

    code = input("🔑 Введіть отриманий 5-значний код: ").strip()
    try:
        await client.sign_in(phone=phone, code=code, phone_code_hash=phone_code_hash)
    except SessionPasswordNeededError:
        password = input("🔒 Введіть пароль двофакторної автентифікації (2FA cloud password): ").strip()
        await client.sign_in(password=password)

    if await client.is_user_authorized():
        print("\n🎉 Авторизація успішна!")
        session_str = StringSession.save(client.session)
        update_env_file(session_str)
        print("=======================================================\n")
    else:
        print("❌ Не вдалося авторизуватись. Перевірте введені дані.")

    await client.disconnect()

if __name__ == "__main__":
    asyncio.run(authenticate_interactive())
