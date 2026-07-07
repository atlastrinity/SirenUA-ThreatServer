import asyncio
from telethon import TelegramClient
from telethon.sessions import StringSession

# API credentials
TELEGRAM_API_ID = 20294647
TELEGRAM_API_HASH = "454a9c055308a8d118608bb6b032bc30"

async def main():
    session_file = "sirenua_userbot_session"
    client = TelegramClient(session_file, TELEGRAM_API_ID, TELEGRAM_API_HASH)
    
    try:
        await client.connect()
        if await client.is_user_authorized():
            # Generate session string correctly from SQLite session
            session_str = StringSession.save(client.session)
            print("\n==================================================")
            print("🎉 Конвертація успішна!")
            print("Скопіюйте наведений нижче рядок і додайте його в")
            print("налаштування (Environment Variables) на Render:\n")
            print("КЛЮЧ: TELEGRAM_SESSION_STRING")
            print(f"ЗНАЧЕННЯ: {session_str}")
            print("==================================================\n")
        else:
            print("❌ Сесію не знайдено або вона не авторизована.")
    except Exception as e:
        print(f"❌ Виникла помилка: {e}")
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
