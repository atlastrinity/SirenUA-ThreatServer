import asyncio
from telethon import TelegramClient

API_ID = 20294647
API_HASH = "454a9c055308a8d118608bb6b032bc30"
SESSION_NAME = "sirenua_userbot_session"

async def main():
    print("=== АВТОРИЗАЦІЯ TELEGRAM ===")
    print("Зараз тебе попросять ввести номер телефону та код.")
    
    # Використовуємо ті ж параметри пристрою, щоб не було помилки з'єднання
    client = TelegramClient(
        SESSION_NAME, 
        API_ID, 
        API_HASH,
        device_model="iPhone 16 Pro Max",
        system_version="iOS 17.5.1",
        app_version="10.14.1"
    )
    
    await client.start()
    
    me = await client.get_me()
    print(f"\n✅ УСПІХ! Авторизовано як: {me.first_name}")
    print("✅ Файл сесії успішно збережено. Тепер можна запускати сервер!")

if __name__ == '__main__':
    asyncio.run(main())
