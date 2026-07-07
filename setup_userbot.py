import asyncio
import os
from telethon import TelegramClient

# API credentials from configuration
TELEGRAM_API_ID = 20294647
TELEGRAM_API_HASH = "454a9c055308a8d118608bb6b032bc30"
SESSION_PATH = "sirenua_userbot_session"

async def main():
    print("==================================================")
    print("      SirenUA Telegram Userbot Session Setup     ")
    print("==================================================")
    print("ВАЖЛИВО: Код підтвердження надійде у ваш офіційний")
    print("додаток Telegram на телефоні або ПК, а НЕ по СМС!")
    print("Будь ласка, тримайте додаток Telegram відкритим.")
    print("==================================================\n")

    client = TelegramClient(SESSION_PATH, TELEGRAM_API_ID, TELEGRAM_API_HASH)
    
    try:
        await client.connect()
        
        if not await client.is_user_authorized():
            phone = input("Введіть ваш номер телефону (наприклад, +380501234567): ").strip()
            
            # Send code request
            sent_code = await client.send_code_request(phone)
            
            code = input("Введіть код підтвердження (з повідомлення від Telegram): ").strip()
            
            try:
                await client.sign_in(phone, code)
            except Exception as e:
                # Handle 2FA password if enabled
                if "Two-step verification" in str(e) or "password" in str(e).lower():
                    password = input("Введіть пароль двофакторної аутентифікації (2FA): ").strip()
                    await client.sign_in(password=password)
                else:
                    raise e
                    
        me = await client.get_me()
        print(f"\n✅ Успішно авторизовано як: {me.first_name} (@{me.username or 'без_юзернейму'})")
        print(f"💾 Файл сесії збережено: {os.path.abspath(SESSION_PATH + '.session')}")
        
        # Test reading from kpszsu channel to verify permissions
        print("\n⏳ Тестуємо читання каналу Повітряних Сил (@kpszsu)...")
        entity = await client.get_input_entity("kpszsu")
        messages = await client.get_messages(entity, limit=1)
        if messages:
            print(f"👉 Останній пост: \"{messages[0].text[:80]}...\"")
            print("🎉 Тест успішний! Юзербот працює на 100%.")
        else:
            print("⚠️ Не вдалося прочитати повідомлення з каналу.")
            
    except Exception as e:
        print(f"\n❌ Виникла помилка: {e}")
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
