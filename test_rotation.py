import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath('/Users/dev/Documents/GitHub/claw-code/serena/SirenUA/threat_server'))

from analyzer.gemini_analyzer import GeminiThreatAnalyzer
import google.generativeai as genai

os.environ["GEMINI_API_KEYS"] = "key1_exhausted,key2_exhausted,key3_working"

async def main():
    analyzer = GeminiThreatAnalyzer()
    print(f"\n[Тест] Знайдено ключів: {len(analyzer.api_keys)}")
    
    call_count = 0
    
    async def mock_generate_content_async(self_model, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        current_key = analyzer.api_keys[analyzer.current_key_idx]
        
        print(f"   [Мок-запит] Спроба {call_count}, використовується ключ: {current_key}")
        
        if "exhausted" in current_key:
            print("   [Мок-сервер] Повертаю помилку 429 Rate Limit...")
            raise Exception("429 Resource has been exhausted (e.g. check quota).")
        else:
            print("   [Мок-сервер] Успішна генерація!")
            class MockResponse:
                text = '[{"threat_level": "low", "is_clear": false}]'
            return MockResponse()
    
    # Мокаємо метод на рівні класу, щоб він не злітав при перестворенні моделі
    genai.GenerativeModel.generate_content_async = mock_generate_content_async
    
    messages = [{"channel": "test", "text": "Тестове повідомлення"}]
    
    print("\n[Тест] Починаємо аналіз батчу...")
    results = await analyzer.analyze_batch(messages)
    
    print(f"\n[Результат] Отримано відповідей: {len(results)}")
    print(f"[Результат] Дані: {results}")
    print(f"[Результат] Фінальний індекс ключа: {analyzer.current_key_idx} (Ключ: {analyzer.api_keys[analyzer.current_key_idx]})")

if __name__ == "__main__":
    asyncio.run(main())
